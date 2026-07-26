package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"strings"
	"time"

	"sign-extension/pkg/types"
	"sign-extension/tools/pkg/contracts/sign"
	"sign-extension/tools/pkg/fdc"
	"sign-extension/tools/pkg/payout"
	"sign-extension/tools/pkg/support"
	instrutils "sign-extension/tools/pkg/utils"

	teetypes "github.com/flare-foundation/tee-node/pkg/types"
	"github.com/pkg/errors"
)

// proofAttempts is how many voting rounds one request gets.
//
// One is not enough. Data providers attest a request by re-fetching the source,
// and a public weather API that is slow for them at that moment leaves the
// request out of that round's tree, silently. Re-requesting costs another fee
// and another round, which beats a demo that fails for a reason outside the
// system being demonstrated.
const proofAttempts = 3

// proofTimeout bounds the wait on one round. Flare quotes 90 to 180 seconds, and
// a round that finalizes without the request never produces the proof however
// long anyone waits, so patience past this point buys nothing.
const proofTimeout = 4 * time.Minute

func runEvaluate(args []string) error {
	fs := flag.NewFlagSet("evaluate", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Print(`aegis evaluate, take one policy from weather data to money.

The whole path, in one command:

  1. Ask the Flare Data Connector to attest the policy's weather feed, and wait
     for its voting round to finalize. Expect 90 to 180 seconds.
  2. Send the attested reading to the enclave. The contract forwards it only
     after checking the Merkle proof and that the attestation is the one this
     policy was bound to, so no caller can hand the enclave a rainfall figure.
  3. Collect the signed decision and settle it on chain, where the signature is
     checked against the TEE registry before any funds move.

Usage:
  aegis evaluate [flags]

Flags:
`)
		fs.PrintDefaults()
	}

	flags := addCommonFlags(fs, true)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := flags.resolve()
	if err != nil {
		return err
	}

	// The decision comes back through the proxy, so it has to be up before an
	// FDC fee is spent waiting to find that out.
	if err := cfg.requireProxy(); err != nil {
		return err
	}

	sup, err := cfg.connect()
	if err != nil {
		return err
	}

	state, err := loadState(cfg.stateFile)
	if err != nil {
		return err
	}

	record := state.get(cfg.policyName)
	switch {
	case record == nil:
		return errors.Errorf(
			"no policy %q yet. Run: aegis register-model --policy %s", cfg.policyName, cfg.policyName)
	case !record.ModelRegistered:
		return errors.Errorf(
			"policy %s has no model in the enclave. Run: aegis register-model --policy %s",
			record.PolicyID, cfg.policyName)
	case record.Settled:
		return errors.Errorf(
			"policy %s is already settled, and a policy pays once. Run: aegis register-model --policy %s --new",
			record.PolicyID, cfg.policyName)
	}

	request, err := hex.DecodeString(strings.TrimPrefix(record.AbiEncodedRequest, "0x"))
	if err != nil || len(request) == 0 {
		return errors.Errorf(
			"the stored attestation request for %s is unusable. Run: aegis register-model --policy %s",
			cfg.policyName, cfg.policyName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	pool, err := resolvePool(ctx, sup, cfg.settlement)
	cancel()
	if err != nil {
		return err
	}

	poolBefore, err := pool.balance(pool.executor)
	if err != nil {
		return err
	}
	recipientBefore, err := pool.balance(cfg.payoutTo)
	if err != nil {
		return err
	}

	step("Policy %s", cfg.policyName)
	field("policy id", "%s", record.PolicyID)
	field("bound to", "%s", record.RequestHash)
	field("pool", "%s at %s", pool.format(poolBefore), shorten(pool.executor.Hex()))

	// The largest claim this model can produce is a secret, so the check happens
	// without naming it. An underfunded pool is worth knowing before an FDC fee
	// is spent.
	if poolBefore.Cmp(demoModel().SumInsuredUnits) < 0 {
		warn("the pool may not cover the largest claim this model can produce. Top it up with cmd/fund-pool")
	}

	proof, err := attest(sup, record, request, state)
	if err != nil {
		return err
	}

	reading, err := fdc.DecodeWeatherReading(proof)
	if err != nil {
		return errors.Errorf("decoding the attested reading: %s", err)
	}

	step("Attested reading")
	field("rainfall", "%s mm over the window (%s tenths of a mm)",
		formatTenths(reading.RainfallTenthsMm), reading.RainfallTenthsMm)
	field("location", "%s, %s",
		formatMicroDegrees(reading.LatitudeMicroDeg), formatMicroDegrees(reading.LongitudeMicroDeg))
	field("voting round", "%d, %d Merkle nodes", proof.Data.VotingRound, len(proof.MerkleProof))
	note("this is public history from Open-Meteo, attested by Flare. Nobody in this demo chose it")

	decision, response, err := scoreInEnclave(sup, cfg, record, proof, state)
	if err != nil {
		return err
	}

	return settleDecision(sup, cfg, pool, record, decision, response, poolBefore, recipientBefore, state)
}

// attest submits the policy's attestation request and waits for a proof,
// re-requesting in a fresh round if the round it landed in came back without it.
//
// Deliberately not done: reaching for a proof from some earlier round the
// request may already sit in. Evaluations must move forward, and quietly using a
// stale round would hollow out the contract's anti replay check to make a demo
// look smoother.
func attest(sup *support.Support, record *policyRecord, request []byte, state *demoState) (*sign.IWeb2JsonProof, error) {
	step("Requesting an FDC attestation")

	fee, err := fdc.RequestFee(sup, request)
	if err == nil {
		field("fee", "%s wei, read from the hub", fee)
	}

	for attempt := 1; ; attempt++ {
		round, txHash, err := fdc.SubmitRequest(sup, request)
		if err != nil {
			return nil, errors.Errorf("submitting the attestation request: %s", err)
		}
		record.VotingRound = round
		if saveErr := state.saveWith(record); saveErr != nil {
			return nil, saveErr
		}

		field("voting round", "%d", round)
		field("tx", "%s", txHash.Hex())

		step("Waiting for round %d to finalize", round)
		note("Flare quotes 90 to 180 seconds for a round")

		proof, err := waitForProof(round, request)
		if err == nil {
			return proof, nil
		}
		if attempt >= proofAttempts {
			return nil, errors.Errorf(
				"no proof after %d rounds, the last was %d. The round finalizes either way, so this means the "+
					"data providers did not attest the request. Check the source API is reachable and not rate "+
					"limiting them. Last error: %s",
				proofAttempts, round, err)
		}

		warn("round %d finalized without attesting the request, re-requesting (attempt %d of %d)",
			round, attempt+1, proofAttempts)
	}
}

// waitForProof polls the Data Availability Layer while printing progress, so a
// three minute wait looks like work rather than a hang.
func waitForProof(round uint64, request []byte) (*sign.IWeb2JsonProof, error) {
	type outcome struct {
		proof *sign.IWeb2JsonProof
		err   error
	}

	ctx, cancel := context.WithTimeout(context.Background(), proofTimeout)
	defer cancel()

	done := make(chan outcome, 1)
	go func() {
		proof, err := fdc.NewClient().WaitForProof(ctx, round, request, 15*time.Second)
		done <- outcome{proof, err}
	}()

	started := time.Now()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case result := <-done:
			if result.err == nil {
				progress("proof retrieved after %ds", int(time.Since(started).Seconds()))
			}
			return result.proof, result.err
		case <-ticker.C:
			progress("round %d not provable yet, %ds elapsed", round, int(time.Since(started).Seconds()))
		}
	}
}

// scoreInEnclave sends the attested reading in and collects the signed decision.
func scoreInEnclave(
	sup *support.Support,
	cfg *settings,
	record *policyRecord,
	proof *sign.IWeb2JsonProof,
	state *demoState,
) (*types.EvaluateResponse, *teetypes.ActionResponse, error) {
	step("Scoring the reading inside the enclave")

	instructionID, txHash, err := instrutils.SendEvaluate(
		sup, cfg.instructionSender, record.id(), cfg.payoutTo, *proof)
	if err != nil {
		return nil, nil, errors.Errorf("evaluate: %s", err)
	}
	record.EvaluateInstructionID = instructionID.Hex()
	if saveErr := state.saveWith(record); saveErr != nil {
		return nil, nil, saveErr
	}

	field("instruction", "%s", instructionID.Hex())
	field("tx", "%s", txHash.Hex())

	response, err := waitForActionResult(cfg.proxyURL, instructionID, 2*time.Minute)
	if err != nil {
		return nil, nil, err
	}
	if response.Result.Status == 0 {
		// The model lives in enclave memory and nowhere else, so a restarted
		// stack has genuinely forgotten it. That is the design, not a fault, and
		// the way back is one command.
		return nil, nil, errors.Errorf(
			"the enclave could not evaluate the policy: %s. If the stack restarted since the model was "+
				"registered, enclave memory is gone by design. Run: aegis register-model --policy %s",
			response.Result.Log, cfg.policyName)
	}

	decision, err := types.DecodeEvaluateResponse(response.Result.Data)
	if err != nil {
		return nil, nil, errors.Errorf("decoding the decision: %s", err)
	}
	if decision.PolicyID != record.id() {
		return nil, nil, errors.Errorf(
			"the decision is for policy %s, expected %s", decision.PolicyID.Hex(), record.PolicyID)
	}
	if decision.PayoutTo != cfg.payoutTo {
		return nil, nil, errors.Errorf(
			"the decision pays %s, expected %s", decision.PayoutTo.Hex(), cfg.payoutTo.Hex())
	}
	if len(response.Signature) == 0 {
		return nil, nil, errors.New("the action result carries no TEE signature, so nothing could settle it")
	}

	record.PayoutUnits = decision.PayoutAmount.String()
	if saveErr := state.saveWith(record); saveErr != nil {
		return nil, nil, saveErr
	}

	field("decision", "%s units to %s", decision.PayoutAmount, decision.PayoutTo.Hex())
	field("signature", "%s", hex.EncodeToString(response.Signature))
	note("the parameters that produced this number stayed in enclave memory, and the signature is what makes the number worth acting on")

	return decision, response, nil
}

// settleDecision relays the signed decision and reports what the money did.
func settleDecision(
	sup *support.Support,
	cfg *settings,
	pool *payoutPool,
	record *policyRecord,
	decision *types.EvaluateResponse,
	response *teetypes.ActionResponse,
	poolBefore, recipientBefore *big.Int,
	state *demoState,
) error {
	step("Settling the decision on chain")
	note("anyone may submit this: the authority is in the signature, not in the sender")

	txHash, settled, err := payout.Settle(sup, cfg.settlement, response)
	if err != nil {
		return errors.Errorf("settle: %s", err)
	}
	record.SettleTx = txHash.Hex()
	record.Settled = true
	if saveErr := state.saveWith(record); saveErr != nil {
		return saveErr
	}

	field("settle tx", "%s", txHash.Hex())
	field("signed by", "TEE machine %s, recovered from the signature", settled.TeeID.Hex())

	poolAfter, err := pool.balance(pool.executor)
	if err != nil {
		return err
	}
	recipientAfter, err := pool.balance(cfg.payoutTo)
	if err != nil {
		return err
	}

	poolDelta := new(big.Int).Sub(poolBefore, poolAfter)
	recipientDelta := new(big.Int).Sub(recipientAfter, recipientBefore)

	field("pool", "%s, was %s", pool.format(poolAfter), pool.format(poolBefore))
	field("recipient", "up by %s", pool.format(recipientDelta))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	record2, err := payout.SettlementOf(ctx, sup, cfg.settlement, record.id())
	cancel()
	if err != nil {
		return err
	}
	field("on chain", "settled=%t amount=%s instruction=%s",
		record2.Settled, pool.format(record2.Amount), shorten(record2.InstructionID.Hex()))

	if decision.PayoutAmount.Sign() == 0 {
		verdict("Closed with nothing owed. The pool is untouched at %s.", pool.format(poolAfter))
		note("same model, same location, a different season. The outcome came from the attested data alone")
		return nil
	}

	if recipientDelta.Cmp(decision.PayoutAmount) != 0 || poolDelta.Cmp(decision.PayoutAmount) != 0 {
		return errors.Errorf(
			"the enclave signed %s but the pool moved %s and the recipient received %s",
			pool.format(decision.PayoutAmount), pool.format(poolDelta), pool.format(recipientDelta))
	}

	headline("Payout: %s to %s", pool.format(decision.PayoutAmount), decision.PayoutTo.Hex())

	return nil
}

// formatTenths renders tenths of a millimetre as millimetres.
func formatTenths(tenths *big.Int) string {
	whole := new(big.Int)
	frac := new(big.Int)
	whole.QuoRem(tenths, big.NewInt(10), frac)
	frac.Abs(frac)

	return fmt.Sprintf("%s.%d", whole, frac.Int64())
}

// formatMicroDegrees renders a signed microdegree coordinate, the form the
// attestation carries so the request stays byte reproducible.
func formatMicroDegrees(micro *big.Int) string {
	prefix := ""
	abs := new(big.Int).Abs(micro)
	if micro.Sign() < 0 {
		prefix = "-"
	}

	whole := new(big.Int)
	frac := new(big.Int)
	whole.QuoRem(abs, big.NewInt(1000000), frac)

	return fmt.Sprintf("%s%s.%06d", prefix, whole, frac.Int64())
}
