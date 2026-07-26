// Package main runs the Aegis extension end-to-end test.
//
// The point of the test is not that a payout comes out — it is that the payout
// can only come out of weather data the Flare Data Connector attested to:
//
//  1. setExtensionId on the deployed InstructionSender (idempotent)
//  2. ask an FDC verifier to encode one Web2Json attestation request per policy
//     (Open-Meteo rainfall over the policy's coverage window)
//  3. bind each policy on-chain to exactly that request (registerPolicyTrigger)
//  4. submit both attestation requests to FdcHub
//  5. meanwhile, ECIES-encrypt each insurer model and load it into the TEE
//  6. wait for the voting round to finalize and pull the Merkle proofs from the
//     Data Availability Layer
//  7. prove the raw-rainfall path is gone: the old evaluate(bytes32,uint256,address)
//     selector is absent from the deployed bytecode, and an attestation belonging
//     to another policy is rejected on-chain
//  8. evaluate both policies with their proofs and check each signed decision
//     against what the hidden model implies for the attested rainfall
//  9. settle those decisions on-chain and check the FXRP actually moved: the
//     recipient gained exactly what the enclave signed, the pool lost exactly
//     that, and the decision cannot be replayed
//
// Two policies cover the same location but different seasons, so the readings
// come from real history and cannot be chosen by the test: a dry-season window
// that should trigger a payout, and a wet-season window that should not.
//
// The model parameters live in this file only because the test plays the role of
// the insurer: it is the one party that legitimately knows them. They travel to
// the TEE encrypted and must never appear in an instruction message, an action
// result, or a log line — assertNoSecrets checks exactly that.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"sign-extension/pkg/types"
	"sign-extension/tools/pkg/configs"
	"sign-extension/tools/pkg/contracts/settlement"
	"sign-extension/tools/pkg/contracts/sign"
	"sign-extension/tools/pkg/fccutils"
	"sign-extension/tools/pkg/fdc"
	"sign-extension/tools/pkg/payout"
	"sign-extension/tools/pkg/support"
	instrutils "sign-extension/tools/pkg/utils"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	teetypes "github.com/flare-foundation/tee-node/pkg/types"
	"github.com/pkg/errors"
)

// testPayoutTo is the policyholder address the decision must echo back.
var testPayoutTo = common.HexToAddress("0x000000000000000000000000000000000000dEaD")

// proofTimeout bounds the wait on one voting round. Flare quotes 90–180 seconds
// for finalization, so four minutes is already generous — and since a round that
// finalizes without the request never produces the proof no matter how long the
// wait, patience past that point buys nothing. Re-requesting (see proofAttempts)
// is what actually recovers.
const proofTimeout = 4 * time.Minute

// testPolicy is one policy under test: an id, the public weather feed it settles
// on, and what the attested reading is expected to do to the payout.
type testPolicy struct {
	label         string
	id            common.Hash
	feed          fdc.DroughtFeed
	shouldTrigger bool

	// Filled in as the test progresses.
	abiEncodedRequest []byte
	votingRound       uint64
	proof             *sign.IWeb2JsonProof

	// decision is the signed action result the enclave returned, kept so the
	// settlement step can relay the very bytes step 8 checked.
	decision *teetypes.ActionResponse
}

// testPolicies covers one location over two seasons. Surabaya's dry season is
// reliably below the insurer's trigger and its wet season reliably above it, but
// the test asserts that rather than assuming it.
//
// Policy ids are scoped to the run. They have to be: a policy pays once and
// closes, and its trigger binding is write-once, so fixed ids would let this
// test pass exactly once per deployment and fail ever after — the worst kind of
// test, since the second failure looks like a regression. The readable prefix is
// kept so logs still say which policy is which.
func testPolicies(runNonce []byte) []*testPolicy {
	const (
		latitude  = "-7.25"
		longitude = "112.75"
	)

	return []*testPolicy{
		{
			label:         "dry season (drought)",
			id:            policyID(0xa3d1, runNonce),
			shouldTrigger: true,
			feed: fdc.DroughtFeed{
				LatitudeDeg:  latitude,
				LongitudeDeg: longitude,
				StartDate:    "2025-06-01",
				EndDate:      "2025-08-31",
			},
		},
		{
			label:         "wet season (normal)",
			id:            policyID(0xa3d2, runNonce),
			shouldTrigger: false,
			feed: fdc.DroughtFeed{
				LatitudeDeg:  latitude,
				LongitudeDeg: longitude,
				StartDate:    "2024-12-01",
				EndDate:      "2025-02-28",
			},
		},
	}
}

// policyID builds a run-unique policy id that still reads as an 0xa3d1-style
// identifier in logs: two bytes of prefix, then the run's nonce.
func policyID(prefix uint16, runNonce []byte) common.Hash {
	var id common.Hash
	id[0] = byte(prefix >> 8)
	id[1] = byte(prefix)
	copy(id[2:], runNonce)

	return id
}

// newRunNonce draws the 30 bytes that make this run's policy ids unique.
func newRunNonce() []byte {
	nonce := make([]byte, 30)
	if _, err := rand.Read(nonce); err != nil {
		fccutils.FatalWithCause(errors.Errorf("drawing a run nonce: %s", err))
	}

	return nonce
}

// testModel is the insurer's confidential model: cover starts below 120.0 mm of
// cumulative rainfall and reaches the full sum insured at or below 40.0 mm,
// scaled by a hidden 0.9 factor. Both policies use it, so any difference in
// outcome comes from the attested rainfall alone.
//
// Amounts are in the payout asset's smallest unit, which for the FXRP executor
// is 1e-6 FXRP. A sum insured of 5 FXRP keeps the whole demo inside what one
// direct mint from the XRPL testnet faucet funds, while staying far enough above
// the dust floor that the ramp is visible.
func testModel() types.ModelParameters {
	return types.ModelParameters{
		TriggerTenthsMm: 1200,
		ExitTenthsMm:    400,
		SumInsuredUnits: big.NewInt(5_000_000), // 5 FXRP
		PayoutFactorBps: 9000,
		MinPayoutUnits:  big.NewInt(100_000), // 0.1 FXRP
	}
}

// secretStrings are the decimal renderings of the model parameters. None of them
// may appear in anything the chain or the proxy can see (FR-8, rule 7).
func secretStrings() []string {
	m := testModel()
	return []string{
		fmt.Sprint(m.TriggerTenthsMm),
		fmt.Sprint(m.ExitTenthsMm),
		m.SumInsuredUnits.String(),
		fmt.Sprint(m.PayoutFactorBps),
		m.MinPayoutUnits.String(),
	}
}

func main() {
	af := flag.String("a", configs.AddressesFile, "file with deployed addresses")
	cf := flag.String("c", configs.ChainNodeURL, "chain node url")
	pf := flag.String("p", configs.ExtensionProxyURL, "extension proxy url")
	instructionSenderF := flag.String("instructionSender", os.Getenv("INSTRUCTION_SENDER"), "InstructionSender contract address")
	settlementF := flag.String("settlement", os.Getenv("POLICY_SETTLEMENT"), "PolicySettlement contract address")
	flag.Parse()

	if *instructionSenderF == "" {
		logger.Fatal("--instructionSender flag is required (or set INSTRUCTION_SENDER in .env)")
	}
	if *settlementF == "" {
		logger.Fatal("--settlement flag is required (or set POLICY_SETTLEMENT in config/settlement.env). " +
			"Deploy it with: go run ./cmd/deploy-settlement --instructionSender <address>")
	}

	instructionSenderAddress := common.HexToAddress(*instructionSenderF)
	settlementAddress := common.HexToAddress(*settlementF)

	testSupport, err := support.DefaultSupport(*af, *cf)
	if err != nil {
		fccutils.FatalWithCause(err)
	}

	policies := testPolicies(newRunNonce())
	fdcClient := fdc.NewClient()

	// --- Step 0: the pool has to be able to cover the worst case ---
	//
	// Checked before anything is spent. An FDC round costs a fee and three
	// minutes, and discovering at the very end that the pool is empty would
	// report as a settlement bug rather than as an unfunded demo.
	pool := checkPoolCanCover(testSupport, settlementAddress, testModel().SumInsuredUnits)

	// --- Step 1: setExtensionId ---
	logger.Infof("Step 1: Setting extension ID on InstructionSender...")
	if err := instrutils.SetExtensionId(testSupport, instructionSenderAddress); err != nil {
		if strings.Contains(err.Error(), "already set") || strings.Contains(err.Error(), "Extension ID already set") {
			logger.Infof("  Extension ID already set on contract, continuing")
		} else {
			fccutils.FatalWithCause(errors.Errorf(
				"setExtensionId failed — is the extension registered? Check pre-build.sh completed. Error: %s", err))
		}
	} else {
		logger.Infof("  Extension ID set.")
	}

	// --- Step 2: encode one attestation request per policy ---
	logger.Infof("Step 2: Encoding Web2Json attestation requests at the FDC verifier...")
	for _, p := range policies {
		requestBody, err := p.feed.RequestBody()
		if err != nil {
			fccutils.FatalWithCause(errors.Errorf("building request body (%s): %s", p.label, err))
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		encoded, err := fdcClient.PrepareRequest(ctx, requestBody)
		cancel()
		if err != nil {
			fccutils.FatalWithCause(errors.Errorf("prepareRequest (%s): %s", p.label, err))
		}
		p.abiEncodedRequest = encoded

		logger.Infof("  %s: %s %s..%s (%d byte request)",
			p.label, fdc.OpenMeteoArchiveURL, p.feed.StartDate, p.feed.EndDate, len(encoded))

		// --- Step 3: bind the policy to that exact request ---
		bindPolicyTrigger(testSupport, instructionSenderAddress, p, requestBody)
	}

	// --- Step 4: submit the attestation requests ---
	logger.Infof("Step 4: Submitting attestation requests to FdcHub...")
	for _, p := range policies {
		round, txHash, err := fdc.SubmitRequest(testSupport, p.abiEncodedRequest)
		if err != nil {
			fccutils.FatalWithCause(errors.Errorf("submit attestation request (%s): %s", p.label, err))
		}
		p.votingRound = round
		logger.Infof("  %s: voting round %d (tx %s)", p.label, round, txHash.Hex())
	}

	// --- Step 5: load the confidential models into the TEE while the round runs ---
	logger.Infof("Step 5: Fetching TEE public key from extension proxy...")
	teeInfo, err := fccutils.TeeInfo(*pf)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("fetch TEE info: %s", err))
	}

	ecdsaPub, err := teetypes.ParsePubKey(teeInfo.MachineData.PublicKey)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("parse TEE public key: %s", err))
	}

	eciesPub := &ecies.PublicKey{
		X:      ecdsaPub.X,
		Y:      ecdsaPub.Y,
		Curve:  ecies.DefaultCurve,
		Params: ecies.ECIES_AES128_SHA256,
	}

	for _, p := range policies {
		registerModel(testSupport, instructionSenderAddress, *pf, eciesPub, p)
	}

	// --- Step 6: collect the Merkle proofs ---
	logger.Infof("Step 6: Waiting for the FDC voting rounds to finalize (90-180s)...")
	for _, p := range policies {
		proof := collectProof(testSupport, fdcClient, p)
		p.proof = proof

		reading, err := fdc.DecodeWeatherReading(proof)
		if err != nil {
			fccutils.FatalWithCause(errors.Errorf("decode weather reading (%s): %s", p.label, err))
		}
		logger.Infof("  %s: attested rainfall %s tenths of mm at %s/%s (round %d, %d proof nodes)",
			p.label, reading.RainfallTenthsMm,
			microDegrees(reading.LatitudeMicroDeg), microDegrees(reading.LongitudeMicroDeg),
			proof.Data.VotingRound, len(proof.MerkleProof))

		assertSeasonMakesSense(p, reading.RainfallTenthsMm)
	}

	// --- Step 7: the raw-rainfall path must be closed ---
	assertRawRainfallPathRemoved(testSupport, instructionSenderAddress)
	assertForeignAttestationRejected(testSupport, instructionSenderAddress, policies)

	// --- Step 8: evaluate both policies against their own attestations ---
	for _, p := range policies {
		reading, err := fdc.DecodeWeatherReading(p.proof)
		if err != nil {
			fccutils.FatalWithCause(errors.Errorf("decode weather reading (%s): %s", p.label, err))
		}

		payout := runEvaluate(testSupport, instructionSenderAddress, *pf, p)

		// The expected payout is recomputed here from the same parameters the
		// insurer registered and the rainfall the FDC attested — the point is that
		// only the insurer and the enclave can do this arithmetic.
		expected := expectedPayout(testModel(), reading.RainfallTenthsMm)
		if payout.Cmp(expected) != 0 {
			fccutils.FatalWithCause(errors.Errorf(
				"FAIL (%s): payout %s wei does not match the model's %s wei for %s tenths of mm",
				p.label, payout, expected, reading.RainfallTenthsMm))
		}
		if p.shouldTrigger && payout.Sign() == 0 {
			fccutils.FatalWithCause(errors.Errorf(
				"FAIL (%s): attested rainfall %s tenths of mm should have paid out, got zero",
				p.label, reading.RainfallTenthsMm))
		}
		if !p.shouldTrigger && payout.Sign() != 0 {
			fccutils.FatalWithCause(errors.Errorf(
				"FAIL (%s): rainfall above the trigger must not pay out, got %s units", p.label, payout))
		}

		logger.Infof("Decision (%s): %s %s", p.label, pool.format(payout), pool.symbol)
	}

	// --- Step 9: settle the decisions and check the money actually moved ---
	for _, p := range policies {
		settlePolicy(testSupport, settlementAddress, pool, p)
	}
	assertReplayRejected(testSupport, settlementAddress, policies[0])

	logger.Infof("All tests passed.")
}

// proofAttempts is how many voting rounds a request gets before the run gives up.
//
// One attempt is not enough. Data providers attest a request by re-fetching the
// source, and a public weather API that is slow or rate-limiting them at that
// moment simply leaves the request out of the round's Merkle tree — silently,
// and for that round only. It is not a failure of anything Aegis built, but it
// does fail the run, which during a recorded demo is indistinguishable from a
// broken payout path. Re-requesting costs one more FDC fee and one more round.
const proofAttempts = 3

// collectProof waits for a policy's attestation to be provable, re-requesting it
// in a fresh round if the round it went into came back without it.
//
// Deliberately NOT done: reusing a proof from some earlier round the request may
// already sit in. Evaluations must move forward — InstructionSender rejects an
// attestation older than the last one a policy accepted — and quietly reaching
// for a stale round would hollow out that check to make a test go green.
func collectProof(s *support.Support, client *fdc.Client, p *testPolicy) *sign.IWeb2JsonProof {
	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), proofTimeout)
		proof, err := client.WaitForProof(ctx, p.votingRound, p.abiEncodedRequest, 15*time.Second)
		cancel()

		if err == nil {
			return proof
		}
		if attempt >= proofAttempts {
			fccutils.FatalWithCause(errors.Errorf(
				"retrieve proof (%s): giving up after %d rounds — the last was %d. "+
					"The round finalizes either way, so this means data providers did not attest "+
					"the request; check the source API is reachable and not rate-limiting them: %s",
				p.label, proofAttempts, p.votingRound, err))
		}

		logger.Warnf("  %s: round %d finalized without attesting the request; re-requesting (attempt %d of %d)",
			p.label, p.votingRound, attempt+1, proofAttempts)

		round, txHash, err := fdc.SubmitRequest(s, p.abiEncodedRequest)
		if err != nil {
			fccutils.FatalWithCause(errors.Errorf("re-submit attestation request (%s): %s", p.label, err))
		}
		p.votingRound = round
		logger.Infof("  %s: re-submitted into voting round %d (tx %s)", p.label, round, txHash.Hex())
	}
}

// bindPolicyTrigger registers the policy's one permitted attestation request, or
// checks the existing registration still matches when the contract is reused.
func bindPolicyTrigger(
	s *support.Support,
	instructionSenderAddress common.Address,
	p *testPolicy,
	requestBody sign.IWeb2JsonRequestBody,
) {
	// Ask the contract for the hash so the registration and the check evaluate()
	// performs are computed by the same code.
	requestHash, err := instrutils.TriggerRequestHash(s, instructionSenderAddress, requestBody)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("triggerRequestHash (%s): %s", p.label, err))
	}

	sender, err := sign.NewInstructionSender(instructionSenderAddress, s.ChainClient)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("bind InstructionSender: %s", err))
	}

	existing, err := sender.PolicyTriggerRequestHash(nil, [32]byte(p.id))
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("read policy trigger (%s): %s", p.label, err))
	}

	switch {
	case common.Hash(existing) == requestHash:
		logger.Infof("  %s: trigger already bound to %s", p.label, requestHash.Hex())
		return
	case common.Hash(existing) != (common.Hash{}):
		// Write-once by design: a live policy cannot be repointed at another feed.
		fccutils.FatalWithCause(errors.Errorf(
			"FAIL (%s): policy is bound to trigger %s, but this run's feed hashes to %s — "+
				"redeploy the contract or use a fresh policy id",
			p.label, common.Hash(existing).Hex(), requestHash.Hex()))
	}

	txHash, err := instrutils.SendRegisterPolicyTrigger(s, instructionSenderAddress, p.id, requestHash)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("registerPolicyTrigger (%s): %s", p.label, err))
	}
	logger.Infof("  %s: trigger bound to %s (tx %s)", p.label, requestHash.Hex(), txHash.Hex())
}

// registerModel seals one policy's model to the enclave public key and loads it.
func registerModel(
	s *support.Support,
	instructionSenderAddress common.Address,
	proxyURL string,
	eciesPub *ecies.PublicKey,
	p *testPolicy,
) {
	registerRequest := types.RegisterModelRequest{PolicyID: p.id, Model: testModel()}
	plaintext, err := registerRequest.Encode()
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("encode register model request (%s): %s", p.label, err))
	}

	ciphertext, err := ecies.Encrypt(rand.Reader, eciesPub, plaintext, nil, nil)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("ECIES encrypt (%s): %s", p.label, err))
	}
	assertSealed(plaintext, ciphertext)

	logger.Infof("  %s: policy %s, encrypted model %d bytes (plaintext never leaves this process)",
		p.label, p.id.Hex(), len(ciphertext))

	registerID, _, err := instrutils.SendRegisterModel(s, instructionSenderAddress, ciphertext)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("registerModel (%s): %s", p.label, err))
	}

	time.Sleep(5 * time.Second)

	registerResp, err := fccutils.ActionResult(proxyURL, registerID)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("poll registerModel (%s): %s", p.label, err))
	}
	if registerResp.Result.Status == 0 {
		fccutils.FatalWithCause(errors.Errorf("registerModel instruction failed (%s): %s", p.label, registerResp.Result.Log))
	}
	logger.Infof("  %s: model registered (status=%d)", p.label, registerResp.Result.Status)
	assertNoSecrets("registerModel action result", []byte(registerResp.Result.Log), registerResp.Result.Data)
}

// runEvaluate sends one evaluate instruction with the policy's attestation, waits
// for the signed decision, and returns the payout amount it carries.
func runEvaluate(
	s *support.Support,
	instructionSenderAddress common.Address,
	proxyURL string,
	p *testPolicy,
) *big.Int {
	logger.Infof("Step 8 (%s): Sending evaluate with the FDC attestation...", p.label)

	evaluateID, _, err := instrutils.SendEvaluate(s, instructionSenderAddress, p.id, testPayoutTo, *p.proof)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("evaluate (%s): %s", p.label, err))
	}
	logger.Infof("  evaluate instruction ID: %s", evaluateID.Hex())

	time.Sleep(5 * time.Second)

	resp, err := fccutils.ActionResult(proxyURL, evaluateID)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("poll evaluate (%s): %s", p.label, err))
	}
	if resp.Result.Status == 0 {
		fccutils.FatalWithCause(errors.Errorf("evaluate instruction failed (%s): %s", p.label, resp.Result.Log))
	}

	decision, err := types.DecodeEvaluateResponse(resp.Result.Data)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("decode evaluate response (%s): %s", p.label, err))
	}

	if decision.PolicyID != p.id {
		fccutils.FatalWithCause(errors.Errorf(
			"FAIL (%s): decision is for policy %s, expected %s", p.label, decision.PolicyID.Hex(), p.id.Hex()))
	}
	if decision.PayoutTo != testPayoutTo {
		fccutils.FatalWithCause(errors.Errorf(
			"FAIL (%s): payout address %s, expected %s", p.label, decision.PayoutTo.Hex(), testPayoutTo.Hex()))
	}

	logger.Infof("  Decision: policy=%s payout=%s units to %s",
		decision.PolicyID.Hex(), decision.PayoutAmount, decision.PayoutTo.Hex())

	// The TEE identity signs every action result; without that signature the
	// decision would be worth no more than an off-chain promise.
	if len(resp.Signature) == 0 {
		fccutils.FatalWithCause(errors.Errorf("FAIL (%s): action result carries no TEE signature", p.label))
	}
	logger.Infof("  TEE signature: %s", hex.EncodeToString(resp.Signature))

	assertNoSecrets(fmt.Sprintf("evaluate action result (%s)", p.label),
		[]byte(resp.Result.Log), resp.Result.Data)

	p.decision = resp

	return decision.PayoutAmount
}

// payoutPool is everything the settlement checks need to know about the money:
// which token, how it renders, and where the float sits.
type payoutPool struct {
	token    *payout.ERC20
	executor common.Address
	symbol   string
	decimals uint8
}

func (p *payoutPool) format(amount *big.Int) string {
	return payout.FormatUnits(amount, p.decimals)
}

func (p *payoutPool) balanceOf(account common.Address) *big.Int {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	balance, err := p.token.BalanceOf(ctx, account)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("reading balance of %s: %s", account.Hex(), err))
	}

	return balance
}

// checkPoolCanCover resolves the payout asset behind the settlement contract and
// refuses to start unless the pool could pay the largest claim the model can
// produce.
//
// Reading the executor out of the settlement contract rather than taking it as a
// flag also proves the wiring: if setPayoutExecutor was never called, this is
// where the run stops, before an FDC fee is spent.
func checkPoolCanCover(s *support.Support, settlementAddress common.Address, worstCase *big.Int) *payoutPool {
	logger.Infof("Step 0: Checking the payout pool...")

	contract, err := settlement.NewPolicySettlement(settlementAddress, s.ChainClient)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("binding PolicySettlement at %s: %s", settlementAddress.Hex(), err))
	}

	executor, err := contract.PayoutExecutor(nil)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("reading payoutExecutor: %s", err))
	}
	if executor == (common.Address{}) {
		fccutils.FatalWithCause(errors.Errorf(
			"FAIL: %s has no payout executor — run cmd/deploy-settlement, which wires one up",
			settlementAddress.Hex()))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	fxrp, err := payout.ResolveFxrp(ctx, s.ChainClient)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("resolving FXRP: %s", err))
	}
	token, err := payout.NewERC20(fxrp, s.ChainClient)
	if err != nil {
		fccutils.FatalWithCause(err)
	}
	symbol, decimals, err := token.Metadata(ctx)
	if err != nil {
		fccutils.FatalWithCause(err)
	}

	pool := &payoutPool{token: token, executor: executor, symbol: symbol, decimals: decimals}
	balance := pool.balanceOf(executor)

	logger.Infof("  Settlement: %s", settlementAddress.Hex())
	logger.Infof("  Executor:   %s holding %s %s", executor.Hex(), pool.format(balance), symbol)

	if balance.Cmp(worstCase) < 0 {
		fccutils.FatalWithCause(errors.Errorf(
			"FAIL: the pool holds %s %s but this model can owe up to %s — fund it with "+
				"cmd/fund-pool (mint test FXRP as described in TUTORIAL.md §8)",
			pool.format(balance), symbol, pool.format(worstCase)))
	}

	return pool
}

// settlePolicy relays one signed decision to PolicySettlement and checks the
// money moved exactly as the decision said it would.
//
// This is the assertion Phase 4 exists for. Everything before it proves the
// enclave decided correctly in private; this proves the chain acted on that
// decision, for the amount the enclave signed, without anyone having to be
// trusted in between.
func settlePolicy(
	s *support.Support,
	settlementAddress common.Address,
	pool *payoutPool,
	p *testPolicy,
) {
	logger.Infof("Step 9 (%s): Settling the signed decision...", p.label)

	if p.decision == nil {
		fccutils.FatalWithCause(errors.Errorf("FAIL (%s): no decision to settle", p.label))
	}

	recipientBefore := pool.balanceOf(testPayoutTo)
	poolBefore := pool.balanceOf(pool.executor)

	txHash, decision, err := payout.Settle(s, settlementAddress, p.decision)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("settle (%s): %s", p.label, err))
	}
	logger.Infof("  settle tx: %s", txHash.Hex())
	// The enclave that signed is recovered off-chain from the same preimage the
	// contract used, so the log names the machine the chain just believed.
	logger.Infof("  signed by TEE %s", decision.TeeID.Hex())

	recipientAfter := pool.balanceOf(testPayoutTo)
	poolAfter := pool.balanceOf(pool.executor)

	recipientDelta := new(big.Int).Sub(recipientAfter, recipientBefore)
	poolDelta := new(big.Int).Sub(poolBefore, poolAfter)

	if recipientDelta.Cmp(decision.PayoutAmount) != 0 {
		fccutils.FatalWithCause(errors.Errorf(
			"FAIL (%s): the enclave decided %s %s but the recipient received %s",
			p.label, pool.format(decision.PayoutAmount), pool.symbol, pool.format(recipientDelta)))
	}
	// The pool must fund the payout exactly — no more left it, no third party
	// topped it up mid-settlement.
	if poolDelta.Cmp(decision.PayoutAmount) != 0 {
		fccutils.FatalWithCause(errors.Errorf(
			"FAIL (%s): the pool moved %s %s for a %s payout",
			p.label, pool.format(poolDelta), pool.symbol, pool.format(decision.PayoutAmount)))
	}

	// And the chain must have recorded it, so the policy cannot be paid again.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	record, err := payout.SettlementOf(ctx, s, settlementAddress, p.id)
	if err != nil {
		fccutils.FatalWithCause(err)
	}
	if !record.Settled {
		fccutils.FatalWithCause(errors.Errorf("FAIL (%s): policy is not recorded as settled", p.label))
	}
	if record.Amount.Cmp(decision.PayoutAmount) != 0 {
		fccutils.FatalWithCause(errors.Errorf(
			"FAIL (%s): recorded %s %s, decision said %s",
			p.label, pool.format(record.Amount), pool.symbol, pool.format(decision.PayoutAmount)))
	}
	if record.InstructionID != p.decision.Result.ID {
		fccutils.FatalWithCause(errors.Errorf(
			"FAIL (%s): recorded instruction %s, settled %s",
			p.label, record.InstructionID.Hex(), p.decision.Result.ID.Hex()))
	}

	if p.shouldTrigger {
		if record.PayoutTo != testPayoutTo {
			fccutils.FatalWithCause(errors.Errorf(
				"FAIL (%s): recorded recipient %s, expected %s",
				p.label, record.PayoutTo.Hex(), testPayoutTo.Hex()))
		}
		logger.Infof("  Paid %s %s to %s (pool now %s)",
			pool.format(decision.PayoutAmount), pool.symbol, testPayoutTo.Hex(), pool.format(poolAfter))
	} else {
		// A policy that owes nothing still closes on-chain, and must not have
		// touched the pool.
		if decision.PayoutAmount.Sign() != 0 {
			fccutils.FatalWithCause(errors.Errorf(
				"FAIL (%s): a wet-season policy settled for %s %s",
				p.label, pool.format(decision.PayoutAmount), pool.symbol))
		}
		logger.Infof("  Closed with nothing owed; the pool is untouched at %s %s",
			pool.format(poolAfter), pool.symbol)
	}
}

// assertReplayRejected proves the settlement record does real work: the same
// signed decision, presented a second time, must not pay again.
//
// Simulated rather than sent, so the check costs no gas and reports the contract's
// own revert reason instead of an opaque failure.
func assertReplayRejected(s *support.Support, settlementAddress common.Address, p *testPolicy) {
	logger.Infof("Step 9: Checking a settled decision cannot be replayed...")

	parsed, err := settlement.PolicySettlementMetaData.GetAbi()
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("loading PolicySettlement ABI: %s", err))
	}

	callData, err := parsed.Pack(
		"settle",
		[32]byte(p.decision.Result.ID),
		p.decision.Result.Status,
		string(p.decision.Result.SubmissionTag),
		[]byte(p.decision.Result.Data),
		[]byte(p.decision.Signature),
	)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("packing replayed settle: %s", err))
	}

	from := crypto.PubkeyToAddress(s.Prv.PublicKey)
	reason := fccutils.SimulateAndDecodeRevert(s.ChainClient, from, settlementAddress, big.NewInt(0), callData)

	// PolicySettlement reverts with custom errors, and the shared decoder only
	// understands Error(string) — so it hands back the raw revert data. Match on
	// the selector instead, derived from the ABI rather than typed out, so a
	// renamed error fails the build instead of silently never matching.
	guard := replayGuardSelectors(parsed)
	if !matchesAnySelector(reason, guard) {
		fccutils.FatalWithCause(errors.Errorf(
			"FAIL: replaying a settled decision was not rejected by a replay guard (got: %q, "+
				"expected one of %v)", reason, guard))
	}

	logger.Infof("  Replay of %s rejected by the settlement record (%s)", p.label, reason)
}

// replayGuardSelectors returns the 4-byte selectors of the two errors that mean
// "this has already been settled", as hex strings.
func replayGuardSelectors(parsed *abi.ABI) []string {
	selectors := make([]string, 0, 2)
	for _, name := range []string{"DecisionAlreadySettled", "PolicyAlreadySettled"} {
		customError, ok := parsed.Errors[name]
		if !ok {
			fccutils.FatalWithCause(errors.Errorf(
				"PolicySettlement ABI has no %s error — was the replay guard renamed?", name))
		}
		selectors = append(selectors, hex.EncodeToString(customError.ID.Bytes()[:4]))
	}

	return selectors
}

func matchesAnySelector(revertData string, selectors []string) bool {
	trimmed := strings.ToLower(strings.TrimPrefix(revertData, "0x"))
	for _, selector := range selectors {
		if strings.HasPrefix(trimmed, selector) {
			return true
		}
	}

	return false
}

// expectedPayout mirrors the enclave's scoring function so the test can check
// the decision without asking the enclave to explain itself.
func expectedPayout(m types.ModelParameters, rainfallTenthsMm *big.Int) *big.Int {
	trigger := new(big.Int).SetUint64(m.TriggerTenthsMm)
	exit := new(big.Int).SetUint64(m.ExitTenthsMm)

	if rainfallTenthsMm.Cmp(trigger) >= 0 {
		return new(big.Int)
	}

	shortfall := new(big.Int).Sub(trigger, rainfallTenthsMm)
	span := new(big.Int).Sub(trigger, exit)
	if shortfall.Cmp(span) > 0 {
		shortfall = span
	}

	payout := new(big.Int).Mul(m.SumInsuredUnits, shortfall)
	payout.Mul(payout, new(big.Int).SetUint64(m.PayoutFactorBps))
	payout.Div(payout, new(big.Int).Mul(span, big.NewInt(10_000)))

	if payout.Cmp(m.SumInsuredUnits) > 0 {
		payout.Set(m.SumInsuredUnits)
	}
	if payout.Cmp(m.MinPayoutUnits) < 0 {
		return new(big.Int)
	}
	return payout
}

// assertSeasonMakesSense fails early if the historical window no longer sits on
// the side of the trigger the test expects, so a surprising payout is reported as
// bad test data rather than as a broken enclave.
func assertSeasonMakesSense(p *testPolicy, rainfallTenthsMm *big.Int) {
	trigger := new(big.Int).SetUint64(testModel().TriggerTenthsMm)

	if p.shouldTrigger && rainfallTenthsMm.Cmp(trigger) >= 0 {
		fccutils.FatalWithCause(errors.Errorf(
			"FAIL (%s): window %s..%s attested %s tenths of mm, which is not a drought under this model",
			p.label, p.feed.StartDate, p.feed.EndDate, rainfallTenthsMm))
	}
	if !p.shouldTrigger && rainfallTenthsMm.Cmp(trigger) < 0 {
		fccutils.FatalWithCause(errors.Errorf(
			"FAIL (%s): window %s..%s attested %s tenths of mm, which is below the trigger",
			p.label, p.feed.StartDate, p.feed.EndDate, rainfallTenthsMm))
	}
}

// assertRawRainfallPathRemoved checks the deployed bytecode no longer dispatches
// the pre-FDC entry point that took a caller-supplied rainfall figure.
//
// Solidity embeds every external function's selector in its dispatcher, so the
// old selector being absent from the runtime code — while the new one is present —
// is direct evidence that no caller can reach the enclave with an unattested
// number, not merely that the current ABI omits it.
func assertRawRainfallPathRemoved(s *support.Support, instructionSenderAddress common.Address) {
	logger.Infof("Step 7: Checking the raw-rainfall entry point is gone...")

	code, err := s.ChainClient.CodeAt(context.Background(), instructionSenderAddress, nil)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("reading deployed bytecode: %s", err))
	}
	if len(code) == 0 {
		fccutils.FatalWithCause(errors.Errorf("no contract deployed at %s", instructionSenderAddress.Hex()))
	}

	rawSelector := selector("evaluate(bytes32,uint256,address)")
	attestedSelector := selector("evaluate(bytes32,address,(bytes32[],(bytes32,bytes32,uint64,uint64,(string,string,string,string,string,string,string),(bytes))))")

	if bytes.Contains(code, rawSelector) {
		fccutils.FatalWithCause(errors.Errorf(
			"FAIL: deployed contract still dispatches evaluate(bytes32,uint256,address) (selector 0x%x) — "+
				"unattested rainfall can still reach the enclave", rawSelector))
	}
	if !bytes.Contains(code, attestedSelector) {
		fccutils.FatalWithCause(errors.Errorf(
			"FAIL: deployed contract does not dispatch the attested evaluate (selector 0x%x) — "+
				"is %s the contract this test just deployed?", attestedSelector, instructionSenderAddress.Hex()))
	}

	logger.Infof("  Raw path absent (0x%x), attested path present (0x%x).", rawSelector, attestedSelector)
}

// assertForeignAttestationRejected proves the binding does real work: a perfectly
// valid FDC attestation that belongs to another policy must not settle this one.
func assertForeignAttestationRejected(
	s *support.Support,
	instructionSenderAddress common.Address,
	policies []*testPolicy,
) {
	if len(policies) < 2 {
		return
	}
	victim, foreign := policies[0], policies[1]

	parsed, err := sign.InstructionSenderMetaData.GetAbi()
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("loading InstructionSender ABI: %s", err))
	}
	callData, err := parsed.Pack("evaluate", [32]byte(victim.id), testPayoutTo, *foreign.proof)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("packing cross-policy evaluate: %s", err))
	}

	from := crypto.PubkeyToAddress(s.Prv.PublicKey)
	reason := fccutils.SimulateAndDecodeRevert(
		s.ChainClient, from, instructionSenderAddress, instrutils.DefaultFee, callData,
	)
	if !strings.Contains(reason, "attestation is not this policy's trigger") {
		fccutils.FatalWithCause(errors.Errorf(
			"FAIL: an attestation of another policy's feed was not rejected as expected (got: %q)", reason))
	}

	logger.Infof("  Attestation of %s rejected for policy %s: %s", foreign.label, victim.label, reason)
}

func selector(signature string) []byte {
	return crypto.Keccak256([]byte(signature))[:4]
}

// microDegrees renders a coordinate scaled by 1e6 back into degrees, for logs only.
func microDegrees(v *big.Int) string {
	f := new(big.Float).Quo(new(big.Float).SetInt(v), big.NewFloat(1e6))
	return f.Text('f', 6)
}

// assertSealed checks the on-chain instruction message really is sealed: the
// plaintext model must not survive anywhere inside the ciphertext.
func assertSealed(plaintext, ciphertext []byte) {
	if bytes.Contains(ciphertext, plaintext) {
		fccutils.FatalWithCause(errors.New("FAIL: registerModel message carries the plaintext model"))
	}
	assertNoSecrets("registerModel instruction message", ciphertext)
}

// assertNoSecrets fails the run if a model parameter shows up somewhere public.
//
// The blobs are searched as raw bytes rather than as hex: hex-encoding random
// ciphertext turns every byte into two characters drawn from the same alphabet
// as a decimal parameter, so short parameters would match by chance and the test
// would fail at random. Structural leaks are covered separately — the decision
// payload is decoded and every field checked against its expected value.
func assertNoSecrets(label string, blobs ...[]byte) {
	for _, blob := range blobs {
		for _, secret := range secretStrings() {
			if bytes.Contains(blob, []byte(secret)) {
				fccutils.FatalWithCause(errors.Errorf("FAIL: %s leaks a model parameter", label))
			}
		}
	}
}
