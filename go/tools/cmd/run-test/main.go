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
	"sign-extension/tools/pkg/contracts/sign"
	"sign-extension/tools/pkg/fccutils"
	"sign-extension/tools/pkg/fdc"
	"sign-extension/tools/pkg/support"
	instrutils "sign-extension/tools/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	teetypes "github.com/flare-foundation/tee-node/pkg/types"
	"github.com/pkg/errors"
)

// testPayoutTo is the policyholder address the decision must echo back.
var testPayoutTo = common.HexToAddress("0x000000000000000000000000000000000000dEaD")

// proofTimeout bounds the wait for a voting round to finalize. Flare quotes
// 90–180 seconds; the extra headroom absorbs a slow round without turning a
// stalled FDC into an hour-long hang.
const proofTimeout = 8 * time.Minute

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
}

// testPolicies covers one location over two seasons. Surabaya's dry season is
// reliably below the insurer's trigger and its wet season reliably above it, but
// the test asserts that rather than assuming it.
func testPolicies() []*testPolicy {
	const (
		latitude  = "-7.25"
		longitude = "112.75"
	)

	return []*testPolicy{
		{
			label:         "dry season (drought)",
			id:            common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000a3d1"),
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
			id:            common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000a3d2"),
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

// testModel is the insurer's confidential model: cover starts below 120.0 mm of
// cumulative rainfall and reaches the full sum insured at or below 40.0 mm,
// scaled by a hidden 0.9 factor. Both policies use it, so any difference in
// outcome comes from the attested rainfall alone.
func testModel() types.ModelParameters {
	return types.ModelParameters{
		TriggerTenthsMm: 1200,
		ExitTenthsMm:    400,
		SumInsuredWei:   big.NewInt(1_000_000_000_000_000_000), // 1 CFLR-equivalent
		PayoutFactorBps: 9000,
		MinPayoutWei:    big.NewInt(1_000_000_000_000),
	}
}

// secretStrings are the decimal renderings of the model parameters. None of them
// may appear in anything the chain or the proxy can see (FR-8, rule 7).
func secretStrings() []string {
	m := testModel()
	return []string{
		fmt.Sprint(m.TriggerTenthsMm),
		fmt.Sprint(m.ExitTenthsMm),
		m.SumInsuredWei.String(),
		fmt.Sprint(m.PayoutFactorBps),
		m.MinPayoutWei.String(),
	}
}

func main() {
	af := flag.String("a", configs.AddressesFile, "file with deployed addresses")
	cf := flag.String("c", configs.ChainNodeURL, "chain node url")
	pf := flag.String("p", configs.ExtensionProxyURL, "extension proxy url")
	instructionSenderF := flag.String("instructionSender", os.Getenv("INSTRUCTION_SENDER"), "InstructionSender contract address")
	flag.Parse()

	if *instructionSenderF == "" {
		logger.Fatal("--instructionSender flag is required (or set INSTRUCTION_SENDER in .env)")
	}

	instructionSenderAddress := common.HexToAddress(*instructionSenderF)

	testSupport, err := support.DefaultSupport(*af, *cf)
	if err != nil {
		fccutils.FatalWithCause(err)
	}

	policies := testPolicies()
	fdcClient := fdc.NewClient()

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
		ctx, cancel := context.WithTimeout(context.Background(), proofTimeout)
		proof, err := fdcClient.WaitForProof(ctx, p.votingRound, p.abiEncodedRequest, 15*time.Second)
		cancel()
		if err != nil {
			fccutils.FatalWithCause(errors.Errorf("retrieve proof (%s): %s", p.label, err))
		}
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
				"FAIL (%s): rainfall above the trigger must not pay out, got %s wei", p.label, payout))
		}

		logger.Infof("Decision (%s): %s wei", p.label, payout)
	}

	logger.Infof("All tests passed.")
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

	logger.Infof("  Decision: policy=%s payout=%s wei to %s",
		decision.PolicyID.Hex(), decision.PayoutAmount, decision.PayoutTo.Hex())

	// The TEE identity signs every action result; without that signature the
	// decision would be worth no more than an off-chain promise.
	if len(resp.Signature) == 0 {
		fccutils.FatalWithCause(errors.Errorf("FAIL (%s): action result carries no TEE signature", p.label))
	}
	logger.Infof("  TEE signature: %s", hex.EncodeToString(resp.Signature))

	assertNoSecrets(fmt.Sprintf("evaluate action result (%s)", p.label),
		[]byte(resp.Result.Log), resp.Result.Data)

	return decision.PayoutAmount
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

	payout := new(big.Int).Mul(m.SumInsuredWei, shortfall)
	payout.Mul(payout, new(big.Int).SetUint64(m.PayoutFactorBps))
	payout.Div(payout, new(big.Int).Mul(span, big.NewInt(10_000)))

	if payout.Cmp(m.SumInsuredWei) > 0 {
		payout.Set(m.SumInsuredWei)
	}
	if payout.Cmp(m.MinPayoutWei) < 0 {
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
