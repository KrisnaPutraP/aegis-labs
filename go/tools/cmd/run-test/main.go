// Package main runs the Aegis extension end-to-end test:
//  1. setExtensionId on the deployed InstructionSender (idempotent)
//  2. fetch TEE public key from the extension proxy
//  3. ECIES-encrypt the insurer's confidential model under the TEE pubkey
//  4. send registerModel on-chain, poll for result
//  5. send evaluate(policyId, rainfall, payoutTo) on-chain for a dry reading
//     and for a wet reading, poll for both results
//  6. ABI-decode (bytes32 policyId, uint256 payoutAmount, address payoutTo)
//     from each result and check the decision against what the model implies
//
// The model parameters live in this file only because the test plays the role of
// the insurer: it is the one party that legitimately knows them. They travel to
// the TEE encrypted and must never appear in an instruction message, an action
// result, or a log line — step 6 asserts exactly that.
package main

import (
	"bytes"
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
	"sign-extension/tools/pkg/fccutils"
	"sign-extension/tools/pkg/support"
	instrutils "sign-extension/tools/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	teetypes "github.com/flare-foundation/tee-node/pkg/types"
	"github.com/pkg/errors"
)

// testPolicyID is the policy the test registers a model for.
var testPolicyID = common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000a3d1")

// testPayoutTo is the policyholder address the decision must echo back.
var testPayoutTo = common.HexToAddress("0x000000000000000000000000000000000000dEaD")

// testModel is the insurer's confidential model for testPolicyID: cover starts
// below 120.0 mm of cumulative rainfall and reaches the full sum insured at or
// below 40.0 mm, scaled by a hidden 0.9 factor.
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

	// --- Step 2: Fetch TEE public key and ECIES-encrypt the confidential model ---
	logger.Infof("Step 2: Fetching TEE public key from extension proxy...")
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

	registerRequest := types.RegisterModelRequest{PolicyID: testPolicyID, Model: testModel()}
	plaintext, err := registerRequest.Encode()
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("encode register model request: %s", err))
	}

	ciphertext, err := ecies.Encrypt(rand.Reader, eciesPub, plaintext, nil, nil)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("ECIES encrypt: %s", err))
	}
	logger.Infof("  Policy ID: %s", testPolicyID.Hex())
	logger.Infof("  Encrypted model: %d bytes (plaintext never leaves this process)", len(ciphertext))

	assertSealed(plaintext, ciphertext)

	// --- Step 3: registerModel ---
	logger.Infof("Step 3: Sending registerModel instruction on-chain...")
	registerID, _, err := instrutils.SendRegisterModel(testSupport, instructionSenderAddress, ciphertext)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("registerModel: %s", err))
	}
	logger.Infof("  registerModel instruction ID: %s", registerID.Hex())

	time.Sleep(5 * time.Second)

	// --- Step 4: poll for registerModel result ---
	logger.Infof("Step 4: Waiting for registerModel result...")
	registerResp, err := fccutils.ActionResult(*pf, registerID)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("poll registerModel: %s", err))
	}
	if registerResp.Result.Status == 0 {
		fccutils.FatalWithCause(errors.Errorf("registerModel instruction failed: %s", registerResp.Result.Log))
	}
	logger.Infof("  registerModel succeeded (status=%d)", registerResp.Result.Status)
	assertNoSecrets("registerModel action result", []byte(registerResp.Result.Log), registerResp.Result.Data)

	// --- Step 5 & 6: evaluate a dry reading and a wet reading ---
	dryPayout := runEvaluate(testSupport, instructionSenderAddress, *pf, "dry season (drought)", big.NewInt(600))
	wetPayout := runEvaluate(testSupport, instructionSenderAddress, *pf, "normal season", big.NewInt(1500))

	logger.Infof("Decisions: dry=%s wei, wet=%s wei", dryPayout, wetPayout)

	if wetPayout.Sign() != 0 {
		fccutils.FatalWithCause(errors.Errorf(
			"FAIL: rainfall above the trigger must not pay out, got %s wei", wetPayout))
	}

	// The expected dry-season payout is recomputed here from the same parameters
	// the insurer registered — the point is that only the insurer and the enclave
	// can do this arithmetic.
	expectedDry := expectedPayout(testModel(), big.NewInt(600))
	if dryPayout.Cmp(expectedDry) != 0 {
		fccutils.FatalWithCause(errors.Errorf(
			"FAIL: dry-season payout %s wei does not match the model's %s wei", dryPayout, expectedDry))
	}

	logger.Infof("All tests passed.")
}

// runEvaluate sends one evaluate instruction, waits for the signed decision, and
// returns the payout amount it carries.
func runEvaluate(
	s *support.Support,
	instructionSenderAddress common.Address,
	proxyURL string,
	label string,
	rainfallTenthsMm *big.Int,
) *big.Int {
	logger.Infof("Step 5 (%s): Sending evaluate instruction, rainfall=%s tenths of mm...", label, rainfallTenthsMm)

	evaluateID, _, err := instrutils.SendEvaluate(s, instructionSenderAddress, testPolicyID, rainfallTenthsMm, testPayoutTo)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("evaluate (%s): %s", label, err))
	}
	logger.Infof("  evaluate instruction ID: %s", evaluateID.Hex())

	time.Sleep(5 * time.Second)

	logger.Infof("Step 6 (%s): Waiting for evaluate result...", label)
	resp, err := fccutils.ActionResult(proxyURL, evaluateID)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("poll evaluate (%s): %s", label, err))
	}
	if resp.Result.Status == 0 {
		fccutils.FatalWithCause(errors.Errorf("evaluate instruction failed (%s): %s", label, resp.Result.Log))
	}

	decision, err := types.DecodeEvaluateResponse(resp.Result.Data)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("decode evaluate response (%s): %s", label, err))
	}

	if decision.PolicyID != testPolicyID {
		fccutils.FatalWithCause(errors.Errorf(
			"FAIL (%s): decision is for policy %s, expected %s", label, decision.PolicyID.Hex(), testPolicyID.Hex()))
	}
	if decision.PayoutTo != testPayoutTo {
		fccutils.FatalWithCause(errors.Errorf(
			"FAIL (%s): payout address %s, expected %s", label, decision.PayoutTo.Hex(), testPayoutTo.Hex()))
	}

	logger.Infof("  Decision: policy=%s payout=%s wei to %s",
		decision.PolicyID.Hex(), decision.PayoutAmount, decision.PayoutTo.Hex())

	// The TEE identity signs every action result; without that signature the
	// decision would be worth no more than an off-chain promise.
	if len(resp.Signature) == 0 {
		fccutils.FatalWithCause(errors.Errorf("FAIL (%s): action result carries no TEE signature", label))
	}
	logger.Infof("  TEE signature: %s", hex.EncodeToString(resp.Signature))

	assertNoSecrets(fmt.Sprintf("evaluate action result (%s)", label),
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
