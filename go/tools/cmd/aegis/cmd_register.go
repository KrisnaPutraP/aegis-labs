package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"time"

	"sign-extension/pkg/types"
	"sign-extension/tools/pkg/contracts/sign"
	"sign-extension/tools/pkg/fccutils"
	"sign-extension/tools/pkg/fdc"
	"sign-extension/tools/pkg/support"
	instrutils "sign-extension/tools/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	teetypes "github.com/flare-foundation/tee-node/pkg/types"
	"github.com/pkg/errors"
)

func runRegisterModel(args []string) error {
	fs := flag.NewFlagSet("register-model", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Print(`aegis register-model, put a policy under cover.

Two things happen, in this order:

  1. The policy is bound on chain to exactly one FDC attestation request, the
     weather feed it may ever settle against. The binding is write once, so a
     live policy cannot later be repointed at a more convenient query.
  2. The insurer's model is encrypted to the enclave's public key and loaded.
     The plaintext parameters never leave this process, the chain carries only
     ciphertext, and the enclave answers with a bare success.

Usage:
  aegis register-model [flags]

Flags:
`)
		fs.PrintDefaults()
	}

	flags := addCommonFlags(fs, true)
	modelFile := fs.String("model-file", "", "read model parameters from a JSON file instead of the demo model")
	forceNew := fs.Bool("new", false, "mint a fresh policy id even if an unsettled one exists")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := flags.resolve()
	if err != nil {
		return err
	}

	model, err := loadModel(*modelFile)
	if err != nil {
		return err
	}

	// Sealing a model needs the enclave's public key, so the proxy has to be up.
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

	template := policyCatalog[cfg.policyName]
	record, minted, err := currentPolicy(state, cfg.policyName, template, *forceNew)
	if err != nil {
		return err
	}

	origin := "reusing the policy from the last run"
	if minted {
		origin = "new policy id for this run"
	}

	step("Policy %s", cfg.policyName)
	field("policy id", "%s", record.PolicyID)
	field("origin", "%s", origin)
	field("feed", "%s, %s to %s", fdc.OpenMeteoArchiveURL, template.feed.StartDate, template.feed.EndDate)
	field("location", "%s, %s", template.feed.LatitudeDeg, template.feed.LongitudeDeg)
	if *modelFile != "" {
		field("model", "loaded from %s", *modelFile)
	}

	requestBody, err := template.feed.RequestBody()
	if err != nil {
		return errors.Errorf("building the attestation request: %s", err)
	}

	step("Encoding the attestation request at the FDC verifier")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	encoded, err := fdc.NewClient().PrepareRequest(ctx, requestBody)
	cancel()
	if err != nil {
		return errors.Errorf("the verifier refused the request: %s", err)
	}
	record.AbiEncodedRequest = "0x" + hex.EncodeToString(encoded)
	field("request", "%d bytes, accepted by the verifier", len(encoded))
	note("the verifier evaluates the jq filter against the live source, so an unusable request fails here")

	if err := bindTrigger(sup, cfg, record, requestBody); err != nil {
		return err
	}
	if err := state.saveWith(record); err != nil {
		return err
	}

	if err := sealModel(sup, cfg, record, model); err != nil {
		return err
	}
	if err := state.saveWith(record); err != nil {
		return err
	}

	headline("Model sealed in enclave. Plaintext never left this process.")
	note("next: aegis evaluate --policy %s", cfg.policyName)

	return nil
}

// currentPolicy decides which policy id this run works on. A settled policy is
// finished, so a demo that reuses one would fail at settlement rather than at
// the point the operator could still fix it.
func currentPolicy(
	state *demoState,
	name string,
	template policyTemplate,
	forceNew bool,
) (*policyRecord, bool, error) {
	existing := state.get(name)
	if existing != nil && !existing.Settled && !forceNew {
		return existing, false, nil
	}

	id, err := newPolicyID(template.prefix)
	if err != nil {
		return nil, false, err
	}

	return &policyRecord{
		Name:      name,
		PolicyID:  id.Hex(),
		CreatedAt: time.Now().UTC(),
	}, true, nil
}

// bindTrigger registers the policy's one permitted attestation request, or
// confirms the existing binding still matches.
func bindTrigger(
	sup *support.Support,
	cfg *settings,
	record *policyRecord,
	requestBody sign.IWeb2JsonRequestBody,
) error {
	step("Binding the policy to that request")

	// The hash comes from the contract, so the registration and the check
	// evaluate() performs are computed by the same code.
	requestHash, err := instrutils.TriggerRequestHash(sup, cfg.instructionSender, requestBody)
	if err != nil {
		return errors.Errorf("asking the contract for the request hash: %s", err)
	}
	record.RequestHash = requestHash.Hex()
	field("request hash", "%s", requestHash.Hex())
	note("the whole request is hashed, not just the coordinates, so a genuine attestation of some other query cannot settle this policy")

	sender, err := sign.NewInstructionSender(cfg.instructionSender, sup.ChainClient)
	if err != nil {
		return errors.Errorf("binding InstructionSender: %s", err)
	}

	existing, err := sender.PolicyTriggerRequestHash(nil, [32]byte(record.id()))
	if err != nil {
		return errors.Errorf("reading the current binding: %s", err)
	}

	switch {
	case common.Hash(existing) == requestHash:
		field("binding", "already bound to this request, nothing to send")
		return nil
	case common.Hash(existing) != (common.Hash{}):
		return errors.Errorf(
			"policy %s is already bound to %s, and the binding is write once. Run with --new for a fresh policy id",
			record.PolicyID, common.Hash(existing).Hex())
	}

	txHash, err := instrutils.SendRegisterPolicyTrigger(sup, cfg.instructionSender, record.id(), requestHash)
	if err != nil {
		return errors.Errorf("registerPolicyTrigger: %s", err)
	}
	field("tx", "%s", txHash.Hex())

	return nil
}

// sealModel encrypts the model to the enclave public key and loads it.
func sealModel(sup *support.Support, cfg *settings, record *policyRecord, model types.ModelParameters) error {
	step("Sealing the model to the enclave")

	teeInfo, err := fccutils.TeeInfo(cfg.proxyURL)
	if err != nil {
		return errors.Errorf("fetching the TEE public key: %s", err)
	}

	ecdsaPub, err := teetypes.ParsePubKey(teeInfo.MachineData.PublicKey)
	if err != nil {
		return errors.Errorf("parsing the TEE public key: %s", err)
	}
	field("enclave key", "%s", shorten(teeInfo.MachineData.PublicKey.X.Hex()))

	eciesPub := &ecies.PublicKey{
		X:      ecdsaPub.X,
		Y:      ecdsaPub.Y,
		Curve:  ecies.DefaultCurve,
		Params: ecies.ECIES_AES128_SHA256,
	}

	request := types.RegisterModelRequest{PolicyID: record.id(), Model: model}
	plaintext, err := request.Encode()
	if err != nil {
		return errors.Errorf("encoding the register request: %s", err)
	}

	ciphertext, err := ecies.Encrypt(rand.Reader, eciesPub, plaintext, nil, nil)
	if err != nil {
		return errors.Errorf("sealing the model: %s", err)
	}
	if err := assertSealed(model, ciphertext); err != nil {
		return err
	}
	field("ciphertext", "%d bytes, sealed to that key alone", len(ciphertext))

	instructionID, txHash, err := instrutils.SendRegisterModel(sup, cfg.instructionSender, ciphertext)
	if err != nil {
		return errors.Errorf("registerModel: %s", err)
	}
	record.RegisterInstructionID = instructionID.Hex()
	field("instruction", "%s", instructionID.Hex())
	field("tx", "%s", txHash.Hex())

	resp, err := waitForActionResult(cfg.proxyURL, instructionID, 2*time.Minute)
	if err != nil {
		return err
	}
	if resp.Result.Status == 0 {
		return errors.Errorf("the enclave rejected the model: %s", resp.Result.Log)
	}

	record.ModelRegistered = true
	field("enclave", "status %d, %d bytes of result data", resp.Result.Status, len(resp.Result.Data))
	note("the result carries no policy id and no parameter, only that it worked")

	return nil
}

// saveWith stores a record and writes the state file in one step, so a demo that
// is interrupted still knows which policy it was working on.
func (s *demoState) saveWith(record *policyRecord) error {
	s.put(record)
	return s.save()
}
