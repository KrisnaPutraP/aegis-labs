package extension

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"

	"sign-extension/internal/config"
	"sign-extension/pkg/types"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	teetypes "github.com/flare-foundation/tee-node/pkg/types"
	teeutils "github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/flare-foundation/tee-node/pkg/processorutils"
)

// Extension holds mutable state for the Aegis extension. Access is serialized
// by the mutex; the framework dispatches actions serially anyway, but the
// state read in stateHandler is concurrent with action processing.
type Extension struct {
	mu     sync.RWMutex
	Server *http.Server

	// signPort is the TEE node's /decrypt endpoint port, used by
	// processRegisterModel to open the insurer's ECIES ciphertext.
	signPort int

	// models holds the confidential risk model per policy.
	//
	// THIS IS THE SECRET (ARCHITECTURE.md §3). It lives only in enclave memory:
	// it is never written to disk, never returned by an action result, never
	// logged, and never mentioned in an error message. Losing it on restart is
	// intentional and acceptable — the insurer re-registers.
	models map[common.Hash]types.ModelParameters
}

// --- DO NOT MODIFY: New(), actionHandler() are boilerplate.
func New(extensionPort, signPort int) *Extension {
	e := &Extension{
		signPort: signPort,
		models:   make(map[common.Hash]types.ModelParameters),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /state", e.stateHandler)
	mux.HandleFunc("POST /action", e.actionHandler)

	e.Server = &http.Server{Addr: fmt.Sprintf(":%d", extensionPort), Handler: mux}
	return e
}

// stateHandler reports how many policies have a model loaded, without exposing
// which policies they are or what the models say.
func (e *Extension) stateHandler(w http.ResponseWriter, r *http.Request) {
	e.mu.RLock()
	stateResponse := types.StateResponse{
		StateVersion: teeutils.ToHash(config.Version),
		State: types.State{
			RegisteredModels: len(e.models),
		},
	}
	e.mu.RUnlock()

	err := json.NewEncoder(w).Encode(stateResponse)
	if err != nil {
		http.Error(w, fmt.Sprintf("sending response: %v", err), http.StatusInternalServerError)
		return
	}
}

func (e *Extension) processAction(action teetypes.Action) (int, []byte) {
	dataFixed, err := processorutils.Parse[instruction.DataFixed](action.Data.Message)
	if err != nil {
		return http.StatusBadRequest, []byte(fmt.Sprintf("decoding fixed data: %v", err))
	}

	switch {
	case dataFixed.OPType == teeutils.ToHash(config.OPTypePolicy):
		return e.processPolicy(action, dataFixed)

	default:
		return http.StatusNotImplemented, []byte(fmt.Sprintf(
			"unsupported op type: received %s, expected %s (%s)",
			dataFixed.OPType.Hex(), teeutils.ToHash(config.OPTypePolicy).Hex(), config.OPTypePolicy,
		))
	}
}

// processPolicy routes POLICY instructions by OPCommand (REGISTER_MODEL or EVALUATE).
func (e *Extension) processPolicy(action teetypes.Action, df *instruction.DataFixed) (int, []byte) {
	switch {
	case df.OPCommand == teeutils.ToHash(config.OPCommandRegisterModel):
		ar := e.processRegisterModel(action, df)
		b, _ := json.Marshal(ar)
		return http.StatusOK, b

	case df.OPCommand == teeutils.ToHash(config.OPCommandEvaluate):
		ar := e.processEvaluate(action, df)
		b, _ := json.Marshal(ar)
		return http.StatusOK, b

	default:
		return http.StatusNotImplemented, []byte(fmt.Sprintf(
			"unsupported op command: received %s, expected one of [%s (%s), %s (%s)]",
			df.OPCommand.Hex(),
			teeutils.ToHash(config.OPCommandRegisterModel).Hex(), config.OPCommandRegisterModel,
			teeutils.ToHash(config.OPCommandEvaluate).Hex(), config.OPCommandEvaluate,
		))
	}
}

// processRegisterModel decrypts the insurer's payload via the TEE node and
// stores the confidential model for the policy it names.
//
// The instruction message on-chain is ciphertext only. The plaintext exists
// solely inside the enclave, and the action result reports nothing but success
// or failure — deliberately no echo of the policy id or the parameters.
func (e *Extension) processRegisterModel(action teetypes.Action, df *instruction.DataFixed) teetypes.ActionResult {
	if len(df.OriginalMessage) == 0 {
		return buildResult(action, df, nil, 0, fmt.Errorf("originalMessage is empty"))
	}

	plaintext, err := decryptViaNode(e.signPort, df.OriginalMessage)
	if err != nil {
		return buildResult(action, df, nil, 0, fmt.Errorf("decryption failed: %v", err))
	}

	req, err := types.DecodeRegisterModelRequest(plaintext)
	if err != nil {
		// DecodeRegisterModelRequest never quotes parameter values, so this is
		// safe to surface.
		return buildResult(action, df, nil, 0, err)
	}

	e.mu.Lock()
	e.models[req.PolicyID] = req.Model
	e.mu.Unlock()

	return buildResult(action, df, nil, 1, nil)
}

// processEvaluate scores attested trigger data against the policy's confidential
// model and returns the payout decision.
//
// The rainfall in the message is FDC-attested by construction: InstructionSender
// is the only address allowed to send instructions to this extension, and it
// only forwards a reading it has extracted from a Web2Json attestation whose
// Merkle proof it verified on-chain.
//
// The result is ABI-encoded (policyId, payoutAmount, payoutTo) and signed by the
// tee-node with the TEE identity key, which is what makes the decision
// verifiable on-chain while the model behind it stays hidden.
func (e *Extension) processEvaluate(action teetypes.Action, df *instruction.DataFixed) teetypes.ActionResult {
	if len(df.OriginalMessage) == 0 {
		return buildResult(action, df, nil, 0, fmt.Errorf("originalMessage is empty"))
	}

	req, err := types.DecodeEvaluateRequest(df.OriginalMessage)
	if err != nil {
		return buildResult(action, df, nil, 0, err)
	}

	e.mu.RLock()
	model, ok := e.models[req.PolicyID]
	e.mu.RUnlock()

	if !ok {
		// Naming the policy is fine — policy ids are public on-chain.
		return buildResult(action, df, nil, 0,
			fmt.Errorf("no model registered for policy %s", req.PolicyID.Hex()))
	}

	payout, err := evaluatePayout(&model, req.RainfallTenthsMm)
	if err != nil {
		return buildResult(action, df, nil, 0, err)
	}

	response := types.EvaluateResponse{
		PolicyID:     req.PolicyID,
		PayoutAmount: payout,
		PayoutTo:     req.PayoutTo,
	}

	encoded, err := response.Encode()
	if err != nil {
		return buildResult(action, df, nil, 0, fmt.Errorf("ABI encoding failed: %v", err))
	}

	return buildResult(action, df, encoded, 1, nil)
}

// bps is one hundred percent in basis points.
var bps = big.NewInt(10_000)

// evaluatePayout is the confidential scoring function — the reason Aegis needs a
// TEE at all. It runs only inside the enclave and its inputs are never echoed.
//
// The cover is a drought indemnity with a hidden linear ramp:
//
//	rainfall >= trigger          → nothing is owed
//	rainfall <= exit             → the full sum insured (times the hidden factor)
//	exit < rainfall < trigger    → pro rata along the ramp
//
// then scaled by PayoutFactorBps, capped at the sum insured, and finally rounded
// down to zero if it lands under the dust floor.
//
// All arithmetic is integer big.Int on purpose: two enclaves scoring the same
// reading must produce byte-identical results, and floating point would not
// guarantee that.
func evaluatePayout(model *types.ModelParameters, rainfallTenthsMm *big.Int) (*big.Int, error) {
	if rainfallTenthsMm == nil || rainfallTenthsMm.Sign() < 0 {
		return nil, fmt.Errorf("rainfall must not be negative")
	}
	// Defence in depth: registration already validated the model, but scoring an
	// unvalidated one could divide by zero.
	if err := model.Validate(); err != nil {
		return nil, err
	}

	trigger := new(big.Int).SetUint64(model.TriggerTenthsMm)
	exit := new(big.Int).SetUint64(model.ExitTenthsMm)

	// Rain at or above the trigger: the policy simply does not respond.
	if rainfallTenthsMm.Cmp(trigger) >= 0 {
		return new(big.Int), nil
	}

	// span > 0 because Validate() rejects exit >= trigger.
	span := new(big.Int).Sub(trigger, exit)
	shortfall := new(big.Int).Sub(trigger, rainfallTenthsMm)
	if shortfall.Cmp(span) > 0 {
		shortfall = span
	}

	// payout = sumInsured * shortfall * factorBps / (span * 10000), truncated.
	payout := new(big.Int).Mul(model.SumInsuredUnits, shortfall)
	payout.Mul(payout, new(big.Int).SetUint64(model.PayoutFactorBps))
	payout.Div(payout, new(big.Int).Mul(span, bps))

	// A factor above 100% must not let a policy pay more than it insures.
	if payout.Cmp(model.SumInsuredUnits) > 0 {
		payout.Set(model.SumInsuredUnits)
	}

	// Dust floor: a payout worth less than its own settlement cost pays nothing.
	if payout.Cmp(model.MinPayoutUnits) < 0 {
		return new(big.Int), nil
	}

	return payout, nil
}
