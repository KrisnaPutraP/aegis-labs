// Package types contains types that could be useful to other apps when interacting with the Aegis extension.
//
// Confidentiality contract (ARCHITECTURE.md §3): the insurer's model parameters
// carried by RegisterModelRequest are SECRET and must never leave the enclave —
// not on-chain, not in logs, not in error messages. Everything in
// EvaluateRequest / EvaluateResponse is public by design: the trigger data is
// FDC-attested public weather data and the decision is meant to be consumed and
// verified on-chain.
package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// State holds the extension's observable state, returned by GET /state.
//
// RegisteredModels reports how many policies currently have a confidential
// model loaded in the enclave. Only the count is exposed — never the policy
// ids, never the parameters.
type State struct {
	RegisteredModels int `json:"registeredModels"`
}

// ModelParameters is the insurer's confidential risk model for a single policy.
//
// SECRET — in-enclave only. It reaches the TEE ECIES-encrypted to the enclave
// public key (see REGISTER_MODEL) and is never serialized back out.
//
// The MVP model is a drought cover with a hidden linear ramp: the further
// cumulative rainfall falls below TriggerTenthsMm, the larger the payout, up to
// the full sum insured at (or below) ExitTenthsMm. Rainfall is carried in tenths
// of a millimetre and money in wei so that evaluation is pure integer maths —
// floating point would make the enclave's decision non-reproducible.
type ModelParameters struct {
	// TriggerTenthsMm is the dry-season rainfall level at which cover starts to
	// pay. Rainfall at or above it pays nothing.
	TriggerTenthsMm uint64 `json:"triggerTenthsMm"`

	// ExitTenthsMm is the level at or below which the full sum insured is paid.
	// Must be strictly below TriggerTenthsMm.
	ExitTenthsMm uint64 `json:"exitTenthsMm"`

	// SumInsuredWei is the maximum payout for the policy.
	SumInsuredWei *big.Int `json:"sumInsuredWei"`

	// PayoutFactorBps scales the ramp (10000 = 1.0). This is the insurer's
	// loading/derating knob — the part competitors would most like to see.
	PayoutFactorBps uint64 `json:"payoutFactorBps"`

	// MinPayoutWei is a dust floor: a computed payout below it settles to zero
	// so the pool is not drained by payouts worth less than their gas.
	MinPayoutWei *big.Int `json:"minPayoutWei"`
}

// RegisterModelRequest is the plaintext an insurer encrypts to the enclave
// public key for OPCommand REGISTER_MODEL. It is JSON-encoded rather than
// ABI-encoded because it never touches the chain: only its ciphertext does.
type RegisterModelRequest struct {
	PolicyID common.Hash     `json:"policyId"`
	Model    ModelParameters `json:"model"`
}

// EvaluateRequest is the instruction payload for OPCommand EVALUATE, ABI-encoded
// on-chain as (bytes32, uint256, address) by InstructionSender.evaluate.
//
// Every field is public. RainfallTenthsMm is cumulative rainfall over the policy
// window; in Fase 3 it stops being a caller-supplied number and becomes the
// value carried by an FDC JsonApi attestation (trust boundary invariant 3).
type EvaluateRequest struct {
	PolicyID         common.Hash
	RainfallTenthsMm *big.Int
	PayoutTo         common.Address
}

// EvaluateResponse is the enclave's decision, ABI-encoded as
// (bytes32, uint256, address) into ActionResult.Data. The tee-node signs the
// action result with the TEE identity key, which is what makes the decision
// verifiable on-chain without revealing how it was reached.
type EvaluateResponse struct {
	PolicyID     common.Hash
	PayoutAmount *big.Int
	PayoutTo     common.Address
}

// --- DO NOT MODIFY below this line. ---

// StateResponse is the envelope returned by GET /state.
type StateResponse struct {
	StateVersion common.Hash `json:"stateVersion"`
	State        State       `json:"state"`
}
