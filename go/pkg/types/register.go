package types

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// Codecs for the two Aegis payloads.
//
//   - EVALUATE request/response cross the chain boundary, so they are ABI-encoded
//     (bytes32 policyId, uint256 value, address payoutTo) — the same tuple a
//     Solidity consumer gets from abi.decode on the action result.
//   - REGISTER_MODEL carries secret parameters that only ever travel as ECIES
//     ciphertext, so JSON is enough and keeps the insurer tooling simple.

// evaluateTupleArgs is the ABI shape shared by EvaluateRequest and
// EvaluateResponse: (bytes32, uint256, address), 96 bytes, all static.
var evaluateTupleArgs abi.Arguments

// evaluateTupleSize is the exact encoded length of evaluateTupleArgs. Decoding
// enforces it so trailing garbage cannot ride along with a valid instruction.
const evaluateTupleSize = 96

func init() {
	bytes32Ty, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		panic(fmt.Sprintf("abi type bytes32: %v", err))
	}
	uint256Ty, err := abi.NewType("uint256", "", nil)
	if err != nil {
		panic(fmt.Sprintf("abi type uint256: %v", err))
	}
	addressTy, err := abi.NewType("address", "", nil)
	if err != nil {
		panic(fmt.Sprintf("abi type address: %v", err))
	}

	evaluateTupleArgs = abi.Arguments{
		{Name: "policyId", Type: bytes32Ty},
		{Name: "value", Type: uint256Ty},
		{Name: "payoutTo", Type: addressTy},
	}
}

// encodeEvaluateTuple ABI-encodes the (bytes32, uint256, address) tuple.
func encodeEvaluateTuple(policyID common.Hash, value *big.Int, payoutTo common.Address) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("value is nil")
	}
	if value.Sign() < 0 {
		return nil, fmt.Errorf("value is negative")
	}
	if value.BitLen() > 256 {
		return nil, fmt.Errorf("value exceeds uint256")
	}

	return evaluateTupleArgs.Pack([32]byte(policyID), value, payoutTo)
}

// decodeEvaluateTuple ABI-decodes the (bytes32, uint256, address) tuple.
func decodeEvaluateTuple(data []byte) (common.Hash, *big.Int, common.Address, error) {
	if len(data) != evaluateTupleSize {
		return common.Hash{}, nil, common.Address{}, fmt.Errorf(
			"expected %d bytes, got %d", evaluateTupleSize, len(data))
	}

	values, err := evaluateTupleArgs.Unpack(data)
	if err != nil {
		return common.Hash{}, nil, common.Address{}, err
	}
	if len(values) != 3 {
		return common.Hash{}, nil, common.Address{}, fmt.Errorf("expected 3 values, got %d", len(values))
	}

	policyID, ok := values[0].([32]byte)
	if !ok {
		return common.Hash{}, nil, common.Address{}, fmt.Errorf("field 0 is %T, want bytes32", values[0])
	}
	value, ok := values[1].(*big.Int)
	if !ok {
		return common.Hash{}, nil, common.Address{}, fmt.Errorf("field 1 is %T, want uint256", values[1])
	}
	payoutTo, ok := values[2].(common.Address)
	if !ok {
		return common.Hash{}, nil, common.Address{}, fmt.Errorf("field 2 is %T, want address", values[2])
	}

	return common.Hash(policyID), value, payoutTo, nil
}

// Encode ABI-encodes the evaluate request the way InstructionSender.evaluate does.
func (r *EvaluateRequest) Encode() ([]byte, error) {
	return encodeEvaluateTuple(r.PolicyID, r.RainfallTenthsMm, r.PayoutTo)
}

// DecodeEvaluateRequest decodes the instruction message sent by
// InstructionSender.evaluate.
func DecodeEvaluateRequest(data []byte) (*EvaluateRequest, error) {
	policyID, rainfall, payoutTo, err := decodeEvaluateTuple(data)
	if err != nil {
		return nil, fmt.Errorf("decoding evaluate request: %w", err)
	}

	return &EvaluateRequest{
		PolicyID:         policyID,
		RainfallTenthsMm: rainfall,
		PayoutTo:         payoutTo,
	}, nil
}

// Encode ABI-encodes the decision for ActionResult.Data, ready for abi.decode
// in a consumer contract.
func (r *EvaluateResponse) Encode() ([]byte, error) {
	return encodeEvaluateTuple(r.PolicyID, r.PayoutAmount, r.PayoutTo)
}

// DecodeEvaluateResponse decodes a signed decision — used by the e2e test and by
// any off-chain consumer that wants to read the action result.
func DecodeEvaluateResponse(data []byte) (*EvaluateResponse, error) {
	policyID, payout, payoutTo, err := decodeEvaluateTuple(data)
	if err != nil {
		return nil, fmt.Errorf("decoding evaluate response: %w", err)
	}

	return &EvaluateResponse{
		PolicyID:     policyID,
		PayoutAmount: payout,
		PayoutTo:     payoutTo,
	}, nil
}

// Encode JSON-encodes the secret model payload. The caller must ECIES-encrypt
// the result to the enclave public key before it goes anywhere near the chain.
func (r *RegisterModelRequest) Encode() ([]byte, error) {
	return json.Marshal(r)
}

// DecodeRegisterModelRequest parses the plaintext recovered from the ECIES
// ciphertext. It rejects models the evaluator could not score deterministically,
// so that a malformed registration fails loudly at registration time instead of
// silently paying zero later.
//
// Error messages here deliberately never quote parameter values (rule 7).
func DecodeRegisterModelRequest(plaintext []byte) (*RegisterModelRequest, error) {
	var req RegisterModelRequest

	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return nil, fmt.Errorf("decoding register model request: invalid payload")
	}
	if decoder.More() {
		return nil, fmt.Errorf("decoding register model request: trailing data")
	}

	if req.PolicyID == (common.Hash{}) {
		return nil, fmt.Errorf("policyId is zero")
	}
	if err := req.Model.Validate(); err != nil {
		return nil, err
	}

	return &req, nil
}

// Validate checks the model is scoreable. It reports which parameter is wrong,
// never what its value is.
func (m *ModelParameters) Validate() error {
	if m.SumInsuredWei == nil || m.SumInsuredWei.Sign() <= 0 {
		return fmt.Errorf("model rejected: sumInsuredWei must be positive")
	}
	if m.SumInsuredWei.BitLen() > 256 {
		return fmt.Errorf("model rejected: sumInsuredWei exceeds uint256")
	}
	if m.MinPayoutWei == nil {
		return fmt.Errorf("model rejected: minPayoutWei is missing")
	}
	if m.MinPayoutWei.Sign() < 0 {
		return fmt.Errorf("model rejected: minPayoutWei must not be negative")
	}
	if m.ExitTenthsMm >= m.TriggerTenthsMm {
		return fmt.Errorf("model rejected: exitTenthsMm must be below triggerTenthsMm")
	}
	if m.PayoutFactorBps == 0 {
		return fmt.Errorf("model rejected: payoutFactorBps must be positive")
	}

	return nil
}
