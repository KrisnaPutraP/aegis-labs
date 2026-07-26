package payout

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	teetypes "github.com/flare-foundation/tee-node/pkg/types"
)

func goldenResponse(t *testing.T) *teetypes.ActionResponse {
	t.Helper()

	return &teetypes.ActionResponse{
		Result:    *goldenActionResult(t),
		Signature: hexutil.Bytes(mustDecodeHex(t, goldenSignature)),
	}
}

func TestDecodeDecisionReadsTheSignedTriple(t *testing.T) {
	decision, err := DecodeDecision(goldenChainID, goldenResponse(t))
	if err != nil {
		t.Fatalf("DecodeDecision: %v", err)
	}

	if decision.PolicyID != common.HexToHash(goldenPolicyID) {
		t.Errorf("policy = %s, want %s", decision.PolicyID.Hex(), goldenPolicyID)
	}
	if decision.PayoutAmount.Cmp(big.NewInt(goldenPayoutAmount)) != 0 {
		t.Errorf("amount = %s, want %d", decision.PayoutAmount, goldenPayoutAmount)
	}
	if decision.PayoutTo != common.HexToAddress(goldenPayoutTo) {
		t.Errorf("payoutTo = %s, want %s", decision.PayoutTo.Hex(), goldenPayoutTo)
	}
	if decision.InstructionID != common.HexToHash(goldenInstructionID) {
		t.Errorf("instruction = %s, want %s", decision.InstructionID.Hex(), goldenInstructionID)
	}
	// The whole point of decoding locally: knowing which enclave signed before
	// paying gas to find out on-chain.
	if decision.TeeID != common.HexToAddress(goldenTeeID) {
		t.Errorf("teeId = %s, want %s", decision.TeeID.Hex(), goldenTeeID)
	}
}

// The Go decode must agree with the Solidity abi.decode, field for field, or a
// caller would settle something other than what it reported.
func TestDecodeDecisionMatchesTheAbiLayout(t *testing.T) {
	response := goldenResponse(t)

	decision, err := DecodeDecision(goldenChainID, response)
	if err != nil {
		t.Fatalf("DecodeDecision: %v", err)
	}

	data := response.Result.Data
	if common.BytesToHash(data[0:32]) != decision.PolicyID {
		t.Error("policy id is not the first word")
	}
	if new(big.Int).SetBytes(data[32:64]).Cmp(decision.PayoutAmount) != 0 {
		t.Error("amount is not the second word")
	}
	if common.BytesToAddress(data[64:96]) != decision.PayoutTo {
		t.Error("payoutTo is not the third word")
	}
}

func TestDecodeDecisionRejectsUnusableResults(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*teetypes.ActionResponse)
	}{
		{
			// A failed action's Data is empty and its Log says why; paying on one
			// would pay on an enclave error.
			"failed action",
			func(r *teetypes.ActionResponse) { r.Result.Status = 0; r.Result.Data = nil },
		},
		{
			"short payload",
			func(r *teetypes.ActionResponse) { r.Result.Data = r.Result.Data[:64] },
		},
		{
			"trailing bytes",
			func(r *teetypes.ActionResponse) { r.Result.Data = append(r.Result.Data, 0x00) },
		},
		{
			"missing signature",
			func(r *teetypes.ActionResponse) { r.Signature = nil },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := goldenResponse(t)
			tt.mutate(response)

			if _, err := DecodeDecision(goldenChainID, response); err == nil {
				t.Errorf("expected an error for %s", tt.name)
			}
		})
	}
}

// A decision signed for one chain must not be presentable on another.
func TestDecodeDecisionIsChainBound(t *testing.T) {
	onOtherChain, err := DecodeDecision(goldenChainID+1, goldenResponse(t))
	if err != nil {
		return // recovery failing outright is fine
	}
	if onOtherChain.TeeID == common.HexToAddress(goldenTeeID) {
		t.Error("the same signature recovered the enclave under a different chain id")
	}
}

func TestFormatUnits(t *testing.T) {
	tests := []struct {
		amount   *big.Int
		decimals uint8
		want     string
	}{
		{big.NewInt(0), 6, "0"},
		{big.NewInt(5_000_000), 6, "5"},
		{big.NewInt(3_375_000), 6, "3.375"},
		{big.NewInt(100_000), 6, "0.1"},
		{big.NewInt(1), 6, "0.000001"},
		{big.NewInt(19_800_000), 6, "19.8"},
		{big.NewInt(42), 0, "42"},
	}

	for _, tt := range tests {
		if got := FormatUnits(tt.amount, tt.decimals); got != tt.want {
			t.Errorf("FormatUnits(%s, %d) = %q, want %q", tt.amount, tt.decimals, got, tt.want)
		}
	}

	if got := FormatUnits(nil, 6); got != "<nil>" {
		t.Errorf("FormatUnits(nil, 6) = %q", got)
	}
}
