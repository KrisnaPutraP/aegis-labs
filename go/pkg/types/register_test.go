package types

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func testModel() ModelParameters {
	return ModelParameters{
		TriggerTenthsMm: 1200,
		ExitTenthsMm:    400,
		SumInsuredWei:   big.NewInt(1_000_000_000_000_000_000),
		PayoutFactorBps: 9000,
		MinPayoutWei:    big.NewInt(1_000_000_000_000),
	}
}

func TestEvaluateRequestRoundTrip(t *testing.T) {
	req := EvaluateRequest{
		PolicyID:         common.HexToHash("0x2a"),
		RainfallTenthsMm: big.NewInt(837),
		PayoutTo:         common.HexToAddress("0x24489D1186a6497134e843C38451b760ac3e358B"),
	}

	encoded, err := req.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(encoded) != evaluateTupleSize {
		t.Fatalf("encoded length = %d, want %d", len(encoded), evaluateTupleSize)
	}

	decoded, err := DecodeEvaluateRequest(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.PolicyID != req.PolicyID {
		t.Errorf("policyId = %s, want %s", decoded.PolicyID.Hex(), req.PolicyID.Hex())
	}
	if decoded.RainfallTenthsMm.Cmp(req.RainfallTenthsMm) != 0 {
		t.Errorf("rainfall = %s, want %s", decoded.RainfallTenthsMm, req.RainfallTenthsMm)
	}
	if decoded.PayoutTo != req.PayoutTo {
		t.Errorf("payoutTo = %s, want %s", decoded.PayoutTo.Hex(), req.PayoutTo.Hex())
	}
}

func TestEvaluateResponseRoundTrip(t *testing.T) {
	resp := EvaluateResponse{
		PolicyID:     common.HexToHash("0x2a"),
		PayoutAmount: big.NewInt(750_000_000_000_000_000),
		PayoutTo:     common.HexToAddress("0x24489D1186a6497134e843C38451b760ac3e358B"),
	}

	encoded, err := resp.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	decoded, err := DecodeEvaluateResponse(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.PolicyID != resp.PolicyID ||
		decoded.PayoutAmount.Cmp(resp.PayoutAmount) != 0 ||
		decoded.PayoutTo != resp.PayoutTo {
		t.Errorf("round trip mismatch: got %+v, want %+v", decoded, resp)
	}
}

func TestEncodeEvaluateRejectsBadValue(t *testing.T) {
	req := EvaluateRequest{PolicyID: common.HexToHash("0x1")}
	if _, err := req.Encode(); err == nil {
		t.Error("expected error for nil value")
	}

	req.RainfallTenthsMm = big.NewInt(-1)
	if _, err := req.Encode(); err == nil {
		t.Error("expected error for negative value")
	}
}

func TestDecodeEvaluateRejectsWrongLength(t *testing.T) {
	req := EvaluateRequest{
		PolicyID:         common.HexToHash("0x1"),
		RainfallTenthsMm: big.NewInt(1),
		PayoutTo:         common.Address{},
	}
	encoded, err := req.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	if _, err := DecodeEvaluateRequest(encoded[:64]); err == nil {
		t.Error("expected error for short payload")
	}
	if _, err := DecodeEvaluateRequest(append(encoded, 0x00)); err == nil {
		t.Error("expected error for trailing byte")
	}
}

func TestRegisterModelRoundTrip(t *testing.T) {
	req := RegisterModelRequest{
		PolicyID: common.HexToHash("0x7"),
		Model:    testModel(),
	}

	encoded, err := req.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	decoded, err := DecodeRegisterModelRequest(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.PolicyID != req.PolicyID {
		t.Errorf("policyId = %s, want %s", decoded.PolicyID.Hex(), req.PolicyID.Hex())
	}
	if decoded.Model.TriggerTenthsMm != req.Model.TriggerTenthsMm ||
		decoded.Model.ExitTenthsMm != req.Model.ExitTenthsMm ||
		decoded.Model.PayoutFactorBps != req.Model.PayoutFactorBps ||
		decoded.Model.SumInsuredWei.Cmp(req.Model.SumInsuredWei) != 0 ||
		decoded.Model.MinPayoutWei.Cmp(req.Model.MinPayoutWei) != 0 {
		t.Errorf("model round trip mismatch: got %+v", decoded.Model)
	}
}

func TestDecodeRegisterModelRejectsBadPayloads(t *testing.T) {
	const (
		policyID = "0x0000000000000000000000000000000000000000000000000000000000000007"
		zeroID   = "0x0000000000000000000000000000000000000000000000000000000000000000"
	)

	// payload builds a register-model JSON body with the given policy id and
	// model object.
	payload := func(id, model string) string {
		return `{"policyId":"` + id + `","model":` + model + `}`
	}
	const validModel = `{"triggerTenthsMm":10,"exitTenthsMm":1,"sumInsuredWei":1,"payoutFactorBps":10000,"minPayoutWei":0}`

	tests := []struct {
		name    string
		payload string
	}{
		{"not json", "definitely not json"},
		{"unknown field", payload(policyID, `{"triggerTenthsMm":10,"exitTenthsMm":1,"sumInsuredWei":1,"payoutFactorBps":10000,"minPayoutWei":0,"backdoor":true}`)},
		{"trailing data", payload(policyID, validModel) + "{}"},
		{"zero policy id", payload(zeroID, validModel)},
		{"exit above trigger", payload(policyID, `{"triggerTenthsMm":10,"exitTenthsMm":20,"sumInsuredWei":1,"payoutFactorBps":10000,"minPayoutWei":0}`)},
		{"zero sum insured", payload(policyID, `{"triggerTenthsMm":10,"exitTenthsMm":1,"sumInsuredWei":0,"payoutFactorBps":10000,"minPayoutWei":0}`)},
		{"zero factor", payload(policyID, `{"triggerTenthsMm":10,"exitTenthsMm":1,"sumInsuredWei":1,"payoutFactorBps":0,"minPayoutWei":0}`)},
		{"missing min payout", payload(policyID, `{"triggerTenthsMm":10,"exitTenthsMm":1,"sumInsuredWei":1,"payoutFactorBps":10000}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecodeRegisterModelRequest([]byte(tt.payload)); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}

	// Control: the same shape with every field valid must decode.
	if _, err := DecodeRegisterModelRequest([]byte(payload(policyID, validModel))); err != nil {
		t.Fatalf("valid payload rejected: %v", err)
	}
}

// Rule 7 / FR-8: a rejection must not quote the parameters it rejected.
func TestModelValidationErrorsDoNotLeakValues(t *testing.T) {
	model := ModelParameters{
		TriggerTenthsMm: 1234,
		ExitTenthsMm:    5678, // invalid: above trigger
		SumInsuredWei:   big.NewInt(4242),
		PayoutFactorBps: 9999,
		MinPayoutWei:    big.NewInt(31337),
	}

	err := model.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}

	for _, secret := range []string{"1234", "5678", "4242", "9999", "31337"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("validation error leaks parameter value %q: %s", secret, err)
		}
	}
}
