package extension

import (
	"bytes"
	"math/big"
	"strings"
	"testing"

	"sign-extension/pkg/types"
)

// rampModel: cover responds below 120.0 mm, pays in full at or below 40.0 mm,
// scaled by a hidden 0.9. The sum insured is deliberately a large round number
// rather than a realistic one — the ramp is pure integer arithmetic and these
// cases exercise its rounding, not any particular payout asset's scale.
func rampModel() types.ModelParameters {
	return types.ModelParameters{
		TriggerTenthsMm: 1200,
		ExitTenthsMm:    400,
		SumInsuredUnits: big.NewInt(1_000_000_000_000_000_000),
		PayoutFactorBps: 9000,
		MinPayoutUnits:  big.NewInt(1_000_000_000_000),
	}
}

func units(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad decimal literal: " + s)
	}
	return n
}

func TestEvaluatePayoutRamp(t *testing.T) {
	model := rampModel()

	tests := []struct {
		name     string
		rainfall int64
		want     *big.Int
	}{
		{"far above trigger", 2000, big.NewInt(0)},
		{"exactly at trigger", 1200, big.NewInt(0)},
		{"just below trigger", 1199, units("1125000000000000")},
		{"midway down the ramp", 800, units("450000000000000000")},
		{"drought reading", 600, units("675000000000000000")},
		{"exactly at exit", 400, units("900000000000000000")},
		{"below exit stays capped", 0, units("900000000000000000")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evaluatePayout(&model, big.NewInt(tt.rainfall))
			if err != nil {
				t.Fatalf("evaluatePayout: %v", err)
			}
			if got.Cmp(tt.want) != 0 {
				t.Errorf("payout = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestEvaluatePayoutDustFloor(t *testing.T) {
	model := rampModel()
	// Raise the floor above what a marginal shortfall can earn.
	model.MinPayoutUnits = units("10000000000000000")

	got, err := evaluatePayout(&model, big.NewInt(1199))
	if err != nil {
		t.Fatalf("evaluatePayout: %v", err)
	}
	if got.Sign() != 0 {
		t.Errorf("payout = %s, want 0 below the dust floor", got)
	}

	// A shortfall well past the floor still pays.
	got, err = evaluatePayout(&model, big.NewInt(600))
	if err != nil {
		t.Fatalf("evaluatePayout: %v", err)
	}
	if got.Cmp(units("675000000000000000")) != 0 {
		t.Errorf("payout = %s, want 675000000000000000", got)
	}
}

func TestEvaluatePayoutNeverExceedsSumInsured(t *testing.T) {
	model := rampModel()
	model.PayoutFactorBps = 25_000 // 250%

	got, err := evaluatePayout(&model, big.NewInt(0))
	if err != nil {
		t.Fatalf("evaluatePayout: %v", err)
	}
	if got.Cmp(model.SumInsuredUnits) != 0 {
		t.Errorf("payout = %s, want it capped at the sum insured %s", got, model.SumInsuredUnits)
	}
}

// The payout must never increase as rainfall increases — an insurer reading the
// ramp backwards would pay most in a good season.
func TestEvaluatePayoutIsMonotonic(t *testing.T) {
	model := rampModel()

	previous := new(big.Int)
	for rainfall := int64(1300); rainfall >= 0; rainfall -= 25 {
		got, err := evaluatePayout(&model, big.NewInt(rainfall))
		if err != nil {
			t.Fatalf("evaluatePayout(%d): %v", rainfall, err)
		}
		if got.Cmp(previous) < 0 {
			t.Fatalf("payout dropped from %s to %s as rainfall fell to %d", previous, got, rainfall)
		}
		previous = got
	}
}

func TestEvaluatePayoutRejectsBadInput(t *testing.T) {
	model := rampModel()

	if _, err := evaluatePayout(&model, nil); err == nil {
		t.Error("expected error for nil rainfall")
	}
	if _, err := evaluatePayout(&model, big.NewInt(-1)); err == nil {
		t.Error("expected error for negative rainfall")
	}

	// A model that slipped past registration must not divide by zero.
	broken := rampModel()
	broken.ExitTenthsMm = broken.TriggerTenthsMm
	if _, err := evaluatePayout(&broken, big.NewInt(100)); err == nil {
		t.Error("expected error for a model with a zero-width ramp")
	}
}

// Same reading, same decision — the on-chain consumer must be able to rely on
// two evaluations of the same instruction agreeing byte for byte.
func TestEvaluateIsDeterministic(t *testing.T) {
	e := New(0, 0)
	if result := registerModel(t, e, secretModel()); result.Status != 1 {
		t.Fatalf("register model status = %d, log = %q", result.Status, result.Log)
	}

	first := evaluate(t, e, 700)
	second := evaluate(t, e, 700)

	if first.Status != 1 || second.Status != 1 {
		t.Fatalf("statuses = %d, %d, want 1", first.Status, second.Status)
	}
	if string(first.Data) != string(second.Data) {
		t.Errorf("decisions differ: %x vs %x", first.Data, second.Data)
	}
}

// End to end through the router: a dry reading pays, a wet one does not.
func TestEvaluateThroughRouterPaysOnlyOnDrought(t *testing.T) {
	e := New(0, 0)
	model := rampModel()
	if result := registerModel(t, e, model); result.Status != 1 {
		t.Fatalf("register model status = %d, log = %q", result.Status, result.Log)
	}

	dry := evaluate(t, e, 600)
	if dry.Status != 1 {
		t.Fatalf("dry evaluate status = %d, log = %q", dry.Status, dry.Log)
	}
	dryDecision, err := types.DecodeEvaluateResponse(dry.Data)
	if err != nil {
		t.Fatalf("decode dry decision: %v", err)
	}
	if dryDecision.PayoutAmount.Cmp(units("675000000000000000")) != 0 {
		t.Errorf("dry payout = %s, want 675000000000000000", dryDecision.PayoutAmount)
	}

	wet := evaluate(t, e, 1500)
	if wet.Status != 1 {
		t.Fatalf("wet evaluate status = %d, log = %q", wet.Status, wet.Log)
	}
	wetDecision, err := types.DecodeEvaluateResponse(wet.Data)
	if err != nil {
		t.Fatalf("decode wet decision: %v", err)
	}
	if wetDecision.PayoutAmount.Sign() != 0 {
		t.Errorf("wet payout = %s, want 0", wetDecision.PayoutAmount)
	}
}

// A registered model must not be inferable from the thresholds an attacker can
// probe: the decision reveals amounts, never the parameters behind them.
func TestDecisionCarriesOnlyThePublicTriple(t *testing.T) {
	e := New(0, 0)
	if result := registerModel(t, e, secretModel()); result.Status != 1 {
		t.Fatalf("register model status = %d", result.Status)
	}

	result := evaluate(t, e, 700)
	if len(result.Data) != 96 {
		t.Errorf("decision payload = %d bytes, want 96 (bytes32, uint256, address)", len(result.Data))
	}

	decision, err := types.DecodeEvaluateResponse(result.Data)
	if err != nil {
		t.Fatalf("decode decision: %v", err)
	}

	// Re-encoding the decoded triple must reproduce the payload byte for byte:
	// there is no room left in it for anything the model knows.
	reEncoded, err := decision.Encode()
	if err != nil {
		t.Fatalf("re-encode decision: %v", err)
	}
	if !bytes.Equal(reEncoded, result.Data) {
		t.Errorf("decision payload carries more than the public triple:\n got %x\nwant %x", result.Data, reEncoded)
	}

	for _, secret := range secretStrings() {
		if strings.Contains(result.Log, secret) {
			t.Errorf("decision log leaks model parameter %q: %s", secret, result.Log)
		}
	}
}
