package extension

import (
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sign-extension/internal/config"
	"sign-extension/pkg/types"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	teetypes "github.com/flare-foundation/tee-node/pkg/types"
	teeutils "github.com/flare-foundation/tee-node/pkg/utils"
)

var (
	testPolicyID = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000007")
	testPayoutTo = common.HexToAddress("0x24489D1186a6497134e843C38451b760ac3e358B")
)

// secretModel uses values distinctive enough to grep for in any output.
func secretModel() types.ModelParameters {
	return types.ModelParameters{
		TriggerTenthsMm: 1234,
		ExitTenthsMm:    321,
		SumInsuredWei:   big.NewInt(4242424242),
		PayoutFactorBps: 8765,
		MinPayoutWei:    big.NewInt(31337),
	}
}

// secretStrings are the decimal renderings of secretModel's fields — none of
// them may ever show up in a log line, action result, or /state response.
func secretStrings() []string {
	return []string{"1234", "321", "4242424242", "8765", "31337"}
}

// startFakeDecryptNode stands in for the tee-node's /decrypt endpoint: it hands
// back the plaintext the test wants the enclave to see. It listens on
// "localhost" so decryptViaNode's dial resolves the same way in any environment.
func startFakeDecryptNode(t *testing.T, plaintext []byte) int {
	t.Helper()

	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /decrypt", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string][]byte{"decryptedMessage": plaintext})
	})

	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	return listener.Addr().(*net.TCPAddr).Port
}

// action wraps an instruction into the envelope the framework posts to /action.
func action(t *testing.T, opType, opCommand string, message []byte) teetypes.Action {
	t.Helper()

	dataFixed := instruction.DataFixed{
		InstructionID:   common.HexToHash("0x1"),
		OPType:          teeutils.ToHash(opType),
		OPCommand:       teeutils.ToHash(opCommand),
		OriginalMessage: message,
	}
	encoded, err := json.Marshal(dataFixed)
	if err != nil {
		t.Fatalf("marshal data fixed: %v", err)
	}

	return teetypes.Action{
		Data: teetypes.ActionData{
			ID:            dataFixed.InstructionID,
			Type:          teetypes.Instruction,
			SubmissionTag: teetypes.Submit,
			Message:       encoded,
		},
	}
}

// run processes an action and returns the parsed action result.
func run(t *testing.T, e *Extension, a teetypes.Action) (int, teetypes.ActionResult) {
	t.Helper()

	status, body := e.processAction(a)

	var result teetypes.ActionResult
	if status == http.StatusOK {
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("unmarshal action result: %v (body: %s)", err, body)
		}
	}

	return status, result
}

func registerModel(t *testing.T, e *Extension, model types.ModelParameters) teetypes.ActionResult {
	t.Helper()

	plaintext, err := (&types.RegisterModelRequest{PolicyID: testPolicyID, Model: model}).Encode()
	if err != nil {
		t.Fatalf("encode register model request: %v", err)
	}
	e.signPort = startFakeDecryptNode(t, plaintext)

	// The on-chain message is ciphertext; the fake node ignores it and returns
	// the plaintext above, so any non-empty payload stands in for it here.
	status, result := run(t, e, action(t, config.OPTypePolicy, config.OPCommandRegisterModel, []byte("ciphertext")))
	if status != http.StatusOK {
		t.Fatalf("register model: http status %d", status)
	}

	return result
}

func evaluate(t *testing.T, e *Extension, rainfallTenthsMm int64) teetypes.ActionResult {
	t.Helper()

	message, err := (&types.EvaluateRequest{
		PolicyID:         testPolicyID,
		RainfallTenthsMm: big.NewInt(rainfallTenthsMm),
		PayoutTo:         testPayoutTo,
	}).Encode()
	if err != nil {
		t.Fatalf("encode evaluate request: %v", err)
	}

	status, result := run(t, e, action(t, config.OPTypePolicy, config.OPCommandEvaluate, message))
	if status != http.StatusOK {
		t.Fatalf("evaluate: http status %d", status)
	}

	return result
}

func TestProcessActionRejectsUnknownOPType(t *testing.T) {
	e := New(0, 0)

	status, _ := e.processAction(action(t, "KEY", config.OPCommandEvaluate, []byte("x")))
	if status != http.StatusNotImplemented {
		t.Errorf("status = %d, want %d", status, http.StatusNotImplemented)
	}
}

func TestProcessPolicyRejectsUnknownCommand(t *testing.T) {
	e := New(0, 0)

	status, _ := e.processAction(action(t, config.OPTypePolicy, "SIGN", []byte("x")))
	if status != http.StatusNotImplemented {
		t.Errorf("status = %d, want %d", status, http.StatusNotImplemented)
	}
}

func TestEvaluateWithoutRegisteredModelFails(t *testing.T) {
	e := New(0, 0)

	result := evaluate(t, e, 500)
	if result.Status != 0 {
		t.Errorf("status = %d, want 0", result.Status)
	}
	if !strings.Contains(result.Log, "no model registered") {
		t.Errorf("log = %q, want it to name the missing model", result.Log)
	}
	if len(result.Data) != 0 {
		t.Errorf("failed evaluation returned data: %x", result.Data)
	}
}

func TestRegisterModelThenEvaluate(t *testing.T) {
	e := New(0, 0)

	if result := registerModel(t, e, secretModel()); result.Status != 1 {
		t.Fatalf("register model status = %d, log = %q", result.Status, result.Log)
	}

	e.mu.RLock()
	loaded := len(e.models)
	e.mu.RUnlock()
	if loaded != 1 {
		t.Fatalf("models loaded = %d, want 1", loaded)
	}

	result := evaluate(t, e, 500)
	if result.Status != 1 {
		t.Fatalf("evaluate status = %d, log = %q", result.Status, result.Log)
	}

	decoded, err := types.DecodeEvaluateResponse(result.Data)
	if err != nil {
		t.Fatalf("decode evaluate response: %v", err)
	}
	if decoded.PolicyID != testPolicyID {
		t.Errorf("policyId = %s, want %s", decoded.PolicyID.Hex(), testPolicyID.Hex())
	}
	if decoded.PayoutTo != testPayoutTo {
		t.Errorf("payoutTo = %s, want %s", decoded.PayoutTo.Hex(), testPayoutTo.Hex())
	}
	if decoded.PayoutAmount == nil || decoded.PayoutAmount.Sign() < 0 {
		t.Errorf("payoutAmount = %v, want a non-negative amount", decoded.PayoutAmount)
	}
}

func TestRegisterModelRejectsMalformedPlaintext(t *testing.T) {
	e := New(0, 0)
	e.signPort = startFakeDecryptNode(t, []byte(`{"policyId":"0x07"}`))

	status, result := run(t, e, action(t, config.OPTypePolicy, config.OPCommandRegisterModel, []byte("ciphertext")))
	if status != http.StatusOK {
		t.Fatalf("http status %d", status)
	}
	if result.Status != 0 {
		t.Errorf("status = %d, want 0 for a malformed model", result.Status)
	}

	e.mu.RLock()
	loaded := len(e.models)
	e.mu.RUnlock()
	if loaded != 0 {
		t.Errorf("models loaded = %d, want 0", loaded)
	}
}

// Trust boundary invariant 1 (ARCHITECTURE.md §3): nothing the extension emits
// may carry the model parameters.
func TestSecretModelNeverLeavesTheEnclave(t *testing.T) {
	e := New(0, 0)

	outputs := map[string]string{}

	registerResult := registerModel(t, e, secretModel())
	registerJSON, err := json.Marshal(registerResult)
	if err != nil {
		t.Fatalf("marshal register result: %v", err)
	}
	outputs["register result"] = string(registerJSON)

	evaluateResult := evaluate(t, e, 500)
	evaluateJSON, err := json.Marshal(evaluateResult)
	if err != nil {
		t.Fatalf("marshal evaluate result: %v", err)
	}
	outputs["evaluate result"] = string(evaluateJSON)

	// A failed evaluation is the likeliest place for a parameter to slip into an
	// error message, so cover it too.
	failedResult := evaluate(t, New(0, 0), 500)
	failedJSON, err := json.Marshal(failedResult)
	if err != nil {
		t.Fatalf("marshal failed result: %v", err)
	}
	outputs["failed evaluate result"] = string(failedJSON)

	recorder := httptest.NewRecorder()
	e.stateHandler(recorder, httptest.NewRequest(http.MethodGet, "/state", nil))
	outputs["state response"] = recorder.Body.String()

	for label, output := range outputs {
		for _, secret := range secretStrings() {
			if strings.Contains(output, secret) {
				t.Errorf("%s leaks model parameter %q: %s", label, secret, output)
			}
		}
	}
}
