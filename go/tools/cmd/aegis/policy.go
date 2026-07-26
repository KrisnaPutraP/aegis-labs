package main

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sign-extension/pkg/types"
	"sign-extension/tools/pkg/fdc"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

// policyTemplate is a named cover an operator can demo: a coverage window over
// one location, and the two byte prefix its policy ids carry so a run is
// recognisable in logs and on the dashboard.
type policyTemplate struct {
	prefix      uint16
	description string
	feed        fdc.DroughtFeed
}

const defaultPolicyName = "drought-surabaya"

// The two windows cover the same coordinates and differ only in season, which is
// the whole demonstration: one model, one location, and an outcome that comes
// from the attested data alone. The prefixes match the ones cmd/run-test uses,
// so a policy created here is labelled the same way everywhere else.
var policyCatalog = map[string]policyTemplate{
	"drought-surabaya": {
		prefix:      0xa3d1,
		description: "dry season over Surabaya, expected to pay",
		feed: fdc.DroughtFeed{
			LatitudeDeg:  "-7.25",
			LongitudeDeg: "112.75",
			StartDate:    "2025-06-01",
			EndDate:      "2025-08-31",
		},
	},
	"monsoon-surabaya": {
		prefix:      0xa3d2,
		description: "wet season over the same point, expected to pay nothing",
		feed: fdc.DroughtFeed{
			LatitudeDeg:  "-7.25",
			LongitudeDeg: "112.75",
			StartDate:    "2024-12-01",
			EndDate:      "2025-02-28",
		},
	},
}

// policyNames lists the catalog with the default first, so help output reads in
// the order a demo runs.
func policyNames() []string {
	return []string{"drought-surabaya", "monsoon-surabaya"}
}

func policyNameList() string {
	return strings.Join(policyNames(), ", ")
}

// demoModel is the insurer's confidential risk model, and the only place in this
// command that holds it.
//
// It carries the same numbers cmd/run-test registers, so a policy created here
// behaves like the ones already settled on Coston2. These values must never be
// printed, logged, or put in an error message (CLAUDE.md rule 7): they travel to
// the enclave ECIES encrypted and nowhere else. Pass --model-file to load an
// insurer's own parameters from outside the repository instead.
func demoModel() types.ModelParameters {
	return types.ModelParameters{
		TriggerTenthsMm: 1200,
		ExitTenthsMm:    400,
		SumInsuredUnits: big.NewInt(5_000_000),
		PayoutFactorBps: 9000,
		MinPayoutUnits:  big.NewInt(100_000),
	}
}

// loadModel reads model parameters from a file when the operator supplies one.
// The enclave validates them again after decryption, which is the check that
// counts; this only fails early and readably.
func loadModel(path string) (types.ModelParameters, error) {
	if path == "" {
		return demoModel(), nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return types.ModelParameters{}, errors.Errorf("reading model file: %s", err)
	}

	var model types.ModelParameters
	if err := json.Unmarshal(raw, &model); err != nil {
		// The message deliberately does not echo the file contents.
		return types.ModelParameters{}, errors.Errorf("model file %s is not valid model JSON", path)
	}
	if model.SumInsuredUnits == nil || model.MinPayoutUnits == nil {
		return types.ModelParameters{}, errors.Errorf(
			"model file %s is missing sumInsuredUnits or minPayoutUnits", path)
	}
	if model.ExitTenthsMm >= model.TriggerTenthsMm {
		return types.ModelParameters{}, errors.Errorf(
			"model file %s has an exit level at or above the trigger level", path)
	}

	return model, nil
}

// secretStrings renders the model parameters the way they would appear if they
// ever leaked into a byte stream. Used only to check they did not.
func secretStrings(m types.ModelParameters) []string {
	return []string{
		big.NewInt(0).SetUint64(m.TriggerTenthsMm).String(),
		big.NewInt(0).SetUint64(m.ExitTenthsMm).String(),
		m.SumInsuredUnits.String(),
		big.NewInt(0).SetUint64(m.PayoutFactorBps).String(),
		m.MinPayoutUnits.String(),
	}
}

// assertSealed refuses to send a ciphertext that still carries a recognisable
// parameter. It is cheap, and it guards the one invariant that would quietly
// destroy the product if a future change broke it: the parameters never leave
// this process in the clear.
func assertSealed(model types.ModelParameters, ciphertext []byte) error {
	blob := string(ciphertext)
	for _, secret := range secretStrings(model) {
		if strings.Contains(blob, secret) {
			// No parameter is named in the error, only the fact of the leak.
			return errors.New("refusing to send: the sealed model still contains a parameter in the clear")
		}
	}
	return nil
}

// newPolicyID builds a run unique id that still reads as an 0xa3d1 style
// identifier: two bytes of prefix, then thirty random bytes.
//
// Ids have to be fresh per demo. A policy pays once and closes, and its trigger
// binding is write once, so a fixed id would work exactly once per deployment
// and then fail in a way that looks like a broken payout path.
func newPolicyID(prefix uint16) (common.Hash, error) {
	nonce := make([]byte, 30)
	if _, err := rand.Read(nonce); err != nil {
		return common.Hash{}, errors.Errorf("drawing a policy nonce: %s", err)
	}

	var id common.Hash
	id[0] = byte(prefix >> 8)
	id[1] = byte(prefix)
	copy(id[2:], nonce)

	return id, nil
}

// policyRecord is what one demo policy looks like between commands. It holds no
// secret: an id, the request it is bound to, and what has happened to it so far.
type policyRecord struct {
	Name              string    `json:"name"`
	PolicyID          string    `json:"policyId"`
	CreatedAt         time.Time `json:"createdAt"`
	RequestHash       string    `json:"requestHash"`
	AbiEncodedRequest string    `json:"abiEncodedRequest"`

	ModelRegistered       bool   `json:"modelRegistered"`
	RegisterInstructionID string `json:"registerInstructionId,omitempty"`

	VotingRound           uint64 `json:"votingRound,omitempty"`
	EvaluateInstructionID string `json:"evaluateInstructionId,omitempty"`
	PayoutUnits           string `json:"payoutUnits,omitempty"`
	SettleTx              string `json:"settleTx,omitempty"`
	Settled               bool   `json:"settled,omitempty"`
}

func (r *policyRecord) id() common.Hash {
	return common.HexToHash(r.PolicyID)
}

// demoState is the small file that lets separate commands work on the same
// policy. It is a demo convenience, not a source of truth: every command reads
// the chain for anything that matters.
type demoState struct {
	path     string
	Policies map[string]*policyRecord `json:"policies"`
}

func loadState(path string) (*demoState, error) {
	state := &demoState{path: path, Policies: map[string]*policyRecord{}}

	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return nil, errors.Errorf("reading %s: %s", path, err)
	}
	if err := json.Unmarshal(raw, state); err != nil {
		return nil, errors.Errorf("parsing %s: %s", path, err)
	}
	if state.Policies == nil {
		state.Policies = map[string]*policyRecord{}
	}
	state.path = path

	return state, nil
}

func (s *demoState) save() error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return errors.Errorf("encoding demo state: %s", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return errors.Errorf("creating %s: %s", filepath.Dir(s.path), err)
	}
	if err := os.WriteFile(s.path, append(raw, '\n'), 0o644); err != nil {
		return errors.Errorf("writing %s: %s", s.path, err)
	}
	return nil
}

func (s *demoState) get(name string) *policyRecord {
	return s.Policies[name]
}

func (s *demoState) put(record *policyRecord) {
	s.Policies[record.Name] = record
}
