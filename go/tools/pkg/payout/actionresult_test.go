package payout

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	teetypes "github.com/flare-foundation/tee-node/pkg/types"
)

// The golden vector. Every literal below also appears verbatim in
// test/PolicySettlement.t.sol, which feeds them to the Solidity implementation
// of the same construction. Two independent implementations agreeing on one
// fixture is the whole point: a real settlement costs an FDC round and a live
// enclave to reproduce, and by then the mismatch would look like a chain
// problem rather than a hashing one.
const (
	goldenChainID       = uint64(31337) // forge's default, so the Solidity side matches
	goldenPrivateKeyHex = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	goldenTeeID         = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
	goldenInstructionID = "0x11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
	goldenSubmissionTag = "threshold"
	goldenPolicyID      = "0x000000000000000000000000000000000000000000000000000000000000a3d1"
	goldenPayoutTo      = "0x000000000000000000000000000000000000dEaD"
	goldenPayoutAmount  = 3_375_000 // 3.375 FXRP
	goldenSignHash      = "0x444fd3bc85ea62c08bbd6ef5313782b9c3bc05d5fc8e684ee5039667fb52a950"
	goldenSignature     = "0x9aef68dc04a5445e22a1b605be2ab82e6c4910399176d7869f92a7683bb5f6dc" +
		"5649079b00ac10f1a7d3bd617ab7207e6ac96c76667b821204c5a2dac892d524" +
		"01"
)

// goldenDecision ABI-encodes the decision payload the enclave would have signed:
// (bytes32 policyId, uint256 payoutAmount, address payoutTo).
func goldenDecision(t *testing.T) []byte {
	t.Helper()

	bytes32Ty, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		t.Fatalf("abi type bytes32: %v", err)
	}
	uint256Ty, err := abi.NewType("uint256", "", nil)
	if err != nil {
		t.Fatalf("abi type uint256: %v", err)
	}
	addressTy, err := abi.NewType("address", "", nil)
	if err != nil {
		t.Fatalf("abi type address: %v", err)
	}

	args := abi.Arguments{{Type: bytes32Ty}, {Type: uint256Ty}, {Type: addressTy}}
	data, err := args.Pack(
		[32]byte(common.HexToHash(goldenPolicyID)),
		big.NewInt(goldenPayoutAmount),
		common.HexToAddress(goldenPayoutTo),
	)
	if err != nil {
		t.Fatalf("packing decision: %v", err)
	}

	return data
}

func goldenActionResult(t *testing.T) *teetypes.ActionResult {
	t.Helper()

	return &teetypes.ActionResult{
		ID:            common.HexToHash(goldenInstructionID),
		SubmissionTag: teetypes.SubmissionTag(goldenSubmissionTag),
		Status:        1,
		Data:          hexutil.Bytes(goldenDecision(t)),
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()

	raw, err := hex.DecodeString(s[2:])
	if err != nil {
		t.Fatalf("decoding %q: %v", s, err)
	}

	return raw
}

func TestActionResultSignHashMatchesGoldenVector(t *testing.T) {
	got, err := ActionResultSignHash(goldenChainID, goldenActionResult(t))
	if err != nil {
		t.Fatalf("ActionResultSignHash: %v", err)
	}

	if got != common.HexToHash(goldenSignHash) {
		t.Errorf("sign hash = %s, want %s — Solidity's actionResultSignHash is pinned to this value",
			got.Hex(), goldenSignHash)
	}
}

// The digest must depend on the chain id, or a decision signed on one Flare
// network would settle on another.
func TestActionResultSignHashIsChainBound(t *testing.T) {
	result := goldenActionResult(t)

	onCoston2, err := ActionResultSignHash(114, result)
	if err != nil {
		t.Fatalf("ActionResultSignHash(114): %v", err)
	}
	onFlare, err := ActionResultSignHash(14, result)
	if err != nil {
		t.Fatalf("ActionResultSignHash(14): %v", err)
	}

	if onCoston2 == onFlare {
		t.Error("sign hash is identical across chain ids")
	}
}

func TestRecoverTeeIDMatchesGoldenVector(t *testing.T) {
	got, err := RecoverTeeID(goldenChainID, goldenActionResult(t), mustDecodeHex(t, goldenSignature))
	if err != nil {
		t.Fatalf("RecoverTeeID: %v", err)
	}

	if got != common.HexToAddress(goldenTeeID) {
		t.Errorf("recovered %s, want %s", got.Hex(), goldenTeeID)
	}
}

// The golden signature must be one the tee-node would actually have produced:
// signed over accounts.TextHash of the digest, with the key the vector names.
// Without this, the vector could drift into agreeing with a construction the
// enclave does not use.
func TestGoldenSignatureIsReproducible(t *testing.T) {
	key, err := crypto.HexToECDSA(goldenPrivateKeyHex)
	if err != nil {
		t.Fatalf("parsing golden key: %v", err)
	}
	if addr := crypto.PubkeyToAddress(key.PublicKey); addr != common.HexToAddress(goldenTeeID) {
		t.Fatalf("golden key derives %s, want %s", addr.Hex(), goldenTeeID)
	}

	signHash, err := ActionResultSignHash(goldenChainID, goldenActionResult(t))
	if err != nil {
		t.Fatalf("ActionResultSignHash: %v", err)
	}
	signature, err := crypto.Sign(accounts.TextHash(signHash[:]), key)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	if hex.EncodeToString(signature) != goldenSignature[2:] {
		t.Errorf("signature = 0x%s, want %s", hex.EncodeToString(signature), goldenSignature)
	}
}

// Every field the tee-node folds into ActionResult.Hash must change the digest,
// or settlement could accept a decision whose status, tag or payload was
// swapped for another.
func TestSignHashCoversEveryHashedField(t *testing.T) {
	base, err := ActionResultSignHash(goldenChainID, goldenActionResult(t))
	if err != nil {
		t.Fatalf("ActionResultSignHash: %v", err)
	}

	tests := []struct {
		name  string
		mutet func(*teetypes.ActionResult)
	}{
		{"id", func(r *teetypes.ActionResult) { r.ID = common.HexToHash("0xdead") }},
		{"submission tag", func(r *teetypes.ActionResult) { r.SubmissionTag = teetypes.End }},
		{"status", func(r *teetypes.ActionResult) { r.Status = 0 }},
		{"data", func(r *teetypes.ActionResult) { r.Data = append(hexutil.Bytes{}, 0x01) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := goldenActionResult(t)
			tt.mutet(result)

			got, err := ActionResultSignHash(goldenChainID, result)
			if err != nil {
				t.Fatalf("ActionResultSignHash: %v", err)
			}
			if got == base {
				t.Errorf("changing %s left the digest unchanged", tt.name)
			}
		})
	}
}

// The second vector: the same enclave deciding a wet-season policy owes
// nothing. Its recovery id happens to be 0 rather than 1, which is the parity a
// Solidity ecrecover gets wrong if it forgets to normalise v.
const (
	zeroInstructionID = "0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff"
	zeroPolicyID      = "0x000000000000000000000000000000000000000000000000000000000000a3d2"
	zeroSignHash      = "0x65af0a4074b9b43ae0053c933f0576598b3e74d10e43c65dd6b20daf206e96f3"
	zeroSignature     = "0x50e57e2f88b7f9086509b40e2a84e5f16845b5250ac93ffd146d53633b89592f" +
		"5e5a08347be92cf84f49906767e49d3845b082d36254175025b26a472ffcabf7" +
		"00"
)

func TestZeroPayoutGoldenVector(t *testing.T) {
	bytes32Ty, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		t.Fatalf("abi type bytes32: %v", err)
	}
	uint256Ty, err := abi.NewType("uint256", "", nil)
	if err != nil {
		t.Fatalf("abi type uint256: %v", err)
	}
	addressTy, err := abi.NewType("address", "", nil)
	if err != nil {
		t.Fatalf("abi type address: %v", err)
	}

	args := abi.Arguments{{Type: bytes32Ty}, {Type: uint256Ty}, {Type: addressTy}}
	data, err := args.Pack(
		[32]byte(common.HexToHash(zeroPolicyID)),
		big.NewInt(0),
		common.HexToAddress(goldenPayoutTo),
	)
	if err != nil {
		t.Fatalf("packing decision: %v", err)
	}

	result := &teetypes.ActionResult{
		ID:            common.HexToHash(zeroInstructionID),
		SubmissionTag: teetypes.SubmissionTag(goldenSubmissionTag),
		Status:        1,
		Data:          hexutil.Bytes(data),
	}

	signHash, err := ActionResultSignHash(goldenChainID, result)
	if err != nil {
		t.Fatalf("ActionResultSignHash: %v", err)
	}
	if signHash != common.HexToHash(zeroSignHash) {
		t.Errorf("sign hash = %s, want %s", signHash.Hex(), zeroSignHash)
	}

	signature := mustDecodeHex(t, zeroSignature)
	if got := signature[64]; got != 0 {
		t.Errorf("recovery id = %d, want 0 — this vector exists to cover that parity", got)
	}

	teeID, err := RecoverTeeID(goldenChainID, result, signature)
	if err != nil {
		t.Fatalf("RecoverTeeID: %v", err)
	}
	if teeID != common.HexToAddress(goldenTeeID) {
		t.Errorf("recovered %s, want %s", teeID.Hex(), goldenTeeID)
	}
}

func TestRecoverTeeIDRejectsMalformedSignature(t *testing.T) {
	result := goldenActionResult(t)
	valid := mustDecodeHex(t, goldenSignature)

	if _, err := RecoverTeeID(goldenChainID, result, valid[:64]); err == nil {
		t.Error("expected an error for a 64-byte signature")
	}
	if _, err := RecoverTeeID(goldenChainID, result, nil); err == nil {
		t.Error("expected an error for a missing signature")
	}
}

// A decision signed for another instruction must not recover to the enclave.
func TestRecoverTeeIDDetectsTamperedResult(t *testing.T) {
	tampered := goldenActionResult(t)
	tampered.Data = hexutil.Bytes(append([]byte(nil), tampered.Data...))
	// Bump the payout amount by one unit.
	tampered.Data[63]++

	got, err := RecoverTeeID(goldenChainID, tampered, mustDecodeHex(t, goldenSignature))
	if err != nil {
		// Recovery failing outright is an acceptable outcome too.
		return
	}
	if got == common.HexToAddress(goldenTeeID) {
		t.Error("a tampered decision recovered to the enclave's address")
	}
}
