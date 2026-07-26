// Package payout carries a TEE-signed payout decision from the extension proxy
// to PolicySettlement on Flare.
//
// The decision is only worth acting on because of the signature over it, so the
// one thing this package must get exactly right is the preimage that signature
// covers. The tee-node builds it in two steps (internal/router/utils.go,
// pkg/types/actions.go):
//
//	resultHash = keccak256(keccak256(data) ‖ id ‖ keccak256(submissionTag) ‖ status)
//	signHash   = keccak256(abi.encode(Payload{"TEE_ACTION_RESULT", chainID, resultHash}))
//	signature  = secp256k1_sign(accounts.TextHash(signHash))
//
// PolicySettlement.actionResultSignHash reproduces the same two steps in
// Solidity. Both are pinned to one another by the golden vector in
// actionresult_test.go and test/PolicySettlement.t.sol, which share the same
// literals — if either side ever drifts, exactly one of those tests fails.
package payout

import (
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	csigning "github.com/flare-foundation/go-flare-common/pkg/signing"
	teetypes "github.com/flare-foundation/tee-node/pkg/types"
	"github.com/pkg/errors"
)

// SignatureLength is the size of a raw secp256k1 signature: r ‖ s ‖ v.
const SignatureLength = 65

// ActionResultSignHash returns the digest the TEE signs over an action result,
// before the Ethereum Signed Message wrapper.
//
// The chain id is part of the preimage, which is what stops a decision signed on
// Coston2 from settling anything on Flare mainnet.
func ActionResultSignHash(chainID uint64, result *teetypes.ActionResult) (common.Hash, error) {
	if result == nil {
		return common.Hash{}, errors.New("action result is nil")
	}

	signHash, err := csigning.NewPayload(
		csigning.TEEActionResult, chainID, common.BytesToHash(result.Hash()),
	).Hash()
	if err != nil {
		return common.Hash{}, errors.Errorf("hashing action result payload: %s", err)
	}

	return signHash, nil
}

// RecoverTeeID recovers the TEE identity that signed an action result.
//
// Callers use it to check a decision before paying gas to settle it on-chain:
// PolicySettlement performs the identical recovery, so a mismatch here is a
// mismatch there.
func RecoverTeeID(chainID uint64, result *teetypes.ActionResult, signature []byte) (common.Address, error) {
	if len(signature) != SignatureLength {
		return common.Address{}, errors.Errorf(
			"signature is %d bytes, want %d", len(signature), SignatureLength)
	}

	signHash, err := ActionResultSignHash(chainID, result)
	if err != nil {
		return common.Address{}, err
	}

	pubKey, err := crypto.SigToPub(accounts.TextHash(signHash[:]), signature)
	if err != nil {
		return common.Address{}, errors.Errorf("recovering signer: %s", err)
	}

	return crypto.PubkeyToAddress(*pubKey), nil
}
