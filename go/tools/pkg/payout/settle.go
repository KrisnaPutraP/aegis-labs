package payout

import (
	"context"
	"math/big"

	"sign-extension/tools/pkg/contracts/settlement"
	"sign-extension/tools/pkg/support"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	teetypes "github.com/flare-foundation/tee-node/pkg/types"
	"github.com/pkg/errors"
)

// Decision is the enclave's verdict, as it is about to be presented on-chain.
type Decision struct {
	PolicyID     common.Hash
	PayoutAmount *big.Int
	PayoutTo     common.Address

	// InstructionID is the evaluation the decision answers, and the key
	// PolicySettlement burns to stop the decision being replayed.
	InstructionID common.Hash

	// TeeID is the enclave recovered from the signature. Recovering it here
	// rather than only on-chain means a decision signed by the wrong machine is
	// caught before a transaction is paid for.
	TeeID common.Address
}

// Settlement is how a policy was closed out, as recorded on-chain.
type Settlement struct {
	Settled       bool
	PayoutTo      common.Address
	Amount        *big.Int
	InstructionID common.Hash
}

// Settle submits a TEE-signed decision to PolicySettlement.
//
// Anyone can call this — the authority is in the signature, not the sender — so
// in the demo it is the test that relays, and in production it would be a bot,
// the policyholder, or the insurer. The recovered enclave is returned so callers
// can report which machine's decision was acted on.
func Settle(
	s *support.Support,
	settlementAddress common.Address,
	response *teetypes.ActionResponse,
) (common.Hash, *Decision, error) {
	if response == nil {
		return common.Hash{}, nil, errors.New("action response is nil")
	}

	decision, err := DecodeDecision(s.ChainID.Uint64(), response)
	if err != nil {
		return common.Hash{}, nil, err
	}

	contract, err := settlement.NewPolicySettlement(settlementAddress, s.ChainClient)
	if err != nil {
		return common.Hash{}, nil, errors.Errorf("binding PolicySettlement: %s", err)
	}

	opts, err := bind.NewKeyedTransactorWithChainID(s.Prv, s.ChainID)
	if err != nil {
		return common.Hash{}, nil, errors.Errorf("creating transactor: %s", err)
	}

	tx, err := contract.Settle(
		opts,
		[32]byte(decision.InstructionID),
		response.Result.Status,
		string(response.Result.SubmissionTag),
		response.Result.Data,
		response.Signature,
	)
	if err != nil {
		return common.Hash{}, decision, errors.Errorf("settle: %s", err)
	}

	receipt, err := support.CheckTx(tx, s.ChainClient)
	if err != nil {
		return tx.Hash(), decision, errors.Errorf("settle: %s", err)
	}

	return receipt.TxHash, decision, nil
}

// DecodeDecision reads and verifies a signed action result without sending
// anything on-chain: it recovers the signer over the same preimage
// PolicySettlement uses and decodes the payload the way the contract will.
func DecodeDecision(chainID uint64, response *teetypes.ActionResponse) (*Decision, error) {
	if response.Result.Status != 1 {
		return nil, errors.Errorf(
			"action result failed (status %d) and carries no decision: %s",
			response.Result.Status, response.Result.Log)
	}
	if len(response.Result.Data) != 96 {
		return nil, errors.Errorf(
			"decision payload is %d bytes, want 96 (bytes32, uint256, address)", len(response.Result.Data))
	}

	teeID, err := RecoverTeeID(chainID, &response.Result, response.Signature)
	if err != nil {
		return nil, err
	}

	policyID := common.BytesToHash(response.Result.Data[0:32])
	amount := new(big.Int).SetBytes(response.Result.Data[32:64])
	payoutTo := common.BytesToAddress(response.Result.Data[64:96])

	return &Decision{
		PolicyID:      policyID,
		PayoutAmount:  amount,
		PayoutTo:      payoutTo,
		InstructionID: response.Result.ID,
		TeeID:         teeID,
	}, nil
}

// SettlementOf reads how a policy was settled, or a zero value if it has not
// been.
func SettlementOf(
	ctx context.Context,
	s *support.Support,
	settlementAddress common.Address,
	policyID common.Hash,
) (*Settlement, error) {
	contract, err := settlement.NewPolicySettlement(settlementAddress, s.ChainClient)
	if err != nil {
		return nil, errors.Errorf("binding PolicySettlement: %s", err)
	}

	record, err := contract.SettlementOf(&bind.CallOpts{Context: ctx}, [32]byte(policyID))
	if err != nil {
		return nil, errors.Errorf("reading settlementOf(%s): %s", policyID.Hex(), err)
	}

	return &Settlement{
		Settled:       record.Settled,
		PayoutTo:      record.PayoutTo,
		Amount:        record.Amount,
		InstructionID: common.Hash(record.InstructionId),
	}, nil
}
