package payout

import (
	"context"
	"time"

	"sign-extension/tools/pkg/contracts/settlement"
	"sign-extension/tools/pkg/support"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/pkg/errors"
)

// deployTimeout bounds each deployment wait. Coston2 blocks are seconds apart;
// two minutes means something is wrong, not slow.
const deployTimeout = 2 * time.Minute

// DeploySettlement deploys PolicySettlement against a live InstructionSender.
//
// Note what is *not* touched: InstructionSender itself, the extension
// registration, and the registered TEE machine. Settlement only reads from
// them, which is why Phase 4 needs no redeploy of the extension and no re-run of
// full-setup.sh — and therefore cannot orphan the running TEE.
func DeploySettlement(
	s *support.Support,
	instructionSender common.Address,
) (common.Address, *settlement.PolicySettlement, error) {
	opts, err := bind.NewKeyedTransactorWithChainID(s.Prv, s.ChainID)
	if err != nil {
		return common.Address{}, nil, errors.Errorf("creating transactor: %s", err)
	}

	// Both registry args are the FlareTeeManager diamond proxy, exactly as in
	// DeployInstructionSender: the diamond routes ExtensionManager and
	// MachineManager calls to the right facets.
	address, tx, contract, err := settlement.DeployPolicySettlement(
		opts, s.ChainClient,
		s.Addresses.FlareTeeManager, s.Addresses.FlareTeeManager, instructionSender,
	)
	if err != nil {
		return common.Address{}, nil, errors.Errorf("deploying PolicySettlement: %s", err)
	}
	if err := waitDeployed(s, tx, "PolicySettlement"); err != nil {
		return common.Address{}, nil, err
	}

	return address, contract, nil
}

// DeployFxrpExecutor deploys the FXRP implementation of IPayoutExecutor, bound
// to the settlement contract that is allowed to spend its pool.
func DeployFxrpExecutor(
	s *support.Support,
	fxrp common.Address,
	settlementAddress common.Address,
) (common.Address, *settlement.FxrpPayoutExecutor, error) {
	opts, err := bind.NewKeyedTransactorWithChainID(s.Prv, s.ChainID)
	if err != nil {
		return common.Address{}, nil, errors.Errorf("creating transactor: %s", err)
	}

	address, tx, contract, err := settlement.DeployFxrpPayoutExecutor(opts, s.ChainClient, fxrp, settlementAddress)
	if err != nil {
		return common.Address{}, nil, errors.Errorf("deploying FxrpPayoutExecutor: %s", err)
	}
	if err := waitDeployed(s, tx, "FxrpPayoutExecutor"); err != nil {
		return common.Address{}, nil, err
	}

	return address, contract, nil
}

// SetExtensionId caches the extension id on the settlement contract, tolerating
// a contract where it is already set so deployment scripts stay re-runnable.
func SetExtensionId(s *support.Support, contract *settlement.PolicySettlement) error {
	opts, err := bind.NewKeyedTransactorWithChainID(s.Prv, s.ChainID)
	if err != nil {
		return errors.Errorf("creating transactor: %s", err)
	}

	tx, err := contract.SetExtensionId(opts)
	if err != nil {
		return errors.Errorf("setExtensionId: %s", err)
	}
	if _, err := support.CheckTx(tx, s.ChainClient); err != nil {
		return errors.Errorf("setExtensionId: %s", err)
	}

	return nil
}

// SetPayoutExecutor points settlement at a payout implementation.
//
// This one call is the whole of ARCHITECTURE.md D4's swappability: replacing
// FXRP with PMW later means deploying a new executor and calling this, with no
// change to the enclave, InstructionSender, or any settled policy.
func SetPayoutExecutor(
	s *support.Support,
	contract *settlement.PolicySettlement,
	executor common.Address,
) (common.Hash, error) {
	opts, err := bind.NewKeyedTransactorWithChainID(s.Prv, s.ChainID)
	if err != nil {
		return common.Hash{}, errors.Errorf("creating transactor: %s", err)
	}

	tx, err := contract.SetPayoutExecutor(opts, executor)
	if err != nil {
		return common.Hash{}, errors.Errorf("setPayoutExecutor: %s", err)
	}
	receipt, err := support.CheckTx(tx, s.ChainClient)
	if err != nil {
		return common.Hash{}, errors.Errorf("setPayoutExecutor: %s", err)
	}

	return receipt.TxHash, nil
}

func waitDeployed(s *support.Support, tx *types.Transaction, label string) error {
	ctx, cancel := context.WithTimeout(context.Background(), deployTimeout)
	defer cancel()

	receipt, err := bind.WaitMined(ctx, s.ChainClient, tx)
	if err != nil {
		return errors.Errorf("%s deployment not mined within %s (tx %s): %s",
			label, deployTimeout, tx.Hash().Hex(), err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return errors.Errorf("%s deployment reverted (tx %s)", label, tx.Hash().Hex())
	}

	return nil
}
