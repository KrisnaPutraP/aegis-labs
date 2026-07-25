package utils

import (
	"context"
	"math/big"
	"os"
	"time"

	"sign-extension/tools/pkg/contracts/sign"
	"sign-extension/tools/pkg/fccutils"
	"sign-extension/tools/pkg/support"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

// DefaultFee is the default fee paid with each instruction.
// Override via FEE_WEI env var.
var DefaultFee = big.NewInt(1_000_000_000_000)

func init() {
	if feeStr := os.Getenv("FEE_WEI"); feeStr != "" {
		if fee, ok := new(big.Int).SetString(feeStr, 10); ok {
			DefaultFee = fee
		}
	}
}

// DeployInstructionSender deploys the sign-extension InstructionSender contract
// and returns its address.
func DeployInstructionSender(s *support.Support) (common.Address, *sign.InstructionSender, error) {
	opts, err := bind.NewKeyedTransactorWithChainID(s.Prv, s.ChainID)
	if err != nil {
		return common.Address{}, nil, errors.Errorf("failed to create transactor: %s", err)
	}

	// Both registry args are the FlareTeeManager diamond proxy: the diamond
	// routes ExtensionManager and MachineManager calls to the right facets.
	// The third is Flare's FdcVerification, which the contract calls to check
	// every weather attestation before it forwards an EVALUATE.
	address, tx, contract, err := sign.DeployInstructionSender(
		opts, s.ChainClient,
		s.Addresses.FlareTeeManager, s.Addresses.FlareTeeManager, s.Addresses.FdcVerification,
	)
	if err != nil {
		return common.Address{}, nil, errors.Errorf("failed to deploy contract: %s", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	receipt, err := bind.WaitMined(ctx, s.ChainClient, tx)
	if err != nil {
		return common.Address{}, nil, errors.Errorf("deployment tx not mined within 2 minutes (tx: %s): %s", tx.Hash().Hex(), err)
	}

	if receipt.Status != types.ReceiptStatusSuccessful {
		return common.Address{}, nil, errors.New("contract deployment failed")
	}

	return address, contract, nil
}

// SetExtensionId calls setExtensionId on the InstructionSender contract.
func SetExtensionId(s *support.Support, instructionSenderAddress common.Address) error {
	sender, err := sign.NewInstructionSender(instructionSenderAddress, s.ChainClient)
	if err != nil {
		return errors.Errorf("failed to bind contract: %s", err)
	}

	opts, err := bind.NewKeyedTransactorWithChainID(s.Prv, s.ChainID)
	if err != nil {
		return errors.Errorf("failed to create transactor: %s", err)
	}

	tx, err := sender.SetExtensionId(opts)
	if err != nil {
		reason := fccutils.DecodeRevertReason(err)
		if reason == "" {
			parsed, _ := sign.InstructionSenderMetaData.GetAbi()
			if parsed != nil {
				callData, packErr := parsed.Pack("setExtensionId")
				if packErr == nil {
					from := crypto.PubkeyToAddress(s.Prv.PublicKey)
					reason = fccutils.SimulateAndDecodeRevert(
						s.ChainClient, from, instructionSenderAddress, nil, callData,
					)
				}
			}
		}
		if reason != "" {
			return errors.Errorf("failed to call setExtensionId: %s (revert reason: %s)", err, reason)
		}
		return errors.Errorf("failed to call setExtensionId: %s", err)
	}

	receipt, err := bind.WaitMined(context.Background(), s.ChainClient, tx)
	if err != nil {
		return errors.Errorf("failed waiting for transaction: %s", err)
	}

	if receipt.Status != types.ReceiptStatusSuccessful {
		parsed, _ := sign.InstructionSenderMetaData.GetAbi()
		if parsed != nil {
			callData, packErr := parsed.Pack("setExtensionId")
			if packErr == nil {
				from := crypto.PubkeyToAddress(s.Prv.PublicKey)
				reason := fccutils.SimulateAndDecodeRevert(
					s.ChainClient, from, instructionSenderAddress, nil, callData,
				)
				if reason != "" {
					return errors.Errorf("setExtensionId transaction failed (revert reason: %s)", reason)
				}
			}
		}
		return errors.New("setExtensionId transaction failed")
	}

	return nil
}

// SendRegisterModel sends a registerModel instruction via the InstructionSender.
//
// encryptedModel must already be ECIES ciphertext sealed to the enclave public
// key — this helper never sees, and must never be handed, plaintext parameters.
// Returns (instructionId, txHash).
func SendRegisterModel(s *support.Support, instructionSenderAddress common.Address, encryptedModel []byte) (common.Hash, common.Hash, error) {
	return sendInstruction(
		s, instructionSenderAddress, "registerModel",
		func(sender *sign.InstructionSender, opts *bind.TransactOpts) (*types.Transaction, error) {
			return sender.RegisterModel(opts, encryptedModel)
		},
		encryptedModel,
	)
}

// SendRegisterPolicyTrigger binds a policy to the one attestation request that may
// settle it. Owner-only on-chain, so the caller must hold the deployer key.
func SendRegisterPolicyTrigger(
	s *support.Support,
	instructionSenderAddress common.Address,
	policyID common.Hash,
	requestBodyHash common.Hash,
) (common.Hash, error) {
	sender, err := sign.NewInstructionSender(instructionSenderAddress, s.ChainClient)
	if err != nil {
		return common.Hash{}, errors.Errorf("failed to bind contract: %s", err)
	}

	opts, err := bind.NewKeyedTransactorWithChainID(s.Prv, s.ChainID)
	if err != nil {
		return common.Hash{}, errors.Errorf("failed to create transactor: %s", err)
	}

	tx, err := sender.RegisterPolicyTrigger(opts, [32]byte(policyID), [32]byte(requestBodyHash))
	if err != nil {
		if reason := fccutils.DecodeRevertReason(err); reason != "" {
			return common.Hash{}, errors.Errorf("failed to send registerPolicyTrigger: %s (revert reason: %s)", err, reason)
		}
		return common.Hash{}, errors.Errorf("failed to send registerPolicyTrigger: %s", err)
	}

	receipt, err := support.CheckTx(tx, s.ChainClient)
	if err != nil {
		return common.Hash{}, errors.Errorf("registerPolicyTrigger: %s", err)
	}

	return receipt.TxHash, nil
}

// TriggerRequestHash asks the contract for the hash of an attestation request body,
// in exactly the form evaluate() compares against. Reading it from the contract
// keeps the insurer's registration and the on-chain check from drifting apart.
func TriggerRequestHash(
	s *support.Support,
	instructionSenderAddress common.Address,
	requestBody sign.IWeb2JsonRequestBody,
) (common.Hash, error) {
	sender, err := sign.NewInstructionSender(instructionSenderAddress, s.ChainClient)
	if err != nil {
		return common.Hash{}, errors.Errorf("failed to bind contract: %s", err)
	}

	hash, err := sender.TriggerRequestHash(&bind.CallOpts{}, requestBody)
	if err != nil {
		return common.Hash{}, errors.Errorf("failed to call triggerRequestHash: %s", err)
	}

	return common.Hash(hash), nil
}

// SendEvaluate sends an evaluate instruction via the InstructionSender.
//
// The rainfall figure is not a parameter: it travels inside the FDC attestation
// and is extracted on-chain after the Merkle proof checks out. There is no path
// that lets this helper — or anyone else — hand the enclave a rainfall number of
// their own choosing.
// Returns (instructionId, txHash).
func SendEvaluate(
	s *support.Support,
	instructionSenderAddress common.Address,
	policyID common.Hash,
	payoutTo common.Address,
	proof sign.IWeb2JsonProof,
) (common.Hash, common.Hash, error) {
	return sendInstruction(
		s, instructionSenderAddress, "evaluate",
		func(sender *sign.InstructionSender, opts *bind.TransactOpts) (*types.Transaction, error) {
			return sender.Evaluate(opts, [32]byte(policyID), payoutTo, proof)
		},
		[32]byte(policyID), payoutTo, proof,
	)
}

// sendInstruction runs the shared send-and-confirm path: bind, pay the fee,
// submit, decode a revert reason if the call fails, wait for the receipt, and
// pull the instruction id out of the TeeInstructionsSent event.
//
// method and callArgs are only used to re-simulate a failed call for a readable
// revert reason.
func sendInstruction(
	s *support.Support,
	instructionSenderAddress common.Address,
	method string,
	send func(*sign.InstructionSender, *bind.TransactOpts) (*types.Transaction, error),
	callArgs ...any,
) (common.Hash, common.Hash, error) {
	sender, err := sign.NewInstructionSender(instructionSenderAddress, s.ChainClient)
	if err != nil {
		return common.Hash{}, common.Hash{}, errors.Errorf("failed to bind contract: %s", err)
	}

	opts, err := bind.NewKeyedTransactorWithChainID(s.Prv, s.ChainID)
	if err != nil {
		return common.Hash{}, common.Hash{}, errors.Errorf("failed to create transactor: %s", err)
	}
	opts.Value = DefaultFee

	tx, err := send(sender, opts)
	if err != nil {
		reason := fccutils.DecodeRevertReason(err)
		if reason == "" {
			parsed, _ := sign.InstructionSenderMetaData.GetAbi()
			if parsed != nil {
				callData, packErr := parsed.Pack(method, callArgs...)
				if packErr == nil {
					from := crypto.PubkeyToAddress(s.Prv.PublicKey)
					reason = fccutils.SimulateAndDecodeRevert(
						s.ChainClient, from, instructionSenderAddress, DefaultFee, callData,
					)
				}
			}
		}
		if reason != "" {
			return common.Hash{}, common.Hash{}, errors.Errorf("failed to send %s: %s (revert reason: %s)", method, err, reason)
		}
		return common.Hash{}, common.Hash{}, errors.Errorf("failed to send %s: %s", method, err)
	}

	receipt, err := bind.WaitMined(context.Background(), s.ChainClient, tx)
	if err != nil {
		return common.Hash{}, common.Hash{}, errors.Errorf("failed waiting for transaction: %s", err)
	}
	if receipt.Status != 1 {
		return common.Hash{}, common.Hash{}, errors.Errorf("%s transaction failed with status: %d", method, receipt.Status)
	}
	if len(receipt.Logs) == 0 {
		return common.Hash{}, common.Hash{}, errors.New("no logs found in receipt")
	}

	instructionSent, err := s.TeeVerification.ParseTeeInstructionsSent(*receipt.Logs[0])
	if err != nil {
		return common.Hash{}, common.Hash{}, errors.Errorf("failed to parse TeeInstructionsSent event: %s", err)
	}
	return instructionSent.InstructionId, receipt.TxHash, nil
}
