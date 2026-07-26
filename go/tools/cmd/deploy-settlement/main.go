// Package main deploys the Aegis Phase 4 payout path: PolicySettlement, which
// verifies TEE-signed decisions, and FxrpPayoutExecutor, the FXRP pool it pays
// from.
//
// This is separate from pre-build.sh on purpose. pre-build mints a new extension
// and a new InstructionSender, and the TEE machine is permanently bound to
// whichever extension it first registered against — so re-running it orphans a
// working TEE. Settlement reads InstructionSender rather than replacing it, so
// deploying it is safe to repeat and never touches the registration.
//
// Output on stdout is one shell-sourceable line per address, so scripts can
// consume it; everything else goes to the log.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"sign-extension/tools/pkg/configs"
	"sign-extension/tools/pkg/fccutils"
	"sign-extension/tools/pkg/payout"
	"sign-extension/tools/pkg/support"
	"sign-extension/tools/pkg/validate"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/pkg/errors"
)

func main() {
	af := flag.String("a", configs.AddressesFile, "file with deployed addresses")
	cf := flag.String("c", configs.ChainNodeURL, "chain node url")
	instructionSenderF := flag.String("instructionSender", os.Getenv("INSTRUCTION_SENDER"),
		"deployed InstructionSender address")
	fxrpF := flag.String("fxrp", os.Getenv("FXRP_ADDRESS"),
		"FXRP token address (default: resolved from the Flare contract registry)")
	outF := flag.String("o", "", "write the deployed addresses to this env file (optional)")
	flag.Parse()

	if *instructionSenderF == "" {
		logger.Fatal("--instructionSender is required (or set INSTRUCTION_SENDER in .env)")
	}
	instructionSender := common.HexToAddress(*instructionSenderF)

	s, err := support.DefaultSupport(*af, *cf)
	if err != nil {
		fccutils.FatalWithCause(err)
	}

	deployer := crypto.PubkeyToAddress(s.Prv.PublicKey)
	logger.Infof("Deployer:           %s", deployer.Hex())
	logger.Infof("Chain ID:           %s", s.ChainID.String())
	logger.Infof("InstructionSender:  %s", instructionSender.Hex())

	if err := validate.AddressHasCode(s.ChainClient, instructionSender, "InstructionSender"); err != nil {
		fccutils.FatalWithCause(err)
	}
	if err := validate.KeyHasFunds(s.ChainClient, s.Prv, validate.MinDeployBalance); err != nil {
		fccutils.FatalWithCause(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// --- Resolve the payout asset ---
	fxrp := common.HexToAddress(*fxrpF)
	if *fxrpF == "" {
		fxrp, err = payout.ResolveFxrp(ctx, s.ChainClient)
		if err != nil {
			fccutils.FatalWithCause(errors.Errorf("resolving FXRP: %s", err))
		}
	}

	token, err := payout.NewERC20(fxrp, s.ChainClient)
	if err != nil {
		fccutils.FatalWithCause(err)
	}
	symbol, decimals, err := token.Metadata(ctx)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("reading FXRP metadata — is %s really a token? %s", fxrp.Hex(), err))
	}
	logger.Infof("Payout asset:       %s (%s, %d decimals)", fxrp.Hex(), symbol, decimals)

	// --- Step 1: PolicySettlement ---
	logger.Infof("Step 1: Deploying PolicySettlement...")
	settlementAddress, settlementContract, err := payout.DeploySettlement(s, instructionSender)
	if err != nil {
		fccutils.FatalWithCause(err)
	}
	logger.Infof("  PolicySettlement:  %s", settlementAddress.Hex())

	// --- Step 2: bind it to the extension InstructionSender was registered under ---
	logger.Infof("Step 2: Caching the extension id...")
	if err := payout.SetExtensionId(s, settlementContract); err != nil {
		fccutils.FatalWithCause(errors.Errorf(
			"setExtensionId failed — is %s a registered instructions sender? %s",
			instructionSender.Hex(), err))
	}
	extensionID, err := settlementContract.ExtensionId(nil)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("reading extensionId: %s", err))
	}
	logger.Infof("  Extension ID:      %s", extensionID.String())

	// --- Step 3: FxrpPayoutExecutor ---
	logger.Infof("Step 3: Deploying FxrpPayoutExecutor...")
	executorAddress, _, err := payout.DeployFxrpExecutor(s, fxrp, settlementAddress)
	if err != nil {
		fccutils.FatalWithCause(err)
	}
	logger.Infof("  FxrpPayoutExecutor: %s", executorAddress.Hex())

	// --- Step 4: wire settlement to the executor ---
	logger.Infof("Step 4: Pointing settlement at the executor...")
	txHash, err := payout.SetPayoutExecutor(s, settlementContract, executorAddress)
	if err != nil {
		fccutils.FatalWithCause(err)
	}
	logger.Infof("  setPayoutExecutor tx: %s", txHash.Hex())

	logger.Infof("Deployment complete. The pool is empty — fund it with cmd/fund-pool.")

	if *outF != "" {
		if err := writeEnvFile(*outF, settlementAddress, executorAddress, fxrp); err != nil {
			fccutils.FatalWithCause(err)
		}
		logger.Infof("Wrote %s", *outF)
	}

	// Machine-readable output for scripts.
	fmt.Printf("POLICY_SETTLEMENT=%s\n", settlementAddress.Hex())
	fmt.Printf("FXRP_PAYOUT_EXECUTOR=%s\n", executorAddress.Hex())
	fmt.Printf("FXRP_ADDRESS=%s\n", fxrp.Hex())
}

func writeEnvFile(path string, settlementAddress, executorAddress, fxrp common.Address) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return errors.Errorf("creating %s: %s", filepath.Dir(path), err)
	}

	content := fmt.Sprintf(
		"# Auto-generated by cmd/deploy-settlement — do not edit manually\n"+
			"POLICY_SETTLEMENT=%s\nFXRP_PAYOUT_EXECUTOR=%s\nFXRP_ADDRESS=%s\n",
		settlementAddress.Hex(), executorAddress.Hex(), fxrp.Hex(),
	)

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return errors.Errorf("writing %s: %s", path, err)
	}

	return nil
}
