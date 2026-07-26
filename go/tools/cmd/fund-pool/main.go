// Package main moves FXRP from the deployer into the payout pool, and reports
// what the pool can cover.
//
// Funding is a plain ERC-20 transfer — FxrpPayoutExecutor has no deposit
// function, its balance *is* the pool — so this command exists for the reporting
// and the guard rails, not because the transfer needs help. Run with no
// --amount to see the balances without moving anything.
package main

import (
	"context"
	"flag"
	"math/big"
	"os"
	"time"

	"sign-extension/tools/pkg/configs"
	"sign-extension/tools/pkg/fccutils"
	"sign-extension/tools/pkg/payout"
	"sign-extension/tools/pkg/support"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/pkg/errors"
)

func main() {
	af := flag.String("a", configs.AddressesFile, "file with deployed addresses")
	cf := flag.String("c", configs.ChainNodeURL, "chain node url")
	executorF := flag.String("executor", os.Getenv("FXRP_PAYOUT_EXECUTOR"), "FxrpPayoutExecutor address")
	fxrpF := flag.String("fxrp", os.Getenv("FXRP_ADDRESS"),
		"FXRP token address (default: resolved from the Flare contract registry)")
	amountF := flag.String("amount", "",
		"amount to transfer, in FXRP base units (1 FXRP = 1000000); omit to only report balances")
	flag.Parse()

	if *executorF == "" {
		logger.Fatal("--executor is required (or set FXRP_PAYOUT_EXECUTOR in config/settlement.env)")
	}
	executor := common.HexToAddress(*executorF)

	s, err := support.DefaultSupport(*af, *cf)
	if err != nil {
		fccutils.FatalWithCause(err)
	}
	funder := crypto.PubkeyToAddress(s.Prv.PublicKey)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

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
		fccutils.FatalWithCause(err)
	}

	report := func(stage string) (*big.Int, *big.Int) {
		funderBalance, err := token.BalanceOf(ctx, funder)
		if err != nil {
			fccutils.FatalWithCause(err)
		}
		poolBalance, err := token.BalanceOf(ctx, executor)
		if err != nil {
			fccutils.FatalWithCause(err)
		}
		logger.Infof("%s funder %s: %s %s | pool %s: %s %s",
			stage,
			funder.Hex(), payout.FormatUnits(funderBalance, decimals), symbol,
			executor.Hex(), payout.FormatUnits(poolBalance, decimals), symbol)

		return funderBalance, poolBalance
	}

	logger.Infof("Payout asset: %s (%s, %d decimals)", fxrp.Hex(), symbol, decimals)
	funderBalance, _ := report("Before:")

	if *amountF == "" {
		logger.Infof("No --amount given; nothing transferred.")
		return
	}

	amount, ok := new(big.Int).SetString(*amountF, 10)
	if !ok || amount.Sign() <= 0 {
		fccutils.FatalWithCause(errors.Errorf("--amount %q is not a positive integer of base units", *amountF))
	}
	// Checked here so an over-large amount fails before a transaction is paid
	// for, and says by how much.
	if amount.Cmp(funderBalance) > 0 {
		fccutils.FatalWithCause(errors.Errorf(
			"funder holds %s %s but %s was requested — mint more first (TUTORIAL.md §8)",
			payout.FormatUnits(funderBalance, decimals), symbol, payout.FormatUnits(amount, decimals)))
	}

	opts, err := bind.NewKeyedTransactorWithChainID(s.Prv, s.ChainID)
	if err != nil {
		fccutils.FatalWithCause(errors.Errorf("creating transactor: %s", err))
	}

	logger.Infof("Transferring %s %s to the pool...", payout.FormatUnits(amount, decimals), symbol)
	txHash, err := token.Transfer(opts, executor, amount)
	if err != nil {
		fccutils.FatalWithCause(err)
	}
	logger.Infof("  tx %s", txHash.Hex())

	if err := waitForBalance(ctx, token, executor, amount); err != nil {
		fccutils.FatalWithCause(err)
	}
	report("After: ")
}

// waitForBalance polls until the pool reflects the transfer, so the reported
// "after" figures are the settled ones rather than a pre-mining snapshot.
func waitForBalance(ctx context.Context, token *payout.ERC20, pool common.Address, minimum *big.Int) error {
	for {
		balance, err := token.BalanceOf(ctx, pool)
		if err != nil {
			return err
		}
		if balance.Cmp(minimum) >= 0 {
			return nil
		}

		select {
		case <-ctx.Done():
			return errors.New("the pool balance did not reflect the transfer before the timeout")
		case <-time.After(2 * time.Second):
		}
	}
}
