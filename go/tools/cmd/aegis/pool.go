package main

import (
	"context"
	"math/big"
	"time"

	"sign-extension/tools/pkg/contracts/settlement"
	"sign-extension/tools/pkg/payout"
	"sign-extension/tools/pkg/support"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

// payoutPool is what the demo needs to know about the money: which executor
// holds it, which asset it is in, and how to render an amount.
//
// The executor is read out of the settlement contract rather than configured,
// which also proves the wiring. Swapping FXRP for PMW later is one
// setPayoutExecutor call, and this command would follow it without a change.
type payoutPool struct {
	token    *payout.ERC20
	executor common.Address
	symbol   string
	decimals uint8
}

func resolvePool(ctx context.Context, sup *support.Support, settlementAddress common.Address) (*payoutPool, error) {
	contract, err := settlement.NewPolicySettlement(settlementAddress, sup.ChainClient)
	if err != nil {
		return nil, errors.Errorf("binding PolicySettlement at %s: %s", settlementAddress.Hex(), err)
	}

	executor, err := contract.PayoutExecutor(nil)
	if err != nil {
		return nil, errors.Errorf("reading payoutExecutor: %s", err)
	}
	if executor == (common.Address{}) {
		return nil, errors.Errorf(
			"%s has no payout executor. Run cmd/deploy-settlement, which wires one up", settlementAddress.Hex())
	}

	asset, err := payout.ResolveFxrp(ctx, sup.ChainClient)
	if err != nil {
		return nil, errors.Errorf("resolving the payout asset: %s", err)
	}

	token, err := payout.NewERC20(asset, sup.ChainClient)
	if err != nil {
		return nil, err
	}

	symbol, decimals, err := token.Metadata(ctx)
	if err != nil {
		return nil, err
	}

	return &payoutPool{token: token, executor: executor, symbol: symbol, decimals: decimals}, nil
}

func (p *payoutPool) balance(account common.Address) (*big.Int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	balance, err := p.token.BalanceOf(ctx, account)
	if err != nil {
		return nil, errors.Errorf("reading the balance of %s: %s", account.Hex(), err)
	}

	return balance, nil
}

func (p *payoutPool) format(amount *big.Int) string {
	return payout.FormatUnits(amount, p.decimals) + " " + p.symbol
}
