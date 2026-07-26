package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

	"sign-extension/pkg/types"
	"sign-extension/tools/pkg/contracts/sign"
	"sign-extension/tools/pkg/payout"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Print(`aegis status, read the policy back from the chain.

Everything printed here is read live: the trigger the policy is bound to, the
last attested voting round, the settlement record, and the pool balance. The
local state file supplies only the policy id, because ids are minted per run.

Usage:
  aegis status [flags]

Flags:
`)
		fs.PrintDefaults()
	}

	flags := addCommonFlags(fs, true)
	all := fs.Bool("all", false, "report every policy in the state file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := flags.resolve()
	if err != nil {
		return err
	}

	sup, err := cfg.connect()
	if err != nil {
		return err
	}

	state, err := loadState(cfg.stateFile)
	if err != nil {
		return err
	}

	names := []string{cfg.policyName}
	if *all {
		names = policyNames()
	}

	sender, err := sign.NewInstructionSender(cfg.instructionSender, sup.ChainClient)
	if err != nil {
		return errors.Errorf("binding InstructionSender: %s", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	pool, err := resolvePool(ctx, sup, cfg.settlement)
	cancel()
	if err != nil {
		return err
	}

	for _, name := range names {
		record := state.get(name)
		step("Policy %s", name)
		if record == nil {
			field("state", "not created here yet. Run: aegis register-model --policy %s", name)
			continue
		}

		policyID := record.id()
		field("policy id", "%s", policyID.Hex())

		bound, err := sender.PolicyTriggerRequestHash(nil, [32]byte(policyID))
		if err != nil {
			return errors.Errorf("reading the policy trigger: %s", err)
		}
		if common.Hash(bound) == (common.Hash{}) {
			field("trigger", "not bound on chain")
		} else {
			field("trigger", "%s", common.Hash(bound).Hex())
		}

		round, err := sender.LastAttestedVotingRound(nil, [32]byte(policyID))
		if err != nil {
			return errors.Errorf("reading the last attested voting round: %s", err)
		}
		if round == 0 {
			field("last round", "none, the policy has not been evaluated")
		} else {
			field("last round", "%d", round)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		settlementRecord, err := payout.SettlementOf(ctx, sup, cfg.settlement, policyID)
		cancel()
		if err != nil {
			return err
		}

		switch {
		case !settlementRecord.Settled:
			field("settlement", "open, nothing settled yet")
		case settlementRecord.Amount.Sign() == 0:
			field("settlement", "closed with nothing owed")
			field("instruction", "%s", settlementRecord.InstructionID.Hex())
		default:
			field("settlement", "paid %s to %s",
				pool.format(settlementRecord.Amount), settlementRecord.PayoutTo.Hex())
			field("instruction", "%s", settlementRecord.InstructionID.Hex())
		}
		if record.SettleTx != "" {
			field("settle tx", "%s", record.SettleTx)
		}
	}

	balance, err := pool.balance(pool.executor)
	if err != nil {
		return err
	}

	step("Payout pool")
	field("executor", "%s", pool.executor.Hex())
	field("balance", "%s", pool.format(balance))
	note("read from the settlement contract, so a swapped executor would show up here")

	step("Enclave")
	models, err := enclaveModelCount(cfg.stateURL)
	if err != nil {
		field("state", "unreachable at %s", cfg.stateURL)
		note("start the read only bridge with ./scripts/state-bridge.sh start")
	} else {
		field("models loaded", "%d, a count and nothing else", models)
	}

	return nil
}

// enclaveModelCount asks the enclave how many models it holds. The endpoint
// reports a number and never the models themselves, which is what aegis reveal
// demonstrates in full.
func enclaveModelCount(stateURL string) (int, error) {
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(stateURL)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, errors.Errorf("state endpoint answered %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err != nil {
		return 0, err
	}

	var state types.StateResponse
	if err := json.Unmarshal(body, &state); err != nil {
		return 0, err
	}

	return state.State.RegisteredModels, nil
}
