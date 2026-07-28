package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"sign-extension/pkg/types"
	"sign-extension/tools/pkg/contracts/sign"
	"sign-extension/tools/pkg/fccutils"
	"sign-extension/tools/pkg/payout"
	"sign-extension/tools/pkg/support"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

// defaultModelsDir is where an operator keeps the parameter files this command
// reads. It is gitignored: the files are the insurer's, not the repository's.
const defaultModelsDir = "config/demo-models"

// defaultWebPolicies is the list the web demo offers. Restoring from it as well
// as from the local state file matters, because the state file keeps only the
// newest policy per name while the page can still be offering older ones that
// have not settled yet.
const defaultWebPolicies = "web/policies.json"

func runReregisterAll(args []string) error {
	fs := flag.NewFlagSet("reregister-all", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Print(`aegis reregister-all, load the demo models back into the enclave.

The enclave keeps models in memory and nowhere else, which is the point: there
is no file, no disk and no chain record a model could be recovered from. The
cost of that is a restart, which empties it. A policy whose model is gone is
still bound on chain and still settleable in principle, but the enclave has
nothing to score it with.

This puts them back. For every policy that is bound on chain and not yet
settled, it reads the insurer's parameters from a local file, encrypts them to
the enclave's public key and loads them, using the same path register-model
uses. The plaintext never leaves this process, the chain carries ciphertext
only, and nothing about a parameter reaches the browser: this is an operator
command, and there is no web route that does it.

It is safe to run repeatedly. Loading a model the enclave already holds writes
the same value over itself.

A restart costs one thing more than the models, and this checks for it first: a
simulated enclave mints a new identity key when it starts, so the machine now
running is not the one the registry knows. Until that is registered, and the
machine it replaced is paused, work sent on chain is handed to an enclave that
no longer exists. See TUTORIAL.md appendix A13.

Parameters are read from ` + defaultModelsDir + `/<policy>.json. Where no file
exists the model built into this command is used, so a demo machine works out
of the box.

Usage:
  aegis reregister-all [flags]

Flags:
`)
		fs.PrintDefaults()
	}

	flags := addCommonFlags(fs, false)
	modelsDir := fs.String("models-dir", defaultModelsDir, "directory of per policy parameter files")
	webConfig := fs.String("web-config", defaultWebPolicies,
		"also restore the policies this file offers, empty to skip")
	dryRun := fs.Bool("dry-run", false, "report what would be restored without sending anything")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := flags.resolve()
	if err != nil {
		return err
	}

	// A dry run reads the chain and the local files only, so it must work with
	// the stack down. That is exactly when an operator wants to ask what a
	// restart cost them.
	if *dryRun {
		// A dry run still reports which enclave is running when the stack is up,
		// but must not fail when it is down.
		_ = cfg.requireProxy()
	} else if err := cfg.requireProxy(); err != nil {
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

	targets, err := restoreTargets(state, *webConfig)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		verdict("No policies to restore. Create one with: aegis register-model")
		return nil
	}

	if err := checkEnclaveRegistered(sup, cfg); err != nil {
		return err
	}

	step("Enclave")
	before, err := enclaveModelCount(cfg.stateURL)
	if err != nil {
		field("models loaded", "unreachable at %s", cfg.stateURL)
		note("start the read only bridge with ./scripts/state-bridge.sh start to see the count")
	} else {
		field("models loaded", "%d", before)
		note("a count and nothing else, and it is zero after a restart")
	}

	sender, err := sign.NewInstructionSender(cfg.instructionSender, sup.ChainClient)
	if err != nil {
		return errors.Errorf("binding InstructionSender: %s", err)
	}

	restored, skipped := 0, 0
	for _, target := range targets {
		reason, err := skipReason(sup, sender, cfg, target)
		if err != nil {
			return err
		}

		step("Policy %s", target.Name)
		field("policy id", "%s", target.PolicyID)
		if reason != "" {
			field("skipped", "%s", reason)
			skipped++
			continue
		}

		model, source, err := modelFor(*modelsDir, target.Name)
		if err != nil {
			return err
		}
		field("parameters", "%s", source)

		if *dryRun {
			field("dry run", "would seal and load this model")
			restored++
			continue
		}

		if err := sealModel(sup, cfg, target, model); err != nil {
			return err
		}
		restored++

		// The state file is the operator's record of the current policy per
		// name. Only entries it already owns are written back, so restoring an
		// older policy the web page still offers does not rewrite it.
		if existing := state.get(target.Name); existing != nil && existing.PolicyID == target.PolicyID {
			if err := state.saveWith(target); err != nil {
				return err
			}
		}
	}

	if *dryRun {
		headline("Dry run: %d policies would be restored, %d skipped.", restored, skipped)
		return nil
	}

	step("Enclave")
	after, err := enclaveModelCount(cfg.stateURL)
	if err != nil {
		field("models loaded", "unreachable at %s", cfg.stateURL)
	} else {
		field("models loaded", "%d", after)
	}

	headline("Restored %d policies, skipped %d. Plaintext never left this process.", restored, skipped)
	note("the models are in enclave memory again, so the web demo and the CLI can both score these policies")

	return nil
}

// checkEnclaveRegistered refuses to send anything to an enclave the chain will
// not accept work from.
//
// This exists because of what a restart actually costs. The simulated TEE mints
// a fresh identity key every time its container starts, so a restart does not
// only empty the models: it produces a machine the registry has never heard of.
// Instructions still go on chain, the registry hands them to whichever machine
// is still listed as active, and the running enclave never sees them. What the
// operator observes is a register that succeeds on chain and then times out
// waiting for a result, two minutes later, with nothing saying why.
//
// The same check catches the other half of that trap. If the old machine was
// left active alongside the new one, the registry picks between them at random
// and roughly half of all instructions vanish into the dead one.
func checkEnclaveRegistered(sup *support.Support, cfg *settings) error {
	if cfg.proxyURL == "" {
		note("skipping the registration check: no proxy to ask which enclave is running")
		return nil
	}

	teeInfo, err := fccutils.TeeInfo(cfg.proxyURL)
	if err != nil {
		return errors.Errorf("asking the proxy which enclave is running: %s", err)
	}
	teeID, _, err := fccutils.TeeProxyId(teeInfo)
	if err != nil {
		return errors.Errorf("deriving the TEE id: %s", err)
	}
	extensionID := teeInfo.MachineData.ExtensionID.Big()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	active, err := sup.TeeMachineRegistry.GetActiveTeeMachines(&bind.CallOpts{Context: ctx}, extensionID)
	cancel()
	if err != nil {
		return errors.Errorf("reading the active TEE machines for extension %s: %s", extensionID, err)
	}

	registered := false
	for _, id := range active.TeeIds {
		if id == teeID {
			registered = true
			break
		}
	}

	step("Registration")
	field("running enclave", "%s", teeID.Hex())
	field("active machines", "%d for extension %s", len(active.TeeIds), extensionID)

	if !registered {
		return errors.Errorf(
			"the enclave now running (%s) is not an active machine for extension %s, so nothing sent to it "+
				"will ever be processed. A restart mints a new TEE identity, which has to be registered before "+
				"models can go back in. Run: bash ./scripts/post-build.sh, then pause the machine the restart "+
				"replaced (TUTORIAL.md appendix A13)",
			teeID.Hex(), extensionID)
	}
	if len(active.TeeIds) > 1 {
		warn("more than one machine is active for this extension, so instructions are handed out at random " +
			"and the ones that reach a stopped enclave never come back. Pause the stale machines " +
			"(TUTORIAL.md appendix A13)")
		for _, id := range active.TeeIds {
			marker := ""
			if id == teeID {
				marker = " (the one running here)"
			}
			field("machine", "%s%s", id.Hex(), marker)
		}
	}

	return nil
}

// restoreTargets collects every policy worth reloading a model for: the ones
// this machine created, plus the ones the web demo offers.
//
// Both sources carry a name and a policy id and nothing secret. Chain state
// decides which of them is actually restorable; this only gathers candidates,
// newest first so a demo run sees the current policy before the history.
func restoreTargets(state *demoState, webConfig string) ([]*policyRecord, error) {
	var targets []*policyRecord
	seen := map[string]bool{}

	add := func(record *policyRecord) {
		id := common.HexToHash(record.PolicyID).Hex()
		if seen[id] {
			return
		}
		seen[id] = true
		targets = append(targets, record)
	}

	for _, name := range policyNames() {
		if record := state.get(name); record != nil {
			add(record)
		}
	}

	if webConfig == "" {
		return targets, nil
	}

	web, err := readWebPolicies(webConfig)
	if err != nil {
		return nil, err
	}
	for i := len(web) - 1; i >= 0; i-- {
		entry := web[i]
		if _, known := policyCatalog[entry.Name]; !known {
			// A policy whose template this command does not know cannot be
			// matched to a model, so it is left alone rather than guessed at.
			continue
		}
		add(&policyRecord{Name: entry.Name, PolicyID: entry.PolicyID, CreatedAt: entry.CreatedAt})
	}

	return targets, nil
}

// skipReason reports why a policy needs no model, reading the chain rather than
// the local state file. It returns an empty string when the policy should be
// restored.
func skipReason(
	sup *support.Support,
	sender *sign.InstructionSender,
	cfg *settings,
	record *policyRecord,
) (string, error) {
	id := record.id()

	bound, err := sender.PolicyTriggerRequestHash(nil, [32]byte(id))
	if err != nil {
		return "", errors.Errorf("reading the policy trigger for %s: %s", record.PolicyID, err)
	}
	if common.Hash(bound) == (common.Hash{}) {
		return "not bound on chain, so nothing can settle it", nil
	}
	if record.RequestHash != "" && common.Hash(bound) != common.HexToHash(record.RequestHash) {
		// Stale local record. Loading a model here would look like it worked and
		// then fail at evaluation, which is the worst time to find out.
		return fmt.Sprintf("bound to %s on chain, not to the request in the state file",
			common.Hash(bound).Hex()), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	settled, err := payout.SettlementOf(ctx, sup, cfg.settlement, id)
	cancel()
	if err != nil {
		return "", err
	}
	if settled.Settled {
		return "already settled, a policy pays once", nil
	}

	return "", nil
}

// modelFor loads the parameters for one policy, preferring the operator's file
// over the model built into this command.
//
// The return says where the parameters came from, never what they are.
func modelFor(dir, name string) (types.ModelParameters, string, error) {
	path := filepath.Join(dir, name+".json")
	if _, err := os.Stat(path); err != nil {
		return demoModel(), fmt.Sprintf("no file at %s, using the model built into this command", path), nil
	}

	model, err := loadModel(path)
	if err != nil {
		return types.ModelParameters{}, "", err
	}
	return model, fmt.Sprintf("loaded from %s", path), nil
}
