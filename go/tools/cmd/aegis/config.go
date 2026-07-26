package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"sign-extension/tools/pkg/support"

	"github.com/ethereum/go-ethereum/common"
	"github.com/joho/godotenv"
	"github.com/pkg/errors"
)

// settings is everything a command needs to reach the deployment. Nothing in it
// is guessed: the addresses come from the files the deploy tooling writes, and a
// missing one is an error rather than a default that would send a transaction
// somewhere unintended.
type settings struct {
	root          string
	chainURL      string
	proxyURL      string
	addressesFile string
	stateURL      string

	instructionSender common.Address
	settlement        common.Address

	policyName string
	payoutTo   common.Address
	stateFile  string
}

type commonFlags struct {
	policy     string
	chainURL   string
	proxyURL   string
	stateURL   string
	stateFile  string
	payoutTo   string
	instrSend  string
	settlement string
}

func addCommonFlags(fs *flag.FlagSet, withPolicy bool) *commonFlags {
	c := &commonFlags{}
	if withPolicy {
		fs.StringVar(&c.policy, "policy", defaultPolicyName,
			"policy to work on: "+policyNameList())
	}
	fs.StringVar(&c.chainURL, "chain-url", "", "chain RPC url (default: CHAIN_URL from .env)")
	fs.StringVar(&c.proxyURL, "proxy", "", "extension proxy url (default: probe 6674 then 6664 on loopback)")
	fs.StringVar(&c.stateURL, "state-url", defaultStateURL,
		"enclave state endpoint, published by scripts/state-bridge.sh")
	fs.StringVar(&c.stateFile, "state-file", "", "where policy ids are kept (default: config/demo-state.json)")
	fs.StringVar(&c.payoutTo, "payout-to", defaultPayoutTo,
		"recipient carried in the evaluation request")
	fs.StringVar(&c.instrSend, "instruction-sender", "", "InstructionSender address (default: config/extension.env)")
	fs.StringVar(&c.settlement, "settlement", "", "PolicySettlement address (default: config/settlement.env)")
	return c
}

// defaultStateURL points at the read only bridge from scripts/state-bridge.sh.
// The enclave itself listens inside the stack's Docker network, where nothing on
// the host can reach it.
const defaultStateURL = "http://127.0.0.1:7703/state"

// defaultPayoutTo matches the recipient the end to end test uses, so a demo run
// lines up with the settlement history already on Coston2.
const defaultPayoutTo = "0x000000000000000000000000000000000000dEaD"

// resolve loads .env, config/extension.env and config/settlement.env from the
// project root and turns flags plus environment into one settled configuration.
//
// It also changes the working directory to the project root, which is what makes
// the relative ADDRESSES_FILE in .env resolve and keeps the shared support
// package from warning about a .env it cannot find.
func (c *commonFlags) resolve() (*settings, error) {
	root, err := projectRoot()
	if err != nil {
		return nil, err
	}
	if err := os.Chdir(root); err != nil {
		return nil, errors.Errorf("entering the project root %s: %s", root, err)
	}

	// godotenv never overwrites a variable that is already set, so anything
	// exported in the shell still wins over the files.
	for _, name := range []string{".env", "config/extension.env", "config/settlement.env"} {
		path := filepath.Join(root, name)
		if _, statErr := os.Stat(path); statErr != nil {
			continue
		}
		if loadErr := godotenv.Load(path); loadErr != nil {
			return nil, errors.Errorf("loading %s: %s", name, loadErr)
		}
	}

	s := &settings{root: root, policyName: c.policy, stateURL: c.stateURL}

	s.chainURL = firstNonEmpty(c.chainURL, os.Getenv("CHAIN_URL"))
	if s.chainURL == "" {
		return nil, errors.New("no chain url: set CHAIN_URL in .env or pass --chain-url")
	}

	s.addressesFile = os.Getenv("ADDRESSES_FILE")
	if s.addressesFile == "" {
		chain := firstNonEmpty(os.Getenv("CHAIN"), "coston2")
		s.addressesFile = filepath.Join("config", chain, "deployed-addresses.json")
	}
	if _, err := os.Stat(s.addressesFile); err != nil {
		return nil, errors.Errorf("addresses file %s is not readable: %s", s.addressesFile, err)
	}

	sender := firstNonEmpty(c.instrSend, os.Getenv("INSTRUCTION_SENDER"))
	if sender == "" {
		return nil, errors.New(
			"no InstructionSender address: expected INSTRUCTION_SENDER in config/extension.env, written by scripts/pre-build.sh")
	}
	if !common.IsHexAddress(sender) {
		return nil, errors.Errorf("InstructionSender %q is not an address", sender)
	}
	s.instructionSender = common.HexToAddress(sender)

	settlementAddr := firstNonEmpty(c.settlement, os.Getenv("POLICY_SETTLEMENT"))
	if settlementAddr == "" {
		return nil, errors.New(
			"no PolicySettlement address: expected POLICY_SETTLEMENT in config/settlement.env, written by cmd/deploy-settlement")
	}
	if !common.IsHexAddress(settlementAddr) {
		return nil, errors.Errorf("PolicySettlement %q is not an address", settlementAddr)
	}
	s.settlement = common.HexToAddress(settlementAddr)

	if !common.IsHexAddress(c.payoutTo) {
		return nil, errors.Errorf("payout recipient %q is not an address", c.payoutTo)
	}
	s.payoutTo = common.HexToAddress(c.payoutTo)

	s.stateFile = c.stateFile
	if s.stateFile == "" {
		s.stateFile = filepath.Join(root, "config", "demo-state.json")
	}

	// The proxy is not probed here. Commands that never talk to the enclave, such
	// as reveal and status, should not fail because the stack happens to be down.
	s.proxyURL = c.proxyURL

	if s.policyName != "" {
		if _, ok := policyCatalog[s.policyName]; !ok {
			return nil, errors.Errorf("unknown policy %q, expected one of %s", s.policyName, policyNameList())
		}
	}

	return s, nil
}

// requireProxy picks the extension proxy for the commands that send work to the
// enclave. The Docker stack publishes it on 6674 and a local run uses 6664, so
// rather than making the operator remember which one is up, the reachable one is
// found and reported.
func (s *settings) requireProxy() error {
	if s.proxyURL != "" {
		return nil
	}

	candidates := []string{"http://127.0.0.1:6674", "http://127.0.0.1:6664"}
	for _, url := range candidates {
		if proxyReachable(url) {
			s.proxyURL = url
			return nil
		}
	}

	return errors.Errorf(
		"no extension proxy answered at %s or %s. Is the stack running? Start it with ./scripts/start-services.sh, or pass --proxy",
		candidates[0], candidates[1])
}

func proxyReachable(url string) bool {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url + "/info")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// projectRoot walks up from the working directory looking for the repository
// layout, so the command works from anywhere inside the tree.
func projectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", errors.Errorf("reading the working directory: %s", err)
	}

	for {
		_, composeErr := os.Stat(filepath.Join(dir, "docker-compose.yaml"))
		_, toolsErr := os.Stat(filepath.Join(dir, "go", "tools"))
		if composeErr == nil && toolsErr == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("could not find the project root: run this from inside the repository")
		}
		dir = parent
	}
}

// connect prints the endpoints in play and opens the chain connection every
// command shares.
func (s *settings) connect() (*support.Support, error) {
	header := fmt.Sprintf("chain %s | sender %s | settlement %s",
		s.chainURL, shorten(s.instructionSender.Hex()), shorten(s.settlement.Hex()))
	if s.proxyURL != "" {
		header += " | proxy " + s.proxyURL
	}
	fmt.Printf("%s\n", paint(ansiDim, header))

	sup, err := support.DefaultSupport(s.addressesFile, s.chainURL)
	if err != nil {
		return nil, errors.Errorf("connecting to the chain: %s", err)
	}
	return sup, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
