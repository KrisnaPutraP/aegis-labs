package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"sign-extension/pkg/types"

	"github.com/pkg/errors"
)

func runReveal(args []string) error {
	fs := flag.NewFlagSet("reveal", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Print(`aegis reveal, try to read the insurer's model out of the enclave.

This makes the attempt for real. It calls the enclave's state endpoint and
prints the response as it came back, so what you see is what the enclave was
willing to say, not a message this command made up.

The endpoint exists to report liveness, and it reports a count. There is no
route that returns a model, because nothing in the extension ever serializes one
back out: the parameters are decrypted inside the enclave and held in memory
that no handler reads from.

The enclave listens inside the stack's Docker network, so a host has no route to
it. scripts/state-bridge.sh publishes this one endpoint on loopback.

Usage:
  aegis reveal [flags]

Flags:
`)
		fs.PrintDefaults()
	}

	flags := addCommonFlags(fs, false)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := flags.resolve()
	if err != nil {
		return err
	}

	step("Asking the enclave for everything it will report")
	field("endpoint", "GET %s", cfg.stateURL)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(cfg.stateURL)
	if err != nil {
		return errors.Errorf(
			"the enclave state endpoint is not reachable: %s. Nothing was revealed, but nothing was proved "+
				"either. Start the read only bridge with ./scripts/state-bridge.sh start", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err != nil {
		return errors.Errorf("reading the response: %s", err)
	}
	raw := strings.TrimSpace(string(body))

	field("http status", "%d", resp.StatusCode)
	fmt.Printf("  %-14s %s\n", "raw response", raw)

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("the endpoint answered %d, so this attempt proved nothing", resp.StatusCode)
	}

	var state types.StateResponse
	if err := json.Unmarshal(body, &state); err != nil {
		return errors.Errorf("the response is not the state envelope this extension serves: %s", err)
	}

	step("What came back")
	field("models loaded", "%d", state.State.RegisteredModels)
	field("state version", "%s", trimZeroBytes(state.StateVersion.Bytes()))
	note("a count, and a version string. No policy ids, no thresholds, no factors")

	verdict("Denied: parameters never leave the enclave.")

	return nil
}

// trimZeroBytes renders the version hash, which is a short ASCII string left
// aligned in 32 bytes.
func trimZeroBytes(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c != 0 {
			out = append(out, c)
		}
	}
	return string(out)
}
