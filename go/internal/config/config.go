// Package config contains configuration values and defaults used by the extension.
package config

import (
	"os"
	"strconv"
	"time"
)

const (
	Version = "0.1.0"

	// OPType and OPCommand strings — must match the bytes32 constants in contracts/InstructionSender.sol.
	//
	// Aegis uses a single OPType (POLICY) with two commands:
	//   REGISTER_MODEL — the insurer loads the confidential risk model for one policy.
	//   EVALUATE       — the TEE scores attested trigger data against that model.
	//
	// Payout execution is deliberately NOT its own OPCommand: ARCHITECTURE.md §5
	// leaves that to the agent, and folding it into the EVALUATE result keeps the
	// swappable PayoutExecutor (PMW vs FXRP, decided in Fase 4) behind a single
	// signed decision instead of a second round trip through the TEE.
	OPTypePolicy           = "POLICY"
	OPCommandRegisterModel = "REGISTER_MODEL"
	OPCommandEvaluate      = "EVALUATE"

	TimeoutShutdown = 5 * time.Second
)

// Defaults — overridden by env vars in init().
var (
	ExtensionPort = 7702
	SignPort      = 7701
	ConfigPort    = 5501
)

func init() {
	if v := os.Getenv("EXTENSION_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			ExtensionPort = n
		}
	}
	if v := os.Getenv("SIGN_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			SignPort = n
		}
	}
	if v := os.Getenv("CONFIG_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			ConfigPort = n
		}
	}
}
