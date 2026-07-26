package main

import (
	"time"

	"sign-extension/tools/pkg/fccutils"

	"github.com/ethereum/go-ethereum/common"
	teetypes "github.com/flare-foundation/tee-node/pkg/types"
	"github.com/pkg/errors"
)

// waitForActionResult polls the extension proxy until the enclave has answered
// an instruction.
//
// The result appears only once the TEE has picked the instruction up, run it and
// signed the answer, which takes a few seconds. Polling with a progress line
// beats a flat sleep: a demo that prints nothing for twenty seconds looks hung,
// and a sleep that is too short reports a working system as broken.
func waitForActionResult(proxyURL string, id common.Hash, timeout time.Duration) (*teetypes.ActionResponse, error) {
	const pollEvery = 3 * time.Second

	deadline := time.Now().Add(timeout)
	started := time.Now()
	lastReport := time.Now()

	for {
		resp, err := fccutils.ActionResult(proxyURL, id)
		if err == nil {
			return resp, nil
		}

		if time.Now().After(deadline) {
			return nil, errors.Errorf(
				"no action result for instruction %s after %s. The enclave may be busy, or a second TEE "+
					"machine may be registered for this extension and holding the instruction (TUTORIAL.md appendix A13). "+
					"Last error: %s",
				id.Hex(), timeout, err)
		}

		if time.Since(lastReport) >= 9*time.Second {
			progress("waiting for the enclave, %ds elapsed", int(time.Since(started).Seconds()))
			lastReport = time.Now()
		}

		time.Sleep(pollEvery)
	}
}
