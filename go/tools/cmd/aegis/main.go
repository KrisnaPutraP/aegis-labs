// Command aegis drives one Aegis policy from the command line, one step at a
// time, against the live deployment.
//
// It exists because the end to end test (cmd/run-test) proves the whole path in
// a single run and then exits, which is the right shape for CI and the wrong
// shape for a demo. Here each step is a command you type, and each command
// reports what actually happened on chain or inside the enclave.
//
// Nothing here reimplements the crypto or the protocol work. The ECIES sealing,
// the instruction sending, the FDC request and proof handling, the action result
// signature recovery and the settlement call all come from the same packages
// run-test uses, so a change to the real path changes this demo too.
//
// What each command does:
//
//	register-model  bind the policy to one attestation request, then seal the
//	                insurer's model to the enclave public key and load it
//	reregister-all  load the demo models back in after the enclave restarted,
//	                from the operator's local parameter files
//	evaluate        request an FDC attestation, wait for the round, score the
//	                attested reading in the enclave, settle the signed decision
//	reveal          try to read the model back out of the enclave and fail
//	status          read the policy, the pool and the settlement from the chain
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	args := os.Args[2:]

	switch os.Args[1] {
	case "register-model":
		err = runRegisterModel(args)
	case "reregister-all":
		err = runReregisterAll(args)
	case "evaluate":
		err = runEvaluate(args)
	case "reveal":
		err = runReveal(args)
	case "status":
		err = runStatus(args)
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "aegis: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fail(err)
	}
}

func usage() {
	fmt.Print(`aegis, the Aegis demo command line.

Aegis is a confidential underwriting engine. The insurer's risk model is scored
inside a TEE, the rainfall that triggers it is attested by the Flare Data
Connector, and the payout settles on chain against the enclave's signature.

Usage:
  aegis <command> [flags]

Commands:
  register-model   Bind a policy to its weather feed and seal the insurer's model into the enclave
  reregister-all   Load the demo models back into the enclave after a restart emptied it
  evaluate         Attest the weather, score it in the enclave, and settle the signed decision
  reveal           Try to read the model parameters out of the enclave, and watch it refuse
  status           Read the policy, the payout pool and the settlement record from the chain

Policies:
`)
	for _, name := range policyNames() {
		p := policyCatalog[name]
		fmt.Printf("  %-18s %s, %s to %s\n", name, p.description, p.feed.StartDate, p.feed.EndDate)
	}
	fmt.Print(`
A typical demo:
  aegis register-model --policy drought-surabaya
  aegis reveal
  aegis evaluate --policy drought-surabaya
  aegis status --policy drought-surabaya

Restarting the stack empties the enclave, because a model lives in its memory
and nowhere else. One command puts every policy that is still open back in
reach, from the operator's local parameter files:
  aegis reregister-all

Every command takes --help. Endpoints and contract addresses are read from .env,
config/extension.env and config/settlement.env, so there is nothing to type
twice; each command prints the ones it used.
`)
}
