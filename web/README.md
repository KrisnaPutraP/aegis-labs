# Aegis web demo

A single page that reads the live Coston2 deployment: what the enclave keeps
sealed, what the Flare Data Connector attested, and what the settlement contract
paid out.

It is read only by design. There is no wallet connection, no signer and no write
path anywhere in the code. Plain HTML, CSS and JavaScript, no build step, no
dependencies.

## Run it

```bash
./scripts/demo-web.sh          # serves http://127.0.0.1:5173
```

The script also starts the read-only state bridge when the extension stack is
running. To control that separately:

```bash
./scripts/state-bridge.sh start | status | stop
```

Any static server works just as well, for example
`python3 -m http.server 5173 --directory web`.

## Where each number comes from

| Panel | Source |
|---|---|
| Models loaded, state version | `GET /state` on the extension, through the bridge |
| Machine status, extension id | `getTeeMachineStatus`, `getExtensionId` on the TEE machine registry, and `PolicySettlement.extensionId()` |
| Rainfall, coordinates, voting round | `PolicyEvaluationRequested` events plus `InstructionSender.lastAttestedVotingRound` |
| TEE signature | the `settle` transaction calldata, which is where the signature the contract verified actually sits |
| Pool balance | `FxrpPayoutExecutor.availableLiquidity()` |
| Paid amount, recipient, policy status | `PolicySettlement.settlementOf(policyId)` |

Contract state is read with `eth_call` against the Coston2 RPC endpoint. Event
history is read from the Coston2 explorer API, because the public RPC caps
`eth_getLogs` at 30 blocks per query, which is far too narrow to find a policy
that settled hours ago.

Only two addresses are configured, in `config.js`, and both are copied from the
files the deploy tooling writes: `config/extension.env` and
`config/settlement.env`. The payout executor, the payout asset and the TEE
machine registry are resolved from `PolicySettlement` at runtime, so swapping the
executor shows up on this page without editing it.

Policies are discovered from `PolicySettled` events rather than hardcoded,
because `run-test` gives every run fresh policy ids. If a value is not on chain
yet, the page says so instead of showing a number.

## Why the state bridge exists

The extension serves `GET /state` on port 7702 inside the stack's Docker
network, and that port is deliberately not published to the host. A browser
therefore has no route to it, and no CORS header would make one appear.

`cmd/state-bridge` is a small read-only proxy that runs as a container on that
same network and publishes on loopback only. It serves `GET /state` and refuses
every other path and method, so `POST /action`, the route that feeds work to the
enclave, stays unreachable from the host. A raw TCP forward would have exposed
it. The bridge copies the enclave's answer through byte for byte and adds
nothing to it.

The endpoint carries a model count and a version string, never a parameter,
which is the point the "try to reveal parameters" button demonstrates: it issues
the request for real and prints whatever comes back.

## Credits

Hero photograph by Sergio Capuzzimati on Unsplash.
