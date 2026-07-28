# Aegis web demo

A single page that reads the live Coston2 deployment: what the enclave keeps
sealed, what the Flare Data Connector attested, and what the settlement contract
paid out.

The dashboard is read only and needs no wallet. On top of it sits one optional
section, "Try it yourself", where a visitor can run an evaluation and a
settlement from their own wallet. Plain HTML, CSS and JavaScript, no build step,
no dependencies.

The two halves are kept apart on purpose. `app.js` is the dashboard and knows
nothing about wallets. `abi.js` and `interact.js` are the write path, and if they
fail to load, or the browser has no wallet, or the interactive config block in
`config.js` is deleted, the page is exactly the read-only dashboard it was
before. That is why the interactive part is a separate section and a separate
script rather than a mode inside the existing code.

The page never asks for, stores, or transmits a private key. It builds calldata
and hands it to the visitor's wallet to sign.

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

## Two profiles, one directory

The same files are served two ways, and the page decides which it is by the
address it was loaded from (`aegisProfile()` in `config.js`).

| | Local | Hosted |
|---|---|---|
| Served from | localhost, a loopback address, or a private LAN address | anywhere else, such as Vercel |
| Contract state, events, pool, settlements | live from the public Coston2 RPC and explorer | the same, unchanged |
| Enclave panel | live `GET /state` through the bridge | replays `enclave-snapshot.json` under a "last known state" label |
| Reveal button | issues the request for real | replays the recorded response, labelled as recorded |
| Try it yourself | wallet actions run | actions are not offered, and the section says why |

The split exists because of what the product is. Settling needs the decision the
enclave signed, and only the running enclave can produce that signature. The
enclave runs on the operator's machine and is deliberately not published, so a
hosted page cannot complete those actions and does not pretend it might. It
states the limit and points at the recording, rather than offering buttons that
would spend a real attestation fee on an evaluation that could never settle.

Everything else on the page needs nobody to be online, which is the whole reason
the hosted copy is worth having: it keeps working while the laptop is off.

## Deploying the hosted copy

Refresh the enclave recording first, while the stack is up:

```bash
./scripts/record-enclave-state.sh      # writes web/enclave-snapshot.json
```

Delete that file to drop the panel entirely. The hosted page removes it rather
than rendering an endpoint it cannot reach.

Then deploy this directory as a static site:

```bash
npx vercel login                 # once
npx vercel deploy web            # preview url
npx vercel deploy --prod web     # production url
```

There is no build step: the files are served exactly as they are. The first
deployment of a new project goes straight to production; after that, `deploy`
makes a preview and `--prod` is what publishes.

Importing the repository from the Vercel dashboard works too. Set **Root
Directory** to `web`.

`vercel.json` in this directory carries the settings that must not be left to a
prompt:

- `outputDirectory: "."`. This directory contains a `public/` subfolder for
  images, and Vercel's default for a project with no framework is to publish
  `public` when it exists. That would put the pictures online and leave
  `index.html` unreachable.
- `framework`, `buildCommand` and `installCommand` set to null, because there is
  nothing to build and no dependencies to install.
- `Cache-Control: no-store` on `config.js`, `policies.json` and
  `enclave-snapshot.json`, the three files that change between deployments.

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

## Try it yourself

Two actions, both already permissionless on the deployed contracts, so a visitor
runs them from their own account without any access control being changed:

| Step | What happens |
|---|---|
| evaluate | The FDC verifier encodes the policy's weather request, the visitor pays the attestation fee to `FdcHub`, the page waits for the voting round to finalize, fetches the Merkle proof from the DA Layer, and calls `InstructionSender.evaluate` |
| settle | The page reads the enclave's signed result and calls `PolicySettlement.settle`, which verifies the TEE signature and pays out if the model triggered |

Creating a policy is not offered. `registerPolicyTrigger` is owner only here, and
opening it up would open a path to drain the payout pool. The policies a visitor
can try are pre-created by the owner:

```bash
cd go/tools
go run ./cmd/aegis register-model --policy drought-surabaya --new --web-config web/policies.json
go run ./cmd/aegis register-model --policy monsoon-surabaya --new --web-config web/policies.json
```

A policy pays at most once and then closes, so each entry is single use and the
list has to be topped up before a demo.

`web/policies.json` carries the attestation request body each policy is bound to,
which the chain does not store and a hash cannot be reversed into. It is public
data by design, and the page verifies every entry before offering it: it asks
`InstructionSender.triggerRequestHash` for the hash of what it holds and compares
that against `policyTriggerRequestHash` on chain. A mismatch is shown as a
warning on the card rather than being quietly skipped.

### Two things a browser cannot do unaided

Both were measured rather than assumed, and only the second needed a workaround.

The **FDC verifier** and the **DA Layer** both answer cross-origin with
`Access-Control-Allow-Origin: *`, so the page calls them directly. One difference
from the Go client is load bearing: requests to the DA Layer must not carry
`X-API-KEY`. Its CORS preflight allows `content-type` but not `x-api-key`, so a
browser sending the key is blocked before the request leaves. The endpoint serves
public testnet data without it.

The **extension proxy** sets no CORS header at all, and reaching it through the
public ngrok tunnel does not help either: that tunnel serves a browser an HTML
interstitial instead of JSON, and the header documented to skip it turns the
fetch into a preflighted request that the tunnel answers with 405. So settling
needs a bridge, in the same shape as the state bridge:

```bash
./scripts/result-bridge.sh start | status | stop
```

`cmd/result-bridge` serves `GET /action/result/{id}` and nothing else, validates
that the id looks like an instruction id before forwarding, reaches the proxy
over the stack's own Docker network so no tunnel is involved, and publishes on
loopback only. `POST /action`, the route that feeds work to the enclave, stays
unreachable. Without it, evaluation still works and only the settle step reports
that the signed result is unreachable.

## Credits

Hero photograph by Sergio Capuzzimati on Unsplash.
