# Aegis

**A confidential underwriting engine on Flare Confidential Compute.** An insurer's
risk model is scored inside a TEE, against data that Flare's Data Connector
attested, and the payout settles on chain against the enclave's signature. The
model itself is never published, never written on chain, and never revealed at
settlement.

Submitted to **Flare Summer Signal, Bounty 2 (Confidential Compute Apps)**, in the
private scoring category. The first instantiation is parametric drought cover for
smallholder farmers, and the engine underneath is not specific to weather.

- Repository: https://github.com/KrisnaPutraP/aegis-labs
- Demo video: [VIDEO_LINK]
- Live on Coston2, with contract addresses and settled transactions under
  [Live deployment](#live-deployment-on-coston2)

---

## The problem

Parametric microinsurance keeps failing to reach the people it is designed for,
and one of the reasons is structural rather than commercial.

An insurer's risk model is the business. Trigger thresholds, loading factors and
the shape of the payout curve are what an underwriter is paid to get right, and
publishing them has two consequences: a competitor copies the pricing, and buyers
select against it, taking cover only in the seasons the model can be predicted to
pay. So the model cannot go into a public smart contract, where bytecode and
storage are readable by anyone.

Keeping the model on the insurer's own server solves that and reintroduces the
original problem. The policyholder now has no cryptographic reason to believe a
payout will arrive when the trigger is met, which is the exact distrust that on
chain insurance was supposed to remove. Zero knowledge proofs can bridge the two
in theory, and remain heavy and awkward for high volume, low value policies.

The result is a market that either dumbs the model down until it is safe to
publish, or asks users to trust an operator.

## What Aegis does

Aegis puts the model inside a TEE and the evidence on chain, so neither side has
to give up what it needs.

The insurer seals a set of model parameters to the enclave's public key. The
policy is bound on chain to exactly one attestation request, the weather feed it
may ever settle against. When the cover window closes, anyone can ask the Flare
Data Connector to attest that feed. The contract forwards the attested reading to
the enclave only after checking the Merkle proof and confirming the attestation is
the one this policy was underwritten against. The enclave scores the reading
against the sealed model and signs a decision: a policy id, an amount, a
recipient. The settlement contract verifies that signature against Flare's TEE
registry and pays from the pool.

Nobody involved has to be trusted. The insurer cannot renege, because the decision
is made by attested code and checked on chain. The farmer does not have to file a
claim, or read the model, or believe anybody. And the model stays sealed, not for
a while, but permanently.

### Who it is for

| Party | What they get |
|---|---|
| Insurer or underwriter | Uses a proprietary pricing model on chain without publishing it, and cannot be accused of settling selectively, because every decision carries a signature from attested code |
| Policyholder, in the MVP a smallholder farmer | An automatic payout with no claims process and no trust in the insurer. The trigger data is public and verifiable, so the outcome can be checked even though the model cannot |
| Flare ecosystem | A worked example that uses FDC, FCC and FAssets together for a financial use case rather than an AI agent demo |

### Why a TEE rather than a plain smart contract

This is the question the bounty asks, so it is worth answering precisely.

The output of this system has to be public and trustless: a payout amount a
contract can act on without asking permission. The input to it has to be secret:
parameters whose value depends on nobody else having them. A smart contract gives
the first property and cannot give the second, because everything it holds is
readable. A private server gives the second and not the first. Confidential
compute is where both hold at once, and Flare is the chain where the attested data
feed, the enclave and the payout asset are all part of one stack.

---

## How it works

```
   INSURER                                        ANYONE (bot, insurer, policyholder)
      |                                                          |
      | 1. seal model to enclave key                             | 2. request attestation
      |    (ECIES, only ciphertext on chain)                     |    of the policy's feed
      |                                                          v
      |                                      +------------------------------------+
      |                                      | Flare Data Connector (Web2Json)    |
      |                                      | Open-Meteo archive, attested under |
      |                                      | the voting round's Merkle root     |
      |                                      +-----------------+------------------+
      v                                                        | 3. proof
+-------------------------------------------------+            |
| InstructionSender.sol                            |<-----------+
|  - policy bound write once to one request hash   |
|  - verifies the Merkle proof (FdcVerification)   |   4. forwards ONLY the attested
|  - voting round must move forward (anti replay)  |      rainfall figure, never a
+--------------------------+-----------------------+      caller supplied one
                           |
                           v  5. EVALUATE instruction, relayed to the enclave
+-------------------------------------------------+
| Aegis TEE extension (Go, inside the enclave)     |
|  - model parameters live in enclave memory only  |
|  - integer only scoring, deterministic           |
|  - signs {policyId, amount, payoutTo}            |
+--------------------------+-----------------------+
                           |
                           v  6. signed decision, relayed by anyone
+-------------------------------------------------+
| PolicySettlement.sol                             |
|  - ecrecover, then checks the signer is a machine|
|    of THIS extension and is in PRODUCTION        |
|  - anti replay per instruction and per policy    |
+--------------------------+-----------------------+
                           |
                           v  7. if amount > 0
+-------------------------------------------------+
| IPayoutExecutor -> FxrpPayoutExecutor            |
|  pays FXRP from its own pool                     |
|  (swap point for PMW: one setPayoutExecutor call)|
+-------------------------------------------------+
```

### What runs privately, what is verified on chain, what you have to trust

**Private, inside the enclave:** the insurer's model parameters (trigger level,
exit level, sum insured, payout factor, dust floor) and the scoring logic that
uses them. They arrive ECIES encrypted to the enclave's public key, are decrypted
inside it, and are held in memory that no handler serializes back out. The
extension's state endpoint reports how many models are loaded, and nothing else.

**Public and verified on chain:** the weather reading and its Merkle proof, the
policy to request binding, the voting round, the decision (policy id, amount,
recipient), the TEE identity that signed it, and the transfer itself.

**What you have to trust:**

1. The TEE hardware and its attestation. For this submission the stack runs in
   **simulated TEE mode** (`SIMULATED_TEE=true`, attestation string `magic_pass`),
   the mode Flare approved for hackathon judging. A production deployment needs
   real GCP Confidential Space attestation through Flare's devops handoff. Nothing
   else in the design changes.
2. Flare's data providers, to the extent that an attestation reflects the source
   API. Aegis inherits FDC's security here and adds nothing to it.
3. That the reproducible Go build makes the attested code hash the code in this
   repository. The extension image is built with `SOURCE_DATE_EPOCH` pinned so it
   is bit for bit reproducible.

The model parameters are never trusted to the chain, and never sent anywhere as
encrypted-but-public data. That is deliberate: the upstream scaffold's own README
warns against storing encrypted secrets on chain, since on chain data is public
forever and encryption ages badly.

---

## How it uses Flare

Three Flare protocols carry weight here. None of them is decoration, and removing
any one of them breaks a property the product depends on.

### Flare Data Connector, Web2Json

The trigger data is cumulative rainfall from the Open-Meteo archive API, attested
through FDC's Web2Json type. What matters is not that FDC is used, but how tightly
the policy is tied to it.

- `registerPolicyTrigger` binds a policy, write once and owner only, to
  `keccak256(abi.encode(IWeb2Json.RequestBody))`. The whole request is hashed: URL,
  query parameters, the jq filter, the ABI signature. A valid Merkle proof proves
  that some data was attested, not that it is the data this policy was underwritten
  against, and the gap between those two is an attack.
- `evaluate` verifies the proof through `FdcVerification.verifyWeb2Json` and
  requires `proof.data.votingRound` to be strictly greater than the last round
  accepted for that policy, so an old attestation cannot be replayed.
- No path exists for a caller to hand the enclave a rainfall figure. The raw
  `evaluate(bytes32,uint256,address)` entry point was removed, and the test suite
  proves it by reading the deployed bytecode and asserting that selector is absent
  while the proof carrying one is present.

Coordinates travel as strings in the request body so the encoding stays byte
reproducible, and the attested reading carries the Open-Meteo grid point
(`-7.275922, 112.785774`) rather than the requested coordinate.

### Flare Confidential Compute

The extension is a fork of `fce-sign`, rekeyed from its key management operations
to `POLICY` with `REGISTER_MODEL` and `EVALUATE`. Scoring is integer only
`big.Int` arithmetic on purpose: two enclaves scoring the same reading must
produce identical bytes, and floating point does not guarantee that.

The decision is signed with the TEE identity key over the action result preimage,
which includes the chain id, so a decision signed on Coston2 cannot be replayed on
Flare mainnet. `PolicySettlement` reconstructs that preimage, recovers the signer,
and then makes the check that actually matters: it asks the TEE machine registry
whether that signer belongs to **this** extension and is in `PRODUCTION`. Any
enclave in Flare's fleet can sign something. Only ours runs this model.

Payout is deliberately not an operation the enclave performs. It rides on the
result of `EVALUATE`, which is what keeps the payout side swappable.

### FXRP, and PMW as the validated next step

Settled claims are paid in FXRP on Flare. The asset is not hardcoded: it is
resolved at runtime through the Flare Contract Registry to the FAssets asset
manager, and from there to `fAsset()`.

PMW, paying real XRP on the XRPL, was investigated before FXRP was chosen, and the
investigation is worth reporting because it was not a shrug. PMW works: a `pay()`
transaction on Flare landing on XRPL Testnet was verified on 20 July 2026, the
interfaces are source verified on the Coston2 explorer, `testXRP` is a supported
source id, and this deployer is already on the wallet project allowlist. The block
is `addPMWMultisigAccount`, which requires an **FDC2** proof. FDC2 is the newer TEE
based generation, it has no public verifier or DA layer URL yet, and on Coston2
that attestation type has been requested twice, both times by Flare. Without it an
XRPL account cannot be registered, so `pay()` can never be called. That is a
platform gate, not a coding problem.

FXRP is also the choice Flare's own insurance guide makes for this use case. The
`IPayoutExecutor` seam means switching later is one `setPayoutExecutor` call: the
enclave, `InstructionSender` and every already settled policy are untouched.

---

## Demo

Video: [VIDEO_LINK]

### Command line

The CLI is the whole path, split at the seams a person would stop at. Each command
reports what actually happened, on chain or inside the enclave.

```bash
./scripts/aegis.sh register-model --policy drought-surabaya
./scripts/aegis.sh reveal
./scripts/aegis.sh evaluate --policy drought-surabaya
./scripts/aegis.sh status --policy drought-surabaya
```

`reveal` is the one to watch. It does not print a claim, it makes the request:

```
==> Asking the enclave for everything it will report
  endpoint       GET http://127.0.0.1:7703/state
  http status    200
  raw response   {"stateVersion":"0x302e312e30...","state":{"registeredModels":7}}

==> What came back
  models loaded  7
  state version  0.1.0
  a count, and a version string. No policy ids, no thresholds, no factors

Denied: parameters never leave the enclave.
```

And `evaluate`, abridged, from the run recorded under
[Live deployment](#live-deployment-on-coston2):

```
==> Requesting an FDC attestation
  voting round   1407221
==> Waiting for round 1407221 to finalize
  round 1407221 not provable yet, 45s elapsed
  proof retrieved after 81s
==> Attested reading
  rainfall       116.7 mm over the window (1167 tenths of a mm)
  location       -7.275922, 112.785774
==> Scoring the reading inside the enclave
  decision       185625 units to 0x000000000000000000000000000000000000dEaD
  signature      64e0005b7a3a95950cad3fb7f4d7601c...
==> Settling the decision on chain
  signed by      TEE machine 0x14fB1e5cF7eAE49B421831761f569D3d15a790F8
  pool           14.443125 FTestXRP, was 14.62875 FTestXRP
  recipient      up by 0.185625 FTestXRP

Payout: 0.185625 FTestXRP to 0x000000000000000000000000000000000000dEaD
```

Run `./scripts/aegis.sh --help`, or `--help` on any subcommand, for the flags and
for what each step is doing.

### Web

A single read only page: a hero, then a dashboard that reads Coston2 live while it
is open. No wallet connection, no signer, no write path in the code at all.

```bash
./scripts/demo-web.sh          # serves http://127.0.0.1:5173
```

It shows the sealed model as five masked fields next to the enclave's live state,
the chain of trust for the policy that paid (data, attestation, signature,
payout), and the settlement record with the two seasons side by side. The "try to
reveal parameters" button issues a real request to the enclave and prints the
response verbatim. With the bridge stopped it reports that the endpoint was
unreachable and that nothing was proved, rather than claiming a refusal it never
observed.

Anything not on chain yet renders as an empty state. There is no mock data on the
page.

### Running it yourself

Prerequisites: Docker, a funded Coston2 key, an ngrok reserved domain so the TEE
proxy is reachable from the network, and a `.env` filled in from `.env.example`.
`INITIAL_OWNER` and `GOVERNANCE_SIGNERS` must both be the address derived from
`DEPLOYMENT_PRIVATE_KEY`, or TEE registration reverts.

```bash
./scripts/start-services.sh          # bring the stack up
ngrok http --url=<your-domain> 6674  # in another shell
bash ./scripts/full-setup.sh --test  # end to end, prints "All tests passed"
```

The demo commands above assume that stack is running. `scripts/state-bridge.sh`
publishes the enclave's state endpoint on loopback for the web page and for
`aegis reveal`. The enclave itself listens inside the Docker network, where a
browser has no route to it, and that bridge serves `GET /state` and refuses every
other path and method.

---

## Live deployment on Coston2

Everything below is on chain and can be opened in the explorer.

| Contract | Address |
|---|---|
| `InstructionSender` | [`0xb810E9c321706F78FDFe12e7479E4D89022EDffd`](https://coston2-explorer.flare.network/address/0xb810E9c321706F78FDFe12e7479E4D89022EDffd) |
| `PolicySettlement` | [`0xdFF93045C6dDFF132cc56EE7BAbD199CE72bF84B`](https://coston2-explorer.flare.network/address/0xdFF93045C6dDFF132cc56EE7BAbD199CE72bF84B) |
| `FxrpPayoutExecutor` | [`0xBDCB786b6080bBf8D3CCF28419C08a3ac02E946b`](https://coston2-explorer.flare.network/address/0xBDCB786b6080bBf8D3CCF28419C08a3ac02E946b) |
| FXRP (FTestXRP, 6 decimals) | [`0x0b6A3645c240605887a5532109323A3E12273dc7`](https://coston2-explorer.flare.network/address/0x0b6A3645c240605887a5532109323A3E12273dc7) |
| TEE extension id | `65700` (`0x...0100a4`) |
| TEE machine that signed | `0x14fB1e5cF7eAE49B421831761f569D3d15a790F8` |

One policy, end to end, driven from the CLI. Dry window over Surabaya, 1 June to
31 August 2025, policy id
`0xa3d19f95e6c68f0edea4563c3df079d5c52c10d386620a83a9c6570aac9d7da8`:

| Step | Transaction |
|---|---|
| Bind the policy to its feed | [`0x6f5ecdfc...6d1551e0`](https://coston2-explorer.flare.network/tx/0x6f5ecdfcb352fed5f8ac9439f3104095bcec9c6b1744d1f34baf4bcf6d1551e0) |
| Load the sealed model | [`0x850d711c...b24ccf4c`](https://coston2-explorer.flare.network/tx/0x850d711c8553cbdf0f5ee8518e9a8513fb1120b9961272de20fcdce1b24ccf4c) |
| Request the FDC attestation | [`0x24c3a86a...6088e96c`](https://coston2-explorer.flare.network/tx/0x24c3a86ab27dbfa5de01e0a7ff44f1284fda68d5c9ff85c078eed7af6088e96c) |
| Evaluate against the proof | [`0x600c4e6a...9031eef1`](https://coston2-explorer.flare.network/tx/0x600c4e6a0497696072f63edf8783307225da98fe89074138d1cfddfc9031eef1) |
| Settle and pay | [`0x26d30c8a...f9e311b9`](https://coston2-explorer.flare.network/tx/0x26d30c8a6d0d28e1a906022b1c8521a22204aa9f861ccd2e90f4afd5f9e311b9) |

Attested rainfall 116.7 mm, voting round 1407221, paid **0.185625 FTestXRP**.

The same model over the same coordinates, for a wet window (1 December 2024 to 28
February 2025), policy id
`0xa3d21efc5c92e2f96b62e10a2c417b3456d693b503cb682b25db1d25c445f50f`:

| Step | Transaction |
|---|---|
| Evaluate against the proof | [`0xacc6fcbe...f31d0c5`](https://coston2-explorer.flare.network/tx/0xacc6fcbe6ee81fbe920db3ddc8e4d15f0c210a5da0435eda5ef93c947f31d0c5) |
| Settle, nothing owed | [`0xa225b2a4...81548e85`](https://coston2-explorer.flare.network/tx/0xa225b2a4e7e3575ece5b99afe5eaf34e01412c4eaebbe67e7b360ba181548e85) |

Attested rainfall 1081.0 mm, voting round 1407223, paid **nothing**, and the pool
was untouched. The policy still closes on chain, because "evaluated, nothing owed"
is a result a policyholder should be able to read rather than be told.

That contrast is the demonstration. One model, one location, and an outcome that
came entirely from data neither side chose.

---

## How this differs from Flare's `weather-insurance-extension`

Flare publishes a weather insurance guide for FCC, so the fair question is what
this adds. The differences are structural, and they sit in the two places the
bounty asks about.

| | Flare's guide | Aegis |
|---|---|---|
| Trigger data | The enclave calls OpenWeatherMap directly. The chain trusts that the TEE fetched honestly, with no attestation of the data itself | Bound to an FDC Web2Json attestation. Each policy is tied write once to one request body hash, the proof is verified on chain, and the voting round must move forward |
| Whose secret | The policyholder's threshold | The insurer's model, a different party and a different kind of asset |
| For how long | Commit and reveal. The secret is opened on chain at settlement, so the privacy is temporary by construction | Never revealed. The parameters stay in enclave memory for the life of the process, with tests that fail if they appear in any instruction, log or result |
| Problem solved | Hiding a bid until settlement | Protecting actuarial IP and preventing adverse selection, which commit and reveal structurally cannot do, because the secret is published in the end |
| Payout | On chain transfer | On chain transfer in FXRP, behind a swappable `IPayoutExecutor`, with PMW investigated and documented |

The guide is a good introduction to writing an extension. It is not a design that
can carry a secret an insurer cares about, because the secret comes out at the
end, and it does not connect the enclave to Flare's own data verification at all.

---

## Evidence of new work

The starting point was Flare's `fce-sign` scaffold
(`github.com/flare-foundation/fce-sign`), an example extension that stores a
private key and signs messages. Its README is kept here as
`README_fce-sign_original.md`, and the scaffold's deployment documents
(`DEPLOYMENT_STEPS.md`, `TESTNET_DEPLOYMENT.md`, `REPRODUCIBILITY.md`) are left
untouched, so the boundary is easy to inspect.

The last scaffold commit is `c5bbf11` (20 July 2026). Everything from `36c83a6`
onward was built for this submission: 60 files changed, about 9,000 lines added.

**From the scaffold:** the TEE node and proxy integration, the Docker and
reproducible build setup, the deployment and registration scripts, the ECIES
helper used to seal payloads to the enclave, the instruction sending plumbing, and
the general shape of an extension with a state endpoint and an action handler.

**Built for this submission:**

| Area | What was written |
|---|---|
| Extension | Rekeyed from `KEY`/`SIGN` to `POLICY` with `REGISTER_MODEL` and `EVALUATE`. The confidential drought model, scored with deterministic `big.Int` arithmetic, held only in enclave memory. 21 tests, including invariants that fail if a parameter reaches an instruction, a log or a result |
| FDC integration | `go/tools/pkg/fdc`, the whole Web2Json path: request building for the Open-Meteo archive, verifier encoding, fee reading, submission, voting round derivation, proof retrieval and decoding through the contract's own ABI. 11 tests |
| Contracts | `PolicySettlement.sol` and `FxrpPayoutExecutor.sol` plus four interfaces, and `InstructionSender.sol` extended with policy binding, FDC proof verification and the anti replay rules. 12 Solidity tests, including a golden vector for the signature preimage, a tampered decision, and a replay |
| Payout | `go/tools/pkg/payout`, signature preimage reconstruction and TEE id recovery off chain, settlement submission, FAssets resolution through the Flare Contract Registry. 13 tests |
| Tooling | `cmd/deploy-settlement`, `cmd/fund-pool`, `cmd/state-bridge`, and an end to end test that reads deployed bytecode to prove the raw rainfall path is gone |
| Demo | The read only web dashboard (`web/`) and the `aegis` CLI (`go/tools/cmd/aegis`, 5 tests) |

Verify it without taking any of this on faith:

```bash
cd go && go test ./...                # extension invariants
cd go/tools && go test ./...          # FDC, payout, CLI
forge test                            # settlement contract, 12 tests
bash ./scripts/full-setup.sh --test   # the whole path against Coston2
```

---

## Traction and deployment status

Kept plain, because an overstated number here is worth less than an honest one.

- **Deployed:** Coston2, live. Contracts, addresses and settled transactions are
  listed above and can be opened in the explorer.
- **Testing:** validated end to end on Coston2 with real FDC attestations and real
  FXRP settlement, most recently on 26 July 2026. Both outcomes are covered: a
  policy that pays, and a policy that closes owing nothing.
- **Users:** none. This has not been put in front of anybody outside the project,
  and there are no pilot users, partners or letters of intent to report.
- **Distribution:** not started. The work so far has been technical.
- **Production readiness:** the stack runs in simulated TEE mode, which is the
  approved mode for judging and not a production posture. Real attestation through
  GCP Confidential Space is the first item on the roadmap.

---

## Known limitations

These are MVP boundaries rather than hidden bugs, and naming them seems better
than letting a reviewer find them.

1. **`registerModel` has no access control, and it overwrites.** Anyone can send a
   `REGISTER_MODEL` instruction, and the enclave stores whatever arrives for that
   policy id. What limits the damage today is that `registerPolicyTrigger` is owner
   only, so an attacker cannot create policies, though they could overwrite the
   model of an existing one. The fix that fits: bind a policy id to its first
   registrant inside the enclave.
2. **`evaluate` accepts any recipient.** The recipient is a call parameter and is
   checked against nothing, because no policyholder address is recorded on chain
   before settlement. Since a policy settles once, whoever calls `evaluate` and
   `settle` first decides where the money goes. The fix that fits: store `payoutTo`
   at `registerPolicyTrigger` and ignore the parameter.
3. **One policy is one fixed window.** Start and end dates are locked to the past,
   so the demo scores an event that has already finished. There is no notion of a
   policy that stays live until some date.
4. **The round check only enforces forward movement.** Double payment is prevented
   by the per policy settlement record, not by the round check, which mainly stops
   an old attestation being replayed into an evaluation.
5. **The model lives in RAM.** A restarted enclave has forgotten it, and the
   insurer registers again. That is the trust boundary working as intended, and it
   does mean any demo script has to account for it.
6. **No premium flow.** There is no policy purchase, no premium, and no
   `PolicyRegistry`. The pool is funded directly by the owner. Underwriting
   economics were out of scope for the MVP.

---

## Roadmap

1. **Real attestation.** GCP Confidential Space through Flare's devops handoff,
   replacing simulated mode, and hardening the trust model around it.
2. **PMW payouts.** Real XRP on the XRPL, as soon as FDC2 opens to third party
   extensions. The interfaces are verified and the executor seam is already in
   place, so this is one contract and one transaction.
3. **Close the MVP gaps above:** registrant binding for models, `payoutTo` stored
   at binding time, rolling policy windows, and a premium flow with a real pool.
4. **More perils, more sources.** Heat index, flight delay, anything with a
   verifiable Web2 feed. The engine is not weather specific: a peril is a request
   body and a model.
5. **A policy marketplace,** with capital pooled from several underwriters, each
   scoring with their own sealed model, and on chain reinsurance behind it.
6. **Policyholder privacy,** so the buyer's sensitive inputs, not only the
   insurer's model, stay inside the enclave.

---

## Repository layout

| Path | What is in it |
|---|---|
| `contracts/` | `InstructionSender.sol`, `PolicySettlement.sol`, `FxrpPayoutExecutor.sol` and interfaces |
| `go/internal/extension/` | The TEE extension: `REGISTER_MODEL`, `EVALUATE`, and the confidential scoring |
| `go/pkg/types/` | Instruction and decision types, and the model definition that never leaves the enclave |
| `go/tools/pkg/fdc/` | Web2Json request building, submission and proof handling |
| `go/tools/pkg/payout/` | Signature recovery, settlement, and FAssets resolution |
| `go/tools/cmd/aegis/` | The demo command line |
| `go/tools/cmd/run-test/` | The end to end test, which reads as a narration of the whole path |
| `web/` | The read only dashboard |
| `scripts/` | Stack setup, the end to end run, the demo web server, and the read only state bridge |

The demo model's parameters live in `go/tools/cmd/run-test/main.go` and in the CLI,
because in this demo the test plays the insurer, the one party that legitimately
knows them. A reviewer who wants to check the arithmetic can read them there. In
the running system they exist in exactly two places: the insurer's process, and
the enclave.

---

## Credits

Built on Flare's `fce-sign` scaffold. Weather data from the Open-Meteo archive
API, attested through the Flare Data Connector. Hero photograph by Sergio
Capuzzimati on Unsplash.
