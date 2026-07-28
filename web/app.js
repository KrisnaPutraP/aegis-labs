'use strict';

// Aegis demo, read side only.
//
// Three sources feed this page and nothing else does:
//   1. The Coston2 JSON-RPC endpoint, for contract state (eth_call) and for the
//      settle transaction's calldata, which is where the TEE signature lives.
//   2. The Coston2 explorer API, for event history. The public RPC caps
//      eth_getLogs at 30 blocks per query, which is far too narrow to find a
//      policy that settled hours ago, so log discovery goes through the
//      explorer instead.
//   3. The enclave's own GET /state, for the sealed model panel.
//
// There is no wallet, no signer, and no write path. Values that are not on
// chain yet are rendered as an empty state, never as a placeholder number.

const CFG = window.AEGIS_CONFIG;

// Which copy of this page is running.
//
// 'local' is served next to the stack, so the enclave answers for itself and
// every panel is live. 'hosted' is served from static hosting, where there is no
// route to the enclave and never will be: the enclave runs on the operator's
// machine, and publishing a path to it is exactly what this project does not do.
//
// That is a deployment fact, not a failure, so the hosted page states it instead
// of rendering an unreachable endpoint as an error. Everything else on the page
// comes from the public Coston2 RPC and the explorer, which need nothing from
// the operator at all.
const HOSTED = CFG.profile === 'hosted';

// Function selectors, taken from the signatures in contracts/. Kept as
// constants so the page needs no ABI encoder for calls this simple.
const SEL = {
  settlementOf: '0xf1d3d381',              // settlementOf(bytes32)
  teeMachineRegistry: '0xd77798a9',        // TEE_MACHINE_REGISTRY()
  payoutExecutor: '0x00761612',            // payoutExecutor()
  extensionId: '0x62d7076e',               // extensionId()
  policyTriggerRequestHash: '0xb3d90546',  // policyTriggerRequestHash(bytes32)
  lastAttestedVotingRound: '0xa0b4472c',   // lastAttestedVotingRound(bytes32)
  availableLiquidity: '0x74375359',        // availableLiquidity()
  payoutDenomination: '0xfc2efed9',        // payoutDenomination()
  fxrp: '0x31d7fd5a',                      // FXRP()
  getTeeMachineStatus: '0x25e30221',       // getTeeMachineStatus(address)
  getExtensionId: '0xaa5bb892',            // getExtensionId(address)
};

// Event topics, keccak256 of the signatures declared in contracts/.
const TOPIC = {
  // PolicySettled(bytes32,bytes32,address,address,uint256)
  policySettled: '0x6f250f1be21508dd6b19c392763f1f439b2f80a8397b0ff9c3cbc168008abf17',
  // PolicyEvaluationRequested(bytes32,bytes32,uint64,int256,int256,uint256)
  policyEvaluationRequested: '0xe7266f99d9906f08ba1fb54d643413569df632277cfbd3f244f1c5c0265a96d6',
  // PolicyTriggerRegistered(bytes32,bytes32)
  policyTriggerRegistered: '0x5999e81899507c39dbb479f6eeb57a1361d3670c96957841e225b7ee7221dd21',
};

// settle(bytes32,uint8,string,bytes,bytes). Checked before the calldata of a
// settle transaction is picked apart for the signature.
const SETTLE_SELECTOR = '0x289db4b1';

// ITeeMachineRegistry.TeeStatus, in declaration order.
const TEE_STATUS = ['NONE', 'INITIALIZED', 'PRODUCTION', 'SUSPENDED', 'PAUSED', 'BANNED'];

// run-test derives its policy ids as two readable bytes followed by a random
// run nonce: 0xa3d1 for the dry window, 0xa3d2 for the wet one. The page uses
// that to label the two seasons and falls back to the paid amount if a
// deployment ever uses different ids.
const DRY_PREFIX = '0xa3d1';
const WET_PREFIX = '0xa3d2';

// ---------------------------------------------------------------- transport

let rpcId = 0;

async function rpc(method, params) {
  const res = await fetch(CFG.rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
  });
  if (!res.ok) throw new Error(`RPC ${method} returned HTTP ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(`RPC ${method}: ${body.error.message}`);
  return body.result;
}

function ethCall(to, data) {
  return rpc('eth_call', [{ to, data }, 'latest']);
}

async function explorerLogs(address) {
  const url = `${CFG.explorerUrl}/api/v2/addresses/${address}/logs`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Explorer returned HTTP ${res.status}`);
  const body = await res.json();
  return Array.isArray(body.items) ? body.items : [];
}

// ------------------------------------------------------------ abi decoding

function word(hex, index) {
  const body = hex.startsWith('0x') ? hex.slice(2) : hex;
  return body.slice(index * 64, (index + 1) * 64);
}

const toBig = (w) => BigInt('0x' + w);
const toBool = (w) => toBig(w) !== 0n;
const toAddress = (w) => '0x' + w.slice(24);

// Two's complement over 256 bits, needed for the signed coordinates.
function toInt(w) {
  const v = toBig(w);
  return v >= (1n << 255n) ? v - (1n << 256n) : v;
}

// Reads a dynamic string from an ABI return blob, given its head slot.
function readString(hex, headIndex) {
  const body = hex.startsWith('0x') ? hex.slice(2) : hex;
  const offset = Number(toBig(word(hex, headIndex))) * 2;
  const length = Number(BigInt('0x' + body.slice(offset, offset + 64)));
  const chars = body.slice(offset + 64, offset + 64 + length * 2);
  return hexToAscii('0x' + chars);
}

function hexToAscii(hex) {
  const body = hex.startsWith('0x') ? hex.slice(2) : hex;
  let out = '';
  for (let i = 0; i + 1 < body.length; i += 2) {
    const code = parseInt(body.slice(i, i + 2), 16);
    if (code !== 0) out += String.fromCharCode(code);
  }
  return out;
}

// --------------------------------------------------------------- formatting

function fmtUnits(value, decimals) {
  const base = 10n ** BigInt(decimals);
  const whole = value / base;
  const frac = (value % base).toString().padStart(decimals, '0');
  return `${whole}.${frac}`;
}

function fmtHash(hash, lead = 6, tail = 4) {
  if (!hash) return '--';
  if (hash.length <= lead + tail + 3) return hash;
  return `${hash.slice(0, 2 + lead)}…${hash.slice(-tail)}`;
}

// Coordinates travel as microdegrees so the attestation stays byte exact.
function fmtMicroDeg(value) {
  const neg = value < 0n;
  const abs = neg ? -value : value;
  const whole = abs / 1000000n;
  const frac = (abs % 1000000n).toString().padStart(6, '0');
  return `${neg ? '-' : ''}${whole}.${frac}`;
}

const fmtTenthsMm = (tenths) => `${(Number(tenths) / 10).toFixed(1)} mm`;

const txUrl = (hash) => `${CFG.explorerUrl}/tx/${hash}`;
const addrUrl = (address) => `${CFG.explorerUrl}/address/${address}`;

// ------------------------------------------------------------------- render

const $ = (id) => document.getElementById(id);

function setText(id, value) {
  const el = $(id);
  if (el) el.textContent = value;
}

function setLink(id, href, label) {
  const el = $(id);
  if (!el) return;
  if (href) {
    el.href = href;
    el.hidden = false;
  } else {
    el.removeAttribute('href');
    el.hidden = true;
  }
  if (label !== undefined) el.textContent = label;
}

// --------------------------------------------------------------- page state

const view = {
  lastOk: 0,
  logs: { at: 0, settled: [], evaluations: [] },
  settleTxCache: new Map(),
};

// ---------------------------------------------------------------- log logic

async function refreshLogs(force) {
  const fresh = Date.now() - view.logs.at < CFG.logsRefreshMs;
  if (fresh && !force) return;

  const [settlementLogs, senderLogs] = await Promise.all([
    explorerLogs(CFG.policySettlement),
    explorerLogs(CFG.instructionSender),
  ]);

  view.logs = {
    at: Date.now(),
    settled: settlementLogs.filter((l) => l.topics[0] === TOPIC.policySettled),
    evaluations: senderLogs.filter((l) => l.topics[0] === TOPIC.policyEvaluationRequested),
  };
}

// The explorer returns newest first. One entry per policy is all this page
// needs, since a policy settles exactly once.
function latestByPolicy(logs) {
  const seen = new Map();
  for (const log of logs) {
    const policyId = log.topics[1];
    if (!seen.has(policyId)) seen.set(policyId, log);
  }
  return [...seen.values()];
}

function decodeSettled(log) {
  return {
    policyId: log.topics[1],
    instructionId: log.topics[2],
    teeId: toAddress(word(log.topics[3], 0)),
    payoutTo: toAddress(word(log.data, 0)),
    amount: toBig(word(log.data, 1)),
    txHash: log.transaction_hash,
    blockNumber: log.block_number,
  };
}

function decodeEvaluation(log) {
  return {
    policyId: log.topics[1],
    instructionId: log.topics[2],
    votingRound: toBig(word(log.data, 0)),
    latitudeMicroDeg: toInt(word(log.data, 1)),
    longitudeMicroDeg: toInt(word(log.data, 2)),
    rainfallTenthsMm: toBig(word(log.data, 3)),
    txHash: log.transaction_hash,
  };
}

function pickSeasons(settled) {
  const byPolicy = latestByPolicy(settled).map(decodeSettled);
  const prefixed = (prefix) => byPolicy.find((s) => s.policyId.startsWith(prefix));

  const dry = prefixed(DRY_PREFIX) || byPolicy.find((s) => s.amount > 0n) || null;
  const wet = prefixed(WET_PREFIX) || byPolicy.find((s) => s.amount === 0n) || null;
  return { dry, wet };
}

// The TEE signature is not in an event, it is an argument of settle(). Pulling
// it from the transaction that the settlement contract accepted is the honest
// place to read it from.
async function teeSignature(txHash) {
  if (!txHash) return null;
  if (view.settleTxCache.has(txHash)) return view.settleTxCache.get(txHash);

  const tx = await rpc('eth_getTransactionByHash', [txHash]);
  let signature = null;
  if (tx && tx.input && tx.input.slice(0, 10) === SETTLE_SELECTOR) {
    const args = tx.input.slice(10);
    const offset = Number(BigInt('0x' + args.slice(4 * 64, 5 * 64))) * 2;
    const length = Number(BigInt('0x' + args.slice(offset, offset + 64)));
    signature = '0x' + args.slice(offset + 64, offset + 64 + length * 2);
  }
  view.settleTxCache.set(txHash, signature);
  return signature;
}

// ------------------------------------------------------------ enclave state

async function readEnclaveState() {
  if (HOSTED) return readEnclaveRecording();

  const res = await fetch(CFG.stateUrl, { cache: 'no-store' });
  const text = (await res.text()).trim();
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    parsed = null;
  }
  return { ok: res.ok, status: res.status, text, parsed };
}

// readEnclaveRecording reads what the enclave answered when the page was built,
// captured by scripts/build-web-vercel.sh from the same GET /state the local
// page calls live.
//
// It is a recording and is labelled as one everywhere it is shown. The body is
// stored and replayed verbatim rather than summarised, because the point of this
// panel is what the enclave says for itself, and a summary written here would be
// this page's claim instead.
let recordingRequest = null;
async function readEnclaveRecording() {
  // A recording does not change while the page is open, so the refresh loop
  // reads it once and reuses the answer.
  if (!recordingRequest) {
    recordingRequest = fetchEnclaveRecording().catch((err) => {
      recordingRequest = null;
      throw err;
    });
  }
  return recordingRequest;
}

async function fetchEnclaveRecording() {
  const res = await fetch(CFG.enclaveSnapshotUrl, { cache: 'no-store' });
  if (!res.ok) throw new Error(`no recording at ${CFG.enclaveSnapshotUrl}`);

  const snapshot = await res.json();
  const text = String(snapshot.body || '').trim();
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    parsed = null;
  }
  return {
    ok: snapshot.httpStatus === 200,
    status: snapshot.httpStatus,
    text,
    parsed,
    recorded: true,
    capturedAt: snapshot.capturedAt,
    endpoint: snapshot.endpoint,
  };
}

function renderEnclaveState(result) {
  if (!result || !result.ok || !result.parsed) {
    // A hosted page has no live endpoint to lose, so an absent recording means
    // the panel has nothing honest to say and is removed rather than filled
    // with the word unreachable.
    if (HOSTED) {
      hide('state-card');
      return;
    }
    setText('state-models', 'unreachable');
    setText('state-version', 'unreachable');
    return;
  }

  const models = result.parsed.state && result.parsed.state.registeredModels;
  setText('state-models', models === undefined ? 'unreachable' : String(models));
  setText('state-version', hexToAscii(result.parsed.stateVersion || '0x') || 'unknown');

  if (result.recorded) {
    setText('state-card-title', 'Enclave state, last known');
    const note = $('state-note');
    if (note) {
      note.textContent =
        `Recorded ${describeCapture(result.capturedAt)} from the enclave's own GET /state. ` +
        'This page is hosted, and the enclave runs on the operator\'s machine, so there is no live route to it from here. ' +
        'The panels above and below are read live from Coston2 and need nobody to be online.';
      note.hidden = false;
    }
  }
}

// describeCapture renders a capture time as something a reader can judge for
// themselves: the timestamp, plus how long ago it was.
function describeCapture(iso) {
  if (!iso) return 'at an unrecorded time';
  const when = new Date(iso);
  if (Number.isNaN(when.getTime())) return `at ${iso}`;

  const days = Math.floor((Date.now() - when.getTime()) / 86400000);
  const ago = days <= 0 ? 'today' : days === 1 ? '1 day ago' : `${days} days ago`;
  return `${when.toISOString().replace('T', ' ').slice(0, 16)} UTC, ${ago}`;
}

function hide(id) {
  const node = $(id);
  if (node) node.hidden = true;
}

// The reveal button runs the attempt for real. Whatever the endpoint answers is
// printed verbatim, including a failure, so the page never claims an outcome it
// did not observe.
async function onReveal() {
  const button = $('reveal-btn');
  const out = $('reveal-out');
  button.disabled = true;
  out.hidden = false;
  out.innerHTML = HOSTED
    ? '<p class="reveal-out__raw">replaying the recorded attempt ...</p>'
    : '<p class="reveal-out__raw">requesting GET /state ...</p>';

  let verdict;
  let verdictClass = '';
  let raw;
  let hint;

  try {
    const result = await readEnclaveState();
    raw = result.text || '(empty response)';
    if (result.ok && result.parsed) {
      verdict = 'Denied by architecture: GET /state returns only the model count, never its contents.';
      hint = result.recorded
        ? `HTTP ${result.status}, recorded ${describeCapture(result.capturedAt)} from ${result.endpoint || 'the enclave state endpoint'}. This is a replay, not a live call, because a hosted page has no route to the enclave. The response carries a count and a version string. There is no route on the enclave that returns a model, because nothing in the extension ever serializes one back out. The demo video shows the same request made live.`
        : `HTTP ${result.status} from ${CFG.stateUrl}. The response carries a count and a version string. There is no route on the enclave that returns a model, because nothing in the extension ever serializes one back out.`;
    } else {
      verdict = `The enclave answered HTTP ${result.status}, and it still did not carry a parameter.`;
      hint = result.recorded
        ? `Recorded ${describeCapture(result.capturedAt)}, replayed here verbatim.`
        : `Raw response from ${CFG.stateUrl}.`;
    }
  } catch (err) {
    verdictClass = ' is-error';
    if (HOSTED) {
      verdict = 'This hosted copy carries no recording of the attempt.';
      raw = String(err && err.message ? err.message : err);
      hint = 'Nothing is claimed here that was not observed. The demo video shows the request being made against the running enclave, and anyone can reproduce it locally with ./scripts/state-bridge.sh start.';
    } else {
      verdict = 'The enclave state endpoint is not reachable from this browser.';
      raw = String(err && err.message ? err.message : err);
      hint = 'Nothing was revealed, but nothing was proved either. Start the read-only bridge with ./scripts/state-bridge.sh start and press the button again to see the enclave answer for itself.';
    }
  }

  out.innerHTML = '';
  const verdictEl = document.createElement('p');
  verdictEl.className = 'reveal-out__verdict' + verdictClass;
  verdictEl.textContent = verdict;
  const rawEl = document.createElement('pre');
  rawEl.className = 'reveal-out__raw';
  rawEl.textContent = raw.length > 400 ? raw.slice(0, 400) + '…' : raw;
  const hintEl = document.createElement('p');
  hintEl.className = 'reveal-out__hint';
  hintEl.textContent = hint;

  out.append(verdictEl, rawEl, hintEl);
  button.disabled = false;
}

// ------------------------------------------------------------- chain reader

async function refreshChain() {
  // Everything hangs off the two configured addresses. The executor, the asset
  // and the registry are resolved from the settlement contract, so a swap is
  // visible here without editing the page.
  const [executorWord, registryWord, extensionIdWord] = await Promise.all([
    ethCall(CFG.policySettlement, SEL.payoutExecutor),
    ethCall(CFG.policySettlement, SEL.teeMachineRegistry),
    ethCall(CFG.policySettlement, SEL.extensionId),
  ]);

  const executor = toAddress(word(executorWord, 0));
  const registry = toAddress(word(registryWord, 0));
  const extensionId = toBig(word(extensionIdWord, 0));

  const [assetWord, denominationBlob, liquidityWord] = await Promise.all([
    ethCall(executor, SEL.fxrp),
    ethCall(executor, SEL.payoutDenomination),
    ethCall(executor, SEL.availableLiquidity),
  ]);

  const asset = toAddress(word(assetWord, 0));
  const symbol = readString(denominationBlob, 0);
  const decimals = Number(toBig(word(denominationBlob, 1)));
  const liquidity = toBig(word(liquidityWord, 0));

  const { dry, wet } = pickSeasons(view.logs.settled);
  const evaluations = view.logs.evaluations.map(decodeEvaluation);
  const evaluationFor = (policyId) => evaluations.find((e) => e.policyId === policyId) || null;

  const dryEval = dry ? evaluationFor(dry.policyId) : null;
  const wetEval = wet ? evaluationFor(wet.policyId) : null;

  let dryChain = null;
  if (dry) {
    const [settlementBlob, requestHash, roundWord] = await Promise.all([
      ethCall(CFG.policySettlement, SEL.settlementOf + dry.policyId.slice(2)),
      ethCall(CFG.instructionSender, SEL.policyTriggerRequestHash + dry.policyId.slice(2)),
      ethCall(CFG.instructionSender, SEL.lastAttestedVotingRound + dry.policyId.slice(2)),
    ]);
    dryChain = {
      settled: toBool(word(settlementBlob, 0)),
      payoutTo: toAddress(word(settlementBlob, 1)),
      amount: toBig(word(settlementBlob, 2)),
      instructionId: '0x' + word(settlementBlob, 3),
      requestHash,
      votingRound: toBig(word(roundWord, 0)),
    };
  }

  let wetChain = null;
  if (wet) {
    const settlementBlob = await ethCall(CFG.policySettlement, SEL.settlementOf + wet.policyId.slice(2));
    wetChain = {
      settled: toBool(word(settlementBlob, 0)),
      amount: toBig(word(settlementBlob, 2)),
    };
  }

  let machine = null;
  if (dry) {
    const [statusWord, machineExtensionWord] = await Promise.all([
      ethCall(registry, SEL.getTeeMachineStatus + '000000000000000000000000' + dry.teeId.slice(2)),
      ethCall(registry, SEL.getExtensionId + '000000000000000000000000' + dry.teeId.slice(2)),
    ]);
    machine = {
      teeId: dry.teeId,
      status: TEE_STATUS[Number(toBig(word(statusWord, 0)))] || 'UNKNOWN',
      extensionId: toBig(word(machineExtensionWord, 0)),
    };
  }

  const signature = dry ? await teeSignature(dry.txHash) : null;

  render({
    executor, registry, extensionId, asset, symbol, decimals, liquidity,
    dry, dryEval, dryChain, wet, wetEval, wetChain, machine, signature,
  });
}

function render(d) {
  // Sealed model panel, chain half.
  if (d.machine) {
    setText('tee-machine', fmtHash(d.machine.teeId, 8, 6));
    const statusEl = $('tee-status');
    const ok = d.machine.status === 'PRODUCTION';
    statusEl.innerHTML = '';
    const pill = document.createElement('span');
    pill.className = 'pill ' + (ok ? 'pill--ok' : 'pill--bad');
    pill.textContent = d.machine.status;
    statusEl.appendChild(pill);
  } else {
    setText('tee-machine', 'no settled policy yet');
    setText('tee-status', 'unknown');
  }
  setText('extension-id', `${d.extensionId} (0x${d.extensionId.toString(16)})`);

  // Chain of trust, driven by the policy that paid.
  if (d.dryEval) {
    setText('data-value', fmtTenthsMm(d.dryEval.rainfallTenthsMm));
    setText('data-note', `Open-Meteo archive, attested grid point ${fmtMicroDeg(d.dryEval.latitudeMicroDeg)}, ${fmtMicroDeg(d.dryEval.longitudeMicroDeg)}`);
    setLink('data-link', txUrl(d.dryEval.txHash), 'evaluate transaction');

    // The round is read back from InstructionSender state when available, since
    // that is the value the anti replay check compares against.
    const round = d.dryChain ? d.dryChain.votingRound : d.dryEval.votingRound;
    setText('fdc-value', `round ${round}`);
    setText('fdc-note', 'Attested by FDC Web2Json, Merkle proof verified on-chain');
    setLink('fdc-link', txUrl(d.dryEval.txHash), 'attested reading');
  } else {
    setText('data-value', 'no evaluation on chain yet');
    setText('fdc-value', 'no attestation on chain yet');
    setLink('data-link', null);
    setLink('fdc-link', null);
  }

  if (d.dry) {
    setText('tee-value', d.signature ? fmtHash(d.signature, 8, 6) : 'signature in settle calldata');
    setText('tee-note', d.machine
      ? `Signed by machine ${fmtHash(d.machine.teeId, 6, 4)}, recovered on-chain`
      : 'Signed inside the enclave, recovered on-chain');
    setLink('tee-link', txUrl(d.dry.txHash), 'settle transaction');

    setText('payout-value', `${fmtUnits(d.dry.amount, d.decimals)} ${d.symbol}`);
    setText('payout-note', `Paid from the executor pool to ${fmtHash(d.dry.payoutTo, 6, 6)}`);
    setLink('payout-link', txUrl(d.dry.txHash), 'settle transaction');
  } else {
    setText('tee-value', 'no signed decision yet');
    setText('payout-value', 'no payout yet');
    setLink('tee-link', null);
    setLink('payout-link', null);
  }

  // Metrics.
  setText('pool-balance', `${fmtUnits(d.liquidity, d.decimals)} ${d.symbol}`);
  setText('pool-note', `Liquidity held by the payout executor, ${fmtHash(d.executor, 6, 4)}`);

  if (d.dryChain) {
    setText('paid-amount', `${fmtUnits(d.dryChain.amount, d.decimals)} ${d.symbol}`);
    setText('paid-note', 'Recipient named inside the signed decision');
    setText('paid-address', d.dryChain.payoutTo);
    setText('policy-status', d.dryChain.settled ? 'Paid and closed' : 'Open');
    setText('policy-note', `settlementOf(${fmtHash(d.dry.policyId, 6, 4)}) on PolicySettlement`);
  } else {
    setText('paid-amount', 'nothing settled yet');
    setText('paid-note', 'No settled policy found on this deployment');
    setText('paid-address', '');
    setText('policy-status', 'none');
    setText('policy-note', 'Run the end to end test to settle a policy');
  }

  // Season contrast.
  if (d.dry) {
    setText('dry-amount', `${fmtUnits(d.dry.amount, d.decimals)} ${d.symbol}`);
    setText('dry-detail', d.dryEval
      ? `Attested rainfall ${fmtTenthsMm(d.dryEval.rainfallTenthsMm)} over the insured window. The model paid.`
      : 'Settled from an attested reading.');
    setText('dry-policy', `policy ${fmtHash(d.dry.policyId, 6, 6)}`);
  } else {
    setText('dry-amount', '--');
    setText('dry-detail', 'No paying policy settled on this deployment yet.');
    setText('dry-policy', '');
  }

  if (d.wet) {
    setText('wet-amount', `${fmtUnits(d.wet.amount, d.decimals)} ${d.symbol}`);
    setText('wet-detail', d.wetEval
      ? `Attested rainfall ${fmtTenthsMm(d.wetEval.rainfallTenthsMm)} over the same location. Closed with nothing owed, the pool is untouched.`
      : 'Closed with nothing owed, the pool is untouched.');
    setText('wet-policy', `policy ${fmtHash(d.wet.policyId, 6, 6)}`);
  } else {
    setText('wet-amount', '--');
    setText('wet-detail', 'No zero payout policy settled on this deployment yet.');
    setText('wet-policy', '');
  }

  // Technical panel.
  setLink('tech-sender', addrUrl(CFG.instructionSender), CFG.instructionSender);
  setLink('tech-settlement', addrUrl(CFG.policySettlement), CFG.policySettlement);
  setLink('tech-executor', addrUrl(d.executor), d.executor);
  setLink('tech-asset', addrUrl(d.asset), `${d.asset} (${d.symbol}, ${d.decimals} decimals)`);
  if (d.dry) {
    setLink('tech-settle-tx', txUrl(d.dry.txHash), fmtHash(d.dry.txHash, 10, 8));
  } else {
    setLink('tech-settle-tx', null, 'none yet');
  }
  if (d.dryEval) {
    setLink('tech-eval-tx', txUrl(d.dryEval.txHash), fmtHash(d.dryEval.txHash, 10, 8));
  } else {
    setLink('tech-eval-tx', null, 'none yet');
  }
  setText('tech-request-hash', d.dryChain ? fmtHash(d.dryChain.requestHash, 10, 8) : 'none yet');
  setText('tech-extension', `${d.extensionId} (0x${d.extensionId.toString(16)})`);
}

// ------------------------------------------------------------------- driver

function setStatus(message, isError) {
  const el = $('status-text');
  el.textContent = message;
  el.classList.toggle('is-error', Boolean(isError));
}

function tickAge() {
  if (!view.lastOk) return;
  const seconds = Math.round((Date.now() - view.lastOk) / 1000);
  setText('status-age', `updated ${seconds}s ago`);
}

async function refresh() {
  // Event history and contract state fail independently. Losing the explorer
  // should not blank out the pool balance, and the page keeps whatever history
  // it already has rather than dropping back to empty panels.
  let warning = null;
  try {
    await refreshLogs(false);
  } catch (err) {
    warning = `Event history unavailable: ${err && err.message ? err.message : err}`;
  }

  try {
    await refreshChain();
    view.lastOk = Date.now();
    setStatus(warning || 'Reading Coston2 live', Boolean(warning));
  } catch (err) {
    setStatus(`Read failed: ${err && err.message ? err.message : err}`, true);
  }

  // The enclave lives outside the chain, so its panel fails on its own terms.
  try {
    renderEnclaveState(await readEnclaveState());
  } catch (err) {
    renderEnclaveState(null);
  }
}

function start() {
  if (HOSTED) {
    // The label has to match what the button does. Live it makes a request;
    // hosted it replays one that was made.
    setText('reveal-btn', 'show the recorded attempt');
    if (!CFG.enclaveSnapshotUrl) hide('state-card');
    setText('footer-sources',
      'Contract state comes from the Coston2 RPC endpoint and event history from the Coston2 explorer API, ' +
      'both public, which is why this page keeps working with nobody online. The enclave panel is a recording, ' +
      'because the enclave runs on the operator\'s machine and is not published.');
  }

  $('reveal-btn').addEventListener('click', onReveal);
  refresh();
  setInterval(refresh, CFG.refreshMs);
  setInterval(tickAge, 1000);
}

start();
