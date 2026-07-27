'use strict';

// Aegis demo, write side.
//
// This file is a layer on top of the read-only dashboard, not a rewrite of it.
// app.js keeps reading Coston2 exactly as before and knows nothing about this
// code. If everything here fails, or the browser has no wallet at all, the page
// below still works as the dashboard it was, which is why the interactive part
// lives in its own section and its own script.
//
// What a visitor can do, both permissionless on the contracts as deployed:
//
//   evaluate   request an FDC attestation of a policy's weather feed, wait for
//              the voting round to finalize, and hand the proof to
//              InstructionSender.evaluate so the enclave scores it
//   settle     carry the enclave's signed decision to PolicySettlement.settle,
//              which verifies the signature and pays out if the model triggered
//
// Creating a policy is not offered. registerPolicyTrigger is owner only in this
// deployment, and opening it would open a path to drain the payout pool, so the
// policies a visitor can try are pre-created by the owner and listed in
// policies.json.
//
// The page never asks for a private key and has no signer. Every transaction is
// built here as calldata and handed to the visitor's wallet to sign.

(function () {
  const CFG = window.AEGIS_CONFIG;
  const ABI = window.AEGIS_ABI;

  // Mirrors cmd/aegis: three voting rounds per request, four minutes on each,
  // polled every fifteen seconds. Matching the CLI matters because the CLI is
  // the fallback path for the same demo, and two different timings would make
  // one of them look broken.
  const PROOF_ATTEMPTS = 3;
  const PROOF_TIMEOUT_MS = 4 * 60 * 1000;
  const POLL_INTERVAL_MS = 15 * 1000;
  const RESULT_TIMEOUT_MS = 2 * 60 * 1000;
  const RESULT_POLL_MS = 3 * 1000;

  // Every instruction sent to the TEE registry carries a fee, and evaluate is an
  // instruction. This is the same value cmd/aegis sends (utils.DefaultFee in
  // go/tools/pkg/utils/instructions.go), which is 0.000001 C2FLR. Sending zero
  // reverts with FeeTooLow, and that revert is mapped below, so if the network
  // ever raises the floor the page says which constant is wrong instead of
  // failing anonymously.
  const INSTRUCTION_FEE_WEI = 1000000000000n;

  const $ = (id) => document.getElementById(id);
  const el = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };

  const state = {
    account: null,
    chainId: null,
    policies: [],
    busy: false,
    // instructionId per policy, so a run interrupted after evaluate can still be
    // settled without repeating the attestation.
    decisions: new Map(),
  };

  // ------------------------------------------------------------------ transport

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

  const ethCall = (to, data) => rpc('eth_call', [{ to, data }, 'latest']);

  // eth_call with the sender set, used to simulate a write before the wallet is
  // asked to sign it. A revert here costs nothing and carries the contract's own
  // reason, which is the difference between a useful message and "transaction
  // failed" after the visitor has already paid gas.
  async function simulate(from, to, data, value) {
    const call = { from, to, data };
    if (value !== undefined) call.value = '0x' + BigInt(value).toString(16);
    try {
      await rpc('eth_call', [call, 'latest']);
      return null;
    } catch (err) {
      return err;
    }
  }

  // ------------------------------------------------------------- revert reasons

  // Custom error selectors, computed from the compiled ABIs in out/, so a renamed
  // error stops matching here rather than being reported as something else.
  const ERRORS = {
    '0xd052894f': () => 'That decision has already been settled. Each signed decision can be used once.',
    '0x0d8e1133': () => 'This policy has already been settled. A parametric policy pays once and closes.',
    '0x9561b7e0': () => 'The settlement contract does not recognise this policy.',
    '0xd84c086d': () => 'The decision was signed by an enclave that does not belong to this extension.',
    '0x2f15dc53': () => 'The signing enclave is not in PRODUCTION status.',
    '0x4d44de49': () => 'The enclave action failed, so it carries no decision to settle.',
    '0x0022e862': () => 'The decision payload is not the expected 96 bytes.',
    '0x55a1e16e': () => 'The TEE signature on this decision is malformed.',
    '0x6866be99': () => 'No payout executor is configured on the settlement contract.',
    // FeeTooLow(), raised by the TEE registry when an instruction underpays.
    '0x732f9413': () => 'The TEE registry rejected the instruction fee as too low. The page sends the same fee the CLI does, so this means the network raised it: INSTRUCTION_FEE_WEI in interact.js needs raising too.',
    '0xa17e11d5': (args) => {
      const requested = ABI.uintAt(args, 0);
      const available = ABI.uintAt(args, 1);
      return `The demo pool is short of liquidity: the decision asks for ${requested} base units and the pool holds ${available}.`;
    },
  };

  // Maps a failed call into something worth reading. Handles the two shapes a
  // revert arrives in: Error(string) from require, and a custom error selector.
  function explainRevert(err, fallback) {
    const message = String((err && err.message) || err || '');

    const hexMatch = message.match(/0x[0-9a-fA-F]{8,}/);
    if (hexMatch) {
      const blob = hexMatch[0];
      const selector = blob.slice(0, 10).toLowerCase();

      if (selector === '0x08c379a0') {
        // Error(string): offset, length, then the UTF-8 bytes.
        try {
          const body = blob.slice(10);
          const length = Number(BigInt('0x' + body.slice(64, 128)));
          const chars = body.slice(128, 128 + length * 2);
          const bytes = new Uint8Array(chars.match(/../g).map((h) => parseInt(h, 16)));
          const reason = new TextDecoder().decode(bytes);
          if (reason) return explainRequireString(reason);
        } catch (ignored) { /* fall through to the raw message */ }
      }

      const known = ERRORS[selector];
      if (known) return known(blob.slice(10));
    }

    if (/insufficient funds/i.test(message)) {
      return 'Your wallet does not hold enough C2FLR to pay for this transaction. The faucet link above tops it up for free.';
    }
    if (/user rejected|user denied|ACTION_REJECTED|4001/i.test(message)) {
      return 'You rejected the request in your wallet, so nothing was sent.';
    }

    return fallback ? `${fallback} ${message}` : message;
  }

  // The InstructionSender guards are require statements, so their text is the
  // contract's own. Rewritten here into something a visitor can act on, with the
  // original kept visible in the detail line.
  function explainRequireString(reason) {
    if (reason.includes("attestation is not this policy's trigger")) {
      return 'The attestation does not match the request this policy is bound to. The binding is write once, so only this policy\'s own weather feed can settle it.';
    }
    if (reason.includes('policy trigger not registered')) {
      return 'This policy is not bound to an attestation request on this deployment.';
    }
    if (reason.includes('invalid FDC attestation')) {
      return 'The FDC verification contract rejected the Merkle proof. The voting round may not be finalized yet.';
    }
    if (reason.includes('attestation older than last evaluation')) {
      return 'That attestation is from a voting round this policy has already used. Evaluations have to move forward, which is what stops an old reading being replayed.';
    }
    return `The contract refused the call: ${reason}`;
  }

  // ------------------------------------------------------------------- FDC calls

  // The verifier accepts, and explicitly allows cross-origin, both the content
  // type and the API key header.
  async function prepareRequest(requestBody) {
    const padded = (name) => {
      const bytes = new TextEncoder().encode(name);
      let hex = '';
      for (const b of bytes) hex += b.toString(16).padStart(2, '0');
      return '0x' + hex.padEnd(64, '0');
    };

    const res = await fetch(`${CFG.fdcVerifierUrl}/verifier/web2/Web2Json/prepareRequest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-KEY': CFG.fdcApiKey },
      body: JSON.stringify({
        attestationType: padded('Web2Json'),
        sourceId: padded('PublicWeb2'),
        requestBody,
      }),
    });
    if (!res.ok) {
      throw new Error(`the FDC verifier returned HTTP ${res.status}`);
    }
    const body = await res.json();
    if (body.status !== 'VALID') {
      throw new Error(`the FDC verifier rejected the request: ${body.status}`);
    }
    return body.abiEncodedRequest;
  }

  // The DA Layer is deliberately called without the X-API-KEY the Go client
  // sends. Its CORS preflight allows content-type but not x-api-key, so a
  // browser that sent the key would be blocked before the request left. The
  // endpoint serves public testnet data without it.
  async function fetchProof(votingRoundId, abiEncodedRequest) {
    const res = await fetch(`${CFG.fdcDaLayerUrl}/api/v1/fdc/proof-by-request-round-raw`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ votingRoundId, requestBytes: abiEncodedRequest }),
    });
    if (!res.ok) return null; // round still open, or the request was not attested
    const body = await res.json();
    if (!body || !body.response_hex) return null;
    return { proof: body.proof || [], responseHex: body.response_hex };
  }

  async function requestFee(abiEncodedRequest) {
    const cfgWord = await ethCall(CFG.fdcHub, ABI.SELECTOR.fdcRequestFeeConfigurations);
    const feeConfig = '0x' + cfgWord.slice(26);
    const feeWord = await ethCall(feeConfig, ABI.encodeGetRequestFee(abiEncodedRequest));
    return BigInt(feeWord);
  }

  // The voting round a request lands in is the epoch containing the block that
  // mined it, using the geometry FlareSystemsManager publishes. Read, never
  // assumed, for the same reason the Go client reads it.
  async function votingRoundOf(blockTimestamp) {
    const [firstWord, durationWord] = await Promise.all([
      ethCall(CFG.flareSystemsManager, ABI.SELECTOR.firstVotingRoundStartTs),
      ethCall(CFG.flareSystemsManager, ABI.SELECTOR.votingEpochDurationSeconds),
    ]);
    const first = BigInt(firstWord);
    const duration = BigInt(durationWord);
    if (duration === 0n) throw new Error('votingEpochDurationSeconds is zero');
    return Number((BigInt(blockTimestamp) - first) / duration);
  }

  // ---------------------------------------------------------------- the wallet

  const provider = () => window.ethereum || null;

  async function walletRequest(method, params) {
    const p = provider();
    if (!p) throw new Error('no injected wallet');
    return p.request({ method, params });
  }

  async function connect() {
    if (!provider()) {
      setWalletNote('No browser wallet detected. MetaMask or any injected EIP-1193 wallet works.', true);
      return;
    }
    try {
      const accounts = await walletRequest('eth_requestAccounts', []);
      state.account = accounts && accounts[0] ? accounts[0] : null;
      state.chainId = await walletRequest('eth_chainId', []);
      await refreshWallet();
    } catch (err) {
      setWalletNote(explainRevert(err, 'Could not connect.'), true);
    }
  }

  // Coston2 parameters, from the same RPC and explorer the dashboard reads.
  const COSTON2_PARAMS = {
    chainId: CFG.chainIdHex,
    chainName: 'Flare Testnet Coston2',
    nativeCurrency: { name: 'Coston2 Flare', symbol: 'C2FLR', decimals: 18 },
    rpcUrls: [CFG.rpcUrl],
    blockExplorerUrls: [CFG.explorerUrl],
  };

  async function switchChain() {
    try {
      await walletRequest('wallet_switchEthereumChain', [{ chainId: CFG.chainIdHex }]);
    } catch (err) {
      // 4902 is "unrecognised chain", the case where it has to be added first.
      const code = err && (err.code || (err.data && err.data.originalError && err.data.originalError.code));
      if (code === 4902) {
        await walletRequest('wallet_addEthereumChain', [COSTON2_PARAMS]);
      } else {
        throw err;
      }
    }
    state.chainId = await walletRequest('eth_chainId', []);
    await refreshWallet();
  }

  const onRightChain = () =>
    state.chainId !== null && Number(BigInt(state.chainId)) === CFG.chainId;

  async function refreshWallet() {
    const connectBtn = $('wallet-connect');
    const addressEl = $('wallet-address');
    const balanceEl = $('wallet-balance');
    const switchBtn = $('wallet-switch');

    if (!state.account) {
      connectBtn.hidden = false;
      connectBtn.textContent = 'connect wallet';
      addressEl.textContent = 'not connected';
      balanceEl.textContent = '--';
      switchBtn.hidden = true;
      setWalletNote('Connect a wallet to run an evaluation. Reading the dashboard needs no wallet at all.');
      renderPolicies();
      return;
    }

    connectBtn.hidden = true;
    addressEl.textContent = state.account;

    if (!onRightChain()) {
      balanceEl.textContent = '--';
      switchBtn.hidden = false;
      setWalletNote(`Your wallet is on chain ${state.chainId}. Aegis is deployed on Coston2, chain ${CFG.chainId}.`, true);
      renderPolicies();
      return;
    }

    switchBtn.hidden = true;
    try {
      const balance = await rpc('eth_getBalance', [state.account, 'latest']);
      const wei = BigInt(balance);
      balanceEl.textContent = `${formatUnits(wei, 18, 4)} C2FLR`;
      if (wei === 0n) {
        setWalletNote('This account holds no C2FLR, so it cannot pay gas yet. The faucet link is free and takes a moment.', true);
      } else {
        setWalletNote('Connected to Coston2. Pick a policy below and run an evaluation.');
      }
    } catch (err) {
      balanceEl.textContent = 'unreadable';
      setWalletNote(explainRevert(err, 'Could not read the balance.'), true);
    }
    renderPolicies();
  }

  function setWalletNote(text, isError) {
    const node = $('wallet-note');
    node.textContent = text;
    node.classList.toggle('is-error', Boolean(isError));
  }

  // A fee of 1000 wei rendered as "0.000000 C2FLR" reads as free, and a fee of
  // zero reads the same way, so small values are reported in wei instead.
  function describeWei(wei) {
    if (wei < 10n ** 12n) return `${wei} wei`;
    return `${formatUnits(wei, 18, 6)} C2FLR`;
  }

  function formatUnits(value, decimals, places) {
    const base = 10n ** BigInt(decimals);
    const whole = value / base;
    const frac = (value % base).toString().padStart(decimals, '0');
    return places === undefined ? `${whole}.${frac}` : `${whole}.${frac.slice(0, places)}`;
  }

  // ------------------------------------------------------------ policy loading

  async function loadPolicies(attempt = 1) {
    let listed = [];
    try {
      const res = await fetch(CFG.policiesUrl, { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      listed = Array.isArray(body.policies) ? body.policies : [];
    } catch (err) {
      $('try-empty').textContent =
        `Could not read ${CFG.policiesUrl}: ${err.message}. The dashboard above is unaffected.`;
      $('try-empty').hidden = false;
      return;
    }

    // Every entry is checked against the chain before it is offered. A config
    // that has drifted from the deployment is shown as a warning rather than
    // being quietly skipped, because a policy that looks tryable and then fails
    // in the wallet is the worst version of this.
    const checked = await Promise.all(listed.map(async (policy) => {
      const result = { ...policy, tryable: false, warning: null, settled: false, amount: 0n };
      try {
        const [boundHash, computedHash, settlementBlob] = await Promise.all([
          ethCall(CFG.instructionSender, ABI.SELECTOR.policyTriggerRequestHash + ABI.strip0x(policy.policyId)),
          ethCall(CFG.instructionSender, ABI.encodeTriggerRequestHash(policy.requestBody)),
          ethCall(CFG.policySettlement, ABI.SELECTOR.settlementOf + ABI.strip0x(policy.policyId)),
        ]);

        result.settled = ABI.uintAt(settlementBlob, 0) !== 0n;
        result.payoutTo = '0x' + ABI.wordAt(settlementBlob, 1).slice(24);
        result.amount = ABI.uintAt(settlementBlob, 2);
        result.instructionId = '0x' + ABI.wordAt(settlementBlob, 3);

        if (BigInt(boundHash) === 0n) {
          result.warning = 'not bound to an attestation request on this deployment';
        } else if (boundHash.toLowerCase() !== computedHash.toLowerCase()) {
          result.warning =
            'the request body in policies.json does not hash to the request this policy is bound to on chain';
        } else if (!result.settled) {
          result.tryable = true;
        }
      } catch (err) {
        result.warning = `could not be checked against the chain: ${err.message}`;
        result.checkFailed = true;
      }
      return result;
    }));

    state.policies = checked;
    renderPolicies();

    // A transient RPC failure would otherwise leave every policy marked
    // unavailable until someone reloads the page, which reads as "the demo is
    // broken" when the truth is one dropped request. Re-check the ones that
    // failed, a few times, backing off.
    if (checked.some((p) => p.checkFailed) && attempt < 4) {
      setTimeout(() => loadPolicies(attempt + 1), 3000 * attempt);
    }
  }

  // ------------------------------------------------------------------ rendering

  function renderPolicies() {
    const open = $('try-open');
    const history = $('try-history');
    open.innerHTML = '';
    history.innerHTML = '';

    const ready = state.account && onRightChain();
    const openPolicies = state.policies.filter((p) => !p.settled);
    const donePolicies = state.policies.filter((p) => p.settled);

    $('try-empty').hidden = state.policies.length > 0;

    for (const policy of openPolicies) {
      open.appendChild(renderOpenPolicy(policy, ready));
    }
    for (const policy of donePolicies) {
      history.appendChild(renderSettledPolicy(policy));
    }
    $('try-history-wrap').hidden = donePolicies.length === 0;

    if (openPolicies.length === 0 && state.policies.length > 0) {
      const note = el('p', 'try__note',
        'Every listed policy has been settled. Each one pays at most once and then closes, which is the anti replay rule doing its job. The operator can mint more with aegis register-model --new --web-config web/policies.json.');
      open.appendChild(note);
    }
  }

  function renderOpenPolicy(policy, ready) {
    const card = el('article', 'trycard');

    const head = el('div', 'trycard__head');
    head.appendChild(el('h3', 'trycard__title', policy.name));
    const status = el('span', 'pill ' + (policy.tryable ? 'pill--ok' : 'pill--bad'),
      policy.tryable ? 'OPEN' : 'UNAVAILABLE');
    head.appendChild(status);
    card.appendChild(head);

    card.appendChild(el('p', 'trycard__desc', policy.description));

    const kv = el('dl', 'trycard__kv');
    const row = (label, value) => {
      const wrap = el('div', 'trycard__row');
      wrap.appendChild(el('dt', null, label));
      wrap.appendChild(el('dd', 'mono', value));
      kv.appendChild(wrap);
    };
    row('Location', `${policy.latitudeDeg}, ${policy.longitudeDeg}`);
    row('Window', `${policy.startDate} to ${policy.endDate}`);
    row('Policy id', `${policy.policyId.slice(0, 12)}…${policy.policyId.slice(-6)}`);
    card.appendChild(kv);

    if (policy.warning) {
      card.appendChild(el('p', 'trycard__warning', `Not offered: ${policy.warning}.`));
      return card;
    }

    const actions = el('div', 'trycard__actions');
    const runBtn = el('button', 'trybtn', 'run evaluation');
    runBtn.type = 'button';
    runBtn.disabled = !ready || state.busy;
    runBtn.addEventListener('click', () => runEvaluate(policy, card));
    actions.appendChild(runBtn);

    const payoutWrap = el('label', 'trycard__payout');
    payoutWrap.appendChild(el('span', null, 'pay to'));
    const payoutInput = el('input', 'trycard__input');
    payoutInput.type = 'text';
    payoutInput.value = state.account || '';
    payoutInput.placeholder = '0x...';
    payoutInput.spellcheck = false;
    payoutInput.dataset.role = 'payout';
    payoutWrap.appendChild(payoutInput);
    actions.appendChild(payoutWrap);

    card.appendChild(actions);

    if (!ready) {
      card.appendChild(el('p', 'trycard__hint',
        state.account ? 'Switch to Coston2 to run this.' : 'Connect a wallet to run this.'));
    }

    const log = el('div', 'trylog');
    log.hidden = true;
    log.dataset.role = 'log';
    card.appendChild(log);

    return card;
  }

  function renderSettledPolicy(policy) {
    const row = el('article', 'trydone');
    row.appendChild(el('span', 'trydone__name', policy.name));
    const paid = policy.amount > 0n
      ? `${formatUnits(policy.amount, 6)} FTestXRP`
      : 'nothing owed';
    row.appendChild(el('span', 'trydone__amount mono', paid));
    row.appendChild(el('span', 'trydone__id mono',
      `${policy.policyId.slice(0, 10)}…${policy.policyId.slice(-4)}`));
    const link = el('a', 'trydone__link', 'settlement');
    link.href = `${CFG.explorerUrl}/address/${CFG.policySettlement}`;
    link.target = '_blank';
    link.rel = 'noopener';
    row.appendChild(link);
    return row;
  }

  // ---------------------------------------------------------------- the run log

  // Progress is reported as a running list rather than a spinner. The wait for a
  // voting round is 90 to 180 seconds and there is no way to shorten it, so the
  // honest thing is to say which round is being waited on and how long it has
  // taken so far.
  function logger(card) {
    const node = card.querySelector('[data-role="log"]');
    node.hidden = false;
    let current = null;

    return {
      step(text) {
        current = el('p', 'trylog__line', text);
        node.appendChild(current);
        return current;
      },
      update(text) {
        if (current) current.textContent = text;
      },
      done(text) {
        if (current) {
          current.textContent = text;
          current.classList.add('is-done');
        }
        current = null;
      },
      fail(text) {
        const line = current || el('p', 'trylog__line', '');
        if (!current) node.appendChild(line);
        line.textContent = text;
        line.classList.add('is-error');
        current = null;
      },
      link(href, text) {
        const line = el('p', 'trylog__line');
        const a = el('a', null, text);
        a.href = href;
        a.target = '_blank';
        a.rel = 'noopener';
        line.appendChild(a);
        node.appendChild(line);
      },
      result(text) {
        const line = el('p', 'trylog__result', text);
        node.appendChild(line);
        return line;
      },
      button(text, onClick) {
        const btn = el('button', 'trybtn trybtn--settle', text);
        btn.type = 'button';
        btn.addEventListener('click', () => onClick(btn));
        node.appendChild(btn);
        return btn;
      },
    };
  }

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  async function waitForReceipt(txHash, log, label) {
    const started = Date.now();
    for (;;) {
      const receipt = await rpc('eth_getTransactionReceipt', [txHash]);
      if (receipt) {
        if (BigInt(receipt.status) === 0n) {
          throw new Error(`${label} reverted on chain`);
        }
        return receipt;
      }
      log.update(`${label}, waiting for the transaction to be mined, ${Math.round((Date.now() - started) / 1000)}s`);
      await sleep(2000);
    }
  }

  // ------------------------------------------------------------------- evaluate

  async function runEvaluate(policy, card) {
    if (state.busy) return;
    state.busy = true;
    renderBusy(true);

    const log = logger(card);
    const payoutInput = card.querySelector('[data-role="payout"]');
    const payoutTo = (payoutInput.value || '').trim() || state.account;

    try {
      if (!/^0x[0-9a-fA-F]{40}$/.test(payoutTo)) {
        throw new Error(`"${payoutTo}" is not an address`);
      }

      log.step("Asking the FDC verifier to encode this policy's weather request");
      const abiEncodedRequest = await prepareRequest(policy.requestBody);
      log.done(`Request encoded and accepted by the verifier, ${(abiEncodedRequest.length - 2) / 2} bytes`);

      log.step('Reading the attestation fee from FdcHub');
      const fee = await requestFee(abiEncodedRequest);
      log.done(`Attestation fee is ${describeWei(fee)}, read from getRequestFee rather than assumed`);

      let proof = null;
      let votingRound = null;

      for (let attempt = 1; attempt <= PROOF_ATTEMPTS; attempt++) {
        log.step('Requesting the attestation, waiting for your wallet');
        const txHash = await walletRequest('eth_sendTransaction', [{
          from: state.account,
          to: CFG.fdcHub,
          data: ABI.encodeRequestAttestation(abiEncodedRequest),
          value: '0x' + fee.toString(16),
        }]);
        log.done('Attestation requested');
        log.link(`${CFG.explorerUrl}/tx/${txHash}`, `requestAttestation transaction ${txHash.slice(0, 12)}…`);

        log.step('Waiting for the transaction to be mined');
        const receipt = await waitForReceipt(txHash, log, 'requestAttestation');
        const block = await rpc('eth_getBlockByNumber', [receipt.blockNumber, false]);
        votingRound = await votingRoundOf(block.timestamp);
        log.done(`Request landed in voting round ${votingRound}`);

        log.step(`Waiting for Flare data providers to finalize round ${votingRound}`);
        proof = await waitForProof(votingRound, abiEncodedRequest, log);
        if (proof) break;

        if (attempt >= PROOF_ATTEMPTS) {
          throw new Error(
            `no proof after ${PROOF_ATTEMPTS} rounds. The rounds finalize either way, so this means the data providers did not attest the request, usually because the weather source was slow or rate limiting.`);
        }
        log.fail(`Round ${votingRound} finalized without attesting the request. Requesting again in a fresh round, attempt ${attempt + 1} of ${PROOF_ATTEMPTS}.`);
        // Deliberately not done: reaching for a proof from an earlier round that
        // already exists. That would hollow out the contract's anti replay check
        // to make a demo look smoother.
      }

      log.step('Handing the proof to InstructionSender.evaluate');
      const evaluateData = ABI.encodeEvaluate(policy.policyId, payoutTo, proof.proof, proof.responseHex);

      const simulated = await simulate(
        state.account, CFG.instructionSender, evaluateData, INSTRUCTION_FEE_WEI);
      if (simulated) {
        throw new Error(explainRevert(simulated, 'evaluate would revert:'));
      }

      const evalTx = await walletRequest('eth_sendTransaction', [{
        from: state.account,
        to: CFG.instructionSender,
        data: evaluateData,
        value: '0x' + INSTRUCTION_FEE_WEI.toString(16),
      }]);
      log.done('Evaluation sent to the enclave');
      log.link(`${CFG.explorerUrl}/tx/${evalTx}`, `evaluate transaction ${evalTx.slice(0, 12)}…`);

      log.step('Waiting for the evaluate transaction');
      const evalReceipt = await waitForReceipt(evalTx, log, 'evaluate');

      // PolicyEvaluationRequested(policyId indexed, instructionId indexed, ...)
      const TOPIC_EVAL = '0xe7266f99d9906f08ba1fb54d643413569df632277cfbd3f244f1c5c0265a96d6';
      const evalLog = (evalReceipt.logs || []).find((l) => l.topics[0] === TOPIC_EVAL);
      if (!evalLog) throw new Error('the evaluate transaction carried no PolicyEvaluationRequested event');
      const instructionId = evalLog.topics[2];
      const rainfall = ABI.uintAt(evalLog.data, 3);
      log.done(`Attested rainfall ${(Number(rainfall) / 10).toFixed(1)} mm forwarded to the enclave, instruction ${instructionId.slice(0, 12)}…`);

      log.step('Waiting for the enclave to score it and sign the result');
      const decision = await waitForActionResult(instructionId, log);
      state.decisions.set(policy.policyId, { instructionId, decision });

      // data is abi.encode(policyId, amount, payoutTo).
      const amount = ABI.uintAt(decision.result.data, 1);
      const recipient = '0x' + ABI.wordAt(decision.result.data, 2).slice(24);

      if (amount > 0n) {
        log.result(`Decision: pay ${formatUnits(amount, 6)} FTestXRP to ${recipient}. Signed by the enclave.`);
      } else {
        log.result('Decision: nothing owed. The model was evaluated and did not trigger, which closes the policy without touching the pool. This is a valid outcome, not a failure.');
      }

      log.button('settle this decision', (btn) => {
        btn.disabled = true;
        runSettle(policy, card, log, instructionId, decision, btn);
      });
    } catch (err) {
      log.fail(explainRevert(err, 'Stopped:'));
    } finally {
      state.busy = false;
      renderBusy(false);
    }
  }

  async function waitForProof(votingRound, abiEncodedRequest, log) {
    const started = Date.now();
    for (;;) {
      const proof = await fetchProof(votingRound, abiEncodedRequest);
      if (proof) {
        log.done(`Round ${votingRound} finalized, proof retrieved with ${proof.proof.length} Merkle nodes`);
        return proof;
      }
      if (Date.now() - started > PROOF_TIMEOUT_MS) return null;
      const elapsed = Math.round((Date.now() - started) / 1000);
      log.update(`Waiting for Flare data providers to finalize round ${votingRound}, ${elapsed}s elapsed. Flare quotes 90 to 180 seconds.`);
      await sleep(POLL_INTERVAL_MS);
    }
  }

  // The signed result lives off chain, behind the extension proxy, reached
  // through the read-only bridge in scripts/result-bridge.sh. The proxy sets no
  // CORS header of its own, so without the bridge this step is the one thing on
  // the page a browser cannot do.
  async function waitForActionResult(instructionId, log) {
    const started = Date.now();
    for (;;) {
      let res;
      try {
        res = await fetch(`${CFG.resultUrl}/action/result/${instructionId}`, { cache: 'no-store' });
      } catch (err) {
        throw new Error(
          `the signed result is not reachable at ${CFG.resultUrl}. Start the read-only bridge with ./scripts/result-bridge.sh start and press settle again. The evaluation itself already succeeded on chain.`);
      }
      if (res.ok) {
        const body = await res.json();
        if (body && body.result && body.signature) return body;
      }
      if (Date.now() - started > RESULT_TIMEOUT_MS) {
        throw new Error(
          `the enclave published no signed result within ${RESULT_TIMEOUT_MS / 1000}s. If the stack has more than one registered TEE machine, the instruction may have gone to a paused one.`);
      }
      log.update(`Waiting for the enclave to sign the decision, ${Math.round((Date.now() - started) / 1000)}s elapsed`);
      await sleep(RESULT_POLL_MS);
    }
  }

  // --------------------------------------------------------------------- settle

  async function runSettle(policy, card, log, instructionId, decision, btn) {
    try {
      log.step('Carrying the signed decision to PolicySettlement.settle');
      const data = ABI.encodeSettle(
        instructionId,
        decision.result.status,
        decision.result.submissionTag,
        decision.result.data,
        decision.signature,
      );

      const simulated = await simulate(state.account, CFG.policySettlement, data);
      if (simulated) {
        throw new Error(explainRevert(simulated, 'settle would revert:'));
      }

      const txHash = await walletRequest('eth_sendTransaction', [{
        from: state.account,
        to: CFG.policySettlement,
        data,
      }]);
      log.done('Settlement sent');
      log.link(`${CFG.explorerUrl}/tx/${txHash}`, `settle transaction ${txHash.slice(0, 12)}…`);

      log.step('Waiting for the settlement transaction');
      await waitForReceipt(txHash, log, 'settle');

      const amount = ABI.uintAt(decision.result.data, 1);
      const recipient = '0x' + ABI.wordAt(decision.result.data, 2).slice(24);

      if (amount > 0n) {
        const poolWord = await ethCall(await payoutExecutor(), '0x74375359'); // availableLiquidity()
        log.done(`Settled. ${formatUnits(amount, 6)} FTestXRP paid to ${recipient}. The pool now holds ${formatUnits(BigInt(poolWord), 6)} FTestXRP.`);
      } else {
        log.done('Settled with nothing owed. The policy is closed and the pool is untouched.');
      }

      // The dashboard above reads the same chain, so the settlement shows up
      // there on its next refresh without this code touching it.
      await loadPolicies();
    } catch (err) {
      log.fail(explainRevert(err, 'Settlement stopped:'));
      btn.disabled = false;
    }
  }

  let executorCache = null;
  async function payoutExecutor() {
    if (!executorCache) {
      const word = await ethCall(CFG.policySettlement, '0x00761612'); // payoutExecutor()
      executorCache = '0x' + word.slice(26);
    }
    return executorCache;
  }

  function renderBusy(busy) {
    for (const btn of document.querySelectorAll('.trybtn')) {
      if (!btn.classList.contains('trybtn--settle')) btn.disabled = busy || !state.account || !onRightChain();
    }
  }

  // ----------------------------------------------------------------- lifecycle

  function start() {
    if (!CFG || !ABI) return;

    $('wallet-connect').addEventListener('click', connect);
    $('wallet-switch').addEventListener('click', () => {
      switchChain().catch((err) => setWalletNote(explainRevert(err, 'Could not switch chain.'), true));
    });
    $('wallet-faucet').href = CFG.faucetUrl;

    const p = provider();
    if (p && p.on) {
      p.on('accountsChanged', (accounts) => {
        state.account = accounts && accounts[0] ? accounts[0] : null;
        refreshWallet();
      });
      p.on('chainChanged', (chainId) => {
        state.chainId = chainId;
        refreshWallet();
      });
    }
    if (!p) {
      setWalletNote('No browser wallet detected. The dashboard above still works, it needs no wallet.');
      $('wallet-connect').disabled = true;
    }

    // An already authorised wallet reconnects without a prompt.
    if (p) {
      walletRequest('eth_accounts', [])
        .then(async (accounts) => {
          if (accounts && accounts[0]) {
            state.account = accounts[0];
            state.chainId = await walletRequest('eth_chainId', []);
            await refreshWallet();
          }
        })
        .catch(() => { /* leave it disconnected */ });
    }

    loadPolicies();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
