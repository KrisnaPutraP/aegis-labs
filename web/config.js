// Deployment constants for the read-only demo.
//
// Only two addresses are fixed here, both copied from the files the deploy
// tooling writes: config/extension.env (InstructionSender) and
// config/settlement.env (PolicySettlement). Everything else the page needs is
// resolved from those two at runtime, on-chain: the payout executor comes from
// PolicySettlement.payoutExecutor(), the payout asset from the executor itself,
// and the TEE machine registry from PolicySettlement.TEE_MACHINE_REGISTRY().
// That way an executor swap (the D4 seam) shows up on this page without anyone
// editing it.
// Which copy of the page this is, decided by where it is being served from.
//
// 'local' means it sits beside the running stack: the enclave answers its own
// state endpoint and the wallet actions can complete, because the signed
// decision they settle is reachable. 'hosted' means static hosting, where there
// is no route to the enclave and never will be, since the enclave runs on the
// operator's machine and is deliberately not published.
//
// It is decided here rather than configured because the same directory is
// deployed both ways, with no build step in between. A page served from a
// private address is still the operator's own machine, which is how the demo is
// recorded from a phone, so those count as local too.
function aegisProfile() {
  const host = location.hostname;
  if (location.protocol === 'file:' || host === '' || host === 'localhost') return 'local';
  if (host === '127.0.0.1' || host === '::1' || host === '[::1]') return 'local';
  if (/^10\./.test(host)) return 'local';
  if (/^192\.168\./.test(host)) return 'local';
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return 'local';
  return 'hosted';
}

window.AEGIS_CONFIG = {
  profile: aegisProfile(),

  // Read by the hosted profile only: what GET /state answered when
  // scripts/record-enclave-state.sh last ran, and the demo video, once there is
  // one. The local page calls the enclave live and ignores both.
  enclaveSnapshotUrl: 'enclave-snapshot.json',
  recordingUrl: 'https://youtu.be/hyK3Ldw0t-A',

  rpcUrl: 'https://coston2-api.flare.network/ext/C/rpc',
  explorerUrl: 'https://coston2-explorer.flare.network',

  instructionSender: '0xb810E9c321706F78FDFe12e7479E4D89022EDffd',
  policySettlement: '0xdFF93045C6dDFF132cc56EE7BAbD199CE72bF84B',

  // The enclave serves GET /state inside the stack's Docker network, where a
  // browser cannot reach it. scripts/state-bridge.sh publishes that one route
  // on loopback. If the bridge is not running the sealed model panel says so
  // rather than inventing a number.
  stateUrl: 'http://127.0.0.1:7703/state',

  // Contract state is cheap to poll. Event history is not, so it refreshes on a
  // slower beat.
  refreshMs: 5000,
  logsRefreshMs: 20000,

  // ---- interactive layer (interact.js) ----
  //
  // Everything below is used only by the "Try it yourself" section. The
  // read-only dashboard above does not touch any of it, so removing this block
  // disables the write path and leaves the rest of the page working.

  chainId: 114,
  chainIdHex: '0x72',
  faucetUrl: 'https://faucet.flare.network/coston2',

  // The FDC's off-chain half. Both are Flare's public testnet services, the same
  // defaults go/tools/pkg/fdc/web2json.go uses, and both were checked to allow
  // cross-origin calls from a browser.
  //
  // One difference from the Go client is deliberate and load bearing: requests to
  // the DA Layer must not carry X-API-KEY. Its CORS preflight allows content-type
  // but not x-api-key, so a browser sending the key is blocked before the request
  // leaves. The endpoint serves public testnet data without it. The verifier, by
  // contrast, allows the header and gets it.
  fdcVerifierUrl: 'https://fdc-verifiers-testnet.flare.network',
  fdcDaLayerUrl: 'https://ctn2-data-availability.flare.network',
  fdcApiKey: '00000000-0000-0000-0000-000000000000',

  // Copied from config/coston2/deployed-addresses.json, the same file the Go
  // tooling resolves these from.
  fdcHub: '0x48aC463d7975828989331F4De43341627b9c5f1D',
  flareSystemsManager: '0xA90Db6D10F856799b10ef2A77EBCbF460aC71e52',

  // The signed decision the settle call needs lives behind the extension proxy,
  // which sets no CORS header, so a browser cannot read it directly.
  // scripts/result-bridge.sh publishes that one route on loopback. Without the
  // bridge, evaluation still works and only the settle step reports it is
  // unreachable.
  resultUrl: 'http://127.0.0.1:7704',

  // Policies a visitor may try. Written by aegis register-model --web-config,
  // and every entry is verified against policyTriggerRequestHash on chain before
  // the page offers it.
  policiesUrl: 'policies.json',
};
