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
window.AEGIS_CONFIG = {
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
};
