#!/usr/bin/env node
/**
 * Anchoring worker entry point.
 *
 *   OREOCHAIN_CHAIN_RPC=… OREOCHAIN_CONTRACT_ADDRESS=… \
 *   OREOCHAIN_ANCHOR_KEY_FILE=… OREOCHAIN_ANCHOR_API_KEY_FILE=… \
 *   node server/anchor-worker.mjs
 *
 * See server/README.md for what an operator has to supply and why.
 */

import { loadAnchorConfig } from "./config.mjs";
import { createAnchorWorker, createGatewayClient } from "./anchor.mjs";
import { createChainClient } from "./chain.mjs";
import { createLogger } from "./log.mjs";

async function main() {
  let log = createLogger({ base: { component: "anchor-worker" } });

  let config;
  try {
    config = loadAnchorConfig(process.env);
  } catch (error) {
    log.error("configuration error", { message: error.message });
    process.exit(1);
  }

  log = createLogger({ level: config.logLevel, base: { component: "anchor-worker" } });

  const chain = await createChainClient({
    rpcUrl: config.rpcUrl,
    contractAddress: config.contractAddress,
    privateKey: config.privateKey,
    log,
  });

  /*
   * Every one of these is a state in which the worker would poll for ever and
   * anchor nothing, or burn gas on transactions that revert. Refusing to start
   * puts the reason in front of whoever deployed it, at the moment they are
   * looking.
   */
  let chainInfo;
  try {
    chainInfo = await chain.preflight();
  } catch (error) {
    log.error("cannot anchor against this chain", { message: error.message });
    process.exit(1);
  }

  const gateway = createGatewayClient({ url: config.gatewayUrl, apiKey: config.apiKey });

  if (!config.uriTemplate) {
    log.warn(
      "OREOCHAIN_ANCHOR_URI is not set, so anchors carry no pointer to where their " +
        "inclusion proofs are served. Set it to a public URL, optionally containing {root}."
    );
  }

  const worker = createAnchorWorker({
    gateway,
    chain,
    log,
    confirmations: config.confirmations,
    intervalMs: config.intervalMs,
    pendingTimeoutMs: config.pendingTimeoutMs,
    uriFor: (batch) => config.uriTemplate.replaceAll("{root}", batch.root),
  });

  log.info("anchor worker started", {
    gateway: config.gatewayUrl,
    contract: config.contractAddress,
    anchorAddress: chainInfo.address,
    chainId: chainInfo.chainId,
    intervalMs: config.intervalMs,
    confirmations: config.confirmations,
  });

  // Once immediately: a restart should pick up a batch left unanchored by the
  // previous process now, not one interval from now.
  await worker.tick().catch((error) => {
    log.error("first tick failed", { message: error.message });
  });
  worker.start();

  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => {
      log.info("shutting down", { signal, counts: worker.counts() });
      worker.stop();
      /*
       * Nothing to drain: a transaction already sent is the chain's business,
       * and the next process to start finds it by asking the contract.
       */
      process.exit(0);
    });
  }

  process.on("unhandledRejection", (reason) => {
    log.error("unhandled rejection", {
      message: reason instanceof Error ? reason.message : String(reason),
      stack: reason instanceof Error ? reason.stack : undefined,
    });
    process.exit(1);
  });
  process.on("uncaughtException", (error) => {
    log.error("uncaught exception", { message: error.message, stack: error.stack });
    process.exit(1);
  });
}

main().catch((error) => {
  createLogger({ base: { component: "anchor-worker" } }).error("failed to start", {
    message: error.message,
    stack: error.stack,
  });
  process.exit(1);
});
