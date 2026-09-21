#!/usr/bin/env node
/**
 * Gateway entry point.
 *
 *   PINATA_JWT=… OREOCHAIN_API_KEYS=… node server/index.mjs
 *
 * See server/README.md for configuration and deployment notes.
 */

import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { assertSafeConfig, loadConfig } from "./config.mjs";
import { createBackend } from "./storage.mjs";
import { createHandler } from "./gateway.mjs";
import { createAnchorConfirmer } from "./confirm.mjs";
import { createChainReader } from "./chain.mjs";
import { createLogger } from "./log.mjs";
import { createProofService, readSigningKey } from "./proofs.mjs";
import { createManifestVerifier } from "./verify.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Beside the proof store unless told otherwise. An in-memory store means an
 * in-memory keyring: receipts that do not survive a restart need no history
 * of keys to verify them with.
 */
function keyringPathFor(config) {
  if (config.keyringPath) return config.keyringPath;
  return config.dbPath === ":memory:" ? ":memory:" : `${config.dbPath}.keys.json`;
}

async function main() {
  // Before the config is read there is no configured level, so start at the
  // default; a configuration error still has to be reportable.
  let log = createLogger();

  let config;
  try {
    config = assertSafeConfig(loadConfig(process.env), { warn: (m, f) => log.warn(m, f) });
  } catch (error) {
    log.error("configuration error", { message: error.message });
    process.exit(1);
  }

  log = createLogger({ level: config.logLevel });

  const backend = createBackend(config);

  const signingKey = readSigningKey();

  /*
   * A receipt is a promise in writing, and an ephemeral key is a promise the
   * service stops honouring at its next restart: every receipt already issued
   * then fails to verify, with the same answer a forgery would get, and the
   * holder cannot tell which. Fine while developing, never in a deployment,
   * so it has to be asked for rather than fallen into.
   */
  if (!signingKey.privateJwk && !config.allowEphemeralReceiptKey) {
    log.error(
      "OREOCHAIN_RECEIPT_KEY is not set. Receipts would be signed with a throwaway key, and " +
        "every restart would invalidate every receipt already issued. Generate one with " +
        "`node scripts/generate-receipt-key.mjs`, or set OREOCHAIN_EPHEMERAL_RECEIPT_KEY=true " +
        "if this is a development instance."
    );
    process.exit(1);
  }
  const verifier = config.verifyManifests ? createManifestVerifier({ backend }) : null;
  if (!verifier) {
    log.warn(
      "OREOCHAIN_VERIFY_MANIFESTS is false: receipts are signed without checking the document " +
        "against its manifest, so a receipt asserts only what the client claimed. Each receipt " +
        'records this as "verified": false.'
    );
  }

  let proofs;
  try {
    proofs = await createProofService({
      ...signingKey,
      dbPath: config.dbPath,
      keyringPath: keyringPathFor(config),
      verifier,
    });
  } catch (error) {
    /*
     * Most likely a second instance pointed at one proof store. That is a
     * configuration mistake with no safe degraded mode — starting anyway would
     * interleave appends and leave anchored documents unprovable — so it is a
     * refusal to start with the reason on one line, not a warning.
     */
    log.error("cannot open the proof store", {
      dbPath: config.dbPath,
      message: error.message,
      holder: error.holder,
    });
    process.exit(1);
  }
  /*
   * Confirm the store still holds what was anchored, before anything is served
   * from it.
   *
   * A restore is the case this exists for. The log is append-only JSON lines,
   * so a copy taken mid-append, or one truncated in transit, reads back
   * without a parse error and simply has fewer records in it — a batch then
   * names documents that are gone, and the proof nobody can build is
   * discovered by the user who needed it. Rebuilding each batch root here
   * turns that into a refusal to start, which is the one moment an operator is
   * still looking.
   */
  if (config.storeCheck !== "off") {
    /*
     * Released before exiting, because this is the first thing in this file
     * that gives up while already holding the store's lock.
     *
     * The lock file left behind names the exiting process's host and pid and
     * carries a heartbeat from a second ago. On a host the next start has a
     * different pid and takes over, so nothing shows. In a container the
     * restarted gateway is pid 1 again, identical to the holder, and the lock
     * refuses — correctly, since a live neighbour sharing a hostname and pid
     * is indistinguishable from a dead predecessor. The operator restoring a
     * backup is then told a second gateway is running, which is false and
     * points at the wrong problem, at the one moment they are reading the
     * logs.
     */
    const refuse = () => {
      proofs.close();
      process.exit(1);
    };

    let report;
    try {
      report = await proofs.checkIntegrity({ depth: config.storeCheck });
    } catch (error) {
      log.error("proof store integrity check failed to run", { message: error.message });
      refuse();
    }

    if (report.ok) {
      log.info("proof store checked", {
        depth: report.depth,
        documents: report.checked.documents,
        batches: report.checked.batches,
        anchored: report.checked.anchoredBatches,
        durationMs: report.durationMs,
      });
    } else {
      for (const problem of report.problems) {
        log.error("proof store problem", problem);
      }
      if (!config.allowDamagedStore) {
        log.error(
          "the proof store does not agree with itself: restore it from a backup rather than " +
            "serving proofs that may be wrong. Set OREOCHAIN_ALLOW_DAMAGED_STORE=true to start " +
            "anyway and serve the intact batches; the damaged ones refuse either way.",
          { problems: report.problems.length, damagedBatches: report.damagedRoots.length }
        );
        refuse();
      }
      log.warn("starting with a damaged proof store", {
        problems: report.problems.length,
        damagedBatches: report.damagedRoots.length,
      });
    }
  }

  if (proofs.ephemeral) {
    log.warn(
      "receipts are signed with a throwaway key, as OREOCHAIN_EPHEMERAL_RECEIPT_KEY allows: " +
        "every restart invalidates every receipt issued before it"
    );
  }

  /*
   * Read-only chain access, so the public verification endpoint can confirm
   * an anchor rather than telling a verifier to go and read a blockchain.
   * Optional: without it the endpoint says it cannot check, which is the one
   * answer that is never wrong.
   */
  let confirmer = null;
  if (config.chainRpc) {
    const reader = await createChainReader({
      rpcUrl: config.chainRpc,
      contractAddress: config.contractAddress,
      log,
    });
    confirmer = createAnchorConfirmer({ reader, log, ttlMs: config.chainCacheMs });
    log.info("chain verification enabled", {
      contract: config.contractAddress,
      cacheMs: config.chainCacheMs,
    });
  }

  /*
   * Flipped on SIGTERM so /ready starts answering 503 while in-flight requests
   * finish. An orchestrator stops routing to this instance before the drain,
   * rather than sending it requests it is about to stop answering.
   */
  const readiness = { draining: false };

  const handler = createHandler(config, backend, {
    staticRoot: REPO_ROOT,
    proofs,
    logger: log,
    readiness,
    confirmer,
  });

  const server = http.createServer((req, res) => {
    handler(req, res).catch((error) => {
      log.error("unhandled request error", { message: error.message, stack: error.stack });
      if (!res.headersSent) res.writeHead(500).end();
    });
  });

  server.headersTimeout = config.readTimeoutMs + 5000;
  server.requestTimeout = config.readTimeoutMs + 10000;

  server.listen(config.port, config.host, () => {
    log.info("gateway listening", {
      url: `http://${config.host}:${config.port}`,
      storage: backend.name,
      auth: config.allowAnonymous ? "anonymous" : `${config.apiKeys.length} key(s)`,
      receiptKid: proofs.kid,
      proofStore: config.dbPath,
      node: process.version,
    });
  });

  // Finish in-flight requests before exiting, so a deploy does not drop an
  // upload mid-chunk.
  let closing = false;
  let closed = false;
  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => {
      if (closing) process.exit(1);
      closing = true;
      // Fail readiness first, so traffic stops arriving while the drain runs.
      readiness.draining = true;
      log.info("shutting down", { signal, delayMs: config.shutdownDelayMs });

      /*
       * Keep serving for a moment before closing the listener. /ready is
       * already answering 503, and this is the window in which the thing
       * routing traffic here gets to notice. Closing immediately would make
       * readiness decorative: requests already on their way would arrive at a
       * closed socket.
       */
      setTimeout(beginClose, config.shutdownDelayMs).unref();

      function beginClose() {
        if (closed) return;
        closed = true;
        server.close(() => {
          proofs.close();
          process.exit(0);
        });

        if (typeof server.closeIdleConnections === "function") {
          server.closeIdleConnections();
        }
      }

      /*
       * On Node 19+ close() closes idle keep-alive sockets itself; on Node 18,
       * which package.json still supports and CI still tests, it waits for
       * them and the timeout below is what ends the process — hard-exiting and
       * killing the uploads the drain was meant to protect. beginClose()
       * calls it, so shutdown behaves the same across the whole supported
       * range.
       */

      setTimeout(() => {
        log.error("drain timed out, exiting anyway");
        process.exit(1);
      }, config.shutdownDelayMs + 10000).unref();
    });
  }

  /*
   * A process that dies without saying why is the worst kind of outage. Node
   * terminates on an unhandled rejection by default, silently, and there was
   * nothing here to log it.
   */
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
  createLogger().error("failed to start", { message: error.message, stack: error.stack });
  process.exit(1);
});
