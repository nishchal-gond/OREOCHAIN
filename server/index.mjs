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
import { createLogger } from "./log.mjs";
import { createProofService, readSigningKey } from "./proofs.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

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
  const proofs = await createProofService({ ...signingKey, dbPath: config.dbPath });
  if (proofs.ephemeral) {
    log.warn(
      "no OREOCHAIN_RECEIPT_KEY set: receipts are signed with a throwaway key, so every " +
        "restart invalidates previously issued receipts. Generate one with " +
        "`node scripts/generate-receipt-key.mjs`"
    );
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
