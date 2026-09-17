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
import { createProofService, readSigningKey } from "./proofs.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

async function main() {
  let config;
  try {
    config = assertSafeConfig(loadConfig());
  } catch (error) {
    console.error(`[oreochain] configuration error: ${error.message}`);
    process.exit(1);
  }

  const backend = createBackend(config);

  const signingKey = readSigningKey();
  const proofs = await createProofService({ ...signingKey });
  if (proofs.ephemeral) {
    console.warn(
      "[oreochain] WARNING: no OREOCHAIN_RECEIPT_KEY set, so receipts are signed with a " +
        "throwaway key. Every restart invalidates previously issued receipts. " +
        "Generate one with: node scripts/generate-receipt-key.mjs"
    );
  }

  const handler = createHandler(config, backend, { staticRoot: REPO_ROOT, proofs });

  const server = http.createServer((req, res) => {
    handler(req, res).catch((error) => {
      console.error("[oreochain] unhandled request error:", error.message);
      if (!res.headersSent) res.writeHead(500).end();
    });
  });

  server.headersTimeout = config.readTimeoutMs + 5000;
  server.requestTimeout = config.readTimeoutMs + 10000;

  server.listen(config.port, config.host, () => {
    console.log(
      `[oreochain] gateway listening on http://${config.host}:${config.port} ` +
        `(storage: ${backend.name}, auth: ${config.allowAnonymous ? "anonymous" : `${config.apiKeys.length} key(s)`}, receipts: ${proofs.kid})`
    );
  });

  // Finish in-flight requests before exiting, so a deploy does not drop an
  // upload mid-chunk.
  let closing = false;
  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => {
      if (closing) process.exit(1);
      closing = true;
      console.log(`[oreochain] ${signal} received, draining…`);
      server.close(() => process.exit(0));
      setTimeout(() => process.exit(1), 10000).unref();
    });
  }
}

main().catch((error) => {
  console.error(`[oreochain] failed to start: ${error.message}`);
  process.exit(1);
});
