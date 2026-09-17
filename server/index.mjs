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

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function main() {
  let config;
  try {
    config = assertSafeConfig(loadConfig());
  } catch (error) {
    console.error(`[oreochain] configuration error: ${error.message}`);
    process.exit(1);
  }

  const backend = createBackend(config);
  const handler = createHandler(config, backend, { staticRoot: REPO_ROOT });

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
        `(storage: ${backend.name}, auth: ${config.allowAnonymous ? "anonymous" : `${config.apiKeys.length} key(s)`})`
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

main();
