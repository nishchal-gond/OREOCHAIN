/**
 * Logging, metrics, and the configuration hygiene they depend on.
 *
 * What is worth testing here is not that a line comes out — it is the things
 * that only fail in production and are miserable to diagnose there: a
 * credential in a log line, a metric label that multiplies into one series per
 * document, a readiness probe that says "ready" while the process is shutting
 * down, and a config loader that leaves the environment altered behind it.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { createLogger, LEVELS, _internals as logInternals } from "../server/log.mjs";
import { createMetrics } from "../server/metrics.mjs";
import { loadConfig, assertSafeConfig } from "../server/config.mjs";
import { readSigningKey } from "../server/proofs.mjs";
import { _internals as gatewayInternals } from "../server/gateway.mjs";

/** A logger that collects parsed entries instead of writing to stdout. */
function collecting(level = "debug") {
  const lines = [];
  const logger = createLogger({ level, write: (line) => lines.push(line), now: () => 1700000000000 });
  return { logger, lines, entries: () => lines.map((line) => JSON.parse(line)) };
}

function tempDir() {
  const dir = mkdtempSync(path.join(tmpdir(), "oreochain-obs-"));
  test.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

// ------------------------------------------------------------------- logging

test("every line is JSON with a time and a level", () => {
  const { logger, entries } = collecting();
  logger.info("pinned", { bytes: 42 });

  const [entry] = entries();
  assert.equal(entry.level, "info");
  assert.equal(entry.msg, "pinned");
  assert.equal(entry.bytes, 42);
  assert.equal(entry.time, "2023-11-14T22:13:20.000Z");
});

test("a line is one line, so a multi-line value cannot forge a second entry", () => {
  const { logger, lines } = collecting();
  logger.warn("authentication failed", { reason: 'x"}\n{"level":"info","msg":"all fine' });

  assert.equal(lines.length, 1);
  assert.equal(lines[0].includes("\n"), false);
});

test("levels below the threshold cost nothing", () => {
  const { logger, lines } = collecting("warn");
  logger.debug("noisy");
  logger.info("routine");
  logger.warn("interesting");

  assert.equal(lines.length, 1);
});

test("an unknown level fails at construction, not at the first line", () => {
  // Accepting it would mean discovering in production that nothing is logged.
  assert.throws(() => createLogger({ level: "verbose" }), /unknown log level/);
});

test("a child logger carries its fields onto every line", () => {
  const { logger, entries } = collecting();
  const request = logger.child({ reqId: "abc-123" });
  request.info("pinned");
  request.error("request failed", { status: 500 });

  assert.deepEqual(
    entries().map((entry) => entry.reqId),
    ["abc-123", "abc-123"]
  );
});

test("a field named after a secret is never printed", () => {
  const { logger, lines } = collecting();
  logger.info("configured", {
    pinataJwt: "eyJhbGciOi.reallysecret",
    apiKey: "0123456789abcdef0123456789abcdef",
    nested: { authorization: "Bearer hunter2" },
  });

  assert.equal(lines[0].includes("reallysecret"), false);
  assert.equal(lines[0].includes("hunter2"), false);
  assert.equal(lines[0].includes("0123456789abcdef"), false);
});

test("a token-shaped value is truncated even under an innocent key", () => {
  // The backstop that matters: the next person to add a log line will not
  // check this list first.
  const { logger, entries } = collecting();
  logger.info("upstream", { detail: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefgh" });

  assert.equal(entries()[0].detail.includes("eyJzdWIiOiIxIn0"), false);
  assert.match(entries()[0].detail, /chars\]$/);
});

test("the identifiers you debug with survive redaction", () => {
  // Redaction that eats file hashes and cids is its own outage: those are
  // what an operator follows a document through the log by. "Any long opaque
  // string" is too blunt a rule for a system whose vocabulary is long opaque
  // strings.
  const fileHash = "0x" + "ab".repeat(32);
  const cid = "bafybeigdyrztktx5j7v4xh3rlv6hmzrjpcvyk4v3m4a2fphzqxnvfjv2ii";

  assert.equal(logInternals.redactValue("fileHash", fileHash), fileHash);
  assert.equal(logInternals.redactValue("cid", cid), cid);
  assert.equal(logInternals.redactValue("root", "0x" + "cd".repeat(32)), "0x" + "cd".repeat(32));
});

test("an Authorization value under an unlisted key is still caught", () => {
  assert.match(logInternals.redactValue("detail", "Bearer hunter2hunter2"), /chars\]$/);
});

test("an Error logs its message and stack, not an empty object", () => {
  const { logger, entries } = collecting();
  logger.error("request failed", { cause: new Error("upstream refused") });

  assert.equal(entries()[0].cause.message, "upstream refused");
  assert.match(entries()[0].cause.stack, /upstream refused/);
});

test("a cyclic field does not take the request down with it", () => {
  const { logger, entries } = collecting();
  const cycle = { name: "loop" };
  cycle.self = cycle;

  assert.doesNotThrow(() => logger.info("odd", { cycle }));
  assert.equal(entries().length, 1);
});

test("silent means silent, for a test or a benchmark", () => {
  const { logger, lines } = collecting("silent");
  logger.error("even this");
  assert.equal(lines.length, 0);
  assert.equal(LEVELS.silent > LEVELS.error, true);
});

// ------------------------------------------------------------------- metrics

test("counters accumulate per label set", () => {
  const metrics = createMetrics({ now: () => 0 });
  metrics.increment("oreochain_requests_total", { route: "pin", status: "2xx" });
  metrics.increment("oreochain_requests_total", { route: "pin", status: "2xx" });
  metrics.increment("oreochain_requests_total", { route: "pin", status: "5xx" });

  const rendered = metrics.render();
  assert.match(rendered, /oreochain_requests_total\{route="pin",status="2xx"\} 2/);
  assert.match(rendered, /oreochain_requests_total\{route="pin",status="5xx"\} 1/);
});

test("a counter is typed, so rate() over it means what it looks like", () => {
  const metrics = createMetrics({ now: () => 0 });
  metrics.increment("oreochain_uploads_shed_total", {});
  assert.match(metrics.render(), /# TYPE oreochain_uploads_shed_total counter/);
});

test("a gauge is read at scrape time rather than remembered", () => {
  let inFlight = 0;
  const metrics = createMetrics({ now: () => 0 });
  metrics.gauge("oreochain_uploads_in_flight", () => inFlight);

  inFlight = 7;
  assert.match(metrics.render(), /oreochain_uploads_in_flight 7/);
});

test("a gauge that throws loses itself, not the whole scrape", () => {
  const metrics = createMetrics({ now: () => 0 });
  metrics.gauge("broken", () => {
    throw new Error("store is closed");
  });
  metrics.gauge("fine", () => 1);

  const rendered = metrics.render();
  assert.equal(rendered.includes("broken"), false);
  assert.match(rendered, /fine 1/);
});

test("a label value cannot break out of the exposition format", () => {
  const metrics = createMetrics({ now: () => 0 });
  metrics.increment("oreochain_auth_failures_total", { reason: 'bad "key"\nfake_metric 99' });

  const lines = metrics.render().trim().split("\n");
  assert.equal(
    lines.some((line) => line.startsWith("fake_metric")),
    false
  );
});

test("routes are labelled by shape, never by identifier", () => {
  // One series per cid would be unbounded cardinality: the standard way to
  // destroy a metrics backend, and irreversible once scraped.
  const cid = "bafybeigdyrztktx5j7v4xh3rlv6hmzrjpcvyk4v3m4a2fphzqxnvfjv2ii";
  assert.equal(gatewayInternals.routeLabel(`/api/storage/${cid}`, "GET"), "fetch");
  assert.equal(
    gatewayInternals.routeLabel("/api/proofs/inclusion/0x" + "ab".repeat(32), "GET"),
    "inclusion"
  );
  assert.equal(gatewayInternals.routeLabel("/api/storage/pin", "POST"), "pin");
  assert.equal(gatewayInternals.routeLabel("/index.html", "GET"), "static");
});

// ---------------------------------------------------------------- request ids

test("a client-supplied request id is used, so a trace crosses the proxy", () => {
  assert.equal(
    gatewayInternals.requestId({ headers: { "x-request-id": "edge-7f3a" } }),
    "edge-7f3a"
  );
});

test("a request id that could break a header or a log line is replaced", () => {
  for (const hostile of ["a\nb", "x".repeat(65), 'q"}{', "a b"]) {
    const id = gatewayInternals.requestId({ headers: { "x-request-id": hostile } });
    assert.notEqual(id, hostile);
    assert.match(id, /^[0-9a-f-]{36}$/);
  }
});

test("no header means a generated id, never an empty one", () => {
  assert.match(gatewayInternals.requestId({ headers: {} }), /^[0-9a-f-]{36}$/);
});

// ------------------------------------------------------------------ config

test("loadConfig leaves the process environment exactly as it found it", () => {
  // It used to swap process.env out and back. Anything reading the
  // environment concurrently — a library, a worker, an async callback — saw
  // the wrong one, and a throw mid-swap left it wrong permanently.
  const before = { ...process.env };
  loadConfig({ OREOCHAIN_STORAGE: "memory", OREOCHAIN_ALLOW_ANONYMOUS: "true", PORT: "9999" });

  assert.deepEqual({ ...process.env }, before);
  assert.equal(process.env.PORT, before.PORT);
});

test("a setting in the passed environment is read from it, not from the process", () => {
  const config = loadConfig({
    OREOCHAIN_STORAGE: "memory",
    OREOCHAIN_ALLOW_ANONYMOUS: "true",
    PORT: "9191",
  });
  assert.equal(config.port, 9191);
});

test("a secret can come from a file, as an orchestrator supplies it", () => {
  const file = path.join(tempDir(), "pinata.jwt");
  writeFileSync(file, "eyJhbGciOiJIUzI1NiJ9.token-from-a-mounted-secret\n");

  const config = loadConfig({
    OREOCHAIN_ALLOW_ANONYMOUS: "true",
    PINATA_JWT_FILE: file,
  });
  // The trailing newline `echo` leaves behind is stripped: with it, the
  // credential fails upstream for no visible reason.
  assert.equal(config.pinataJwt, "eyJhbGciOiJIUzI1NiJ9.token-from-a-mounted-secret");
});

test("API keys can come from a file too", () => {
  const file = path.join(tempDir(), "keys");
  const key = "k".repeat(32);
  writeFileSync(file, `${key},${"j".repeat(40)}\n`);

  const config = loadConfig({ OREOCHAIN_STORAGE: "memory", OREOCHAIN_API_KEYS_FILE: file });
  assert.deepEqual(config.apiKeys, [key, "j".repeat(40)]);
});

test("an unreadable secret file stops startup instead of starting unauthenticated", () => {
  assert.throws(
    () =>
      loadConfig({
        OREOCHAIN_STORAGE: "memory",
        OREOCHAIN_API_KEYS_FILE: "/nonexistent/keys",
      }),
    /could not be read/
  );
});

test("an empty secret file is an error, not an empty credential", () => {
  const file = path.join(tempDir(), "empty");
  writeFileSync(file, "\n");
  assert.throws(() => loadConfig({ OREOCHAIN_ALLOW_ANONYMOUS: "true", PINATA_JWT_FILE: file }), /empty/);
});

test("setting both the value and its file is refused rather than guessed", () => {
  const file = path.join(tempDir(), "both");
  writeFileSync(file, "from-the-file");

  assert.throws(
    () =>
      loadConfig({
        OREOCHAIN_ALLOW_ANONYMOUS: "true",
        PINATA_JWT: "from-the-environment",
        PINATA_JWT_FILE: file,
      }),
    /remove one/
  );
});

test("a mistyped log level fails at startup rather than silencing the service", () => {
  assert.throws(
    () =>
      loadConfig({
        OREOCHAIN_STORAGE: "memory",
        OREOCHAIN_ALLOW_ANONYMOUS: "true",
        OREOCHAIN_LOG_LEVEL: "verbose",
      }),
    /OREOCHAIN_LOG_LEVEL must be one of/
  );
});

test("warnings go to the supplied sink, so they are structured like everything else", () => {
  const { logger, entries } = collecting();
  assertSafeConfig(
    loadConfig({
      OREOCHAIN_STORAGE: "memory",
      OREOCHAIN_ALLOW_ANONYMOUS: "true",
      OREOCHAIN_DB_PATH: ":memory:",
    }),
    { warn: (message, fields) => logger.warn(message, fields) }
  );

  assert.equal(entries().length, 1);
  assert.match(entries()[0].msg, /:memory:/);
});

test("the pre-stop window is configurable and defaults to instant", () => {
  const base = { OREOCHAIN_STORAGE: "memory", OREOCHAIN_ALLOW_ANONYMOUS: "true" };

  // Zero by default: a local Ctrl-C should not hang for five seconds.
  assert.equal(loadConfig(base).shutdownDelayMs, 0);
  assert.equal(loadConfig({ ...base, OREOCHAIN_SHUTDOWN_DELAY_MS: "5000" }).shutdownDelayMs, 5000);
  assert.throws(
    () => loadConfig({ ...base, OREOCHAIN_SHUTDOWN_DELAY_MS: "-1" }),
    /must be an integer/
  );
});

test("the receipt signing key can come from a mounted file", async () => {
  // The one secret most worth keeping out of the environment: it signs every
  // receipt, so anyone who reads it can forge one.
  const { generateSigningKey } = await import("../js/core/receipt.js");
  const keys = await generateSigningKey();
  const file = path.join(tempDir(), "receipt-key.json");
  writeFileSync(file, JSON.stringify(keys.exported) + "\n");

  const read = readSigningKey({ OREOCHAIN_RECEIPT_KEY_FILE: file });
  assert.deepEqual(read.publicJwk, keys.exported.publicJwk);
  assert.ok(read.privateJwk);
});

test("no receipt key at all is still allowed, and still ephemeral", () => {
  assert.deepEqual(readSigningKey({}), { privateJwk: null, publicJwk: null });
});
