/**
 * Gateway tests run against a real HTTP server on an ephemeral port, because
 * the things worth checking here — body caps, timing-safe auth, traversal
 * defences — are properties of actual socket handling, not of a mocked object.
 */

import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { loadConfig, assertSafeConfig } from "../server/config.mjs";
import { createHandler, _internals as gatewayInternals } from "../server/gateway.mjs";
import { createMemoryBackend } from "../server/storage.mjs";
import { authenticate, extractToken } from "../server/auth.mjs";
import { createRateLimiter } from "../server/ratelimit.mjs";
import { createLogger } from "../server/log.mjs";

import { equalBytes, fromUtf8, randomBytes, utf8 } from "../js/core/bytes.js";
import { createPinataAdapter, putAll } from "../js/storage/ipfs.js";
import { createProofService, readSigningKey } from "../server/proofs.mjs";
import { createManifestVerifier } from "../server/verify.mjs";
import { generateSigningKey, importPublicKey, verifyReceipt } from "../js/core/receipt.js";
import { verifyInBatch } from "../js/core/anchor.js";
import { openManifest, packFile, restoreFile, sealManifest } from "../js/core/manifest.js";

// Argon2id at production settings costs seconds per derivation — see
// ARGON2ID_PROFILE in js/core/kdf.js for the figure, which is not repeated here
// — and that would make this suite take minutes. Tests declare cheap parameters
// explicitly, and a matching floor, rather than silently inheriting defaults.
const TEST_KDF = { name: "argon2id", memoryKiB: 8, iterations: 1, parallelism: 1 };

const KEY = "k".repeat(48);
/**
 * A second key, the only one allowed to drive anchoring. Every anchoring test
 * below uses this and every other test uses KEY, so the separation is
 * exercised by the whole suite rather than asserted once.
 */
const ANCHOR_KEY = "a".repeat(48);
const TEST_LIMITS = { minArgon2MemoryKiB: 8 };

function baseEnv(overrides = {}) {
  return {
    OREOCHAIN_API_KEYS: `${KEY},${ANCHOR_KEY}`,
    OREOCHAIN_ANCHOR_API_KEYS: ANCHOR_KEY,
    OREOCHAIN_STORAGE: "memory",
    ...overrides,
  };
}

/** Start a gateway on an ephemeral port; returns its URL and a stop function. */
async function startGateway(envOverrides = {}, deps = {}) {
  const config = assertSafeConfig(loadConfig(baseEnv(envOverrides)));
  const backend = deps.backend || createMemoryBackend();
  const proofs = deps.proofs === false ? null : deps.proofs || (await createProofService());
  const handler = createHandler(config, backend, {
    logger: createLogger({ level: "silent" }),
    sweeper: false,
    ...deps,
    proofs,
  });

  const server = http.createServer((req, res) => {
    handler(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500).end();
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();

  return {
    url: `http://127.0.0.1:${port}`,
    backend,
    proofs,
    config,
    stop: () => new Promise((resolve) => server.close(resolve)),
  };
}

function authed(extra = {}) {
  return { Authorization: `Bearer ${KEY}`, ...extra };
}

/** The anchoring worker's credential, which an uploader's key is not. */
function anchorAuthed(extra = {}) {
  return { Authorization: `Bearer ${ANCHOR_KEY}`, ...extra };
}

// ------------------------------------------------------------ configuration

test("the gateway refuses to start with no API keys", () => {
  assert.throws(
    () => loadConfig({ OREOCHAIN_STORAGE: "memory" }),
    /No API keys configured/
  );
});

test("short API keys are rejected", () => {
  assert.throws(
    () => loadConfig({ OREOCHAIN_API_KEYS: "short", OREOCHAIN_STORAGE: "memory" }),
    /at least 32 characters/
  );
});

test("a missing pinning credential is caught at startup, not at first upload", () => {
  assert.throws(() => loadConfig({ OREOCHAIN_API_KEYS: KEY }), /PINATA_JWT is not set/);
});

test("a wildcard CORS origin is rejected on authenticated endpoints", () => {
  assert.throws(
    () => assertSafeConfig(loadConfig(baseEnv({ OREOCHAIN_ALLOWED_ORIGINS: "*" }))),
    /must not be "\*"/
  );
});

test("anonymous access must be opted into explicitly", () => {
  const config = loadConfig({ OREOCHAIN_ALLOW_ANONYMOUS: "true", OREOCHAIN_STORAGE: "memory" });
  assert.equal(config.allowAnonymous, true);
  assert.deepEqual(config.apiKeys, []);
});

test("malformed numeric settings are rejected rather than silently defaulted", () => {
  assert.throws(
    () => loadConfig(baseEnv({ OREOCHAIN_MAX_CHUNK_BYTES: "banana" })),
    /must be an integer/
  );
  assert.throws(() => loadConfig(baseEnv({ PORT: "99999" })), /must be an integer between/);
});

// --------------------------------------------------------------------- auth

test("bearer tokens are extracted case-insensitively and trimmed", () => {
  assert.equal(extractToken({ headers: { authorization: "Bearer abc" } }), "abc");
  assert.equal(extractToken({ headers: { authorization: "bearer  abc  " } }), "abc");
  assert.equal(extractToken({ headers: {} }), null);
  assert.equal(extractToken({ headers: { authorization: "Basic abc" } }), null);
});

test("authentication accepts the right key and rejects everything else", () => {
  const config = { apiKeys: [KEY], allowAnonymous: false };

  assert.equal(authenticate({ headers: { authorization: `Bearer ${KEY}` } }, config).ok, true);
  assert.equal(authenticate({ headers: { authorization: "Bearer wrong" } }, config).ok, false);
  assert.equal(authenticate({ headers: {} }, config).ok, false);
  // A near-miss must not be accepted.
  assert.equal(
    authenticate({ headers: { authorization: `Bearer ${KEY.slice(0, -1)}x` } }, config).ok,
    false
  );
});

test("the key id in logs is a digest, never the key itself", () => {
  const result = authenticate(
    { headers: { authorization: `Bearer ${KEY}` } },
    { apiKeys: [KEY], allowAnonymous: false }
  );
  assert.ok(result.ok);
  assert.ok(!result.keyId.includes(KEY));
  assert.match(result.keyId, /^[0-9a-f]{12}$/);
});

// -------------------------------------------------------------- rate limits

test("the token bucket allows a burst then throttles", () => {
  let now = 0;
  const limiter = createRateLimiter({ perMinute: 60, burst: 5, now: () => now });

  for (let i = 0; i < 5; i++) assert.equal(limiter.take("k").allowed, true, `burst ${i}`);
  assert.equal(limiter.take("k").allowed, false, "burst was not capped");

  now += 1000; // one token per second at 60/minute
  assert.equal(limiter.take("k").allowed, true, "bucket did not refill");
});

test("rate limits are per key, so one client cannot starve another", () => {
  let now = 0;
  const limiter = createRateLimiter({ perMinute: 60, burst: 2, now: () => now });

  limiter.take("a");
  limiter.take("a");
  assert.equal(limiter.take("a").allowed, false);
  assert.equal(limiter.take("b").allowed, true, "second key was affected by the first");
});

test("idle buckets are swept so memory stays bounded", () => {
  let now = 0;
  const limiter = createRateLimiter({ perMinute: 60, burst: 2, now: () => now });
  for (let i = 0; i < 100; i++) limiter.take(`key${i}`);
  assert.equal(limiter.size(), 100);

  now += 7200000;
  limiter.sweep(3600000);
  assert.equal(limiter.size(), 0);
});

// ------------------------------------------------------------------- routes

test("health is public and reports the backend", async () => {
  const gw = await startGateway();
  try {
    const response = await fetch(`${gw.url}/health`);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.status, "ok");
    assert.equal(body.storage, "memory");
  } finally {
    await gw.stop();
  }
});

test("API endpoints reject unauthenticated requests", async () => {
  const gw = await startGateway();
  try {
    for (const [path, init] of [
      ["/api/storage/pin", { method: "POST", body: "x" }],
      ["/api/storage/memory0000000000", {}],
    ]) {
      const response = await fetch(`${gw.url}${path}`, init);
      assert.equal(response.status, 401, `${path} was not protected`);
      assert.match(response.headers.get("www-authenticate") || "", /Bearer/);
      // The error must not hint at which part was wrong. The request id is
      // the only other field, and it identifies the request rather than
      // saying anything about the credential.
      const body = await response.json();
      assert.equal(body.error, "unauthorized");
      assert.deepEqual(Object.keys(body).sort(), ["error", "requestId"]);
    }
  } finally {
    await gw.stop();
  }
});

test("a chunk round-trips through the gateway", async () => {
  const gw = await startGateway();
  try {
    const payload = randomBytes(2048);

    const pinned = await fetch(`${gw.url}/api/storage/pin`, {
      method: "POST",
      headers: authed({ "Content-Type": "application/octet-stream", "X-Chunk-Name": "chunk-000001" }),
      body: payload,
    });
    assert.equal(pinned.status, 200);
    const { cid } = await pinned.json();
    assert.match(cid, /^memory\d{10}$/);

    const fetched = await fetch(`${gw.url}/api/storage/${cid}`, { headers: authed() });
    assert.equal(fetched.status, 200);
    assert.ok(equalBytes(new Uint8Array(await fetched.arrayBuffer()), payload));
  } finally {
    await gw.stop();
  }
});

test("an oversized body is refused rather than buffered", async () => {
  const gw = await startGateway({ OREOCHAIN_MAX_CHUNK_BYTES: "4096" });
  try {
    const response = await fetch(`${gw.url}/api/storage/pin`, {
      method: "POST",
      headers: authed({ "Content-Type": "application/octet-stream" }),
      body: randomBytes(8192),
    });
    assert.equal(response.status, 413);
  } finally {
    await gw.stop();
  }
});

test("a chunked upload with no Content-Length is still capped as bytes arrive", async () => {
  // The Content-Length short-circuit does not apply here, so this exercises the
  // limit that actually bounds memory: the one enforced per data event.
  const gw = await startGateway({ OREOCHAIN_MAX_CHUNK_BYTES: "4096" });
  try {
    const status = await new Promise((resolve, reject) => {
      const request = http.request(
        `${gw.url}/api/storage/pin`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${KEY}`,
            "Content-Type": "application/octet-stream",
            "Transfer-Encoding": "chunked",
          },
        },
        (response) => {
          response.resume();
          resolve(response.statusCode);
        }
      );
      request.on("error", reject);

      // Write well past the cap in small pieces.
      let written = 0;
      const pump = () => {
        while (written < 64 * 1024) {
          written += 1024;
          if (!request.write(Buffer.alloc(1024))) {
            request.once("drain", pump);
            return;
          }
        }
        request.end();
      };
      pump();
    });

    assert.equal(status, 413);
  } finally {
    await gw.stop();
  }
});

test("an empty body is rejected", async () => {
  const gw = await startGateway();
  try {
    const response = await fetch(`${gw.url}/api/storage/pin`, {
      method: "POST",
      headers: authed(),
      body: new Uint8Array(0),
    });
    assert.equal(response.status, 400);
  } finally {
    await gw.stop();
  }
});

test("traversal and injection in the CID route do not reach the backend", async () => {
  const gw = await startGateway();
  try {
    let reached = false;
    const original = gw.backend.get.bind(gw.backend);
    gw.backend.get = async (cid) => {
      reached = true;
      return original(cid);
    };

    for (const path of [
      "/api/storage/../../etc/passwd",
      "/api/storage/..%2f..%2fetc%2fpasswd",
      "/api/storage/abc/def",
      "/api/storage/",
    ]) {
      const response = await fetch(`${gw.url}${path}`, { headers: authed(), redirect: "manual" });
      assert.ok(response.status >= 400, `${path} returned ${response.status}`);
    }
    assert.equal(reached, false, "a hostile path reached the storage backend");
  } finally {
    await gw.stop();
  }
});

test("a missing cid returns 404, not a server error", async () => {
  const gw = await startGateway();
  try {
    const response = await fetch(`${gw.url}/api/storage/memory9999999999`, { headers: authed() });
    assert.equal(response.status, 404);
  } finally {
    await gw.stop();
  }
});

test("rate limiting kicks in and reports Retry-After", async () => {
  const gw = await startGateway({
    OREOCHAIN_RATE_LIMIT_PER_MINUTE: "60",
    OREOCHAIN_RATE_LIMIT_BURST: "3",
  });
  try {
    const statuses = [];
    for (let i = 0; i < 6; i++) {
      const response = await fetch(`${gw.url}/api/storage/pin`, {
        method: "POST",
        headers: authed(),
        body: randomBytes(64),
      });
      statuses.push(response.status);
      if (response.status === 429) {
        assert.ok(Number(response.headers.get("retry-after")) >= 1);
      }
    }
    assert.ok(statuses.includes(429), `never rate limited: ${statuses.join(",")}`);
    assert.equal(statuses[0], 200, "the first request should have succeeded");
  } finally {
    await gw.stop();
  }
});

test("security headers are always set", async () => {
  const gw = await startGateway();
  try {
    const response = await fetch(`${gw.url}/health`);
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    assert.equal(response.headers.get("x-frame-options"), "DENY");
    assert.match(response.headers.get("content-security-policy") || "", /object-src 'none'/);
  } finally {
    await gw.stop();
  }
});

test("a disallowed origin gets no CORS grant", async () => {
  const gw = await startGateway({ OREOCHAIN_ALLOWED_ORIGINS: "https://app.example.com" });
  try {
    const allowed = await fetch(`${gw.url}/api/storage/pin`, {
      method: "POST",
      headers: authed({ Origin: "https://app.example.com" }),
      body: randomBytes(32),
    });
    assert.equal(allowed.headers.get("access-control-allow-origin"), "https://app.example.com");

    const denied = await fetch(`${gw.url}/api/storage/pin`, {
      method: "POST",
      headers: authed({ Origin: "https://evil.example.com" }),
      body: randomBytes(32),
    });
    assert.equal(denied.status, 403);
    assert.equal(denied.headers.get("access-control-allow-origin"), null);
  } finally {
    await gw.stop();
  }
});

test("anonymous callers are rate limited by source address, not as one pool", async () => {
  const gw = await startGateway({
    OREOCHAIN_API_KEYS: "",
    OREOCHAIN_ANCHOR_API_KEYS: "",
    OREOCHAIN_ALLOW_ANONYMOUS: "true",
    OREOCHAIN_RATE_LIMIT_PER_MINUTE: "60",
    OREOCHAIN_RATE_LIMIT_BURST: "2",
  });
  try {
    const statuses = [];
    for (let i = 0; i < 4; i++) {
      const response = await fetch(`${gw.url}/api/storage/pin`, {
        method: "POST",
        body: randomBytes(32),
      });
      statuses.push(response.status);
    }
    // All four come from the same loopback address, so the burst still applies.
    assert.deepEqual(statuses.slice(0, 2), [200, 200]);
    assert.ok(statuses.includes(429), `never rate limited: ${statuses.join(",")}`);
  } finally {
    await gw.stop();
  }
});

// ---------------------------------------------------------- static frontend

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("serving the frontend does not serve the rest of the repository", async () => {
  const gw = await startGateway({ OREOCHAIN_SERVE_STATIC: "true" }, { staticRoot: REPO_ROOT });
  try {
    // The static root is the repository, so everything below is a real file
    // sitting next to the pages. Each one used to come back 200.
    const secret = [
      "/.git/config",
      "/.git/HEAD",
      "/server/config.mjs",
      "/server/gateway.mjs",
      "/package.json",
      "/package-lock.json",
      "/auto_update.txt",
      "/test/gateway.test.js",
      "/node_modules/.package-lock.json",
      "/node_modules/web3/package.json",
      "/js/kkk.java",
    ];

    for (const pathname of secret) {
      const response = await fetch(`${gw.url}${pathname}`);
      assert.equal(response.status, 404, `${pathname} is reachable`);
    }
  } finally {
    await gw.stop();
  }
});

test("serving the frontend still serves the frontend", async () => {
  const gw = await startGateway({ OREOCHAIN_SERVE_STATIC: "true" }, { staticRoot: REPO_ROOT });
  try {
    // Every page, plus one file from each allowlisted directory — including the
    // two node_modules bundles the pages load directly, which is the reason the
    // allowlist cannot simply exclude node_modules.
    const expected = [
      ["/", "text/html"],
      ["/index.html", "text/html"],
      ["/upload.html", "text/html"],
      ["/verify.html", "text/html"],
      ["/retrieve.html", "text/html"],
      ["/admin.html", "text/html"],
      ["/delete.html", "text/html"],
      ["/css/main.css", "text/css"],
      ["/js/chunked-app.js", "text/javascript"],
      ["/js/core/kdf.js", "text/javascript"],
      ["/js/storage/ipfs.js", "text/javascript"],
      ["/files/loader.svg", "image/svg+xml"],
      ["/assets/images/icon.png", "image/png"],
      ["/node_modules/web3/dist/web3.min.js", "text/javascript"],
      ["/node_modules/@noble/hashes/esm/argon2.js", "text/javascript"],
      ["/node_modules/@noble/ciphers/esm/chacha.js", "text/javascript"],
    ];

    for (const [pathname, type] of expected) {
      const response = await fetch(`${gw.url}${pathname}`);
      assert.equal(response.status, 200, `${pathname} is not served`);
      assert.ok(
        response.headers.get("content-type").startsWith(type),
        `${pathname} served as ${response.headers.get("content-type")}, expected ${type}`
      );
      await response.arrayBuffer();
    }
  } finally {
    await gw.stop();
  }
});

test("traversal out of the static root is refused", async () => {
  const gw = await startGateway({ OREOCHAIN_SERVE_STATIC: "true" }, { staticRoot: REPO_ROOT });
  try {
    for (const pathname of ["/../etc/passwd", "/js/../../etc/passwd", "/%2e%2e/etc/passwd"]) {
      const response = await fetch(`${gw.url}${pathname}`);
      assert.ok(response.status === 403 || response.status === 404, `${pathname} -> ${response.status}`);
      assert.ok(!(await response.text()).includes("root:"));
    }
  } finally {
    await gw.stop();
  }
});

test("the allowlist is a prefix match on directories, not a substring match", () => {
  const { isServablePath } = gatewayInternals;

  assert.equal(isServablePath("index.html"), true);
  assert.equal(isServablePath("js/core/kdf.js"), true);
  assert.equal(isServablePath("node_modules/@noble/hashes/esm/argon2.js"), true);

  assert.equal(isServablePath("package.json"), false);
  assert.equal(isServablePath(".git/config"), false);
  assert.equal(isServablePath("server/config.mjs"), false);
  assert.equal(isServablePath("node_modules/ws/index.js"), false);
  // A sibling directory whose name merely starts with an allowed one.
  assert.equal(isServablePath("js-private/secrets.js"), false);
  assert.equal(isServablePath("cssx/leak.css"), false);
});

test("uploads past the concurrency limit are shed, not buffered", async () => {
  // Hold every upload open so they pile up, which is the state the limit
  // exists for: the per-request cap bounds one body, not how many are live.
  let release;
  const held = new Promise((resolve) => {
    release = resolve;
  });

  const blocking = {
    name: "memory",
    async put() {
      await held;
      return "memoryHeld";
    },
    async get() {
      throw Object.assign(new Error("not found"), { status: 404 });
    },
  };

  const gw = await startGateway({}, { backend: blocking, maxConcurrentUploads: 2 });
  try {
    const send = () =>
      fetch(`${gw.url}/api/storage/pin`, {
        method: "POST",
        headers: authed({ "Content-Type": "application/octet-stream" }),
        body: new Uint8Array([1, 2, 3]),
      });

    const first = send();
    const second = send();
    // Give the two a moment to be counted before the third arrives.
    await new Promise((resolve) => setTimeout(resolve, 50));
    const third = await send();

    assert.equal(third.status, 503, "a third concurrent upload was accepted");
    assert.equal(third.headers.get("retry-after"), "1");

    release();
    assert.equal((await first).status, 200);
    assert.equal((await second).status, 200);

    // The slot is returned, so the gateway recovers rather than staying shut.
    assert.equal((await send()).status, 200, "the limit did not release");
  } finally {
    release();
    await gw.stop();
  }
});

test("health reports how many uploads are in flight", async () => {
  const gw = await startGateway();
  try {
    const body = await (await fetch(`${gw.url}/health`)).json();
    assert.equal(body.inFlightUploads, 0);
  } finally {
    await gw.stop();
  }
});

// ------------------------------------------------- readiness and observability

test("readiness is a separate answer from liveness", async () => {
  const gw = await startGateway();
  try {
    // Liveness says the process is up. Readiness says it should be sent
    // traffic. Conflating them is how a draining instance keeps receiving
    // requests, and how a dependency outage turns into a crash loop.
    assert.equal((await fetch(`${gw.url}/health`)).status, 200);

    const ready = await fetch(`${gw.url}/ready`);
    assert.equal(ready.status, 200);
    assert.equal((await ready.json()).status, "ready");
  } finally {
    await gw.stop();
  }
});

test("a draining instance fails readiness while still answering liveness", async () => {
  const readiness = { draining: false };
  const gw = await startGateway({}, { readiness });
  try {
    readiness.draining = true;

    const ready = await fetch(`${gw.url}/ready`);
    assert.equal(ready.status, 503, "a draining instance still invited traffic");
    assert.equal((await ready.json()).draining, true);

    // Still alive — an orchestrator must stop routing, not restart it.
    assert.equal((await fetch(`${gw.url}/health`)).status, 200);
  } finally {
    await gw.stop();
  }
});

test("readiness fails when the proof store cannot answer", async () => {
  const broken = {
    kid: "test",
    publicJwk: {},
    status() {
      throw new Error("store is closed");
    },
    proofFor: async () => null,
    close() {},
  };

  const gw = await startGateway({}, { proofs: broken });
  try {
    const response = await fetch(`${gw.url}/ready`);
    assert.equal(response.status, 503);
    assert.match((await response.json()).store, /store is closed/);
  } finally {
    await gw.stop();
  }
});

test("metrics are behind the same key as the API", async () => {
  const gw = await startGateway();
  try {
    // Request volume, error rates and queue depth are operational shape. A
    // gateway with keys should not hand them to anyone who asks.
    assert.equal((await fetch(`${gw.url}/metrics`)).status, 401);
    assert.equal((await fetch(`${gw.url}/metrics`, { headers: authed() })).status, 200);
  } finally {
    await gw.stop();
  }
});

test("metrics count what actually happened", async () => {
  const gw = await startGateway();
  try {
    await fetch(`${gw.url}/api/storage/pin`, {
      method: "POST",
      headers: { ...authed(), "Content-Type": "application/octet-stream" },
      body: new Uint8Array([1, 2, 3, 4]),
    });
    await fetch(`${gw.url}/api/storage/pin`, { method: "POST", body: "x" }); // unauthorised

    const body = await (await fetch(`${gw.url}/metrics`, { headers: authed() })).text();
    assert.match(body, /oreochain_requests_total\{route="pin",status="2xx"\} 1/);
    assert.match(body, /oreochain_auth_failures_total/);
    assert.match(body, /oreochain_bytes_pinned_total\S* 4/);
    assert.match(body, /oreochain_uploads_in_flight 0/);
    assert.match(body, /oreochain_documents_pending 0/);

    // Zero until something checks, and zero is also the healthy value, so the
    // timestamp is what distinguishes "nothing wrong" from "never looked".
    assert.match(body, /oreochain_store_damaged_batches 0/);
    assert.match(body, /oreochain_store_check_timestamp_seconds 0/);
  } finally {
    await gw.stop();
  }
});

test("a request id is returned, so a user can quote one that identifies theirs", async () => {
  const gw = await startGateway();
  try {
    const generated = await fetch(`${gw.url}/health`);
    assert.match(generated.headers.get("x-request-id"), /^[0-9a-f-]{36}$/);

    // A client or an edge proxy that already has an id keeps it, so one trace
    // spans both sides.
    const supplied = await fetch(`${gw.url}/health`, { headers: { "X-Request-Id": "edge-42" } });
    assert.equal(supplied.headers.get("x-request-id"), "edge-42");
  } finally {
    await gw.stop();
  }
});

test("an error response carries the id that finds it in the log", async () => {
  const gw = await startGateway();
  try {
    const response = await fetch(`${gw.url}/api/nope`, { headers: authed() });
    const body = await response.json();
    assert.equal(body.requestId, response.headers.get("x-request-id"));
  } finally {
    await gw.stop();
  }
});

test("the log line for a request carries its id and no credential", async () => {
  const lines = [];
  const gw = await startGateway(
    {},
    { logger: createLogger({ level: "debug", write: (line) => lines.push(line) }) }
  );
  try {
    await fetch(`${gw.url}/api/storage/pin`, {
      method: "POST",
      headers: { ...authed(), "X-Request-Id": "trace-9" },
      body: new Uint8Array([1, 2, 3]),
    });

    const pinned = lines.map((line) => JSON.parse(line)).find((e) => e.msg === "pinned");
    assert.ok(pinned, "the upload produced no log line");
    assert.equal(pinned.reqId, "trace-9");
    assert.equal(pinned.bytes, 3);
    assert.equal(lines.join("\n").includes(KEY), false, "an api key reached the log");
  } finally {
    await gw.stop();
  }
});

// ------------------------------------------- receipts mean what they say

test("the record route refuses a document its manifest does not describe", async () => {
  const payload = utf8("a genuine document");
  const packed = await packFile(payload, {
    fileName: "genuine.txt",
    mimeType: "text/plain",
    limits: TEST_LIMITS,
  });
  const manifest = await sealManifest(
    packed,
    packed.chunks.map((_, i) => `bafyChunk${i}`)
  );

  // Pin the manifest through the gateway, exactly as a client would, so the
  // verifier reads it back through the same backend.
  const backend = createMemoryBackend();
  const manifestCID = await backend.put(utf8(JSON.stringify(manifest)), "manifest");

  const keys = await generateSigningKey();
  const proofs = await createProofService({
    ...keys.exported,
    verifier: createManifestVerifier({ backend, limits: TEST_LIMITS }),
  });

  const gw = await startGateway({}, { backend, proofs });
  try {
    const honest = {
      fileHash: manifest.fileHash,
      merkleRoot: manifest.merkleRoot,
      fileSize: manifest.fileSize,
      manifestCID,
    };

    const accepted = await fetch(`${gw.url}/api/proofs/record`, {
      method: "POST",
      headers: authed({ "Content-Type": "application/json" }),
      body: JSON.stringify(honest),
    });
    assert.equal(accepted.status, 200);
    assert.equal((await accepted.json()).receipt.statement.verified, true);

    // The same manifest, a different claimed document. This is the request
    // that used to come back with a valid signature over a fiction.
    const forged = await fetch(`${gw.url}/api/proofs/record`, {
      method: "POST",
      headers: authed({ "Content-Type": "application/json" }),
      body: JSON.stringify({ ...honest, fileHash: `0x${"aa".repeat(32)}` }),
    });
    assert.equal(forged.status, 400);
    assert.match((await forged.json()).error, /does not match manifest/);
  } finally {
    await gw.stop();
  }
});

test("a manifest the gateway cannot read is a retryable 503, not a rejection", async () => {
  const keys = await generateSigningKey();
  const backend = createMemoryBackend();
  const proofs = await createProofService({
    ...keys.exported,
    verifier: createManifestVerifier({ backend, limits: TEST_LIMITS }),
  });

  const gw = await startGateway({}, { backend, proofs });
  try {
    // Nothing was pinned, so the manifest cannot be fetched. That is not the
    // client's document being wrong, and telling them so would be misleading.
    const response = await fetch(`${gw.url}/api/proofs/record`, {
      method: "POST",
      headers: authed({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        fileHash: `0x${"bb".repeat(32)}`,
        merkleRoot: `0x${"cc".repeat(32)}`,
        fileSize: 10,
        manifestCID: "bafyNeverPinned",
      }),
    });

    assert.equal(response.status, 503);
    assert.equal(response.headers.get("retry-after"), "5");
  } finally {
    await gw.stop();
  }
});

test("an unknown endpoint is a 404", async () => {
  const gw = await startGateway();
  try {
    const response = await fetch(`${gw.url}/api/nope`, { headers: authed() });
    assert.equal(response.status, 404);
  } finally {
    await gw.stop();
  }
});

// -------------------------------------------------------- full client flow

test("a whole document round-trips through the gateway, client-side encrypted", async () => {
  const gw = await startGateway({ OREOCHAIN_RATE_LIMIT_BURST: "500" });
  try {
    const data = randomBytes(12000);
    const passphrase = "gateway-round-trip-passphrase";

    // The adapter a browser would use, pointed at this gateway.
    const adapter = createPinataAdapter({
      mode: "backend",
      endpoint: `${gw.url}/api/storage/pin`,
      gateways: [`${gw.url}/api/storage/`],
      retry: { maxAttempts: 2, backoffBaseMs: 1 },
    });

    // The gateway requires auth, so wrap the adapter's calls with the header.
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (url, init = {}) =>
      originalFetch(url, { ...init, headers: { ...(init.headers || {}), ...authed() } });

    let manifest;
    let manifestCid;
    let restored;
    try {
      const packed = await packFile(data, {
        fileName: "contract.pdf",
        mimeType: "application/pdf",
        passphrase,
        chunkSize: 1024,
        kdf: TEST_KDF,
      });

      const locations = await putAll(adapter, packed.chunks, { concurrency: 4 });
      manifest = await sealManifest(packed, locations);
      manifestCid = await adapter.put(utf8(JSON.stringify(manifest)), "manifest");

      // Retrieval: fetch the manifest back through the gateway, then the chunks.
      const manifestBytes = await adapter.get(manifestCid);
      const fetchedManifest = JSON.parse(fromUtf8(manifestBytes));
      const opened = await openManifest(fetchedManifest, passphrase, { limits: TEST_LIMITS });

      restored = await restoreFile(fetchedManifest, opened, (loc) => adapter.get(loc), {
        expectedMerkleRoot: fetchedManifest.merkleRoot,
        limits: TEST_LIMITS,
      });
    } finally {
      globalThis.fetch = originalFetch;
    }

    assert.ok(equalBytes(restored.bytes, data));
    assert.equal(restored.fileName, "contract.pdf");

    // The gateway stored 12 chunks plus the manifest, and never saw plaintext.
    assert.equal(gw.backend.blocks.size, 13);
    for (const [cid, stored] of gw.backend.blocks) {
      if (cid === manifestCid) continue;
      assert.ok(
        !equalBytes(stored.subarray(0, 1024), data.subarray(0, 1024)),
        "the gateway holds plaintext"
      );
    }
  } finally {
    await gw.stop();
  }
});

// --------------------------------------------------------------- proofs API

test("the receipt verification key is public — verifying needs no account", async () => {
  // A court or employer checking a certificate has no API key and should not
  // need one.
  const gw = await startGateway();
  try {
    const response = await fetch(`${gw.url}/api/proofs/key`);
    assert.equal(response.status, 200);

    const body = await response.json();
    assert.equal(body.algorithm, "ECDSA-P256-SHA256");
    assert.match(body.kid, /^[A-Za-z0-9]{16}$/);
    assert.equal(body.publicJwk.crv, "P-256");
    // A public key must never carry the private component.
    assert.equal(body.publicJwk.d, undefined);
  } finally {
    await gw.stop();
  }
});

test("recording a document requires authentication", async () => {
  const gw = await startGateway();
  try {
    const response = await fetch(`${gw.url}/api/proofs/record`, {
      method: "POST",
      body: JSON.stringify({ fileHash: "0x" + "11".repeat(32) }),
    });
    assert.equal(response.status, 401);
  } finally {
    await gw.stop();
  }
});

test("a recorded document comes back with a receipt that verifies", async () => {
  const gw = await startGateway();
  try {
    const document = {
      fileHash: "0x" + "ab".repeat(32),
      merkleRoot: "0x" + "cd".repeat(32),
      manifestCID: "bafyReceiptTest",
      fileSize: 4096,
      totalChunks: 1,
      encrypted: true,
      suite: "aes-256-gcm",
    };

    const recorded = await fetch(`${gw.url}/api/proofs/record`, {
      method: "POST",
      headers: authed({ "Content-Type": "application/json" }),
      body: JSON.stringify(document),
    });
    assert.equal(recorded.status, 200);

    const { receipt, queued } = await recorded.json();
    assert.equal(queued, true);

    // Verify with only the public key, exactly as an outside party would.
    const { publicJwk } = await (await fetch(`${gw.url}/api/proofs/key`)).json();
    const result = await verifyReceipt(receipt, await importPublicKey(publicJwk));

    assert.ok(result.valid, result.reason);
    assert.equal(result.statement.fileHash, document.fileHash);
    assert.equal(result.statement.manifestCID, document.manifestCID);
  } finally {
    await gw.stop();
  }
});

test("a receipt for a document that was never recorded does not verify", async () => {
  const gw = await startGateway();
  try {
    const { publicJwk } = await (await fetch(`${gw.url}/api/proofs/key`)).json();
    const publicKey = await importPublicKey(publicJwk);

    const recorded = await fetch(`${gw.url}/api/proofs/record`, {
      method: "POST",
      headers: authed({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        fileHash: "0x" + "11".repeat(32),
        merkleRoot: "0x" + "22".repeat(32),
        manifestCID: "bafyReal",
        fileSize: 10,
        totalChunks: 1,
      }),
    });
    const { receipt } = await recorded.json();

    // Forge a different document into the signed statement.
    receipt.statement.manifestCID = "bafyForged";
    assert.equal((await verifyReceipt(receipt, publicKey)).valid, false);
  } finally {
    await gw.stop();
  }
});

test("a malformed document is rejected rather than receipted", async () => {
  const gw = await startGateway();
  try {
    for (const body of ['{"fileHash":"0x11"}', "{}", "not json", "[]"]) {
      const response = await fetch(`${gw.url}/api/proofs/record`, {
        method: "POST",
        headers: authed({ "Content-Type": "application/json" }),
        body,
      });
      assert.ok(response.status >= 400, `accepted malformed body: ${body}`);
    }
  } finally {
    await gw.stop();
  }
});

test("many documents anchor in one batch, and each still proves independently", async () => {
  // This is the property that removes per-user gas: 12 documents, 1 anchor.
  const gw = await startGateway({ OREOCHAIN_RATE_LIMIT_BURST: "200" });
  try {
    const documents = Array.from({ length: 12 }, (_, i) => ({
      fileHash: "0x" + i.toString(16).padStart(64, "0"),
      merkleRoot: "0x" + (i + 4096).toString(16).padStart(64, "0"),
      manifestCID: `bafyBatched${i}`,
      fileSize: 1000 + i,
      totalChunks: 1,
      encrypted: true,
      suite: "aes-256-gcm",
    }));

    for (const document of documents) {
      const response = await fetch(`${gw.url}/api/proofs/record`, {
        method: "POST",
        headers: authed({ "Content-Type": "application/json" }),
        body: JSON.stringify(document),
      });
      assert.equal(response.status, 200);
    }

    const status = await (
      await fetch(`${gw.url}/api/proofs/status`, { headers: authed() })
    ).json();
    assert.equal(status.pending, 12);

    const { batch } = await (
      await fetch(`${gw.url}/api/proofs/batch`, { method: "POST", headers: anchorAuthed() })
    ).json();
    assert.equal(batch.size, 12);
    assert.match(batch.root, /^0x[0-9a-f]{64}$/);

    // Every document proves against the single anchored root, and inclusion
    // proofs are public — the verifier sends no credentials.
    for (const document of documents) {
      const proofResponse = await fetch(`${gw.url}/api/proofs/inclusion/${document.fileHash}`);
      assert.equal(proofResponse.status, 200, `no proof for ${document.fileHash}`);

      const inclusion = await proofResponse.json();
      const verified = await verifyInBatch(inclusion, batch.root);
      assert.ok(verified.valid, `inclusion proof failed for ${document.fileHash}`);
    }

    // The queue is drained, so the next batch starts empty.
    const after = await (
      await fetch(`${gw.url}/api/proofs/status`, { headers: authed() })
    ).json();
    assert.equal(after.pending, 0);
  } finally {
    await gw.stop();
  }
});

test("building a batch with nothing pending is not an error", async () => {
  const gw = await startGateway();
  try {
    const response = await fetch(`${gw.url}/api/proofs/batch`, {
      method: "POST",
      headers: anchorAuthed(),
    });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).batch, null);
  } finally {
    await gw.stop();
  }
});

test("a document that cannot be anchored is refused, not receipted and queued", async () => {
  const gw = await startGateway();
  try {
    // Every one of these passes issueReceipt's "three non-empty strings" check
    // and fails the anchor's. They used to be signed, queued, and only rejected
    // when the batch was built.
    const good = {
      fileHash: `0x${"11".repeat(32)}`,
      merkleRoot: `0x${"22".repeat(32)}`,
      manifestCID: "bafyGood",
      fileSize: 10,
    };
    const unanchorable = [
      { ...good, fileHash: "0xNOPE" },
      { ...good, merkleRoot: "0x22" },
      { ...good, fileSize: undefined },
      { ...good, fileSize: -1 },
    ];

    for (const document of unanchorable) {
      const response = await fetch(`${gw.url}/api/proofs/record`, {
        method: "POST",
        headers: authed({ "Content-Type": "application/json" }),
        body: JSON.stringify(document),
      });
      assert.equal(response.status, 400, `accepted ${JSON.stringify(document)}`);
    }

    assert.equal(gw.proofs.status().pending, 0, "an unanchorable document was queued");
  } finally {
    await gw.stop();
  }
});

test("documents recorded while a batch is building stay queued for the next one", async () => {
  const proofs = await createProofService();
  const document = (i) => ({
    fileHash: `0x${i.toString(16).padStart(64, "0")}`,
    merkleRoot: `0x${"22".repeat(32)}`,
    manifestCID: `bafy${i}`,
    fileSize: 10,
  });

  for (let i = 0; i < 3; i++) await proofs.record(document(i));

  // Start the build, then record a fourth before it settles.
  const building = proofs.buildPendingBatch();
  await proofs.record(document(3));
  const batch = await building;

  assert.equal(batch.size, 3, "the late document was swept into this batch");
  assert.equal(proofs.status().pending, 1, "the late document was dropped");

  const next = await proofs.buildPendingBatch();
  assert.equal(next.size, 1);
  assert.ok(await proofs.proofFor(document(3).fileHash));
});

test("hex is normalised, so a document is receipted and anchored under one spelling", async () => {
  const proofs = await createProofService();
  const upper = {
    fileHash: `0x${"AB".repeat(32)}`,
    merkleRoot: `0x${"CD".repeat(32)}`,
    manifestCID: "bafyUpper",
    fileSize: 10,
  };

  const { receipt } = await proofs.record(upper);
  assert.equal(receipt.statement.fileHash, upper.fileHash.toLowerCase());

  await proofs.buildPendingBatch();
  assert.ok(await proofs.proofFor(upper.fileHash), "an uppercase hash could not be looked up");
  assert.ok(await proofs.proofFor(upper.fileHash.toLowerCase()));
});

// ------------------------------------------------- reporting an anchor back

/**
 * The anchoring worker is a separate process that cannot open the proof store
 * — the single-writer lock exists precisely to stop it — so what it submitted
 * comes back over the API. That makes these the only endpoints where a
 * client's claim ends up in a receipt, which is why none of it is trusted.
 */

/** Record enough documents to build one batch, and return its root. */
async function buildOneBatch(gw, count = 2) {
  for (let i = 0; i < count; i++) {
    const response = await fetch(`${gw.url}/api/proofs/record`, {
      method: "POST",
      headers: authed({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        fileHash: "0x" + `${Date.now()}${i}`.padStart(64, "0").slice(-64),
        merkleRoot: "0x" + `${i}`.padStart(64, "7"),
        manifestCID: `bafyReported${i}`,
        fileSize: 512 + i,
      }),
    });
    assert.equal(response.status, 200);
  }
  const { batch } = await (
    await fetch(`${gw.url}/api/proofs/batch`, { method: "POST", headers: anchorAuthed() })
  ).json();
  return batch;
}

function reportAnchor(gw, body) {
  return fetch(`${gw.url}/api/proofs/anchored`, {
    method: "POST",
    headers: anchorAuthed({ "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });
}

test("a built batch is listed as unanchored until a transaction is reported", async () => {
  const gw = await startGateway();
  try {
    const listed = async () =>
      (await (await fetch(`${gw.url}/api/proofs/unanchored`, { headers: anchorAuthed() })).json())
        .batches;

    assert.deepEqual(await listed(), [], "nothing is owed an anchor yet");

    const batch = await buildOneBatch(gw);
    const waiting = await listed();
    assert.equal(waiting.length, 1);
    assert.equal(waiting[0].root, batch.root);
    assert.equal(waiting[0].size, 2);

    const response = await reportAnchor(gw, {
      root: batch.root,
      txHash: "0x" + "1a".repeat(32),
      block: 4242,
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {
      root: batch.root,
      size: 2,
      txHash: "0x" + "1a".repeat(32),
      block: 4242,
    });

    assert.deepEqual(await listed(), [], "an anchored batch is no longer owed one");
  } finally {
    await gw.stop();
  }
});

test("a reported anchor is validated, not taken on trust", async () => {
  const gw = await startGateway();
  try {
    const batch = await buildOneBatch(gw);

    // Each of these would otherwise be written into the store and served to
    // every verifier asking about the batch, pointing them at a transaction
    // that does not exist.
    const rejected = [
      [{ root: batch.root, txHash: "not-a-hash", block: 1 }, /txHash must be/],
      [{ root: batch.root, txHash: "0x" + "2b".repeat(32) }, /block must be/],
      [{ root: batch.root, txHash: "0x" + "2b".repeat(32), block: -1 }, /block must be/],
      [{ root: batch.root, txHash: "0x" + "2b".repeat(32), block: 1.5 }, /block must be/],
      [{ root: "0xshort", txHash: "0x" + "2b".repeat(32), block: 1 }, /root must be/],
    ];

    for (const [body, expected] of rejected) {
      const response = await reportAnchor(gw, body);
      assert.equal(response.status, 400, `accepted ${JSON.stringify(body)}`);
      assert.match((await response.json()).error, expected);
    }
  } finally {
    await gw.stop();
  }
});

test("an anchor for a batch the gateway never built is a 404", async () => {
  const gw = await startGateway();
  try {
    const response = await reportAnchor(gw, {
      root: "0x" + "99".repeat(32),
      txHash: "0x" + "3c".repeat(32),
      block: 12,
    });
    assert.equal(response.status, 404);
  } finally {
    await gw.stop();
  }
});

test("re-reporting the same transaction is fine; a different one is a conflict", async () => {
  const gw = await startGateway();
  try {
    const batch = await buildOneBatch(gw);
    const txHash = "0x" + "4d".repeat(32);

    assert.equal((await reportAnchor(gw, { root: batch.root, txHash, block: 9 })).status, 200);

    // A worker that crashed after reporting will report again on restart. The
    // same transaction has to be accepted, or a restart deadlocks the batch.
    assert.equal((await reportAnchor(gw, { root: batch.root, txHash, block: 9 })).status, 200);

    // Two different transactions for one root means something upstream is
    // wrong. Overwriting would hide it and break proofs already served.
    const conflict = await reportAnchor(gw, {
      root: batch.root,
      txHash: "0x" + "5e".repeat(32),
      block: 10,
    });
    assert.equal(conflict.status, 409);
    assert.match((await conflict.json()).error, /already anchored/);
  } finally {
    await gw.stop();
  }
});

test("an uploader's key cannot drive anchoring", async () => {
  const gw = await startGateway();
  try {
    const batch = await buildOneBatch(gw);

    /*
     * The privilege that matters. A key that can record a document must not
     * also be able to declare a batch anchored: the transaction hash it
     * supplies is served to everyone who asks for a proof in that batch, and
     * a well-formed fictitious one would send every verifier to a
     * transaction that does not exist — and then make the real anchor a 409,
     * so the batch could never be corrected.
     */
    const forged = await fetch(`${gw.url}/api/proofs/anchored`, {
      method: "POST",
      headers: authed({ "Content-Type": "application/json" }),
      body: JSON.stringify({ root: batch.root, txHash: "0x" + "de".repeat(32), block: 1 }),
    });
    assert.equal(forged.status, 403);
    assert.match((await forged.json()).error, /OREOCHAIN_ANCHOR_API_KEYS/);

    // Reading what is outstanding, and forcing a batch, are the same
    // privilege: both are the worker's business.
    assert.equal(
      (await fetch(`${gw.url}/api/proofs/unanchored`, { headers: authed() })).status,
      403
    );
    assert.equal(
      (await fetch(`${gw.url}/api/proofs/batch`, { method: "POST", headers: authed() })).status,
      403
    );

    // And the uploader key still does everything it is for.
    assert.equal(
      (await fetch(`${gw.url}/api/proofs/status`, { headers: authed() })).status,
      200
    );

    // The real anchor still lands, because nothing forged got through.
    const real = await reportAnchor(gw, {
      root: batch.root,
      txHash: "0x" + "0c".repeat(32),
      block: 5,
    });
    assert.equal(real.status, 200);
  } finally {
    await gw.stop();
  }
});

test("with no anchoring key configured, nothing may anchor", async () => {
  // Fail closed. The alternative — every authenticated key may anchor until
  // the operator narrows it — is the state this privilege exists to end.
  const gw = await startGateway({ OREOCHAIN_ANCHOR_API_KEYS: "" });
  try {
    const response = await fetch(`${gw.url}/api/proofs/unanchored`, { headers: authed() });
    assert.equal(response.status, 403);
  } finally {
    await gw.stop();
  }
});

test("a configuration naming an anchoring key that cannot authenticate is refused", () => {
  assert.throws(
    () =>
      loadConfig({
        OREOCHAIN_API_KEYS: KEY,
        OREOCHAIN_ANCHOR_API_KEYS: ANCHOR_KEY,
        OREOCHAIN_STORAGE: "memory",
      }),
    /must also be in OREOCHAIN_API_KEYS/,
    "otherwise the worker is rejected at authentication and the privilege never comes up"
  );
});

test("a gateway with no anchoring key warns that nothing will be anchored", () => {
  const warnings = [];
  assertSafeConfig(
    loadConfig({ OREOCHAIN_API_KEYS: KEY, OREOCHAIN_STORAGE: "memory" }),
    { warn: (message) => warnings.push(message) }
  );
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /built but never anchored/);
});

test("reporting an anchor needs a credential", async () => {
  const gw = await startGateway();
  try {
    const batch = await buildOneBatch(gw);
    for (const path of ["/api/proofs/unanchored", "/api/proofs/anchored"]) {
      const response = await fetch(`${gw.url}${path}`, {
        method: path.endsWith("anchored") ? "POST" : "GET",
        headers: { "Content-Type": "application/json" },
        body: path.endsWith("anchored")
          ? JSON.stringify({ root: batch.root, txHash: "0x" + "6f".repeat(32), block: 1 })
          : undefined,
      });
      assert.equal(response.status, 401, `${path} was reachable without a key`);
    }
  } finally {
    await gw.stop();
  }
});

test("an inclusion proof for an unknown document is a 404", async () => {
  const gw = await startGateway();
  try {
    const response = await fetch(`${gw.url}/api/proofs/inclusion/0x${"99".repeat(32)}`);
    assert.equal(response.status, 404);
  } finally {
    await gw.stop();
  }
});

test("a configured signing key survives a restart; an ephemeral one does not", async () => {
  const { generateSigningKey } = await import("../js/core/receipt.js");
  const keys = await generateSigningKey();

  // Two services started from the same configured key — a restart.
  const before = await createProofService({ ...keys.exported });
  const after = await createProofService({ ...keys.exported });

  assert.equal(before.ephemeral, false);
  assert.equal(after.ephemeral, false);
  assert.equal(before.kid, after.kid, "a configured key must keep its identity across restarts");

  // A receipt issued before the restart still verifies after it.
  const document = {
    fileHash: "0x" + "aa".repeat(32),
    merkleRoot: "0x" + "bb".repeat(32),
    manifestCID: "bafyAcrossRestart",
    fileSize: 512,
    totalChunks: 1,
  };
  const { receipt } = await before.record(document);
  const verified = await verifyReceipt(receipt, await importPublicKey(after.publicJwk));
  assert.ok(verified.valid, verified.reason);

  // Without a configured key, each start is a new identity and old receipts
  // become unverifiable — which is why the server warns loudly about it.
  const ephemeralA = await createProofService();
  const ephemeralB = await createProofService();
  assert.equal(ephemeralA.ephemeral, true);
  assert.notEqual(ephemeralA.kid, ephemeralB.kid);

  const orphaned = await ephemeralA.record(document);
  const orphanResult = await verifyReceipt(
    orphaned.receipt,
    await importPublicKey(ephemeralB.publicJwk)
  );
  assert.equal(orphanResult.valid, false);
});

test("readSigningKey rejects a malformed environment value", () => {
  assert.throws(() => readSigningKey({ OREOCHAIN_RECEIPT_KEY: "{oops" }), /not valid JSON/);
  assert.throws(
    () => readSigningKey({ OREOCHAIN_RECEIPT_KEY: '{"privateJwk":{}}' }),
    /must be/
  );
  assert.deepEqual(readSigningKey({}), { privateJwk: null, publicJwk: null });
});
