/**
 * Gateway tests run against a real HTTP server on an ephemeral port, because
 * the things worth checking here — body caps, timing-safe auth, traversal
 * defences — are properties of actual socket handling, not of a mocked object.
 */

import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

import { loadConfig, assertSafeConfig } from "../server/config.mjs";
import { createHandler } from "../server/gateway.mjs";
import { createMemoryBackend } from "../server/storage.mjs";
import { authenticate, extractToken } from "../server/auth.mjs";
import { createRateLimiter } from "../server/ratelimit.mjs";

import { equalBytes, fromUtf8, randomBytes, utf8 } from "../js/core/bytes.js";
import { createPinataAdapter, putAll } from "../js/storage/ipfs.js";
import { openManifest, packFile, restoreFile, sealManifest } from "../js/core/manifest.js";

const KEY = "k".repeat(48);
const TEST_LIMITS = { minIterations: 1000 };

function baseEnv(overrides = {}) {
  return {
    OREOCHAIN_API_KEYS: KEY,
    OREOCHAIN_STORAGE: "memory",
    ...overrides,
  };
}

/** Start a gateway on an ephemeral port; returns its URL and a stop function. */
async function startGateway(envOverrides = {}, deps = {}) {
  const config = assertSafeConfig(loadConfig(baseEnv(envOverrides)));
  const backend = createMemoryBackend();
  const handler = createHandler(config, backend, { log: () => {}, sweeper: false, ...deps });

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
    config,
    stop: () => new Promise((resolve) => server.close(resolve)),
  };
}

function authed(extra = {}) {
  return { Authorization: `Bearer ${KEY}`, ...extra };
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
      // The error must not hint at which part was wrong.
      assert.deepEqual(await response.json(), { error: "unauthorized" });
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
        iterations: 1000,
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
