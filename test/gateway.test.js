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
import { createProofService, readSigningKey } from "../server/proofs.mjs";
import { importPublicKey, verifyReceipt } from "../js/core/receipt.js";
import { verifyInBatch } from "../js/core/anchor.js";
import { openManifest, packFile, restoreFile, sealManifest } from "../js/core/manifest.js";

// Argon2id at production settings costs ~0.7s per derivation, which would make
// this suite take minutes. Tests declare cheap parameters explicitly, and a
// matching floor, rather than silently inheriting defaults.
const TEST_KDF = { name: "argon2id", memoryKiB: 8, iterations: 1, parallelism: 1 };

const KEY = "k".repeat(48);
const TEST_LIMITS = { minArgon2MemoryKiB: 8 };

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
  const proofs = deps.proofs === false ? null : deps.proofs || (await createProofService());
  const handler = createHandler(config, backend, {
    log: () => {},
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
      await fetch(`${gw.url}/api/proofs/batch`, { method: "POST", headers: authed() })
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
      headers: authed(),
    });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).batch, null);
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
