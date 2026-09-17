import test from "node:test";
import assert from "node:assert/strict";

import { equalBytes, randomBytes } from "../js/core/bytes.js";
import {
  createAdapterFromConfig,
  createGatewayAdapter,
  createPinataAdapter,
  putAll,
  withRetry,
  _internals,
} from "../js/storage/ipfs.js";

/** Swap in a fake fetch for the duration of one call. */
async function withFetch(impl, fn) {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  try {
    return await fn();
  } finally {
    globalThis.fetch = original;
  }
}

function okResponse(bytes) {
  return {
    ok: true,
    status: 200,
    arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
  };
}

function jsonResponse(body) {
  return { ok: true, status: 200, json: async () => body };
}

function httpError(status) {
  return { ok: false, status, text: async () => `HTTP ${status}` };
}

// Retries are disabled in most tests so call counts stay meaningful.
const NO_RETRY = { maxAttempts: 1 };

// ------------------------------------------------------------------- retrying

test("withRetry retries transient failures and eventually succeeds", async () => {
  let attempts = 0;
  const result = await withRetry(
    async () => {
      attempts++;
      if (attempts < 3) {
        const error = new Error("boom");
        error.status = 503;
        throw error;
      }
      return "done";
    },
    { backoffBaseMs: 1 }
  );

  assert.equal(result, "done");
  assert.equal(attempts, 3);
});

test("withRetry gives up after maxAttempts and rethrows the last error", async () => {
  let attempts = 0;
  await assert.rejects(
    () =>
      withRetry(
        async () => {
          attempts++;
          const error = new Error("still down");
          error.status = 500;
          throw error;
        },
        { maxAttempts: 3, backoffBaseMs: 1 }
      ),
    /still down/
  );
  assert.equal(attempts, 3);
});

test("withRetry does not retry permanent failures", async () => {
  // Retrying a 401 or a 400 wastes time and hammers the service.
  for (const status of [400, 401, 403, 404]) {
    let attempts = 0;
    await assert.rejects(() =>
      withRetry(
        async () => {
          attempts++;
          const error = new Error(`HTTP ${status}`);
          error.status = status;
          throw error;
        },
        { maxAttempts: 4, backoffBaseMs: 1 }
      )
    );
    assert.equal(attempts, 1, `status ${status} should not be retried`);
  }
});

test("withRetry does retry 408, 429 and 5xx", async () => {
  for (const status of [408, 429, 500, 502, 503]) {
    let attempts = 0;
    await assert.rejects(() =>
      withRetry(
        async () => {
          attempts++;
          const error = new Error(`HTTP ${status}`);
          error.status = status;
          throw error;
        },
        { maxAttempts: 2, backoffBaseMs: 1 }
      )
    );
    assert.equal(attempts, 2, `status ${status} should be retried`);
  }
});

test("withRetry stops immediately when aborted", async () => {
  const controller = new AbortController();
  let attempts = 0;

  const promise = withRetry(
    async () => {
      attempts++;
      controller.abort();
      const error = new Error("transient");
      error.status = 500;
      throw error;
    },
    { maxAttempts: 5, backoffBaseMs: 50, signal: controller.signal }
  );

  await assert.rejects(promise, (error) => error.name === "AbortError" || /transient/.test(error.message));
  assert.ok(attempts <= 2, `aborted retry loop ran ${attempts} times`);
});

test("backoff is capped and jittered, never a fixed burst", async () => {
  const delays = [];
  let attempts = 0;
  await assert.rejects(() =>
    withRetry(
      async () => {
        attempts++;
        const error = new Error("nope");
        error.status = 500;
        throw error;
      },
      {
        maxAttempts: 5,
        backoffBaseMs: 100,
        maxBackoffMs: 250,
        onRetry: (_attempt, delay) => delays.push(delay),
      }
    )
  );
  assert.equal(delays.length, 4);
  for (const delay of delays) assert.ok(delay >= 0 && delay <= 250, `delay ${delay} out of range`);
});

// ------------------------------------------------------------------ gateways

test("the gateway adapter falls back to the next gateway on failure", async () => {
  const payload = randomBytes(64);
  const tried = [];

  const result = await withFetch(
    async (url) => {
      tried.push(url);
      return tried.length < 3 ? httpError(504) : okResponse(payload);
    },
    () =>
      createGatewayAdapter({
        gateways: ["https://a/ipfs/", "https://b/ipfs/", "https://c/ipfs/"],
        retry: NO_RETRY,
      }).get("CID123")
  );

  assert.equal(tried.length, 3);
  assert.equal(tried[2], "https://c/ipfs/CID123");
  assert.ok(equalBytes(result, payload));
});

test("each gateway is retried before moving to the next", async () => {
  const payload = randomBytes(8);
  const tried = [];

  const result = await withFetch(
    async (url) => {
      tried.push(url);
      // The first gateway fails twice, then succeeds on its third attempt.
      if (url.startsWith("https://a/") && tried.length < 3) return httpError(503);
      return okResponse(payload);
    },
    () =>
      createGatewayAdapter({
        gateways: ["https://a/ipfs/", "https://b/ipfs/"],
        retry: { maxAttempts: 4, backoffBaseMs: 1 },
      }).get("CID")
  );

  assert.ok(equalBytes(result, payload));
  assert.ok(tried.every((url) => url.startsWith("https://a/")), "should not have needed gateway b");
});

test("a fetch that throws is treated as a failed gateway, not a crash", async () => {
  const payload = randomBytes(16);
  const result = await withFetch(
    async (url) => {
      if (url.startsWith("https://a/")) throw new Error("DNS failure");
      return okResponse(payload);
    },
    () =>
      createGatewayAdapter({
        gateways: ["https://a/ipfs/", "https://b/ipfs/"],
        retry: NO_RETRY,
      }).get("X")
  );
  assert.ok(equalBytes(result, payload));
});

test("exhausting every gateway reports all the failures", async () => {
  await withFetch(
    async () => httpError(500),
    async () => {
      await assert.rejects(
        () =>
          createGatewayAdapter({
            gateways: ["https://a/ipfs/", "https://b/ipfs/"],
            retry: NO_RETRY,
          }).get("X"),
        /could not fetch X from any gateway/
      );
    }
  );
});

// ----------------------------------------------------------- location safety

test("an unsafe storage location is refused before any request is made", async () => {
  // A location is interpolated into a URL, so path traversal and scheme
  // switching must be impossible.
  const hostile = [
    "../../../etc/passwd",
    "..%2f..%2fsecret",
    "file:///etc/passwd",
    "http://169.254.169.254/latest/meta-data/",
    "CID/../../admin",
    "",
    "a".repeat(513),
  ];

  let fetched = 0;
  await withFetch(
    async () => {
      fetched++;
      return okResponse(randomBytes(4));
    },
    async () => {
      for (const location of hostile) {
        await assert.rejects(
          () => createGatewayAdapter({ retry: NO_RETRY }).get(location),
          /unsafe storage location/,
          `accepted hostile location: ${location}`
        );
      }
    }
  );
  assert.equal(fetched, 0, "a hostile location reached the network");
});

test("a cid returned by an upload endpoint is validated too", async () => {
  await withFetch(
    async () => jsonResponse({ cid: "../../evil" }),
    async () => {
      await assert.rejects(
        () => createPinataAdapter({ mode: "backend", retry: NO_RETRY }).put(randomBytes(8)),
        /unsafe storage location/
      );
    }
  );
});

test("the location pattern accepts real CIDs and rejects separators", () => {
  const { SAFE_LOCATION } = _internals;
  assert.ok(SAFE_LOCATION.test("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"));
  assert.ok(SAFE_LOCATION.test("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"));
  assert.ok(!SAFE_LOCATION.test("with/slash"));
  assert.ok(!SAFE_LOCATION.test("with.dot"));
  assert.ok(!SAFE_LOCATION.test("with:colon"));
});

// -------------------------------------------------------------------- upload

test("the read-only adapter refuses uploads", async () => {
  await assert.rejects(() => createGatewayAdapter().put(randomBytes(8)), /read-only/);
});

test("direct mode requires a token and is refused without one", () => {
  assert.throws(() => createPinataAdapter({ mode: "direct" }), /needs a Pinata JWT/);
});

test("an unknown storage mode is rejected", () => {
  assert.throws(() => createPinataAdapter({ mode: "whatever" }), /unknown storage mode/);
});

test("backend mode posts raw bytes and never sends credentials", async () => {
  let seenUrl = null;
  let seenInit = null;

  const cid = await withFetch(
    async (url, init) => {
      seenUrl = url;
      seenInit = init;
      return jsonResponse({ cid: "bafyTest" });
    },
    () =>
      createPinataAdapter({ mode: "backend", endpoint: "/api/pin", retry: NO_RETRY }).put(
        randomBytes(32),
        "chunk-0"
      )
  );

  assert.equal(cid, "bafyTest");
  assert.equal(seenUrl, "/api/pin");
  assert.equal(seenInit.headers["Content-Type"], "application/octet-stream");
  assert.equal(seenInit.headers["X-Chunk-Name"], "chunk-0");
  assert.equal(
    seenInit.headers.Authorization,
    undefined,
    "backend mode must not attach credentials"
  );
});

test("an upload endpoint that returns no cid is an error", async () => {
  await withFetch(
    async () => jsonResponse({ ok: true }),
    async () => {
      await assert.rejects(
        () => createPinataAdapter({ mode: "backend", retry: NO_RETRY }).put(randomBytes(4)),
        /did not return a cid/
      );
    }
  );
});

test("a failed upload is retried", async () => {
  let calls = 0;
  const cid = await withFetch(
    async () => {
      calls++;
      return calls < 3 ? httpError(502) : jsonResponse({ cid: "bafyRetried" });
    },
    () =>
      createPinataAdapter({
        mode: "backend",
        retry: { maxAttempts: 4, backoffBaseMs: 1 },
      }).put(randomBytes(16))
  );

  assert.equal(cid, "bafyRetried");
  assert.equal(calls, 3);
});

// -------------------------------------------------------------------- putAll

test("putAll uploads every chunk, in order, with bounded concurrency", async () => {
  const chunks = Array.from({ length: 23 }, (_, i) => ({ payload: new Uint8Array([i]) }));
  let inFlight = 0;
  let peak = 0;
  const progress = [];

  const adapter = {
    async put(bytes) {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 1));
      inFlight--;
      return `cid${bytes[0]}`;
    },
  };

  const locations = await putAll(adapter, chunks, {
    concurrency: 4,
    onProgress: (done, total) => progress.push([done, total]),
  });

  assert.equal(locations.length, 23);
  locations.forEach((loc, i) => assert.equal(loc, `cid${i}`, `chunk ${i} out of order`));
  assert.ok(peak <= 4, `concurrency limit exceeded: ${peak}`);
  assert.deepEqual(progress[progress.length - 1], [23, 23]);
});

test("putAll resumes an interrupted upload instead of redoing it", async () => {
  const chunks = Array.from({ length: 10 }, (_, i) => ({ payload: new Uint8Array([i]) }));

  // Six chunks already landed before the connection dropped.
  const resumeFrom = ["a0", "a1", "a2", "a3", "a4", "a5"];
  const uploaded = [];

  const locations = await putAll(
    { async put(bytes) { uploaded.push(bytes[0]); return `new${bytes[0]}`; } },
    chunks,
    { resumeFrom, concurrency: 3 }
  );

  assert.deepEqual(uploaded.sort((a, b) => a - b), [6, 7, 8, 9], "re-uploaded work already done");
  assert.deepEqual(locations.slice(0, 6), resumeFrom, "existing locations were not preserved");
  assert.deepEqual(locations.slice(6), ["new6", "new7", "new8", "new9"]);
});

test("putAll reports progress including chunks skipped by resume", async () => {
  const chunks = Array.from({ length: 4 }, (_, i) => ({ payload: new Uint8Array([i]) }));
  const progress = [];

  await putAll({ async put() { return "x"; } }, chunks, {
    resumeFrom: ["a", "b", null, null],
    onProgress: (done, total) => progress.push([done, total]),
  });

  assert.deepEqual(progress[0], [2, 4], "resumed chunks should count towards progress");
  assert.deepEqual(progress[progress.length - 1], [4, 4]);
});

test("putAll surfaces an upload failure rather than returning a partial list", async () => {
  const chunks = Array.from({ length: 5 }, (_, i) => ({ payload: new Uint8Array([i]) }));
  await assert.rejects(
    () =>
      putAll(
        {
          async put(bytes) {
            if (bytes[0] === 3) throw new Error("pinning service rejected the block");
            return `cid${bytes[0]}`;
          },
        },
        chunks,
        { concurrency: 1 }
      ),
    /pinning service rejected the block/
  );
});

test("putAll stops when aborted", async () => {
  const chunks = Array.from({ length: 50 }, (_, i) => ({ payload: new Uint8Array([i % 256]) }));
  const controller = new AbortController();
  let uploaded = 0;

  await assert.rejects(
    () =>
      putAll(
        {
          async put() {
            uploaded++;
            if (uploaded === 5) controller.abort();
            return "cid";
          },
        },
        chunks,
        { concurrency: 2, signal: controller.signal }
      ),
    (error) => error.name === "AbortError"
  );

  assert.ok(uploaded < 50, `abort did not stop the upload (${uploaded} chunks sent)`);
});

test("putAll handles an empty chunk list", async () => {
  assert.deepEqual(await putAll({ put: async () => "x" }, []), []);
});

test("config selects the adapter", () => {
  assert.equal(createAdapterFromConfig({}).readOnly, true);
  assert.equal(
    createAdapterFromConfig({ storage: { provider: "pinata", mode: "backend" } }).readOnly,
    false
  );
});
