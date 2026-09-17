import test from "node:test";
import assert from "node:assert/strict";

import { equalBytes, randomBytes } from "../js/core/bytes.js";
import {
  createAdapterFromConfig,
  createGatewayAdapter,
  createPinataAdapter,
  putAll,
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
  return { ok: true, status: 200, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) };
}

test("the gateway adapter falls back to the next gateway on failure", async () => {
  const payload = randomBytes(64);
  const tried = [];

  const result = await withFetch(
    async (url) => {
      tried.push(url);
      if (tried.length < 3) return { ok: false, status: 504, text: async () => "gateway timeout" };
      return okResponse(payload);
    },
    () =>
      createGatewayAdapter({
        gateways: ["https://a/ipfs/", "https://b/ipfs/", "https://c/ipfs/"],
      }).get("CID123")
  );

  assert.equal(tried.length, 3);
  assert.equal(tried[2], "https://c/ipfs/CID123");
  assert.ok(equalBytes(result, payload));
});

test("a fetch that throws is treated as a failed gateway, not a crash", async () => {
  const payload = randomBytes(16);
  const result = await withFetch(
    async (url) => {
      if (url.startsWith("https://a/")) throw new Error("DNS failure");
      return okResponse(payload);
    },
    () => createGatewayAdapter({ gateways: ["https://a/ipfs/", "https://b/ipfs/"] }).get("X")
  );
  assert.ok(equalBytes(result, payload));
});

test("exhausting every gateway reports all the failures", async () => {
  await withFetch(
    async () => ({ ok: false, status: 500, text: async () => "boom" }),
    async () => {
      await assert.rejects(
        () => createGatewayAdapter({ gateways: ["https://a/ipfs/", "https://b/ipfs/"] }).get("X"),
        /could not fetch X from any gateway/
      );
    }
  );
});

test("the read-only adapter refuses uploads", async () => {
  await assert.rejects(() => createGatewayAdapter().put(randomBytes(8)), /read-only/);
});

test("direct mode requires a token and is refused without one", () => {
  assert.throws(
    () => createPinataAdapter({ mode: "direct" }),
    /needs a Pinata JWT/
  );
});

test("an unknown storage mode is rejected", () => {
  assert.throws(() => createPinataAdapter({ mode: "whatever" }), /unknown storage mode/);
});

test("backend mode posts to the configured endpoint and never sends a token", async () => {
  let seenUrl = null;
  let seenHeaders = null;

  const cid = await withFetch(
    async (url, init) => {
      seenUrl = url;
      seenHeaders = init.headers;
      return { ok: true, status: 200, json: async () => ({ cid: "bafyTest" }) };
    },
    () =>
      createPinataAdapter({ mode: "backend", endpoint: "/api/pin" }).put(
        randomBytes(32),
        "chunk-0"
      )
  );

  assert.equal(cid, "bafyTest");
  assert.equal(seenUrl, "/api/pin");
  assert.equal(seenHeaders, undefined, "backend mode must not attach credentials");
});

test("an upload endpoint that returns no cid is an error", async () => {
  await withFetch(
    async () => ({ ok: true, status: 200, json: async () => ({ ok: true }) }),
    async () => {
      await assert.rejects(
        () => createPinataAdapter({ mode: "backend" }).put(randomBytes(4)),
        /did not return a cid/
      );
    }
  );
});

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
      return `cid-${bytes[0]}`;
    },
  };

  const locations = await putAll(adapter, chunks, {
    concurrency: 4,
    onProgress: (done, total) => progress.push([done, total]),
  });

  assert.equal(locations.length, 23);
  locations.forEach((loc, i) => assert.equal(loc, `cid-${i}`, `chunk ${i} out of order`));
  assert.ok(peak <= 4, `concurrency limit exceeded: ${peak}`);
  assert.equal(progress.length, 23);
  assert.deepEqual(progress[22], [23, 23]);
});

test("putAll handles an empty chunk list", async () => {
  const locations = await putAll({ put: async () => "x" }, []);
  assert.deepEqual(locations, []);
});

test("config selects the adapter", () => {
  assert.equal(createAdapterFromConfig({}).readOnly, true);
  assert.equal(
    createAdapterFromConfig({ storage: { provider: "pinata", mode: "backend" } }).readOnly,
    false
  );
});
