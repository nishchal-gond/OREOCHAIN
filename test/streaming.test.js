/**
 * The streaming path is what a server uses: it must verify exactly as strictly
 * as restoreFile() while never holding the whole file.
 */

import test from "node:test";
import assert from "node:assert/strict";

import { concat, equalBytes, randomBytes } from "../js/core/bytes.js";
import {
  openManifest,
  packFile,
  restoreFile,
  restoreFileStream,
  sealManifest,
} from "../js/core/manifest.js";

// Argon2id at production settings costs ~0.7s per derivation, which would make
// this suite take minutes. Tests declare cheap parameters explicitly, and a
// matching floor, rather than silently inheriting defaults.
const TEST_KDF = { name: "argon2id", memoryKiB: 8, iterations: 1, parallelism: 1 };

const PASSPHRASE = "streaming-test-passphrase";
const TEST_LIMITS = { minArgon2MemoryKiB: 8 };

async function build(size, { chunkSize = 1024, passphrase = PASSPHRASE } = {}) {
  const data = randomBytes(size);
  const blocks = new Map();
  let n = 0;

  const packed = await packFile(data, {
    fileName: "stream.bin",
    passphrase,
    chunkSize,
    kdf: TEST_KDF,
  });

  const locations = packed.chunks.map((chunk) => {
    const id = `bafyBlock${n++}`;
    blocks.set(id, chunk.payload);
    return id;
  });

  const manifest = await sealManifest(packed, locations);
  const opened = await openManifest(manifest, passphrase, { limits: TEST_LIMITS });
  return { data, blocks, manifest, opened, fetch: (loc) => blocks.get(loc) };
}

test("the stream yields chunks in order and rebuilds the file", async () => {
  const { data, manifest, opened, fetch } = await build(9000);

  const received = [];
  for await (const chunk of restoreFileStream(manifest, opened, fetch, {
    concurrency: 3,
    limits: TEST_LIMITS,
  })) {
    assert.equal(chunk.index, received.length, "chunks arrived out of order");
    received.push(chunk.bytes);
  }

  assert.equal(received.length, 9);
  assert.ok(equalBytes(concat(...received), data));
});

test("the stream verifies the Merkle root against the chain", async () => {
  const { manifest, opened, fetch } = await build(4000);

  await assert.rejects(async () => {
    for await (const _ of restoreFileStream(manifest, opened, fetch, {
      expectedMerkleRoot: "0x" + "11".repeat(32),
      limits: TEST_LIMITS,
    })) {
      // drain
    }
  }, /does not match the root recorded on-chain/);
});

test("a tampered chunk fails the stream even at high concurrency", async () => {
  // With look-ahead, a bad chunk can reject long before the consumer reaches it.
  const { manifest, opened, blocks, fetch } = await build(20000);

  const ids = [...blocks.keys()];
  const corrupted = blocks.get(ids[15]).slice();
  corrupted[0] ^= 0xff;
  blocks.set(ids[15], corrupted);

  await assert.rejects(async () => {
    for await (const _ of restoreFileStream(manifest, opened, fetch, {
      concurrency: 8,
      limits: TEST_LIMITS,
    })) {
      // drain
    }
  }, /does not match its recorded hash/);
});

test("a chunk of unexpected length is rejected before it is hashed", async () => {
  const { manifest, opened, blocks } = await build(3000);
  const ids = [...blocks.keys()];

  await assert.rejects(async () => {
    for await (const _ of restoreFileStream(
      manifest,
      opened,
      (loc) => (loc === ids[1] ? new Uint8Array(5) : blocks.get(loc)),
      { limits: TEST_LIMITS }
    )) {
      // drain
    }
  }, /but the manifest declares/);
});

test("a fetch returning something other than bytes is rejected", async () => {
  const { manifest, opened } = await build(2000);

  await assert.rejects(async () => {
    for await (const _ of restoreFileStream(manifest, opened, async () => "not bytes", {
      limits: TEST_LIMITS,
    })) {
      // drain
    }
  }, /expected bytes/);
});

test("abandoning the stream early does not leak an unhandled rejection", async () => {
  // Look-ahead fetches are in flight when the consumer breaks out.
  const { manifest, opened, fetch } = await build(30000, { chunkSize: 1024 });

  let seen = 0;
  for await (const _ of restoreFileStream(manifest, opened, fetch, {
    concurrency: 8,
    limits: TEST_LIMITS,
  })) {
    if (++seen === 3) break;
  }

  assert.equal(seen, 3);
  // Give any orphaned promise a tick to reject; an unhandled one fails the run.
  await new Promise((resolve) => setTimeout(resolve, 20));
});

test("an abort signal stops the stream", async () => {
  const { manifest, opened, fetch } = await build(30000);
  const controller = new AbortController();

  let seen = 0;
  await assert.rejects(
    async () => {
      for await (const _ of restoreFileStream(manifest, opened, fetch, {
        concurrency: 2,
        signal: controller.signal,
        limits: TEST_LIMITS,
      })) {
        if (++seen === 4) controller.abort();
      }
    },
    (error) => error.name === "AbortError"
  );

  assert.ok(seen < 29, `abort did not stop the stream (${seen} chunks)`);
});

test("concurrency does not change the result", async () => {
  const { data, manifest, opened, fetch } = await build(12000);

  for (const concurrency of [1, 2, 5, 16, 64]) {
    const parts = [];
    for await (const chunk of restoreFileStream(manifest, opened, fetch, {
      concurrency,
      limits: TEST_LIMITS,
    })) {
      parts.push(chunk.bytes);
    }
    assert.ok(equalBytes(concat(...parts), data), `mismatch at concurrency ${concurrency}`);
  }
});

test("streaming and buffered restore agree", async () => {
  const { data, manifest, opened, fetch } = await build(7000);

  const buffered = await restoreFile(manifest, opened, fetch, { limits: TEST_LIMITS });

  const parts = [];
  for await (const chunk of restoreFileStream(manifest, opened, fetch, { limits: TEST_LIMITS })) {
    parts.push(chunk.bytes);
  }

  assert.ok(equalBytes(buffered.bytes, data));
  assert.ok(equalBytes(concat(...parts), buffered.bytes));
});

test("restoreFile refuses a file above the in-memory budget", async () => {
  const { manifest, opened, fetch } = await build(3000);

  await assert.rejects(
    () =>
      restoreFile(manifest, opened, fetch, {
        limits: { ...TEST_LIMITS, maxInMemoryBytes: 100 },
      }),
    /above the in-memory limit/
  );

  // ...but streaming the same file is fine, which is the point of the limit.
  const parts = [];
  for await (const chunk of restoreFileStream(manifest, opened, fetch, {
    limits: { ...TEST_LIMITS, maxInMemoryBytes: 100 },
  })) {
    parts.push(chunk.bytes);
  }
  assert.equal(parts.length, 3);
});

test("an unencrypted file streams too", async () => {
  const { data, manifest, opened, fetch } = await build(5000, { passphrase: null });
  assert.equal(manifest.encrypted, false);

  const parts = [];
  for await (const chunk of restoreFileStream(manifest, opened, fetch, { limits: TEST_LIMITS })) {
    parts.push(chunk.bytes);
  }
  assert.ok(equalBytes(concat(...parts), data));
});
