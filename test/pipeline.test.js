import test from "node:test";
import assert from "node:assert/strict";

import { equalBytes, fromUtf8, randomBytes, utf8 } from "../js/core/bytes.js";
import {
  checkChunkProof,
  openManifest,
  packFile,
  proveChunk,
  restoreFile,
  sealManifest,
} from "../js/core/manifest.js";
import { splitIntoChunks } from "../js/core/chunker.js";

// Argon2id at production settings costs seconds per derivation — see
// ARGON2ID_PROFILE in js/core/kdf.js for the figure, which is not repeated here
// — and that would make this suite take minutes. Tests declare cheap parameters
// explicitly, and a matching floor, rather than silently inheriting defaults.
const TEST_KDF = { name: "argon2id", memoryKiB: 8, iterations: 1, parallelism: 1 };

const PASSPHRASE = "a-long-enough-test-passphrase";
const FAST = 1000; // keep PBKDF2 cheap in tests

// Manifests made with FAST would be rejected by the production floor of 600k
// iterations, which is exactly what that check is for. Tests opt into a lower
// floor explicitly rather than weakening the validator.
const TEST_LIMITS = { minArgon2MemoryKiB: 8 };

/** An in-memory stand-in for IPFS: content-addressed put/get. */
function memoryStore() {
  const blocks = new Map();
  let counter = 0;
  return {
    blocks,
    async put(bytes) {
      const id = `mem-${counter++}`;
      blocks.set(id, bytes.slice());
      return id;
    },
    async get(id) {
      if (!blocks.has(id)) throw new Error(`no such block: ${id}`);
      return blocks.get(id);
    },
  };
}

async function storeAll(packed, store) {
  const locations = [];
  for (const chunk of packed.chunks) locations.push(await store.put(chunk.payload));
  return sealManifest(packed, locations);
}

async function roundTrip(data, options = {}) {
  const store = memoryStore();
  const packed = await packFile(data, {
    fileName: "test.bin",
    mimeType: "application/octet-stream",
    passphrase: PASSPHRASE,
    chunkSize: 1024,
    kdf: TEST_KDF,
    ...options,
  });
  const manifest = await storeAll(packed, store);
  return { store, packed, manifest };
}

test("a file survives chunking, encryption, storage and reassembly", async () => {
  const data = randomBytes(5000); // spans 5 chunks at 1 KiB
  const { store, manifest } = await roundTrip(data);

  const opened = await openManifest(manifest, PASSPHRASE, { limits: TEST_LIMITS });
  const restored = await restoreFile(manifest, opened, (loc) => store.get(loc), {
    expectedMerkleRoot: manifest.merkleRoot,
    limits: TEST_LIMITS,
  });

  assert.ok(equalBytes(restored.bytes, data));
  assert.equal(restored.fileName, "test.bin");
  assert.equal(manifest.totalChunks, 5);
});

test("binary content is preserved byte-for-byte", async () => {
  // Every possible byte value, including the ones UTF-8 decoding would destroy.
  const data = new Uint8Array(256);
  for (let i = 0; i < 256; i++) data[i] = i;

  const { store, manifest } = await roundTrip(data, { chunkSize: 64 });
  const opened = await openManifest(manifest, PASSPHRASE, { limits: TEST_LIMITS });
  const restored = await restoreFile(manifest, opened, (loc) => store.get(loc), { limits: TEST_LIMITS });

  assert.ok(equalBytes(restored.bytes, data));
});

test("text content round-trips including non-ASCII", async () => {
  const text = "OREOCHAIN 🍪 — café, naïve, 日本語, ₹1000";
  const { store, manifest } = await roundTrip(utf8(text), { chunkSize: 16 });
  const opened = await openManifest(manifest, PASSPHRASE, { limits: TEST_LIMITS });
  const restored = await restoreFile(manifest, opened, (loc) => store.get(loc), { limits: TEST_LIMITS });
  assert.equal(fromUtf8(restored.bytes), text);
});

test("files at and around exact chunk boundaries round-trip", async () => {
  for (const size of [0, 1, 1023, 1024, 1025, 2048]) {
    const data = randomBytes(size);
    const { store, manifest } = await roundTrip(data);
    const opened = await openManifest(manifest, PASSPHRASE, { limits: TEST_LIMITS });
    const restored = await restoreFile(manifest, opened, (loc) => store.get(loc), { limits: TEST_LIMITS });
    assert.ok(equalBytes(restored.bytes, data), `failed at ${size} bytes`);
  }
});

test("chunks are stored encrypted — the plaintext is not recoverable from storage", async () => {
  const marker = utf8("TOP-SECRET-MARKER-STRING-DO-NOT-LEAK");
  const data = new Uint8Array(3000);
  data.set(marker, 100);

  const { store } = await roundTrip(data);

  for (const block of store.blocks.values()) {
    const haystack = Array.from(block).join(",");
    const needle = Array.from(marker).join(",");
    assert.ok(!haystack.includes(needle), "plaintext marker found in stored chunk");
  }
});

test("the manifest hides the file name and chunk locations until unlocked", async () => {
  const { manifest } = await roundTrip(randomBytes(100), { fileName: "payroll-2026.pdf" });
  const serialized = JSON.stringify(manifest);

  assert.ok(!serialized.includes("payroll-2026.pdf"), "file name leaked in manifest header");
  assert.equal(typeof manifest.body, "string", "manifest body should be ciphertext");
  // The public header still carries what the chain needs to verify.
  assert.match(manifest.fileHash, /^0x[0-9a-f]{64}$/);
  assert.match(manifest.merkleRoot, /^0x[0-9a-f]{64}$/);
});

test("the wrong passphrase cannot open the manifest", async () => {
  const { manifest } = await roundTrip(randomBytes(100));
  await assert.rejects(() => openManifest(manifest, "not-the-passphrase", { limits: TEST_LIMITS }), /wrong passphrase/);
});

test("an encrypted manifest refuses to open with no passphrase", async () => {
  const { manifest } = await roundTrip(randomBytes(100));
  await assert.rejects(() => openManifest(manifest, null, { limits: TEST_LIMITS }), /passphrase is required/);
});

test("a tampered stored chunk is caught before decryption", async () => {
  const { store, manifest } = await roundTrip(randomBytes(3000));
  const opened = await openManifest(manifest, PASSPHRASE, { limits: TEST_LIMITS });

  const [firstId] = [...store.blocks.keys()];
  const corrupted = store.blocks.get(firstId).slice();
  corrupted[0] ^= 0xff;
  store.blocks.set(firstId, corrupted);

  await assert.rejects(
    () => restoreFile(manifest, opened, (loc) => store.get(loc), { limits: TEST_LIMITS }),
    /does not match its recorded hash/
  );
});

test("swapping two stored chunks is detected", async () => {
  const { store, manifest } = await roundTrip(randomBytes(3000));
  const opened = await openManifest(manifest, PASSPHRASE, { limits: TEST_LIMITS });

  const ids = [...store.blocks.keys()];
  const a = store.blocks.get(ids[0]);
  const b = store.blocks.get(ids[1]);
  store.blocks.set(ids[0], b);
  store.blocks.set(ids[1], a);

  await assert.rejects(() => restoreFile(manifest, opened, (loc) => store.get(loc), { limits: TEST_LIMITS }));
});

test("a chunk replaced with one from another file is detected", async () => {
  const first = await roundTrip(randomBytes(3000));
  const second = await roundTrip(randomBytes(3000));

  const opened = await openManifest(first.manifest, PASSPHRASE, { limits: TEST_LIMITS });
  const victimId = [...first.store.blocks.keys()][1];
  const intruder = [...second.store.blocks.values()][1];
  first.store.blocks.set(victimId, intruder);

  await assert.rejects(
    () => restoreFile(first.manifest, opened, (loc) => first.store.get(loc), {
        limits: TEST_LIMITS,
      })
  );
});

test("a manifest claiming a different on-chain root is rejected", async () => {
  const { store, manifest } = await roundTrip(randomBytes(2000));
  const opened = await openManifest(manifest, PASSPHRASE, { limits: TEST_LIMITS });

  await assert.rejects(
    () =>
      restoreFile(manifest, opened, (loc) => store.get(loc), {
        expectedMerkleRoot: "0x" + "11".repeat(32),
        limits: TEST_LIMITS,
      }),
    /does not match the root recorded on-chain/
  );
});

test("a manifest with a missing chunk entry is rejected", async () => {
  const { store, manifest } = await roundTrip(randomBytes(3000));
  const opened = await openManifest(manifest, PASSPHRASE, { limits: TEST_LIMITS });
  opened.body.chunks.splice(1, 1);

  await assert.rejects(
    () => restoreFile(manifest, opened, (loc) => store.get(loc), { limits: TEST_LIMITS }),
    /declares|gap at index/
  );
});

test("sealManifest refuses a mismatched number of locations", async () => {
  const packed = await packFile(randomBytes(3000), {
    passphrase: PASSPHRASE,
    chunkSize: 1024,
    kdf: TEST_KDF,
  });
  await assert.rejects(() => sealManifest(packed, ["only-one"]), /expected 3 chunk locations/);
  await assert.rejects(() => sealManifest(packed, null), /expected 3 chunk locations/);
});

test("public (unencrypted) mode still chunks and verifies", async () => {
  const data = utf8("a public certificate that anyone may read");
  const store = memoryStore();
  const packed = await packFile(data, {
    fileName: "certificate.txt",
    passphrase: null,
    chunkSize: 16,
  });
  const manifest = await storeAll(packed, store);

  assert.equal(manifest.encrypted, false);
  assert.equal(typeof manifest.body, "object");

  const opened = await openManifest(manifest, null, { limits: TEST_LIMITS });
  const restored = await restoreFile(manifest, opened, (loc) => store.get(loc), {
    expectedMerkleRoot: manifest.merkleRoot,
    limits: TEST_LIMITS,
  });
  assert.ok(equalBytes(restored.bytes, data));
});

test("a single chunk can be proven against the on-chain root", async () => {
  const data = randomBytes(5000);
  const chunks = splitIntoChunks(data, 1024);

  for (let i = 0; i < chunks.length; i++) {
    const proof = await proveChunk(chunks, i);
    assert.ok(await checkChunkProof(proof.leaf, proof.proof, proof.root), `chunk ${i}`);
  }
});

test("a chunk proof from a different file does not verify", async () => {
  const a = splitIntoChunks(randomBytes(5000), 1024);
  const b = splitIntoChunks(randomBytes(5000), 1024);

  const proofA = await proveChunk(a, 2);
  const proofB = await proveChunk(b, 2);

  assert.equal(await checkChunkProof(proofA.leaf, proofA.proof, proofB.root), false);
});

test("two uploads of the same file produce different ciphertext", async () => {
  // Random per-file keys mean identical documents are not linkable in storage.
  const data = randomBytes(2000);
  const first = await roundTrip(data);
  const second = await roundTrip(data);

  const a = [...first.store.blocks.values()][0];
  const b = [...second.store.blocks.values()][0];
  assert.ok(!equalBytes(a, b), "identical plaintext produced identical ciphertext");

  // ...but the public file hash and Merkle root still match, so the chain can
  // recognise it as the same document.
  assert.equal(first.manifest.fileHash, second.manifest.fileHash);
  assert.equal(first.manifest.merkleRoot, second.manifest.merkleRoot);
});
