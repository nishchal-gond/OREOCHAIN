/**
 * Regression tests for the client-side sealing core.
 *
 * Everything here is a bug that was reproduced against the code before it was
 * fixed, and each test fails without its fix. They are grouped in one file
 * because they share a theme rather than a module: these are the failures a
 * user cannot recover from once their file is sealed, uploaded and anchored —
 * a manifest that will never open again, plaintext that was never encrypted,
 * bytes handed to a consumer before anything checked them against the chain.
 */

import test from "node:test";
import assert from "node:assert/strict";

import { concatAll, fromHex, randomBytes, utf8 } from "../js/core/bytes.js";
import { MAX_PROOF_STEPS, verifyMerkleProof } from "../js/core/chunker.js";
import {
  checkChunkProof,
  openManifest,
  packFile,
  readManifest,
  restoreFileStream,
  sealManifest,
} from "../js/core/manifest.js";
import { verifyInBatch } from "../js/core/anchor.js";
import { deriveKeyEncryptionKey } from "../js/core/kdf.js";
import { MANIFEST_LIMITS } from "../js/core/limits.js";

const TEST_KDF = { name: "argon2id", memoryKiB: 8, iterations: 1, parallelism: 1 };
const PASSPHRASE = "a-long-enough-test-passphrase";

// -------------------------------------------------------------- the manifest

/*
 * parseManifestJson() used to scan the raw document for `"__proto__"`,
 * `"constructor"` and `"prototype"`. A scan of text cannot tell a key from a
 * value, so an unencrypted manifest describing a file *named* one of those
 * words was rejected on sight — and stayed rejected, with the chunks already in
 * storage and the root already on-chain.
 */
for (const name of ["constructor", "prototype", "__proto__"]) {
  test(`a file named "${name}" still has a readable manifest`, async () => {
    const packed = await packFile(utf8("hello"), { fileName: name });
    const manifest = await sealManifest(packed, ["QmChunkZero"]);

    const parsed = readManifest(JSON.stringify(manifest));
    assert.equal(parsed.fileHash, manifest.fileHash);

    const opened = await openManifest(parsed, null);
    assert.equal(opened.body.fileName, name);
  });
}

test("a manifest carrying a forbidden key is still rejected, loudly", () => {
  const hostile = '{"version":"oreochain-manifest-v1","__proto__":{"polluted":true}}';
  assert.throws(() => readManifest(hostile), /forbidden key "__proto__"/);
  assert.equal({}.polluted, undefined);
});

/*
 * The manifest body's key AND nonce are both derived from (fileKey, fileSalt),
 * which is safe exactly once. Sealing one packed file twice with different
 * chunk locations — an upload retry that lands on new CIDs — encrypted two
 * plaintexts under one key and nonce, which cancels the keystream and hands
 * anyone holding both manifests the file name and every chunk location without
 * the passphrase.
 */
test("one packed file cannot be sealed twice with different locations", async () => {
  const packed = await packFile(utf8("something private"), {
    fileName: "secret.txt",
    passphrase: PASSPHRASE,
    kdf: TEST_KDF,
  });

  await sealManifest(packed, ["QmFirstLocation"]);
  await assert.rejects(
    () => sealManifest(packed, ["QmSecondLocation"]),
    /already been sealed with a different chunk table/
  );
});

test("re-sealing with the same locations is allowed and deterministic", async () => {
  const packed = await packFile(utf8("something private"), {
    fileName: "secret.txt",
    passphrase: PASSPHRASE,
    kdf: TEST_KDF,
  });

  const first = await sealManifest(packed, ["QmSameLocation"]);
  const second = await sealManifest(packed, ["QmSameLocation"]);
  assert.equal(first.body, second.body);
});

// ------------------------------------------------------------ packing inputs

/*
 * packFile() enforced none of the limits validateManifestHeader() enforces, so
 * it would happily seal, encrypt and hand back a manifest no reader would ever
 * accept.
 */
test("packFile refuses a chunkSize the reader would reject", async () => {
  await assert.rejects(
    () => packFile(utf8("hello"), { chunkSize: MANIFEST_LIMITS.maxChunkSize + 1 }),
    /could never be read back/
  );
});

test("packFile refuses a chunk count above the manifest limit", async () => {
  await assert.rejects(
    () => packFile(randomBytes(4096), { chunkSize: 1, limits: { maxTotalChunks: 1000 } }),
    /above the maximum of 1000/
  );
});

/*
 * `typeof passphrase === "string" && passphrase.length > 0` answered "not
 * encrypted" for an empty string and for a number, so a caller that believed it
 * had encrypted a document got plaintext on a public gateway instead.
 */
test("an empty passphrase is an error, not a silent plaintext upload", async () => {
  await assert.rejects(() => packFile(utf8("secret"), { passphrase: "" }), /passphrase is empty/);
});

test("a non-string passphrase is an error, not a silent plaintext upload", async () => {
  await assert.rejects(
    () => packFile(utf8("secret"), { passphrase: 12345 }),
    /passphrase must be a string or null/
  );
  await assert.rejects(
    () => packFile(utf8("secret"), { passphrase: { value: "x" } }),
    /passphrase must be a string or null/
  );
});

test("passphrase: null still stores in the clear", async () => {
  const packed = await packFile(utf8("public"), { passphrase: null });
  assert.equal(packed.encrypted, false);
});

// ------------------------------------------------------------ the restore path

function memoryFetcher(packed) {
  const payloads = packed.chunks.map((chunk) => chunk.payload);
  return async (_location, entry) => payloads[entry.index];
}

/*
 * The stream's own documentation says the Merkle root is checked before the
 * final chunk is yielded. It was checked after the loop instead, so a consumer
 * piping straight into an HTTP response had already sent every byte — including
 * the last — by the time the root turned out to be wrong. For an unencrypted
 * file that root is the only thing tying the bytes to the on-chain record.
 */
test("the stream withholds the last chunk until the Merkle root checks out", async () => {
  const packed = await packFile(utf8("A".repeat(10)), { fileName: "f.txt", chunkSize: 4 });
  const manifest = await sealManifest(packed, ["QmA", "QmB", "QmC"]);
  const opened = await openManifest(manifest, null);

  const tampered = { ...manifest, merkleRoot: `0x${"11".repeat(32)}` };
  const yielded = [];

  await assert.rejects(async () => {
    for await (const chunk of restoreFileStream(tampered, opened, memoryFetcher(packed))) {
      yielded.push(chunk.index);
    }
  }, /Merkle root does not match/);

  assert.deepEqual(yielded, [0, 1], "the final chunk must not reach the consumer");
});

test("the stream still yields every chunk of an honest file", async () => {
  const packed = await packFile(utf8("A".repeat(10)), { fileName: "f.txt", chunkSize: 4 });
  const manifest = await sealManifest(packed, ["QmA", "QmB", "QmC"]);
  const opened = await openManifest(manifest, null);

  const yielded = [];
  for await (const chunk of restoreFileStream(manifest, opened, memoryFetcher(packed))) {
    yielded.push(chunk.index);
  }
  assert.deepEqual(yielded, [0, 1, 2]);
});

test("a short chunk table cannot slip past the root check", async () => {
  const packed = await packFile(utf8("A".repeat(10)), { fileName: "f.txt", chunkSize: 4 });
  const manifest = await sealManifest(packed, ["QmA", "QmB", "QmC"]);
  const opened = await openManifest(manifest, null);
  const truncated = { ...opened, body: { ...opened.body, chunks: opened.body.chunks.slice(0, 1) } };

  await assert.rejects(async () => {
    for await (const _ of restoreFileStream(manifest, truncated, memoryFetcher(packed)));
  }, /1 entries but the header declares 3/);
});

/*
 * restoreFile() assembled with `concat(...plainChunks)`. Spreading an array
 * puts every element on the call stack, and a file restored at a small chunk
 * size reaches the stack limit well inside the sizes this project permits.
 */
test("assembly survives a chunk count that would overflow the call stack", () => {
  const many = Array.from({ length: 300_000 }, () => new Uint8Array([7]));
  assert.throws(() => concatAll(...many), RangeError, "spreading this many arguments overflows");
  assert.equal(concatAll(many).length, 300_000);
});

// ------------------------------------------------------------------- decoding

/*
 * parseInt("1z", 16) is 1, not NaN, so the old per-pair decode silently
 * invented bytes for malformed hex rather than rejecting the string.
 */
test("fromHex rejects malformed hex instead of inventing bytes", () => {
  assert.throws(() => fromHex("0x1z"), /invalid hex string/);
  assert.throws(() => fromHex("zz"), /invalid hex string/);
  assert.throws(() => fromHex("12 3"), /invalid hex string/);
  assert.throws(() => fromHex("abc"), /odd length/);
  assert.throws(() => fromHex(null), /hex must be a string/);
  assert.deepEqual(fromHex("0xAABB"), new Uint8Array([0xaa, 0xbb]));
});

// --------------------------------------------------------------------- proofs

test("a Merkle proof longer than the tree could be is refused", async () => {
  const step = { hash: new Uint8Array(32), side: "left" };
  const overlong = Array.from({ length: MAX_PROOF_STEPS + 1 }, () => step);
  await assert.rejects(
    () => verifyMerkleProof(new Uint8Array(32), overlong, new Uint8Array(32)),
    /above the maximum/
  );
});

test("a proof step with an unrecognised side is refused, not read as left", async () => {
  await assert.rejects(
    () =>
      verifyMerkleProof(
        new Uint8Array(32),
        [{ hash: new Uint8Array(32), side: "banana" }],
        new Uint8Array(32)
      ),
    /expected "left" or "right"/
  );
});

test("checkChunkProof answers false for hostile input rather than throwing", async () => {
  const leaf = `0x${"11".repeat(32)}`;
  const root = `0x${"22".repeat(32)}`;
  const step = { hash: `0x${"00".repeat(32)}`, side: "left" };

  assert.equal(await checkChunkProof(leaf, Array.from({ length: 5000 }, () => step), root), false);
  assert.equal(await checkChunkProof(leaf, [{ hash: "0xnothex", side: "left" }], root), false);
  assert.equal(await checkChunkProof(leaf, [{ hash: step.hash, side: "up" }], root), false);
  assert.equal(await checkChunkProof(leaf, "not an array", root), false);
});

test("verifyInBatch answers with a reason for hostile input rather than throwing", async () => {
  const document = {
    fileHash: `0x${"11".repeat(32)}`,
    merkleRoot: `0x${"22".repeat(32)}`,
    fileSize: 1,
    manifestCID: "QmSomething",
  };
  const step = { hash: `0x${"00".repeat(32)}`, side: "left" };

  const overlong = await verifyInBatch(
    { fileHash: document.fileHash, document, proof: Array.from({ length: 5000 }, () => step) },
    `0x${"33".repeat(32)}`
  );
  assert.equal(overlong.valid, false);
  assert.match(overlong.reason, /above the maximum/);

  const noPath = await verifyInBatch({ fileHash: document.fileHash, document }, `0x${"33".repeat(32)}`);
  assert.equal(noPath.valid, false);
  assert.match(noPath.reason, /missing its path/);

  const badRoot = await verifyInBatch({ fileHash: document.fileHash, document, proof: [] }, "0xnope");
  assert.equal(badRoot.valid, false);
  assert.match(badRoot.reason, /32-byte hex/);
});

// ------------------------------------------------------------------ the KDF

/*
 * `typeof Worker` is undefined on Node, so defaultWorkerFactory() returned null
 * there and every server-side and CLI derivation ran Argon2id inline — seconds
 * of hashing on the thread that was meant to be serving other requests — even
 * though kdf-worker.js has supported worker_threads all along.
 */
test("Argon2id derivation reaches a worker thread on Node", async () => {
  const salt = randomBytes(16);
  let fellBack = null;

  const viaWorker = await deriveKeyEncryptionKey("a passphrase", salt, TEST_KDF, {
    onFallback: (error) => (fellBack = error),
  });
  const inline = await deriveKeyEncryptionKey("a passphrase", salt, TEST_KDF, { worker: false });

  assert.equal(fellBack, null, "the default factory must produce a worker on Node");
  assert.deepEqual(viaWorker, inline, "the worker must derive the same key as the inline path");
});

test("the event loop keeps running while a derivation is in a worker", async () => {
  // The whole point of the worker: on the inline path this count is 0.
  let ticks = 0;
  const timer = setInterval(() => ticks++, 1);
  try {
    await deriveKeyEncryptionKey("a passphrase", randomBytes(16), {
      name: "argon2id",
      memoryKiB: 4096,
      iterations: 2,
      parallelism: 1,
    });
  } finally {
    clearInterval(timer);
  }
  assert.ok(ticks > 0, `expected the event loop to run during derivation, got ${ticks} ticks`);
});
