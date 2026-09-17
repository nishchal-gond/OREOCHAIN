/**
 * A manifest arrives from whatever storage served the CID. Everyone who can
 * serve those bytes controls every field before a single cryptographic check
 * runs, so these tests treat it as hostile input.
 */

import test from "node:test";
import assert from "node:assert/strict";

import {
  assertWithinBudget,
  ManifestError,
  parseManifestJson,
  validateManifestBody,
  validateManifestHeader,
} from "../js/core/validate.js";
import { MANIFEST_LIMITS } from "../js/core/limits.js";

const HASH = "0x" + "ab".repeat(32);
const ROOT = "0x" + "cd".repeat(32);
const B64 = "AAAAAAAAAAAAAAAAAAAAAA==";
const LIMITS = { minIterations: 1000 };

function header(overrides = {}) {
  return {
    version: "oreochain-manifest-v1",
    encrypted: false,
    fileHash: HASH,
    merkleRoot: ROOT,
    chunkSize: 1024,
    totalChunks: 3,
    fileSize: 3000,
    body: { fileName: "x.bin", mimeType: "application/octet-stream", chunks: [] },
    ...overrides,
  };
}

function body(count, overrides = {}) {
  return {
    fileName: "doc.pdf",
    mimeType: "application/pdf",
    chunks: Array.from({ length: count }, (_, i) => ({
      index: i,
      location: `bafyChunk${i}`,
      plainHash: HASH,
      payloadHash: ROOT,
      plainSize: 1000,
      storedSize: 1016,
    })),
    ...overrides,
  };
}

// ------------------------------------------------------- prototype pollution

test("a manifest containing __proto__ is rejected outright", () => {
  assert.throws(
    () => parseManifestJson('{"version":"v1","__proto__":{"isAdmin":true}}'),
    /forbidden key "__proto__"/
  );
  assert.equal({}.isAdmin, undefined, "Object.prototype was polluted");
});

test("constructor and prototype keys are rejected too", () => {
  assert.throws(() => parseManifestJson('{"constructor":{"x":1}}'), /forbidden key/);
  assert.throws(() => parseManifestJson('{"prototype":{"x":1}}'), /forbidden key/);
});

test("nested pollution attempts are rejected", () => {
  assert.throws(
    () => parseManifestJson('{"body":{"chunks":[{"__proto__":{"polluted":1}}]}}'),
    /forbidden key/
  );
  assert.equal({}.polluted, undefined);
});

test("malformed JSON and non-objects are rejected", () => {
  assert.throws(() => parseManifestJson("not json"), /not valid JSON/);
  assert.throws(() => parseManifestJson("[]"), /must be a JSON object/);
  assert.throws(() => parseManifestJson("null"), /must be a JSON object/);
  assert.throws(() => parseManifestJson('"a string"'), /must be a JSON object/);
  assert.throws(() => parseManifestJson(12345), /must be text/);
});

test("an oversized manifest is rejected before parsing", () => {
  const huge = "x".repeat(MANIFEST_LIMITS.maxManifestBytes + 1);
  assert.throws(() => parseManifestJson(huge), /larger than/);
});

test("a well-formed manifest parses", () => {
  assert.deepEqual(parseManifestJson('{"version":"v1","n":2}'), { version: "v1", n: 2 });
});

// ------------------------------------------------------------ resource bombs

test("an absurd chunk count is rejected instead of hanging the restore loop", () => {
  assert.throws(
    () => validateManifestHeader(header({ totalChunks: 4_000_000_000 })),
    /totalChunks exceeds the maximum/
  );
});

test("an absurd file size is rejected instead of inviting a huge allocation", () => {
  assert.throws(
    () => validateManifestHeader(header({ fileSize: 1e15, totalChunks: 1 })),
    /fileSize exceeds the maximum/
  );
});

test("an absurd chunk size is rejected", () => {
  assert.throws(
    () => validateManifestHeader(header({ chunkSize: 1e12 })),
    /chunkSize exceeds the maximum/
  );
});

test("declared sizes must agree with each other", () => {
  // A manifest claiming a small file but a huge chunk table, or the reverse.
  assert.throws(
    () => validateManifestHeader(header({ fileSize: 100, totalChunks: 5000 })),
    /inconsistent with fileSize/
  );
  assert.throws(
    () => validateManifestHeader(header({ fileSize: 100000, totalChunks: 1 })),
    /inconsistent with fileSize/
  );
});

test("assertWithinBudget refuses a file too large to hold in memory", () => {
  assert.throws(
    () => assertWithinBudget(MANIFEST_LIMITS.maxInMemoryBytes + 1),
    /above the in-memory limit/
  );
  assert.throws(
    () => assertWithinBudget(MANIFEST_LIMITS.maxInMemoryBytes + 1),
    /restoreFileStream/
  );
  assert.doesNotThrow(() => assertWithinBudget(1024));
});

// ------------------------------------------------------------ field validity

test("hashes must be 0x-prefixed 32-byte hex", () => {
  for (const bad of ["", "0x", "deadbeef", HASH.toUpperCase(), HASH + "00", "0xzz".padEnd(66, "0")]) {
    assert.throws(
      () => validateManifestHeader(header({ fileHash: bad })),
      ManifestError,
      `accepted bad hash: ${bad}`
    );
  }
});

test("encrypted manifests must carry complete KDF parameters", () => {
  const base = { encrypted: true, suite: "aes-256-gcm", fileSalt: B64, body: B64 };
  const wrapped = { iv: B64, ciphertext: B64 };

  assert.throws(
    () => validateManifestHeader(header({ ...base, wrappedKey: wrapped })),
    /kdf parameters are missing/
  );
  assert.throws(
    () =>
      validateManifestHeader(
        header({ ...base, wrappedKey: wrapped, kdf: { name: "PBKDF2-SHA256", salt: B64 } })
      ),
    /kdf.iterations must be an integer/
  );
});

test("a manifest weakening the iteration count is rejected", () => {
  // An attacker who can serve the manifest could otherwise set iterations to 1
  // and make an offline attack on the passphrase essentially free.
  const weak = header({
    encrypted: true,
    suite: "aes-256-gcm",
    fileSalt: B64,
    body: B64,
    wrappedKey: { iv: B64, ciphertext: B64 },
    kdf: { name: "PBKDF2-SHA256", iterations: 1, salt: B64 },
  });

  assert.throws(() => validateManifestHeader(weak), /kdf.iterations must be at least 600000/);
});

test("an absurd iteration count is rejected so it cannot be used to hang a client", () => {
  const slow = header({
    encrypted: true,
    suite: "aes-256-gcm",
    fileSalt: B64,
    body: B64,
    wrappedKey: { iv: B64, ciphertext: B64 },
    kdf: { name: "PBKDF2-SHA256", iterations: 10 ** 12, salt: B64 },
  });

  assert.throws(() => validateManifestHeader(slow), /kdf.iterations exceeds the maximum/);
});

test("base64 fields must actually be base64", () => {
  const bad = header({
    encrypted: true,
    suite: "aes-256-gcm",
    fileSalt: "not base64!!",
    body: B64,
    wrappedKey: { iv: B64, ciphertext: B64 },
    kdf: { name: "PBKDF2-SHA256", iterations: 600000, salt: B64 },
  });
  assert.throws(() => validateManifestHeader(bad), /fileSalt is malformed/);
});

test("a valid header passes", () => {
  assert.doesNotThrow(() => validateManifestHeader(header()));
});

// -------------------------------------------------------------- chunk tables

test("the chunk table must match the declared chunk count", () => {
  const manifest = header({ totalChunks: 3, fileSize: 3000 });
  assert.throws(
    () => validateManifestBody(body(2), manifest, LIMITS),
    /has 2 entries but the header declares 3/
  );
});

test("duplicate chunk indices are rejected", () => {
  const manifest = header({ totalChunks: 3, fileSize: 3000 });
  const table = body(3);
  table.chunks[2].index = 1;
  assert.throws(() => validateManifestBody(table, manifest, LIMITS), /duplicate chunk index 1/);
});

test("an out-of-range chunk index is rejected", () => {
  const manifest = header({ totalChunks: 3, fileSize: 3000 });
  const table = body(3);
  table.chunks[1].index = 99;
  assert.throws(() => validateManifestBody(table, manifest, LIMITS), /chunk.index exceeds/);
});

test("chunk sizes must total the declared file size", () => {
  const manifest = header({ totalChunks: 3, fileSize: 3000 });
  const table = body(3);
  table.chunks[0].plainSize = 1;
  assert.throws(() => validateManifestBody(table, manifest, LIMITS), /chunk sizes total/);
});

test("a chunk claiming to be larger than the chunk size is rejected", () => {
  const manifest = header({ totalChunks: 3, fileSize: 3000, chunkSize: 1024 });
  const table = body(3);
  table.chunks[0].plainSize = 999999;
  assert.throws(() => validateManifestBody(table, manifest, LIMITS), /plainSize exceeds/);
});

test("a stored size beyond plaintext plus AEAD overhead is rejected", () => {
  const manifest = header({ totalChunks: 3, fileSize: 3000, chunkSize: 1024 });
  const table = body(3);
  table.chunks[0].storedSize = 1024 + MANIFEST_LIMITS.maxAeadOverhead + 1;
  assert.throws(() => validateManifestBody(table, manifest, LIMITS), /storedSize exceeds/);
});

test("hostile chunk locations are rejected", () => {
  const manifest = header({ totalChunks: 1, fileSize: 1000, chunkSize: 1024 });
  for (const location of ["../../etc/passwd", "http://169.254.169.254/", "a/b", ""]) {
    const table = body(1, { chunks: undefined });
    table.chunks = [
      {
        index: 0,
        location,
        plainHash: HASH,
        payloadHash: ROOT,
        plainSize: 1000,
        storedSize: 1016,
      },
    ];
    assert.throws(
      () => validateManifestBody(table, manifest, LIMITS),
      ManifestError,
      `accepted hostile location: ${location}`
    );
  }
});

test("a chunk table entry that is not an object is rejected", () => {
  const manifest = header({ totalChunks: 1, fileSize: 1000 });
  for (const entry of [null, "string", 42, []]) {
    assert.throws(
      () => validateManifestBody({ fileName: "a", mimeType: "b", chunks: [entry] }, manifest, LIMITS),
      ManifestError
    );
  }
});

test("an overlong file name is rejected", () => {
  const manifest = header({ totalChunks: 1, fileSize: 1000 });
  assert.throws(
    () => validateManifestBody(body(1, { fileName: "x".repeat(513) }), manifest, LIMITS),
    /fileName exceeds/
  );
});

test("a valid chunk table passes", () => {
  const manifest = header({ totalChunks: 3, fileSize: 3000, chunkSize: 1024 });
  assert.doesNotThrow(() => validateManifestBody(body(3), manifest, LIMITS));
});
