import test from "node:test";
import assert from "node:assert/strict";

import { equalBytes, randomBytes, toHex } from "../js/core/bytes.js";
import {
  CASCADE_SUITE,
  DEFAULT_SUITE,
  getSuite,
  listSuites,
  SUITES,
} from "../js/core/suites.js";
import {
  chunkAad,
  decryptChunk,
  deriveChunkMaterial,
  encryptChunk,
  generateFileKey,
  generateSalt,
} from "../js/core/crypto.js";
import { openManifest, packFile, restoreFile, sealManifest } from "../js/core/manifest.js";

const ALL = Object.keys(SUITES);
const TEST_LIMITS = { minIterations: 1000 };
const AAD = chunkAad("0xfeedface", 2, 9);

test("the default suite is hardware-accelerated AES", () => {
  assert.equal(DEFAULT_SUITE, "aes-256-gcm");
  assert.ok(listSuites().length >= 3);
});

test("an unknown suite name is rejected with the valid options", () => {
  assert.throws(() => getSuite("rot13-supreme"), /unknown cipher suite/);
  assert.throws(() => getSuite("rot13-supreme"), /aes-256-gcm/);
});

for (const name of ALL) {
  test(`${name}: seals and opens a chunk`, async () => {
    const fileKey = generateFileKey();
    const fileSalt = generateSalt();
    const plain = randomBytes(4096);

    const sealed = await encryptChunk(plain, fileKey, fileSalt, 2, AAD, name);
    assert.ok(!equalBytes(sealed.subarray(0, plain.length), plain));

    const opened = await decryptChunk(sealed, fileKey, fileSalt, 2, AAD, name);
    assert.ok(equalBytes(opened, plain));
  });

  test(`${name}: detects a flipped ciphertext bit`, async () => {
    const fileKey = generateFileKey();
    const fileSalt = generateSalt();
    const sealed = await encryptChunk(randomBytes(512), fileKey, fileSalt, 2, AAD, name);

    const tampered = sealed.slice();
    tampered[3] ^= 0x80;

    await assert.rejects(
      () => decryptChunk(tampered, fileKey, fileSalt, 2, AAD, name),
      /failed authentication/
    );
  });

  test(`${name}: detects a chunk moved to another position`, async () => {
    const fileKey = generateFileKey();
    const fileSalt = generateSalt();
    const sealed = await encryptChunk(
      randomBytes(256),
      fileKey,
      fileSalt,
      2,
      chunkAad("0xfeedface", 2, 9),
      name
    );

    await assert.rejects(
      () => decryptChunk(sealed, fileKey, fileSalt, 3, chunkAad("0xfeedface", 3, 9), name),
      /failed authentication/
    );
  });
}

test("each suite derives different key material from the same file key", async () => {
  const fileKey = generateFileKey();
  const fileSalt = generateSalt();

  const seen = new Set();
  for (const name of ALL) {
    const material = await deriveChunkMaterial(fileKey, fileSalt, 0, 32, name);
    seen.add(toHex(material));
  }
  assert.equal(seen.size, ALL.length, "suites reused key material");
});

test("a chunk sealed by one suite cannot be opened by another", async () => {
  const fileKey = generateFileKey();
  const fileSalt = generateSalt();
  const sealed = await encryptChunk(randomBytes(256), fileKey, fileSalt, 0, AAD, "aes-256-gcm");

  await assert.rejects(
    () => decryptChunk(sealed, fileKey, fileSalt, 0, AAD, "xchacha20-poly1305"),
    /failed authentication/
  );
});

test("the cascade produces ciphertext distinct from either layer alone", async () => {
  const fileKey = generateFileKey();
  const fileSalt = generateSalt();
  const plain = randomBytes(1024);

  const aes = await encryptChunk(plain, fileKey, fileSalt, 0, AAD, "aes-256-gcm");
  const chacha = await encryptChunk(plain, fileKey, fileSalt, 0, AAD, "xchacha20-poly1305");
  const cascade = await encryptChunk(plain, fileKey, fileSalt, 0, AAD, CASCADE_SUITE);

  assert.ok(!equalBytes(cascade, aes));
  assert.ok(!equalBytes(cascade, chacha));
  // Two AEAD tags instead of one.
  assert.equal(cascade.length, plain.length + SUITES[CASCADE_SUITE].overheadBytes);
});

test("the cascade's two layers use independent key material", async () => {
  const fileKey = generateFileKey();
  const fileSalt = generateSalt();
  const material = await deriveChunkMaterial(
    fileKey,
    fileSalt,
    0,
    SUITES[CASCADE_SUITE].materialBytes,
    CASCADE_SUITE
  );

  const inner = toHex(material.subarray(0, 44));
  const outer = toHex(material.subarray(44));
  assert.notEqual(inner, outer.slice(0, inner.length));
});

test("a full file round-trips under every suite", async () => {
  for (const name of ALL) {
    const data = randomBytes(3000);
    const blocks = new Map();
    let n = 0;

    const packed = await packFile(data, {
      fileName: `${name}.bin`,
      passphrase: "suite-test-passphrase",
      suite: name,
      chunkSize: 1024,
      iterations: 1000,
    });
    const locations = packed.chunks.map((chunk) => {
      const id = `b${n++}`;
      blocks.set(id, chunk.payload);
      return id;
    });
    const manifest = await sealManifest(packed, locations);

    assert.equal(manifest.suite, name);

    const opened = await openManifest(manifest, "suite-test-passphrase", { limits: TEST_LIMITS });
    const restored = await restoreFile(manifest, opened, (loc) => blocks.get(loc), {
      expectedMerkleRoot: manifest.merkleRoot,
      limits: TEST_LIMITS,
    });

    assert.ok(equalBytes(restored.bytes, data), `round trip failed for ${name}`);
    assert.equal(restored.fileName, `${name}.bin`);
  }
});

test("packFile rejects an unknown suite before doing any work", async () => {
  await assert.rejects(
    () => packFile(randomBytes(10), { passphrase: "x", suite: "not-a-suite" }),
    /unknown cipher suite/
  );
});

test("the Merkle root is identical across suites — it commits to plaintext", async () => {
  const data = randomBytes(3000);
  const roots = new Set();

  for (const name of ALL) {
    const packed = await packFile(data, {
      passphrase: "same-passphrase",
      suite: name,
      chunkSize: 1024,
      iterations: 1000,
    });
    roots.add(packed.merkleRootHex);
  }
  assert.equal(roots.size, 1, "encryption choice must not change the on-chain commitment");
});
