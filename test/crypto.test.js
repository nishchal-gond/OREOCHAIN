import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { equalBytes, randomBytes, toHex, utf8 } from "../js/core/bytes.js";
import {
  chunkAad,
  decryptChunk,
  DEFAULT_PBKDF2_ITERATIONS,
  deriveChunkKey,
  deriveKeyEncryptionKey,
  deriveManifestKey,
  encryptChunk,
  generateFileKey,
  generateSalt,
  unwrapFileKey,
  wrapFileKey,
} from "../js/core/crypto.js";

// Argon2id at production settings costs ~0.7s per derivation, which would make
// this suite take minutes. Tests declare cheap parameters explicitly, and a
// matching floor, rather than silently inheriting defaults.
const TEST_KDF = { name: "argon2id", memoryKiB: 8, iterations: 1, parallelism: 1 };

// Tests use a low iteration count for speed; production uses the default.
const FAST = 1000;
const AAD = chunkAad("0xdeadbeef", 0, 1);

test("the shipped PBKDF2 iteration count meets the OWASP floor", () => {
  assert.ok(
    DEFAULT_PBKDF2_ITERATIONS >= 600000,
    `expected >= 600000 iterations, got ${DEFAULT_PBKDF2_ITERATIONS}`
  );
});

test("every chunk gets a distinct key and a distinct nonce", async () => {
  const fileKey = generateFileKey();
  const fileSalt = generateSalt();

  const seenKeys = new Set();
  const seenIvs = new Set();
  for (let i = 0; i < 64; i++) {
    const { key, iv } = await deriveChunkKey(fileKey, fileSalt, i);
    seenKeys.add(toHex(key));
    seenIvs.add(toHex(iv));
  }
  assert.equal(seenKeys.size, 64, "chunk keys repeated");
  assert.equal(seenIvs.size, 64, "chunk nonces repeated — AES-GCM would be broken");
});

test("the manifest key is unrelated to any chunk key", async () => {
  const fileKey = generateFileKey();
  const fileSalt = generateSalt();

  const manifestKey = await deriveManifestKey(fileKey, fileSalt);
  for (let i = 0; i < 8; i++) {
    const chunk = await deriveChunkKey(fileKey, fileSalt, i);
    assert.notEqual(toHex(manifestKey.key), toHex(chunk.key));
  }
});

test("two files never share chunk keys, even with the same passphrase", async () => {
  const salt = generateSalt();
  const a = await deriveChunkKey(generateFileKey(), salt, 0);
  const b = await deriveChunkKey(generateFileKey(), salt, 0);
  assert.notEqual(toHex(a.key), toHex(b.key));
});

test("key derivation is deterministic for the same inputs", async () => {
  const fileKey = generateFileKey();
  const fileSalt = generateSalt();
  const a = await deriveChunkKey(fileKey, fileSalt, 7);
  const b = await deriveChunkKey(fileKey, fileSalt, 7);
  assert.ok(equalBytes(a.key, b.key));
  assert.ok(equalBytes(a.iv, b.iv));
});

test("a chunk encrypts and decrypts back to the original bytes", async () => {
  const fileKey = generateFileKey();
  const fileSalt = generateSalt();
  const plain = randomBytes(4096);

  const sealed = await encryptChunk(plain, fileKey, fileSalt, 0, AAD);
  assert.ok(!equalBytes(sealed.subarray(0, plain.length), plain), "ciphertext equals plaintext");

  const opened = await decryptChunk(sealed, fileKey, fileSalt, 0, AAD);
  assert.ok(equalBytes(opened, plain));
});

test("flipping one bit of ciphertext is detected", async () => {
  const fileKey = generateFileKey();
  const fileSalt = generateSalt();
  const sealed = await encryptChunk(randomBytes(512), fileKey, fileSalt, 0, AAD);

  const tampered = sealed.slice();
  tampered[10] ^= 0x01;

  await assert.rejects(
    () => decryptChunk(tampered, fileKey, fileSalt, 0, AAD),
    /failed authentication/
  );
});

test("truncating the authentication tag is detected", async () => {
  const fileKey = generateFileKey();
  const fileSalt = generateSalt();
  const sealed = await encryptChunk(randomBytes(512), fileKey, fileSalt, 0, AAD);

  await assert.rejects(
    () => decryptChunk(sealed.subarray(0, sealed.length - 1), fileKey, fileSalt, 0, AAD),
    /failed authentication/
  );
});

test("a chunk cannot be decrypted at a different position", async () => {
  // This is the property that makes chunk reordering and splicing detectable.
  const fileKey = generateFileKey();
  const fileSalt = generateSalt();
  const plain = randomBytes(256);

  const sealedAt3 = await encryptChunk(
    plain,
    fileKey,
    fileSalt,
    3,
    chunkAad("0xabc", 3, 10)
  );

  await assert.rejects(
    () => decryptChunk(sealedAt3, fileKey, fileSalt, 4, chunkAad("0xabc", 4, 10)),
    /failed authentication/
  );
});

test("a chunk cannot be replayed into a different file", async () => {
  const fileKey = generateFileKey();
  const fileSalt = generateSalt();
  const plain = randomBytes(256);

  const sealed = await encryptChunk(plain, fileKey, fileSalt, 0, chunkAad("0xaaa", 0, 1));

  await assert.rejects(
    () => decryptChunk(sealed, fileKey, fileSalt, 0, chunkAad("0xbbb", 0, 1)),
    /failed authentication/
  );
});

test("changing the declared chunk count is detected", async () => {
  // Defeats truncation: dropping the tail and claiming the file was shorter.
  const fileKey = generateFileKey();
  const fileSalt = generateSalt();
  const sealed = await encryptChunk(
    randomBytes(256),
    fileKey,
    fileSalt,
    0,
    chunkAad("0xaaa", 0, 10)
  );

  await assert.rejects(
    () => decryptChunk(sealed, fileKey, fileSalt, 0, chunkAad("0xaaa", 0, 9)),
    /failed authentication/
  );
});

test("the file key round-trips through passphrase wrapping", async () => {
  const fileKey = generateFileKey();
  const kdfSalt = generateSalt();

  const wrapped = await wrapFileKey(fileKey, "correct horse battery staple", kdfSalt, TEST_KDF);
  const unwrapped = await unwrapFileKey(wrapped, "correct horse battery staple", kdfSalt, TEST_KDF);

  assert.ok(equalBytes(unwrapped, fileKey));
});

test("a wrong passphrase fails cleanly instead of returning garbage", async () => {
  const fileKey = generateFileKey();
  const kdfSalt = generateSalt();
  const wrapped = await wrapFileKey(fileKey, "right", kdfSalt, TEST_KDF);

  await assert.rejects(
    () => unwrapFileKey(wrapped, "wrong", kdfSalt, TEST_KDF),
    /wrong passphrase/
  );
});

test("the same passphrase with a different salt yields a different key", async () => {
  const a = await deriveKeyEncryptionKey("same passphrase", generateSalt(), TEST_KDF);
  const b = await deriveKeyEncryptionKey("same passphrase", generateSalt(), TEST_KDF);
  assert.notEqual(toHex(a), toHex(b));
});

test("an empty passphrase is refused rather than silently accepted", async () => {
  await assert.rejects(
    () => deriveKeyEncryptionKey("", generateSalt(), TEST_KDF),
    /passphrase is required/
  );
});

test("the additional authenticated data pins file, index and count", () => {
  const aad = new TextDecoder().decode(chunkAad("0xfeed", 5, 12));
  assert.match(aad, /0xfeed/);
  assert.match(aad, /\|5\|/);
  assert.match(aad, /\|12$/);
  assert.notEqual(toHex(chunkAad("0xfeed", 5, 12)), toHex(chunkAad("0xfeed", 6, 12)));
  assert.ok(utf8("sanity").length === 6);
});

test("the crypto core works without globalThis.crypto", () => {
  /*
   * Node exposed Web Crypto as a global only from v19. On v18 the same
   * implementation exists but must be taken off node:crypto, and every
   * cryptographic operation in this project failed there — 129 tests at once —
   * until bytes.js learned to fall back.
   *
   * A child process with the global deleted reproduces that runtime exactly,
   * which is the only way to cover it from a newer Node.
   */
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const script = `
    delete globalThis.crypto;
    const { sha256 } = await import(${JSON.stringify(`${root}/js/core/chunker.js`)});
    const { toHex } = await import(${JSON.stringify(`${root}/js/core/bytes.js`)});
    const {
      generateFileKey, generateSalt, chunkAad, encryptChunk, decryptChunk,
    } = await import(${JSON.stringify(`${root}/js/core/crypto.js`)});

    const digest = toHex(await sha256(new Uint8Array([1, 2, 3])));

    const key = generateFileKey();
    const salt = generateSalt();
    const aad = chunkAad("0xab", 0, 1);
    const sealed = await encryptChunk(new Uint8Array([9, 9, 9]), key, salt, 0, aad);
    const opened = await decryptChunk(sealed, key, salt, 0, aad);

    console.log(JSON.stringify({ digest, opened: Array.from(opened) }));
  `;

  const output = execFileSync(process.execPath, ["--input-type=module", "-e", script], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });

  const result = JSON.parse(output.trim().split("\n").pop());
  // SHA-256 of the bytes 01 02 03.
  assert.equal(
    result.digest,
    "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81"
  );
  assert.deepEqual(result.opened, [9, 9, 9]);
});
