import test from "node:test";
import assert from "node:assert/strict";

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

  const wrapped = await wrapFileKey(fileKey, "correct horse battery staple", kdfSalt, FAST);
  const unwrapped = await unwrapFileKey(wrapped, "correct horse battery staple", kdfSalt, FAST);

  assert.ok(equalBytes(unwrapped, fileKey));
});

test("a wrong passphrase fails cleanly instead of returning garbage", async () => {
  const fileKey = generateFileKey();
  const kdfSalt = generateSalt();
  const wrapped = await wrapFileKey(fileKey, "right", kdfSalt, FAST);

  await assert.rejects(
    () => unwrapFileKey(wrapped, "wrong", kdfSalt, FAST),
    /wrong passphrase/
  );
});

test("the same passphrase with a different salt yields a different key", async () => {
  const a = await deriveKeyEncryptionKey("same passphrase", generateSalt(), FAST);
  const b = await deriveKeyEncryptionKey("same passphrase", generateSalt(), FAST);
  assert.notEqual(toHex(a), toHex(b));
});

test("an empty passphrase is refused rather than silently accepted", async () => {
  await assert.rejects(
    () => deriveKeyEncryptionKey("", generateSalt(), FAST),
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
