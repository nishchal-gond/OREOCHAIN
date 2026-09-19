/**
 * OREOCHAIN envelope encryption.
 *
 * Design notes (see docs/SECURITY.md for the full rationale):
 *
 *  - Every file gets a fresh random 256-bit *file key*. The passphrase never
 *    encrypts data directly; it only derives a key-encryption key (KEK) that
 *    wraps the file key. Changing a passphrase therefore rewraps 60 bytes
 *    instead of re-encrypting gigabytes.
 *
 *  - Every *chunk* gets its own key and nonce, derived from the file key with
 *    HKDF. Chunk keys are independent: recovering one reveals nothing about the
 *    others, and because each key is used exactly once, nonce reuse — the
 *    failure mode that breaks AES-GCM catastrophically — cannot occur.
 *
 *  - Each chunk is sealed with AES-256-GCM using additional authenticated data
 *    that names the file, the chunk's index and the total chunk count. The
 *    position is therefore part of what the authentication tag covers, so
 *    reordering chunks, duplicating one, truncating the file or splicing in a
 *    chunk from a different file all fail to decrypt rather than silently
 *    producing wrong plaintext.
 *
 * Primitives are the vetted standards (AES-256-GCM, HKDF-SHA256, PBKDF2-SHA256)
 * as implemented by the platform's WebCrypto. The novelty is in how they are
 * composed, not in any home-made cipher.
 */

import { concat, randomBytes, utf8, webcrypto } from "./bytes.js";
import { DEFAULT_SUITE, getSuite } from "./suites.js";
import { DEFAULT_KDF, deriveKeyEncryptionKey, kdfSpec, PBKDF2_DEFAULTS } from "./kdf.js";

// Re-exported so callers have one import for the passphrase path.
export { deriveKeyEncryptionKey, kdfSpec, DEFAULT_KDF };

export const ENVELOPE_VERSION = "oreochain-envelope-v1";

/** Kept for callers that still name PBKDF2 explicitly; see js/core/kdf.js. */
export const DEFAULT_PBKDF2_ITERATIONS = PBKDF2_DEFAULTS.iterations;

const KEY_BITS = 256;
const IV_BYTES = 12; // 96-bit nonce, the size AES-GCM is specified for
const SALT_BYTES = 16;

export function generateFileKey() {
  return randomBytes(KEY_BITS / 8);
}

export function generateSalt() {
  return randomBytes(SALT_BYTES);
}

async function importAesKey(raw, usages) {
  return webcrypto().subtle.importKey("raw", raw, { name: "AES-GCM" }, false, usages);
}

/**
 * Derive a purpose-specific subkey from the file key.
 *
 * `info` domain-separates the derivations, so the manifest key, chunk 0's key
 * and chunk 1's key are unrelated despite sharing one input key.
 */
async function hkdf(fileKey, salt, info, bytes) {
  const subtle = webcrypto().subtle;
  const material = await subtle.importKey("raw", fileKey, "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: utf8(info) },
    material,
    bytes * 8
  );
  return new Uint8Array(bits);
}

/**
 * Derive raw key material for one chunk. The suite name is part of the HKDF
 * info string, so the same file key never produces the same bytes for two
 * different cipher suites.
 */
export async function deriveChunkMaterial(fileKey, fileSalt, index, bytes, suiteName = DEFAULT_SUITE) {
  return hkdf(fileKey, fileSalt, `${ENVELOPE_VERSION}/${suiteName}/chunk/${index}`, bytes);
}

/**
 * Derive the AES key and nonce for one chunk. 44 bytes of HKDF output are split
 * into a 32-byte key and a 12-byte nonce, so both are unique per chunk.
 */
export async function deriveChunkKey(fileKey, fileSalt, index) {
  const material = await deriveChunkMaterial(
    fileKey,
    fileSalt,
    index,
    KEY_BITS / 8 + IV_BYTES,
    DEFAULT_SUITE
  );
  return {
    key: material.subarray(0, KEY_BITS / 8),
    iv: material.subarray(KEY_BITS / 8),
  };
}

export async function deriveManifestKey(fileKey, fileSalt) {
  const material = await hkdf(
    fileKey,
    fileSalt,
    `${ENVELOPE_VERSION}/manifest`,
    KEY_BITS / 8 + IV_BYTES
  );
  return {
    key: material.subarray(0, KEY_BITS / 8),
    iv: material.subarray(KEY_BITS / 8),
  };
}

/**
 * The additional authenticated data bound into every chunk's tag.
 * It is authenticated but not encrypted, and it is reconstructed independently
 * by the reader — so a mismatch means someone moved, swapped or dropped a chunk.
 */
export function chunkAad(fileHashHex, index, totalChunks) {
  return utf8(`${ENVELOPE_VERSION}|${fileHashHex}|${index}|${totalChunks}`);
}

export async function encryptChunk(
  plaintext,
  fileKey,
  fileSalt,
  index,
  aad,
  suiteName = DEFAULT_SUITE
) {
  const suite = getSuite(suiteName);
  const material = await deriveChunkMaterial(
    fileKey,
    fileSalt,
    index,
    suite.materialBytes,
    suiteName
  );
  return suite.seal(material, aad, plaintext);
}

export async function decryptChunk(
  ciphertext,
  fileKey,
  fileSalt,
  index,
  aad,
  suiteName = DEFAULT_SUITE
) {
  const suite = getSuite(suiteName);
  const material = await deriveChunkMaterial(
    fileKey,
    fileSalt,
    index,
    suite.materialBytes,
    suiteName
  );
  try {
    return await suite.open(material, aad, ciphertext);
  } catch (err) {
    throw new Error(
      `chunk ${index} failed authentication — it was modified, truncated, reordered, or belongs to another file`
    );
  }
}

/**
 * Seal the file key under the passphrase-derived KEK.
 *
 * @param {object|string} kdf parameter set, see js/core/kdf.js
 */
export async function wrapFileKey(fileKey, passphrase, kdfSalt, kdf = DEFAULT_KDF) {
  const kek = await deriveKeyEncryptionKey(passphrase, kdfSalt, kdf);
  const cryptoKey = await importAesKey(kek, ["encrypt"]);
  const iv = randomBytes(IV_BYTES);
  const sealed = await webcrypto().subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: utf8(ENVELOPE_VERSION), tagLength: 128 },
    cryptoKey,
    fileKey
  );
  return { iv, ciphertext: new Uint8Array(sealed) };
}

export async function unwrapFileKey(wrapped, passphrase, kdfSalt, kdf = DEFAULT_KDF) {
  const kek = await deriveKeyEncryptionKey(passphrase, kdfSalt, kdf);
  const cryptoKey = await importAesKey(kek, ["decrypt"]);
  try {
    const opened = await webcrypto().subtle.decrypt(
      {
        name: "AES-GCM",
        iv: wrapped.iv,
        additionalData: utf8(ENVELOPE_VERSION),
        tagLength: 128,
      },
      cryptoKey,
      wrapped.ciphertext
    );
    return new Uint8Array(opened);
  } catch (err) {
    throw new Error("wrong passphrase — the file key could not be unwrapped");
  }
}

/** Encrypt arbitrary bytes (used for the manifest body) with a derived subkey. */
export async function sealWithDerivedKey(plaintext, derived, aadString) {
  const cryptoKey = await importAesKey(derived.key, ["encrypt"]);
  const sealed = await webcrypto().subtle.encrypt(
    { name: "AES-GCM", iv: derived.iv, additionalData: utf8(aadString), tagLength: 128 },
    cryptoKey,
    plaintext
  );
  return new Uint8Array(sealed);
}

export async function openWithDerivedKey(ciphertext, derived, aadString) {
  const cryptoKey = await importAesKey(derived.key, ["decrypt"]);
  try {
    const opened = await webcrypto().subtle.decrypt(
      { name: "AES-GCM", iv: derived.iv, additionalData: utf8(aadString), tagLength: 128 },
      cryptoKey,
      ciphertext
    );
    return new Uint8Array(opened);
  } catch (err) {
    throw new Error("manifest failed authentication — it was tampered with or the key is wrong");
  }
}

export const _internals = { concat, IV_BYTES, KEY_BITS, SALT_BYTES };
