/**
 * Cipher suites, and why there is more than one.
 *
 * "Improving" AES or ChaCha20 by editing their internals — fewer/more rounds,
 * a tweaked S-box, different rotation constants — produces a weaker cipher, not
 * a stronger one. Their security is not a property of the design on paper; it
 * is the accumulated result of decades of public cryptanalysis against those
 * exact constants. A modified variant inherits the name and none of the
 * evidence.
 *
 * What genuinely improves on a single cipher is *agility* and *cascading*:
 *
 *   aes-256-gcm          Hardware-accelerated on any modern x86/ARM CPU
 *                        (AES-NI). Fastest option where that hardware exists,
 *                        and the only one available from WebCrypto alone.
 *
 *   xchacha20-poly1305   Faster than AES in pure software (older phones,
 *                        embedded devices, WASM) and immune to the cache-timing
 *                        side channels that table-based AES implementations
 *                        suffer from. Its 192-bit nonce also makes random
 *                        nonces safe at any volume.
 *
 *   cascade-aes-xchacha  Both, in sequence, under independently derived keys.
 *                        Plaintext stays sealed unless BOTH ciphers are broken.
 *                        Roughly 2x the CPU cost — the right default for
 *                        long-lived secrets, overkill for routine documents.
 *
 * Every chunk records which suite sealed it, so the format can migrate to a
 * post-quantum or future AEAD without breaking files already stored. That
 * migration path is the improvement worth engineering; a bespoke cipher is not.
 */

import { concat, webcrypto } from "./bytes.js";

export const DEFAULT_SUITE = "aes-256-gcm";
export const CASCADE_SUITE = "cascade-aes-xchacha";

const AES_KEY_BYTES = 32;
const AES_NONCE_BYTES = 12;
const XCHACHA_KEY_BYTES = 32;
const XCHACHA_NONCE_BYTES = 24;

// XChaCha20-Poly1305 is not part of WebCrypto, so it comes from @noble/ciphers.
// The path resolves identically from a browser (served from the project root)
// and from Node (on disk), so no bundler is required.
const NOBLE_CHACHA_URL = "../../node_modules/@noble/ciphers/esm/chacha.js";

let chachaImpl = null;

/** Inject an XChaCha20-Poly1305 implementation (e.g. from a CDN or a bundler). */
export function registerChaCha(xchacha20poly1305) {
  chachaImpl = xchacha20poly1305;
}

async function loadChaCha() {
  if (chachaImpl) return chachaImpl;
  try {
    const mod = await import(NOBLE_CHACHA_URL);
    chachaImpl = mod.xchacha20poly1305;
    return chachaImpl;
  } catch (err) {
    throw new Error(
      "XChaCha20-Poly1305 is unavailable. Run `npm install` so @noble/ciphers is " +
        "present, or call registerChaCha() with an implementation. " +
        `(${err.message})`
    );
  }
}

async function aesKey(raw, usages) {
  return webcrypto().subtle.importKey("raw", raw, { name: "AES-GCM" }, false, usages);
}

async function aesSeal(material, aad, plaintext) {
  const key = await aesKey(material.subarray(0, AES_KEY_BYTES), ["encrypt"]);
  const iv = material.subarray(AES_KEY_BYTES, AES_KEY_BYTES + AES_NONCE_BYTES);
  const sealed = await webcrypto().subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
    key,
    plaintext
  );
  return new Uint8Array(sealed);
}

async function aesOpen(material, aad, ciphertext) {
  const key = await aesKey(material.subarray(0, AES_KEY_BYTES), ["decrypt"]);
  const iv = material.subarray(AES_KEY_BYTES, AES_KEY_BYTES + AES_NONCE_BYTES);
  const opened = await webcrypto().subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
    key,
    ciphertext
  );
  return new Uint8Array(opened);
}

async function xchachaSeal(material, aad, plaintext) {
  const xchacha = await loadChaCha();
  const key = material.subarray(0, XCHACHA_KEY_BYTES);
  const nonce = material.subarray(XCHACHA_KEY_BYTES, XCHACHA_KEY_BYTES + XCHACHA_NONCE_BYTES);
  return xchacha(key, nonce, aad).encrypt(plaintext);
}

async function xchachaOpen(material, aad, ciphertext) {
  const xchacha = await loadChaCha();
  const key = material.subarray(0, XCHACHA_KEY_BYTES);
  const nonce = material.subarray(XCHACHA_KEY_BYTES, XCHACHA_KEY_BYTES + XCHACHA_NONCE_BYTES);
  return xchacha(key, nonce, aad).decrypt(ciphertext);
}

const AES_MATERIAL = AES_KEY_BYTES + AES_NONCE_BYTES;
const XCHACHA_MATERIAL = XCHACHA_KEY_BYTES + XCHACHA_NONCE_BYTES;

export const SUITES = {
  "aes-256-gcm": {
    name: "aes-256-gcm",
    label: "AES-256-GCM",
    materialBytes: AES_MATERIAL,
    overheadBytes: 16,
    seal: aesSeal,
    open: aesOpen,
  },

  "xchacha20-poly1305": {
    name: "xchacha20-poly1305",
    label: "XChaCha20-Poly1305",
    materialBytes: XCHACHA_MATERIAL,
    overheadBytes: 16,
    seal: xchachaSeal,
    open: xchachaOpen,
  },

  /**
   * Inner AES-256-GCM, then outer XChaCha20-Poly1305, with key material sliced
   * from one HKDF expansion so the two keys are independent. Both layers
   * authenticate the same AAD, so a tampered chunk fails at the outer layer
   * before the inner one is even touched.
   */
  [CASCADE_SUITE]: {
    name: CASCADE_SUITE,
    label: "AES-256-GCM + XChaCha20-Poly1305 (cascade)",
    materialBytes: AES_MATERIAL + XCHACHA_MATERIAL,
    overheadBytes: 32,
    async seal(material, aad, plaintext) {
      const inner = await aesSeal(material.subarray(0, AES_MATERIAL), aad, plaintext);
      return xchachaSeal(material.subarray(AES_MATERIAL), aad, inner);
    },
    async open(material, aad, ciphertext) {
      const inner = await xchachaOpen(material.subarray(AES_MATERIAL), aad, ciphertext);
      return aesOpen(material.subarray(0, AES_MATERIAL), aad, inner);
    },
  },
};

export function getSuite(name = DEFAULT_SUITE) {
  const suite = SUITES[name];
  if (!suite) {
    throw new Error(
      `unknown cipher suite "${name}" — expected one of: ${Object.keys(SUITES).join(", ")}`
    );
  }
  return suite;
}

export function listSuites() {
  return Object.values(SUITES).map((s) => ({
    name: s.name,
    label: s.label,
    overheadBytes: s.overheadBytes,
  }));
}

export const _internals = { concat, AES_MATERIAL, XCHACHA_MATERIAL };
