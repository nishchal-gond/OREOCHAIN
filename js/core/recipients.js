/**
 * Sharing a document without sharing a passphrase.
 *
 * The passphrase path wraps the file key under a key derived from something a
 * person knows. That works for one person. It does not work for three, because
 * the only way to let a second person open the file is to tell them the
 * passphrase — and a passphrase, once told, cannot be untold, covers every file
 * it ever protected, and is as strong as the weakest place its holder wrote it
 * down.
 *
 * So the file key is additionally wrapped to *public keys*. Each recipient
 * generates a keypair once, publishes the public half, and keeps the private
 * half. Anyone can seal a file to them; only they can open it. Revoking a
 * recipient is re-sealing without them rather than a conversation about
 * changing a shared secret.
 *
 * THE SCHEME
 * ----------
 * One ephemeral-static ECDH per recipient — the classic ECIES construction,
 * with the file key as the payload:
 *
 *   (e, E)  = a fresh P-256 keypair, generated per recipient per file
 *   Z       = ECDH(e, R)                        // R is the recipient's public key
 *   key‖iv  = HKDF-SHA256(Z, salt=fileSalt, info=<version> ‖ E ‖ R)
 *   entry   = E, AES-256-GCM(key, iv, fileKey, aad=<envelope>|recipient|<fileHash>)
 *
 * P-256 rather than X25519, which is the nicer curve: this has to run in
 * whatever browser the person opening the document happens to have, and P-256
 * ECDH is the one asymmetric primitive WebCrypto has offered everywhere for a
 * decade. X25519 reached WebCrypto in Chrome only in 2025 and is not universal
 * yet. A sharing feature that works for the sender and fails for the recipient
 * is not a sharing feature, and the alternative — shipping a curve
 * implementation of our own — trades a platform primitive for code this project
 * would then have to be trusted to have got right.
 *
 * Both public keys go into the HKDF info, so the wrapping key is bound to the
 * exact pair it was agreed between. Without that binding an attacker who
 * re-points an entry at a key of their own produces a wrap that still derives
 * cleanly — the unknown key-share shape, where two parties agree on a key while
 * disagreeing about who they agreed it with.
 *
 * The file hash goes into the AEAD's additional data, so an entry cannot be
 * lifted out of one file's manifest and pasted into another's: it will not open
 * against a different file's hash.
 *
 * The nonce is derived alongside the key rather than stored. It is a function
 * of a freshly generated ephemeral key, so it is unique by construction, and
 * deriving it removes a field a hostile manifest would otherwise get to choose.
 *
 * WHAT THE MANIFEST DOES NOT SAY
 * ------------------------------
 * An entry is an ephemeral public key and a ciphertext. It does not name the
 * recipient, or carry a key id, or a fingerprint — because the manifest header
 * is public, and a list of recipient keys in it publishes who a document was
 * shared with to everyone who can fetch the CID. That is often the most
 * sensitive fact about a document; the file's existence is rarely news, but who
 * received it is.
 *
 * The cost is that opening a file means trying each entry in turn until one
 * decrypts. That is one ECDH and one AES-GCM open per entry, bounded by
 * MANIFEST_LIMITS.maxRecipients, which is microseconds against an Argon2id
 * derivation measured in seconds.
 */

import {
  concatAll,
  fromBase64Url,
  randomBytes,
  toBase64Url,
  utf8,
  webcrypto,
} from "./bytes.js";
import { ENVELOPE_VERSION } from "./crypto.js";
import { MANIFEST_LIMITS } from "./limits.js";

/** Bumped if the derivation or the wire shape of an entry ever changes. */
export const RECIPIENT_WRAP_VERSION = "oreochain-recipient-wrap-v1";

const CURVE = "P-256";

/** Uncompressed point: 0x04 ‖ X ‖ Y. */
const PUBLIC_KEY_BYTES = 65;
const SCALAR_BYTES = 32;
/** A private identity carries its own public half so a sender can be told it. */
const IDENTITY_BYTES = SCALAR_BYTES + PUBLIC_KEY_BYTES;

const WRAP_KEY_BYTES = 32;
const WRAP_IV_BYTES = 12;
/** A 32-byte file key sealed under AES-256-GCM, with its 16-byte tag. */
const WRAPPED_KEY_BYTES = 32 + 16;

/**
 * The two halves are prefixed, and differently, because the failure this
 * prevents is unrecoverable: a person who pastes their identity where a
 * recipient key belongs publishes their private key inside a manifest that
 * anyone can fetch, and every file ever sealed to that key is open from then
 * on. A shared prefix would make the two look interchangeable at a glance.
 * These do not, and parseRecipient() refuses an identity by name rather than
 * by a decoding error.
 */
export const RECIPIENT_PREFIX = "oreo-recipient-v1:";
export const IDENTITY_PREFIX = "oreo-identity-v1:";

/** base64url of the longest legal entry field, for the validator's bounds. */
export const RECIPIENT_FIELD_LIMITS = {
  ephemeral: Math.ceil((PUBLIC_KEY_BYTES * 4) / 3),
  ciphertext: Math.ceil((WRAPPED_KEY_BYTES * 4) / 3),
};

/**
 * Generate a recipient keypair.
 *
 * @returns {Promise<{recipient: string, identity: string}>} the public half to
 *   publish, and the private half to keep. Both are single-line strings.
 */
export async function generateIdentity() {
  const subtle = webcrypto().subtle;
  const pair = await subtle.generateKey({ name: "ECDH", namedCurve: CURVE }, true, [
    "deriveBits",
  ]);

  const publicKey = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  const jwk = await subtle.exportKey("jwk", pair.privateKey);
  const scalar = fromBase64Url(jwk.d);

  // Exported as raw scalar ‖ raw point rather than PKCS#8, so the format is
  // fixed-length and has no DER parser between a person's key and their file.
  if (scalar.length !== SCALAR_BYTES || publicKey.length !== PUBLIC_KEY_BYTES) {
    throw new Error("WebCrypto returned an unexpected P-256 key shape");
  }

  return {
    recipient: RECIPIENT_PREFIX + toBase64Url(publicKey),
    identity: IDENTITY_PREFIX + toBase64Url(concatAll([scalar, publicKey])),
  };
}

/** The public half of an identity, to hand to whoever is sealing a file. */
export function recipientOf(identity) {
  const { publicKey } = parseIdentity(identity);
  return RECIPIENT_PREFIX + toBase64Url(publicKey);
}

function decode(text, prefix, expectedBytes, what) {
  if (typeof text !== "string") throw new Error(`${what} must be a string`);
  const trimmed = text.trim();

  if (!trimmed.startsWith(prefix)) {
    // Naming the other half explicitly: "malformed recipient key" would send
    // someone looking for a typo in a string that is not a typo at all.
    const other = prefix === RECIPIENT_PREFIX ? IDENTITY_PREFIX : RECIPIENT_PREFIX;
    if (trimmed.startsWith(other)) {
      throw new Error(
        prefix === RECIPIENT_PREFIX
          ? "that is a private identity, not a recipient key — share the " +
            "recipient key that was generated alongside it, and never put an " +
            "identity anywhere it would end up in a manifest"
          : "that is a public recipient key, not an identity — opening a file needs the private half"
      );
    }
    throw new Error(`${what} must start with "${prefix}"`);
  }

  let bytes;
  try {
    bytes = fromBase64Url(trimmed.slice(prefix.length));
  } catch (error) {
    throw new Error(`${what} is malformed (${error.message})`);
  }
  if (bytes.length !== expectedBytes) {
    throw new Error(`${what} must decode to ${expectedBytes} bytes, got ${bytes.length}`);
  }
  return bytes;
}

/** Decode a recipient key. Throws for anything that is not one. */
export function parseRecipient(recipient) {
  const publicKey = decode(recipient, RECIPIENT_PREFIX, PUBLIC_KEY_BYTES, "recipient key");
  if (publicKey[0] !== 0x04) {
    throw new Error("recipient key is not an uncompressed P-256 point");
  }
  return publicKey;
}

/** Decode an identity into its private scalar and its public point. */
export function parseIdentity(identity) {
  const bytes = decode(identity, IDENTITY_PREFIX, IDENTITY_BYTES, "identity");
  const publicKey = bytes.subarray(SCALAR_BYTES);
  if (publicKey[0] !== 0x04) {
    throw new Error("identity does not carry an uncompressed P-256 point");
  }
  return { scalar: bytes.subarray(0, SCALAR_BYTES), publicKey };
}

/**
 * Import a public point.
 *
 * WebCrypto checks that the point is on the curve and is not the identity
 * element, which is what makes an invalid-curve attack — feeding a "public key"
 * from a weaker curve to harvest the private scalar one ECDH at a time —
 * a rejection here rather than a slow key recovery. Nothing in this module
 * touches a point that has not been through this function.
 */
async function importPublicKey(publicKey, what) {
  try {
    return await webcrypto().subtle.importKey(
      "raw",
      publicKey,
      { name: "ECDH", namedCurve: CURVE },
      false,
      []
    );
  } catch (error) {
    throw new Error(`${what} is not a valid P-256 public key (${error.message})`);
  }
}

async function importPrivateKey({ scalar, publicKey }) {
  const jwk = {
    kty: "EC",
    crv: CURVE,
    d: toBase64Url(scalar),
    x: toBase64Url(publicKey.subarray(1, 1 + SCALAR_BYTES)),
    y: toBase64Url(publicKey.subarray(1 + SCALAR_BYTES)),
    ext: true,
    key_ops: ["deriveBits"],
  };
  try {
    return await webcrypto().subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDH", namedCurve: CURVE },
      false,
      ["deriveBits"]
    );
  } catch (error) {
    // Reached when the scalar and the point in an identity do not belong
    // together, which no generated identity ever is.
    throw new Error(`identity is not a usable P-256 private key (${error.message})`);
  }
}

/**
 * The AEAD's additional data. Authenticated, not encrypted, and rebuilt
 * independently by the reader from the manifest header it is opening — so an
 * entry copied here from another file's manifest fails to open.
 */
function wrapAad(fileHashHex) {
  return utf8(`${ENVELOPE_VERSION}|recipient|${fileHashHex}`);
}

/**
 * Agree the wrapping key and nonce for one (ephemeral, recipient) pair.
 *
 * Both public keys are in the HKDF info; the file's salt is the HKDF salt, so
 * the same pair of keys wrapping two different files agrees two unrelated keys.
 */
async function deriveWrapMaterial(privateKey, peerPublicKey, ephemeral, recipient, fileSalt) {
  const subtle = webcrypto().subtle;

  const shared = new Uint8Array(
    await subtle.deriveBits({ name: "ECDH", public: peerPublicKey }, privateKey, SCALAR_BYTES * 8)
  );
  const material = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  // The raw ECDH output is a group element, not a key: it has structure, and
  // is never used as one. HKDF is what turns it into uniform key bytes.
  shared.fill(0);

  const info = concatAll([utf8(`${RECIPIENT_WRAP_VERSION}|`), ephemeral, recipient]);
  const bits = new Uint8Array(
    await subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: fileSalt, info },
      material,
      (WRAP_KEY_BYTES + WRAP_IV_BYTES) * 8
    )
  );

  return { key: bits.subarray(0, WRAP_KEY_BYTES), iv: bits.subarray(WRAP_KEY_BYTES) };
}

async function aesKey(raw, usages) {
  return webcrypto().subtle.importKey("raw", raw, { name: "AES-GCM" }, false, usages);
}

/**
 * Wrap one file key to each recipient.
 *
 * @param {Uint8Array} fileKey the 32-byte file key from generateFileKey()
 * @param {string[]} recipients public recipient keys
 * @param {object} context
 * @param {Uint8Array} context.fileSalt the manifest's file salt
 * @param {string} context.fileHashHex the plaintext file hash, 0x-prefixed
 * @param {object} [context.limits] overrides for MANIFEST_LIMITS
 * @returns {Promise<Array<{ephemeral: string, ciphertext: string}>>}
 */
export async function wrapToRecipients(fileKey, recipients, context = {}) {
  const { fileSalt, fileHashHex, limits = {} } = context;
  const bounds = { ...MANIFEST_LIMITS, ...limits };

  if (!(fileKey instanceof Uint8Array) || fileKey.length !== WRAP_KEY_BYTES) {
    throw new Error(`fileKey must be ${WRAP_KEY_BYTES} bytes`);
  }
  if (!(fileSalt instanceof Uint8Array) || fileSalt.length === 0) {
    throw new Error("fileSalt is required to wrap a file key to a recipient");
  }
  if (typeof fileHashHex !== "string" || fileHashHex.length === 0) {
    throw new Error("fileHashHex is required to wrap a file key to a recipient");
  }
  if (!Array.isArray(recipients) || recipients.length === 0) {
    throw new Error("wrapToRecipients needs at least one recipient");
  }
  if (recipients.length > bounds.maxRecipients) {
    throw new Error(
      `${recipients.length} recipients is above the maximum of ${bounds.maxRecipients}`
    );
  }

  const parsed = recipients.map(parseRecipient);

  // A repeated recipient is a duplicate entry that opens for the same person
  // twice. Harmless, but it is a symptom — a list built by concatenation, or a
  // key pasted twice where a second person's was meant to go — and the second
  // of those means someone is missing from a share they were promised.
  const seen = new Set();
  for (const publicKey of parsed) {
    const key = toBase64Url(publicKey);
    if (seen.has(key)) throw new Error("the same recipient key appears more than once");
    seen.add(key);
  }

  const aad = wrapAad(fileHashHex);
  const entries = [];

  for (const recipient of parsed) {
    const peer = await importPublicKey(recipient, "recipient key");
    const pair = await webcrypto().subtle.generateKey(
      { name: "ECDH", namedCurve: CURVE },
      true,
      ["deriveBits"]
    );
    const ephemeral = new Uint8Array(
      await webcrypto().subtle.exportKey("raw", pair.publicKey)
    );

    const wrap = await deriveWrapMaterial(pair.privateKey, peer, ephemeral, recipient, fileSalt);
    const sealed = new Uint8Array(
      await webcrypto().subtle.encrypt(
        { name: "AES-GCM", iv: wrap.iv, additionalData: aad, tagLength: 128 },
        await aesKey(wrap.key, ["encrypt"]),
        fileKey
      )
    );
    wrap.key.fill(0);

    entries.push({ ephemeral: toBase64Url(ephemeral), ciphertext: toBase64Url(sealed) });
  }

  return entries;
}

/**
 * Recover the file key from whichever entry belongs to this identity.
 *
 * Entries carry no recipient identifier — see the note at the top of this file
 * — so this tries each in turn. A failure to open is the ordinary case for
 * every entry but one, not an error, and is why the loop swallows them.
 *
 * @param {Array<{ephemeral: string, ciphertext: string}>} entries
 * @param {string} identity the private half
 * @param {object} context as for wrapToRecipients
 * @returns {Promise<Uint8Array>} the file key
 */
export async function unwrapWithIdentity(entries, identity, context = {}) {
  const { fileSalt, fileHashHex, limits = {} } = context;
  const bounds = { ...MANIFEST_LIMITS, ...limits };

  if (!Array.isArray(entries) || entries.length === 0) {
    throw new Error("this manifest has no recipient entries");
  }
  // Bounded before the first ECDH, not during: the entry list arrives from
  // storage, and an attacker who can serve a manifest would otherwise get to
  // choose how many scalar multiplications the reader performs.
  if (entries.length > bounds.maxRecipients) {
    throw new Error(
      `manifest lists ${entries.length} recipients, above the maximum of ${bounds.maxRecipients}`
    );
  }
  if (!(fileSalt instanceof Uint8Array) || fileSalt.length === 0) {
    throw new Error("fileSalt is required to unwrap a file key");
  }
  if (typeof fileHashHex !== "string" || fileHashHex.length === 0) {
    throw new Error("fileHashHex is required to unwrap a file key");
  }

  const parsed = parseIdentity(identity);
  const privateKey = await importPrivateKey(parsed);
  const aad = wrapAad(fileHashHex);

  for (const entry of entries) {
    if (entry === null || typeof entry !== "object") continue;

    let ephemeral;
    let ciphertext;
    try {
      ephemeral = fromBase64Url(entry.ephemeral);
      ciphertext = fromBase64Url(entry.ciphertext);
    } catch {
      continue; // a malformed entry is simply not this reader's entry
    }
    if (ephemeral.length !== PUBLIC_KEY_BYTES || ciphertext.length !== WRAPPED_KEY_BYTES) {
      continue;
    }

    let peer;
    try {
      peer = await importPublicKey(ephemeral, "ephemeral key");
    } catch {
      continue; // an off-curve point: hostile or corrupt, but not ours either way
    }

    const wrap = await deriveWrapMaterial(
      privateKey,
      peer,
      ephemeral,
      parsed.publicKey,
      fileSalt
    );
    try {
      const opened = new Uint8Array(
        await webcrypto().subtle.decrypt(
          { name: "AES-GCM", iv: wrap.iv, additionalData: aad, tagLength: 128 },
          await aesKey(wrap.key, ["decrypt"]),
          ciphertext
        )
      );
      if (opened.length !== WRAP_KEY_BYTES) continue;
      return opened;
    } catch {
      // Not our entry. Keep going.
    } finally {
      wrap.key.fill(0);
    }
  }

  throw new Error(
    "this file is not shared with your key — no recipient entry could be opened with it"
  );
}

export const _internals = {
  CURVE,
  PUBLIC_KEY_BYTES,
  IDENTITY_BYTES,
  WRAPPED_KEY_BYTES,
  wrapAad,
};
