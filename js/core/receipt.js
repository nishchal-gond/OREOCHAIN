/**
 * Signed storage receipts — proof without a wallet.
 *
 * A receipt is what the user actually holds. The moment their document is
 * stored, the service signs a statement of what it accepted and when, and hands
 * it over. No wallet, no gas, no transaction, no waiting for a block.
 *
 * A receipt and an anchor answer different questions, and a platform needs both:
 *
 *   receipt  "this service accepted this exact document at this time"
 *            — instant, free, but only as trustworthy as the signing service
 *   anchor   "this document is committed to in a public, immutable record"
 *            — independently verifiable by anyone, but batched and periodic
 *
 * The receipt covers the seconds-to-hours before the next batch is anchored,
 * and stays useful afterwards as the service's own countersignature. Because it
 * commits to the same fileHash and Merkle root that the anchor commits to, the
 * two cannot disagree: a service that issued a receipt and then anchored
 * something different is caught by comparing them.
 *
 * ECDSA over P-256 is used rather than Ed25519 because WebCrypto supports it
 * everywhere — every current browser and Node. Ed25519 is the nicer primitive
 * but is still uneven across browsers, and a signature nobody can verify in the
 * browser is not useful here.
 */

import { fromBase64, fromUtf8, toBase64, utf8, webcrypto } from "./bytes.js";

export const RECEIPT_VERSION = "oreochain-receipt-v1";

const ALGORITHM = { name: "ECDSA", namedCurve: "P-256" };
const SIGNING = { name: "ECDSA", hash: "SHA-256" };

/**
 * Deterministic JSON: object keys sorted at every level.
 *
 * Signatures cover bytes, not objects. Two encoders that order keys differently
 * produce different bytes for the same data and therefore a signature that
 * fails to verify — so the serialisation must be pinned, not left to whatever
 * JSON.stringify happens to do with insertion order.
 */
export function canonicalize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;

  const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
}

export async function generateSigningKey() {
  const pair = await webcrypto().subtle.generateKey(ALGORITHM, true, ["sign", "verify"]);
  return {
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    exported: {
      privateJwk: await webcrypto().subtle.exportKey("jwk", pair.privateKey),
      publicJwk: await webcrypto().subtle.exportKey("jwk", pair.publicKey),
    },
  };
}

export async function importPrivateKey(jwk) {
  return webcrypto().subtle.importKey("jwk", jwk, ALGORITHM, false, ["sign"]);
}

export async function importPublicKey(jwk) {
  return webcrypto().subtle.importKey("jwk", jwk, ALGORITHM, true, ["verify"]);
}

/**
 * A short, stable identifier for a public key, so a receipt can say which key
 * signed it without embedding the whole key.
 */
export async function keyId(publicKey) {
  const jwk = await webcrypto().subtle.exportKey("jwk", publicKey);
  const digest = await webcrypto().subtle.digest("SHA-256", utf8(canonicalize({ x: jwk.x, y: jwk.y })));
  return toBase64(new Uint8Array(digest)).replace(/[+/=]/g, "").slice(0, 16);
}

/**
 * Issue a receipt for a stored document.
 *
 * @param {object} document fileHash, merkleRoot, manifestCID, fileSize, totalChunks, encrypted, suite
 * @param {CryptoKey} privateKey
 * @param {object} [options] issuer label, key id, clock override
 */
export async function issueReceipt(document, privateKey, options = {}) {
  const { issuer = "oreochain-gateway", kid = null, now = () => new Date() } = options;

  for (const field of ["fileHash", "merkleRoot", "manifestCID"]) {
    if (typeof document[field] !== "string" || document[field].length === 0) {
      throw new Error(`receipt requires ${field}`);
    }
  }

  const statement = {
    version: RECEIPT_VERSION,
    issuer,
    kid,
    issuedAt: now().toISOString(),
    fileHash: document.fileHash.toLowerCase(),
    merkleRoot: document.merkleRoot.toLowerCase(),
    manifestCID: document.manifestCID,
    fileSize: document.fileSize,
    totalChunks: document.totalChunks,
    encrypted: Boolean(document.encrypted),
    suite: document.suite || null,

    /*
     * Whether the issuer checked this document against its manifest before
     * signing, rather than signing the claim as given.
     *
     * Additive on purpose: the signature covers whatever the statement
     * contains, so receipts issued before this field existed still verify, and
     * absent reads as "not asserted" rather than false. Bumping
     * RECEIPT_VERSION would instead invalidate every receipt already in a
     * user's hands, which is a far worse trade for a field that is new
     * information rather than a changed meaning.
     */
    verified: Boolean(document.verified),
  };

  const signature = await webcrypto().subtle.sign(
    SIGNING,
    privateKey,
    utf8(canonicalize(statement))
  );

  return { statement, signature: toBase64(new Uint8Array(signature)) };
}

/**
 * Verify a receipt against a known public key.
 *
 * Returns a reason rather than throwing, because "this receipt is invalid" is a
 * normal answer a UI needs to display, not an exceptional condition.
 */
export async function verifyReceipt(receipt, publicKey, options = {}) {
  const { maxAgeMs = null, now = () => Date.now() } = options;

  if (!receipt || typeof receipt !== "object" || !receipt.statement || !receipt.signature) {
    return { valid: false, reason: "malformed receipt" };
  }
  if (receipt.statement.version !== RECEIPT_VERSION) {
    return { valid: false, reason: `unsupported receipt version ${receipt.statement.version}` };
  }

  let signature;
  try {
    signature = fromBase64(receipt.signature);
  } catch {
    return { valid: false, reason: "signature is not valid base64" };
  }

  const ok = await webcrypto().subtle.verify(
    SIGNING,
    publicKey,
    signature,
    utf8(canonicalize(receipt.statement))
  );
  if (!ok) return { valid: false, reason: "signature does not verify" };

  const issuedAt = Date.parse(receipt.statement.issuedAt);
  if (Number.isNaN(issuedAt)) return { valid: false, reason: "issuedAt is not a valid timestamp" };

  // A receipt dated in the future is either a clock problem or a forgery
  // attempt; either way it should not be silently accepted.
  if (issuedAt > now() + 300000) return { valid: false, reason: "receipt is dated in the future" };
  if (maxAgeMs !== null && now() - issuedAt > maxAgeMs) {
    return { valid: false, reason: "receipt is older than the accepted window" };
  }

  return { valid: true, statement: receipt.statement };
}

/**
 * Check that a receipt and an on-chain anchor describe the same document.
 *
 * This is the cross-check that makes the pair stronger than either alone: the
 * service cannot issue you one receipt and quietly anchor something else.
 */
export function receiptMatchesAnchor(receipt, inclusion) {
  const statement = receipt.statement || {};
  const document = inclusion.document || {};

  if (statement.fileHash !== document.fileHash) {
    return { consistent: false, reason: "fileHash differs between receipt and anchor" };
  }
  if (statement.merkleRoot !== document.merkleRoot) {
    return { consistent: false, reason: "merkleRoot differs between receipt and anchor" };
  }
  if (statement.manifestCID !== document.manifestCID) {
    return { consistent: false, reason: "manifestCID differs between receipt and anchor" };
  }
  return { consistent: true };
}

export function exportReceipt(receipt) {
  return canonicalize(receipt);
}

export function importReceipt(text) {
  const parsed = JSON.parse(text);
  if (!parsed || typeof parsed !== "object") throw new Error("receipt must be a JSON object");
  return parsed;
}
