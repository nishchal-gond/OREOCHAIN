/**
 * Strict validation for untrusted manifests.
 *
 * A manifest arrives from whatever storage the CID pointed at. Anyone who can
 * serve bytes for that CID — a hostile gateway, a compromised pinning service,
 * a man in the middle on a plain-HTTP gateway — controls every field in it
 * before a single cryptographic check runs.
 *
 * That makes the manifest a parser-level attack surface, and the interesting
 * attacks are the ones that never reach the crypto:
 *
 *   - `totalChunks: 4000000000` turns the restore loop into a hang.
 *   - `fileSize: 1e15` invites an allocation that kills the tab or the server.
 *   - a `__proto__` key in parsed JSON can poison Object.prototype.
 *   - a chunk `location` of "../../etc/passwd" or "file:///…" is a request
 *     forgery primitive once an adapter interpolates it into a URL.
 *   - duplicate indices make the chunk table disagree with itself.
 *
 * So every field is checked for type, format and range before it is used, and
 * limits are explicit and caller-supplied rather than implied by whatever the
 * machine happens to tolerate.
 */

import { MANIFEST_LIMITS } from "./limits.js";
import { assertArgon2Shape, KDF_ARGON2ID, KDF_PBKDF2, normalizeKdfName } from "./kdf.js";
import { RECIPIENT_FIELD_LIMITS } from "./recipients.js";

const HEX32 = /^0x[0-9a-f]{64}$/;
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;
const BASE64URL = /^[A-Za-z0-9_-]*$/;
// CIDs are base32/base58/base36 alphanumerics. Deliberately strict: no slashes,
// dots, colons or control characters, so a location can never escape a path or
// switch protocol when an adapter builds a URL from it.
const LOCATION = /^[A-Za-z0-9_-]{1,512}$/;

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

export class ManifestError extends Error {
  constructor(message) {
    super(`invalid manifest: ${message}`);
    this.name = "ManifestError";
  }
}

function fail(message) {
  throw new ManifestError(message);
}

/** Reject prototype-polluting keys anywhere in a parsed structure. */
function assertNoPollution(value, path = "manifest") {
  if (value === null || typeof value !== "object") return;

  if (Array.isArray(value)) {
    value.forEach((item, i) => assertNoPollution(item, `${path}[${i}]`));
    return;
  }

  for (const key of Object.keys(value)) {
    if (FORBIDDEN_KEYS.has(key)) fail(`forbidden key "${key}" at ${path}`);
    assertNoPollution(value[key], `${path}.${key}`);
  }
}

/**
 * Parse manifest JSON safely.
 * Uses a reviver so a `__proto__` key is dropped during parsing rather than
 * being assigned, which is the only reliable way to stop it with JSON.parse.
 */
export function parseManifestJson(text) {
  if (typeof text !== "string") fail("manifest must be text");
  if (text.length > MANIFEST_LIMITS.maxManifestBytes) {
    fail(`manifest is larger than ${MANIFEST_LIMITS.maxManifestBytes} bytes`);
  }

  // A manifest carrying one of these keys is hostile, and is rejected rather
  // than quietly sanitised so the caller learns something attacked them.
  //
  // The test used to be `text.includes('"__proto__"')` — a scan of the raw
  // document, which cannot tell a key from a value. An unencrypted manifest
  // describing a file *named* "constructor" contains `"fileName":"constructor"`
  // and was rejected on sight, permanently: the chunks are in storage and the
  // root is on-chain, and nothing will ever open it again. So the reviver does
  // the detecting instead, where a key is a key.
  let attacked = null;
  let parsed;
  try {
    // The reviver drops the key during parsing, which is the only reliable way
    // to stop __proto__ being assigned by JSON.parse; the flag turns that
    // silent sanitisation back into a refusal.
    parsed = JSON.parse(text, function reviver(key, value) {
      if (FORBIDDEN_KEYS.has(key)) {
        attacked = key;
        return undefined;
      }
      return value;
    });
  } catch (error) {
    if (error instanceof ManifestError) throw error;
    fail(`not valid JSON (${error.message})`);
  }
  if (attacked !== null) fail(`forbidden key "${attacked}" present`);

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    fail("manifest must be a JSON object");
  }
  assertNoPollution(parsed);
  return parsed;
}

function requireString(value, field, { max = 1024, pattern = null } = {}) {
  if (typeof value !== "string") fail(`${field} must be a string`);
  if (value.length === 0) fail(`${field} must not be empty`);
  if (value.length > max) fail(`${field} exceeds ${max} characters`);
  if (pattern && !pattern.test(value)) fail(`${field} is malformed`);
  return value;
}

function requireInteger(value, field, { min = 0, max }) {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    fail(`${field} must be an integer`);
  }
  if (value < min) fail(`${field} must be at least ${min}`);
  if (value > max) fail(`${field} exceeds the maximum of ${max}`);
  return value;
}

function requireBoolean(value, field) {
  if (typeof value !== "boolean") fail(`${field} must be a boolean`);
  return value;
}

/**
 * Validate the public header — everything needed before a passphrase is asked
 * for, and everything the on-chain record commits to.
 *
 * @param {object} manifest
 * @param {object} [limits] overrides for MANIFEST_LIMITS
 */
export function validateManifestHeader(manifest, limits = {}) {
  const bounds = { ...MANIFEST_LIMITS, ...limits };

  if (manifest === null || typeof manifest !== "object" || Array.isArray(manifest)) {
    fail("manifest must be an object");
  }

  requireString(manifest.version, "version", { max: 64 });
  requireString(manifest.fileHash, "fileHash", { max: 66, pattern: HEX32 });
  requireString(manifest.merkleRoot, "merkleRoot", { max: 66, pattern: HEX32 });
  requireBoolean(manifest.encrypted, "encrypted");

  requireInteger(manifest.totalChunks, "totalChunks", {
    min: 1,
    max: bounds.maxTotalChunks,
  });
  requireInteger(manifest.fileSize, "fileSize", { min: 0, max: bounds.maxFileSize });
  requireInteger(manifest.chunkSize, "chunkSize", {
    min: 1,
    max: bounds.maxChunkSize,
  });

  // The declared numbers must agree with each other, so a manifest cannot claim
  // a small file while listing a huge chunk table (or the reverse).
  const minChunks = Math.max(1, Math.ceil(manifest.fileSize / manifest.chunkSize));
  if (manifest.totalChunks !== minChunks) {
    fail(
      `totalChunks ${manifest.totalChunks} is inconsistent with fileSize ${manifest.fileSize} at chunkSize ${manifest.chunkSize} (expected ${minChunks})`
    );
  }

  if (manifest.encrypted) {
    requireString(manifest.fileSalt, "fileSalt", { max: 128, pattern: BASE64 });

    // The file key may be wrapped under a passphrase, to a set of recipient
    // public keys, or both — but an encrypted manifest carrying neither
    // describes a file nobody can ever open, including whoever wrote it.
    const byPassphrase = manifest.wrappedKey !== undefined && manifest.wrappedKey !== null;
    const byRecipient = manifest.recipients !== undefined && manifest.recipients !== null;

    if (!byPassphrase && !byRecipient) {
      fail("an encrypted manifest must carry a wrappedKey, recipients, or both");
    }

    if (byPassphrase) {
      if (typeof manifest.wrappedKey !== "object" || Array.isArray(manifest.wrappedKey)) {
        fail("wrappedKey must be an object");
      }
      requireString(manifest.wrappedKey.iv, "wrappedKey.iv", { max: 64, pattern: BASE64 });
      requireString(manifest.wrappedKey.ciphertext, "wrappedKey.ciphertext", {
        max: 256,
        pattern: BASE64,
      });

      // Only the passphrase path derives anything, so only it needs these.
      // A file shared purely to recipient keys has no passphrase to stretch.
      if (manifest.kdf === null || typeof manifest.kdf !== "object") {
        fail("kdf parameters are missing");
      }
      requireString(manifest.kdf.name, "kdf.name", { max: 64 });
      requireString(manifest.kdf.salt, "kdf.salt", { max: 128, pattern: BASE64 });
      validateKdfParameters(manifest.kdf, bounds);
    }

    if (byRecipient) validateRecipients(manifest.recipients, bounds);

    requireString(manifest.suite, "suite", { max: 64 });
    requireString(manifest.body, "body", {
      max: bounds.maxManifestBytes,
      pattern: BASE64,
    });
  } else if (manifest.body === null || typeof manifest.body !== "object") {
    fail("an unencrypted manifest must carry a plain body object");
  }

  return manifest;
}

/**
 * Validate the recipient entries of a manifest sealed to public keys.
 *
 * Each entry is an ephemeral public key and a wrapped file key, and both are
 * fixed-length: a field of any other length cannot be what it claims to be, so
 * it is rejected here rather than being fed to an EC point import further in.
 * The count is bounded before that, because opening a file tries every entry in
 * turn and the list arrives from whoever served the manifest.
 */
export function validateRecipients(recipients, limits = {}) {
  const bounds = { ...MANIFEST_LIMITS, ...limits };

  if (!Array.isArray(recipients)) fail("recipients must be an array");
  if (recipients.length === 0) {
    fail("recipients is present but empty — omit it, or list at least one recipient");
  }
  if (recipients.length > bounds.maxRecipients) {
    fail(`recipients lists ${recipients.length} entries, above the maximum of ${bounds.maxRecipients}`);
  }

  const seen = new Set();

  recipients.forEach((entry, i) => {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      fail(`recipients[${i}] must be an object`);
    }

    requireString(entry.ephemeral, `recipients[${i}].ephemeral`, {
      max: RECIPIENT_FIELD_LIMITS.ephemeral,
      pattern: BASE64URL,
    });
    requireString(entry.ciphertext, `recipients[${i}].ciphertext`, {
      max: RECIPIENT_FIELD_LIMITS.ciphertext,
      pattern: BASE64URL,
    });

    // Each entry is wrapped under a freshly generated ephemeral key, and the
    // wrapping key AND nonce are derived from it. Two entries sharing one
    // ephemeral key therefore encrypt twice under one key and nonce for any
    // recipient they are both addressed to — the AES-GCM failure that hands
    // over the plaintext. No honest writer produces it.
    if (seen.has(entry.ephemeral)) {
      fail(`recipients[${i}] reuses the ephemeral key of an earlier entry`);
    }
    seen.add(entry.ephemeral);
  });

  return recipients;
}

/**
 * Validate the chunk table, after decryption for an encrypted manifest.
 * Indices must form exactly 0..totalChunks-1 with no gaps and no duplicates.
 */
export function validateManifestBody(body, manifest, limits = {}) {
  const bounds = { ...MANIFEST_LIMITS, ...limits };

  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    fail("manifest body must be an object");
  }
  assertNoPollution(body, "body");

  requireString(body.fileName, "body.fileName", { max: 512 });
  requireString(body.mimeType, "body.mimeType", { max: 255 });

  if (!Array.isArray(body.chunks)) fail("body.chunks must be an array");
  if (body.chunks.length !== manifest.totalChunks) {
    fail(
      `body.chunks has ${body.chunks.length} entries but the header declares ${manifest.totalChunks}`
    );
  }

  // A stored chunk is its plaintext plus at most the largest AEAD overhead.
  const maxStored = manifest.chunkSize + bounds.maxAeadOverhead;
  const seen = new Set();
  let totalPlain = 0;

  for (const entry of body.chunks) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      fail("every chunk entry must be an object");
    }

    requireInteger(entry.index, "chunk.index", { min: 0, max: manifest.totalChunks - 1 });
    if (seen.has(entry.index)) fail(`duplicate chunk index ${entry.index}`);
    seen.add(entry.index);

    requireString(entry.location, `chunk[${entry.index}].location`, {
      max: 512,
      pattern: LOCATION,
    });
    requireString(entry.plainHash, `chunk[${entry.index}].plainHash`, {
      max: 66,
      pattern: HEX32,
    });
    requireString(entry.payloadHash, `chunk[${entry.index}].payloadHash`, {
      max: 66,
      pattern: HEX32,
    });
    requireInteger(entry.plainSize, `chunk[${entry.index}].plainSize`, {
      min: 0,
      max: manifest.chunkSize,
    });
    requireInteger(entry.storedSize, `chunk[${entry.index}].storedSize`, {
      min: 0,
      max: maxStored,
    });

    totalPlain += entry.plainSize;
  }

  if (seen.size !== manifest.totalChunks) {
    fail(`chunk table is missing indices (${seen.size} of ${manifest.totalChunks})`);
  }
  if (totalPlain !== manifest.fileSize) {
    fail(`chunk sizes total ${totalPlain} but the header declares fileSize ${manifest.fileSize}`);
  }

  return body;
}

/**
 * Check the KDF parameters a manifest asks a reader to reproduce.
 *
 * Both directions are attacks. Parameters below the floor make cracking the
 * passphrase cheap for whoever serves the manifest — the whole reason for
 * moving to Argon2id. Parameters above the ceiling turn opening a file into a
 * denial of service against the reader, who would otherwise dutifully allocate
 * the gigabytes the manifest demanded.
 */
export function validateKdfParameters(kdf, limits = {}) {
  const bounds = { ...MANIFEST_LIMITS, ...limits };

  let name;
  try {
    name = normalizeKdfName(kdf.name);
  } catch (error) {
    fail(error.message);
  }

  if (name === KDF_ARGON2ID) {
    requireInteger(kdf.memoryKiB, "kdf.memoryKiB", {
      min: bounds.minArgon2MemoryKiB,
      max: bounds.maxArgon2MemoryKiB,
    });
    requireInteger(kdf.iterations, "kdf.iterations", {
      min: bounds.minArgon2Iterations,
      max: bounds.maxArgon2Iterations,
    });
    requireInteger(kdf.parallelism, "kdf.parallelism", {
      min: bounds.minArgon2Parallelism,
      max: bounds.maxArgon2Parallelism,
    });
    try {
      assertArgon2Shape(kdf);
    } catch (error) {
      fail(error.message);
    }
    return name;
  }

  if (name === KDF_PBKDF2) {
    requireInteger(kdf.iterations, "kdf.iterations", {
      min: bounds.minIterations,
      max: bounds.maxIterations,
    });
    return name;
  }

  return fail(`unsupported kdf ${kdf.name}`);
}

/** Reject a file the caller is not prepared to hold in memory. */
export function assertWithinBudget(fileSize, limits = {}) {
  const bounds = { ...MANIFEST_LIMITS, ...limits };
  if (fileSize > bounds.maxInMemoryBytes) {
    throw new ManifestError(
      `file is ${fileSize} bytes, above the in-memory limit of ${bounds.maxInMemoryBytes}. ` +
        "Use restoreFileStream() to process it without buffering the whole file."
    );
  }
}
