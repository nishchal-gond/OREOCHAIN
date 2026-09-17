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

const HEX32 = /^0x[0-9a-f]{64}$/;
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;
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

  // A manifest that mentions these keys at all is hostile — reject it rather
  // than quietly sanitising, so the caller learns something attacked them.
  for (const key of FORBIDDEN_KEYS) {
    if (text.includes(`"${key}"`)) fail(`forbidden key "${key}" present`);
  }

  let parsed;
  try {
    // The reviver is belt-and-braces: it drops the key during parsing, which is
    // the only reliable way to stop __proto__ being assigned by JSON.parse.
    parsed = JSON.parse(text, function reviver(key, value) {
      if (FORBIDDEN_KEYS.has(key)) return undefined;
      return value;
    });
  } catch (error) {
    if (error instanceof ManifestError) throw error;
    fail(`not valid JSON (${error.message})`);
  }

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
    if (manifest.kdf === null || typeof manifest.kdf !== "object") {
      fail("kdf parameters are missing");
    }
    requireString(manifest.kdf.name, "kdf.name", { max: 64 });
    requireInteger(manifest.kdf.iterations, "kdf.iterations", {
      min: bounds.minIterations,
      max: bounds.maxIterations,
    });
    requireString(manifest.kdf.salt, "kdf.salt", { max: 128, pattern: BASE64 });
    requireString(manifest.fileSalt, "fileSalt", { max: 128, pattern: BASE64 });

    if (manifest.wrappedKey === null || typeof manifest.wrappedKey !== "object") {
      fail("wrappedKey is missing");
    }
    requireString(manifest.wrappedKey.iv, "wrappedKey.iv", { max: 64, pattern: BASE64 });
    requireString(manifest.wrappedKey.ciphertext, "wrappedKey.ciphertext", {
      max: 256,
      pattern: BASE64,
    });

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
