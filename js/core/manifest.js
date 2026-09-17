/**
 * The chunked-storage pipeline: file in, verifiable encrypted chunks + manifest
 * out, and back again.
 *
 * This module is deliberately storage-agnostic. It never talks to IPFS, Pinata,
 * S3 or a database — the caller supplies functions that put and get bytes. That
 * keeps the whole security core reusable by a Node server, a CLI or the web UI
 * without change.
 *
 * THE MANIFEST
 * ------------
 * A manifest is split into a public header and an encrypted body:
 *
 *   header  version, KDF parameters, the wrapped file key, the file's salt,
 *           the plaintext file hash, the Merkle root, chunk count, total size.
 *           Anyone can read this; it is what the on-chain record commits to.
 *
 *   body    file name, MIME type, and the per-chunk table (index, storage id,
 *           plaintext hash, ciphertext hash, size). Encrypted, because the chunk
 *           locations and the file's name are themselves sensitive: without the
 *           passphrase an observer cannot even enumerate which blocks belong to
 *           the file.
 */

import {
  concat,
  equalBytes,
  fromBase64,
  fromHex,
  fromUtf8,
  to0x,
  toBase64,
  toHex,
  utf8,
} from "./bytes.js";
import {
  DEFAULT_CHUNK_SIZE,
  hashChunks,
  leafHash,
  merkleProof,
  merkleRoot,
  sha256,
  splitIntoChunks,
  verifyMerkleProof,
} from "./chunker.js";
import {
  chunkAad,
  decryptChunk,
  deriveManifestKey,
  encryptChunk,
  ENVELOPE_VERSION,
  generateFileKey,
  generateSalt,
  openWithDerivedKey,
  sealWithDerivedKey,
  unwrapFileKey,
  wrapFileKey,
} from "./crypto.js";
import { DEFAULT_SUITE, getSuite } from "./suites.js";
import { DEFAULT_KDF, kdfSpec } from "./kdf.js";
import { MANIFEST_LIMITS, NETWORK_LIMITS } from "./limits.js";
import {
  assertWithinBudget,
  ManifestError,
  parseManifestJson,
  validateManifestBody,
  validateManifestHeader,
} from "./validate.js";

export const MANIFEST_VERSION = "oreochain-manifest-v1";
const MANIFEST_AAD = `${ENVELOPE_VERSION}/manifest-body`;

/**
 * Split, hash and (optionally) encrypt a file.
 *
 * @param {Uint8Array} fileBytes raw file content
 * @param {object} options
 * @param {string} options.fileName
 * @param {string} [options.mimeType]
 * @param {string|null} [options.passphrase] omit or pass null to store in the clear
 * @param {string} [options.suite] cipher suite name, see js/core/suites.js
 * @param {object|string} [options.kdf] passphrase KDF, see js/core/kdf.js
 * @param {number} [options.chunkSize]
 * @param {(done:number,total:number)=>void} [options.onProgress]
 * @returns {Promise<object>} a packed file, ready for the caller to upload
 */
export async function packFile(fileBytes, options = {}) {
  const {
    fileName = "document",
    mimeType = "application/octet-stream",
    passphrase = null,
    suite = DEFAULT_SUITE,
    chunkSize = DEFAULT_CHUNK_SIZE,
    kdf = DEFAULT_KDF,
    onProgress,
  } = options;

  const encrypted = typeof passphrase === "string" && passphrase.length > 0;
  // Fail fast on an unknown suite or KDF, before doing any expensive work.
  const kdfParams = encrypted ? kdfSpec(kdf) : null;
  if (encrypted) getSuite(suite);

  const plainChunks = splitIntoChunks(fileBytes, chunkSize);
  const totalChunks = plainChunks.length;

  const fileHash = await sha256(fileBytes);
  const fileHashHex = to0x(fileHash);

  const leaves = await hashChunks(plainChunks);
  const root = await merkleRoot(leaves);

  const fileKey = encrypted ? generateFileKey() : null;
  const fileSalt = encrypted ? generateSalt() : null;
  const kdfSalt = encrypted ? generateSalt() : null;

  const chunks = [];
  for (let index = 0; index < totalChunks; index++) {
    const plain = plainChunks[index];
    const payload = encrypted
      ? await encryptChunk(
          plain,
          fileKey,
          fileSalt,
          index,
          chunkAad(fileHashHex, index, totalChunks),
          suite
        )
      : plain;

    chunks.push({
      index,
      payload,
      plainHash: leaves[index],
      payloadHash: await sha256(payload),
      plainSize: plain.length,
      storedSize: payload.length,
    });

    if (onProgress) onProgress(index + 1, totalChunks);
  }

  return {
    encrypted,
    suite: encrypted ? suite : null,
    fileName,
    mimeType,
    fileSize: fileBytes.length,
    fileHash,
    fileHashHex,
    merkleRoot: root,
    merkleRootHex: to0x(root),
    chunkSize,
    totalChunks,
    chunks,
    leaves,
    // Retained only long enough to seal the manifest; never persisted as-is.
    _fileKey: fileKey,
    _fileSalt: fileSalt,
    _kdfSalt: kdfSalt,
    _kdf: kdfParams,
    _passphrase: passphrase,
  };
}

/**
 * Build the final manifest once the caller knows where each chunk landed.
 *
 * @param {object} packed result of packFile
 * @param {string[]} locations storage id (e.g. IPFS CID) per chunk, in order
 */
export async function sealManifest(packed, locations) {
  if (!Array.isArray(locations) || locations.length !== packed.totalChunks) {
    throw new Error(
      `expected ${packed.totalChunks} chunk locations, received ${
        Array.isArray(locations) ? locations.length : typeof locations
      }`
    );
  }
  if (locations.some((cid) => typeof cid !== "string" || cid.length === 0)) {
    throw new Error("every chunk location must be a non-empty string");
  }

  const body = {
    fileName: packed.fileName,
    mimeType: packed.mimeType,
    chunks: packed.chunks.map((chunk, i) => ({
      index: chunk.index,
      location: locations[i],
      plainHash: to0x(chunk.plainHash),
      payloadHash: to0x(chunk.payloadHash),
      plainSize: chunk.plainSize,
      storedSize: chunk.storedSize,
    })),
  };

  const header = {
    version: MANIFEST_VERSION,
    envelope: ENVELOPE_VERSION,
    createdAt: new Date().toISOString(),
    encrypted: packed.encrypted,
    suite: packed.suite,
    fileHash: packed.fileHashHex,
    merkleRoot: packed.merkleRootHex,
    chunkSize: packed.chunkSize,
    totalChunks: packed.totalChunks,
    fileSize: packed.fileSize,
  };

  if (packed.encrypted) {
    const wrapped = await wrapFileKey(
      packed._fileKey,
      packed._passphrase,
      packed._kdfSalt,
      packed._kdf
    );
    // The full parameter set travels with the file: a reader must reproduce the
    // derivation exactly, and hardcoding it would strand files on one setting.
    header.kdf = { ...packed._kdf, salt: toBase64(packed._kdfSalt) };
    header.fileSalt = toBase64(packed._fileSalt);
    header.wrappedKey = {
      iv: toBase64(wrapped.iv),
      ciphertext: toBase64(wrapped.ciphertext),
    };

    const derived = await deriveManifestKey(packed._fileKey, packed._fileSalt);
    const sealed = await sealWithDerivedKey(
      utf8(JSON.stringify(body)),
      derived,
      MANIFEST_AAD
    );
    header.body = toBase64(sealed);
  } else {
    header.body = body;
  }

  return header;
}

/**
 * Recover the file key and the chunk table from a manifest.
 * For an encrypted manifest this is where a wrong passphrase is caught.
 */
export async function openManifest(manifest, passphrase = null, options = {}) {
  const { limits = {} } = options;

  validateManifestHeader(manifest, limits);
  if (manifest.version !== MANIFEST_VERSION) {
    throw new ManifestError(`unsupported version: ${manifest.version}`);
  }

  if (!manifest.encrypted) {
    return {
      fileKey: null,
      fileSalt: null,
      body: validateManifestBody(manifest.body, manifest, limits),
    };
  }

  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new Error("this file is encrypted — a passphrase is required");
  }

  getSuite(manifest.suite); // reject an unknown suite before doing PBKDF2 work

  const kdfSalt = fromBase64(manifest.kdf.salt);
  const fileKey = await unwrapFileKey(
    {
      iv: fromBase64(manifest.wrappedKey.iv),
      ciphertext: fromBase64(manifest.wrappedKey.ciphertext),
    },
    passphrase,
    kdfSalt,
    manifest.kdf
  );

  const fileSalt = fromBase64(manifest.fileSalt);
  const derived = await deriveManifestKey(fileKey, fileSalt);
  const plain = await openWithDerivedKey(fromBase64(manifest.body), derived, MANIFEST_AAD);

  let body;
  try {
    body = JSON.parse(fromUtf8(plain));
  } catch (error) {
    throw new ManifestError(`decrypted body is not valid JSON (${error.message})`);
  }

  return { fileKey, fileSalt, body: validateManifestBody(body, manifest, limits) };
}

/**
 * Parse and validate a manifest fetched from storage.
 *
 * Always use this on bytes that came off the network — it is the only entry
 * point that treats the manifest as hostile input.
 */
export function readManifest(bytes, options = {}) {
  const text = typeof bytes === "string" ? bytes : fromUtf8(bytes);
  const manifest = parseManifestJson(text);
  return validateManifestHeader(manifest, options.limits || {});
}

/**
 * Fetch, verify, decrypt and reassemble a file.
 *
 * Verification happens at three independent levels:
 *   1. the stored bytes match the recorded payload hash (cheap, pre-decryption);
 *   2. AES-GCM authenticates the chunk *and its position* (encrypted files);
 *   3. the reassembled chunk hashes rebuild the Merkle root, which must equal
 *      the root anchored on-chain — this is the check that ties the bytes you
 *      just downloaded to the blockchain record.
 *
 * @param {object} manifest
 * @param {object} opened result of openManifest
 * @param {(location:string,entry:object)=>Promise<Uint8Array>} fetchChunk
 * @param {object} [options]
 * @param {string} [options.expectedMerkleRoot] the on-chain root, 0x-prefixed
 * @param {(done:number,total:number)=>void} [options.onProgress]
 */
export async function restoreFile(manifest, opened, fetchChunk, options = {}) {
  const { expectedMerkleRoot, onProgress, limits = {} } = options;

  validateManifestHeader(manifest, limits);
  assertWithinBudget(manifest.fileSize, limits);

  const plainChunks = [];
  for await (const chunk of restoreFileStream(manifest, opened, fetchChunk, options)) {
    plainChunks.push(chunk.bytes);
    if (onProgress) onProgress(plainChunks.length, manifest.totalChunks);
  }

  const bytes = concat(...plainChunks);

  // The stream already verified every chunk and the Merkle root. These two
  // checks cover the whole-file invariants a per-chunk pass cannot see.
  const fileHashHex = to0x(await sha256(bytes));
  if (fileHashHex !== manifest.fileHash) {
    throw new Error("reassembled file hash does not match the manifest");
  }
  if (bytes.length !== manifest.fileSize) {
    throw new Error("reassembled file size does not match the manifest");
  }

  return {
    bytes,
    fileName: opened.body.fileName,
    mimeType: opened.body.mimeType,
    fileHash: fileHashHex,
    merkleRoot: expectedMerkleRoot ? expectedMerkleRoot.toLowerCase() : manifest.merkleRoot,
  };
}

/**
 * Fetch, verify and decrypt chunks, yielding verified plaintext in order
 * without ever holding the whole file.
 *
 * This is what a server should use: a 4 GB download costs a bounded window of
 * memory rather than 4 GB of it. Chunks are fetched `concurrency` at a time and
 * yielded strictly in order, so the consumer can pipe them straight to a
 * response.
 *
 * Verification is identical to restoreFile() except for the whole-file SHA-256,
 * which cannot be computed incrementally with WebCrypto. That loses nothing:
 * the Merkle root is checked before the final chunk is yielded, and the root
 * commits to every chunk's content and position, so it is an equally complete
 * statement about the bytes.
 *
 * @param {object} manifest validated manifest header
 * @param {object} opened result of openManifest
 * @param {(location:string, entry:object, ctx:object)=>Promise<Uint8Array>} fetchChunk
 * @param {object} [options]
 * @param {string} [options.expectedMerkleRoot] the on-chain root
 * @param {number} [options.concurrency] chunks in flight
 * @param {AbortSignal} [options.signal] cancels in-flight and pending fetches
 */
export async function* restoreFileStream(manifest, opened, fetchChunk, options = {}) {
  const {
    expectedMerkleRoot,
    concurrency = NETWORK_LIMITS.concurrency,
    signal,
    limits = {},
  } = options;

  validateManifestHeader(manifest, limits);
  const entries = [...opened.body.chunks].sort((a, b) => a.index - b.index);
  entries.forEach((entry, i) => {
    if (entry.index !== i) throw new ManifestError(`chunk table has a gap at index ${i}`);
  });

  const width = Math.max(1, Math.min(concurrency, entries.length));
  const inFlight = new Map();
  const leaves = [];

  const start = (index) => {
    if (index >= entries.length || inFlight.has(index)) return;
    const pending = fetchAndVerify(manifest, opened, entries[index], fetchChunk, signal);
    // A look-ahead fetch can reject before the consumer reaches that index —
    // a tampered chunk 5 rejects while chunk 0 is still being yielded. Without
    // a handler attached now, that surfaces as an unhandled rejection and can
    // tear down the process instead of failing this call. Attaching a no-op
    // handler marks it handled; awaiting the original below still throws.
    pending.catch(() => {});
    inFlight.set(index, pending);
  };

  for (let i = 0; i < width; i++) start(i);

  try {
    for (let index = 0; index < entries.length; index++) {
      throwIfAborted(signal);

      const pending = inFlight.get(index);
      inFlight.delete(index);
      const plain = await pending;

      start(index + width);

      leaves.push(await leafHash(plain));
      yield { index, bytes: plain, entry: entries[index] };
    }

    const rootHex = to0x(await merkleRoot(leaves));
    if (rootHex !== manifest.merkleRoot) {
      throw new Error("reassembled Merkle root does not match the manifest");
    }
    if (expectedMerkleRoot && rootHex !== expectedMerkleRoot.toLowerCase()) {
      throw new Error(
        "reassembled Merkle root does not match the root recorded on-chain — this file is not the registered document"
      );
    }
  } finally {
    inFlight.clear();
  }
}

function throwIfAborted(signal) {
  if (signal && signal.aborted) {
    const error = new Error("operation aborted");
    error.name = "AbortError";
    throw error;
  }
}

/** One chunk: fetch, check the stored hash, authenticate, decrypt, size-check. */
async function fetchAndVerify(manifest, opened, entry, fetchChunk, signal) {
  throwIfAborted(signal);

  const payload = await fetchChunk(entry.location, entry, { signal });

  if (!(payload instanceof Uint8Array)) {
    throw new Error(`chunk ${entry.index}: fetch returned ${typeof payload}, expected bytes`);
  }
  if (payload.length !== entry.storedSize) {
    throw new Error(
      `chunk ${entry.index} is ${payload.length} bytes but the manifest declares ${entry.storedSize}`
    );
  }

  const payloadHash = await sha256(payload);
  if (!equalBytes(payloadHash, fromHex(entry.payloadHash))) {
    throw new Error(
      `chunk ${entry.index} does not match its recorded hash — the stored block was altered`
    );
  }

  const plain = manifest.encrypted
    ? await decryptChunk(
        payload,
        opened.fileKey,
        opened.fileSalt,
        entry.index,
        chunkAad(manifest.fileHash, entry.index, manifest.totalChunks),
        manifest.suite || DEFAULT_SUITE
      )
    : payload;

  if (plain.length !== entry.plainSize) {
    throw new Error(
      `chunk ${entry.index} decrypted to ${plain.length} bytes but the manifest declares ${entry.plainSize}`
    );
  }

  return plain;
}

/**
 * Prove a single chunk belongs to a registered file, without fetching the rest.
 * This is what makes per-chunk auditing possible: a storage provider can be
 * challenged on one 256 KiB block and the proof checks against the on-chain root.
 */
export async function proveChunk(plainChunks, index) {
  const leaves = await hashChunks(plainChunks);
  const proof = await merkleProof(leaves, index);
  return {
    index,
    leaf: to0x(leaves[index]),
    proof: proof.map((step) => ({ hash: to0x(step.hash), side: step.side })),
    root: to0x(await merkleRoot(leaves)),
  };
}

export async function checkChunkProof(leafHex, proof, rootHex) {
  return verifyMerkleProof(
    fromHex(leafHex),
    proof.map((step) => ({ hash: fromHex(step.hash), side: step.side })),
    fromHex(rootHex)
  );
}

export { toHex, to0x };
