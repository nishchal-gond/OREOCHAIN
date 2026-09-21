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
 *   header  version, KDF parameters, the wrapped file key (under a passphrase,
 *           to a set of recipient public keys, or both), the file's salt,
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
  concatAll,
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
import {
  parseRecipient,
  unwrapWithIdentity,
  wrapToRecipients,
} from "./recipients.js";
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
 * Decide whether this call is an encrypting one, and refuse the shapes that
 * would quietly answer "no".
 *
 * `null` (or an omitted option) means "store in the clear" and is honoured. A
 * passphrase of the wrong type, or an empty one, used to fall through the same
 * `typeof passphrase === "string" && passphrase.length > 0` test and produce an
 * unencrypted file — a caller that believed it had encrypted a document would
 * get a manifest whose `encrypted: false` nobody reads, and the plaintext would
 * be sitting on a public gateway. Anything other than null or a non-empty
 * string is a mistake, so it is an error.
 */
function shouldEncrypt(passphrase) {
  if (passphrase === null || passphrase === undefined) return false;
  if (typeof passphrase !== "string") {
    throw new Error(
      `passphrase must be a string or null, received ${typeof passphrase} — ` +
        "pass null to store a file unencrypted"
    );
  }
  if (passphrase.length === 0) {
    throw new Error(
      "passphrase is empty — pass null to store a file unencrypted, rather than \"\""
    );
  }
  return true;
}

/**
 * The same question for the recipient list, answered the same way.
 *
 * An omitted list means "no recipients" and is honoured. An explicitly empty
 * one is a mistake with the same shape as the empty passphrase above — a list
 * built by filtering, where the filter matched nothing — and answering it with
 * a plaintext file on a public gateway is the wrong answer. A caller who means
 * to store in the clear says so by passing neither.
 */
function shouldSealToRecipients(recipients) {
  if (recipients === null || recipients === undefined) return false;
  if (!Array.isArray(recipients)) {
    throw new Error(
      `recipients must be an array of recipient keys or null, received ${typeof recipients}`
    );
  }
  if (recipients.length === 0) {
    throw new Error(
      "recipients is an empty list — omit it to store a file without recipients, rather than []"
    );
  }
  return true;
}

/** The writer's half of validateManifestHeader(): what the reader will demand. */
function assertPackable(fileBytes, chunkSize, limits) {
  const bounds = { ...MANIFEST_LIMITS, ...limits };

  if (!(fileBytes instanceof Uint8Array)) {
    throw new Error("fileBytes must be a Uint8Array");
  }
  if (!Number.isInteger(chunkSize) || chunkSize < 1) {
    throw new Error("chunkSize must be a positive integer");
  }
  if (chunkSize > bounds.maxChunkSize) {
    throw new Error(
      `chunkSize ${chunkSize} is above the maximum of ${bounds.maxChunkSize}; ` +
        "a manifest written at this size could never be read back"
    );
  }
  if (fileBytes.length > bounds.maxFileSize) {
    throw new Error(`file is ${fileBytes.length} bytes, above the maximum of ${bounds.maxFileSize}`);
  }

  const totalChunks = Math.max(1, Math.ceil(fileBytes.length / chunkSize));
  if (totalChunks > bounds.maxTotalChunks) {
    throw new Error(
      `${fileBytes.length} bytes at chunkSize ${chunkSize} is ${totalChunks} chunks, ` +
        `above the maximum of ${bounds.maxTotalChunks}`
    );
  }
}

/**
 * Split, hash and (optionally) encrypt a file.
 *
 * @param {Uint8Array} fileBytes raw file content
 * @param {object} options
 * @param {string} options.fileName
 * @param {string} [options.mimeType]
 * @param {string|null} [options.passphrase] omit or pass null to store in the clear
 * @param {string[]|null} [options.recipients] recipient public keys to seal the
 *   file key to as well as, or instead of, a passphrase — see js/core/recipients.js
 * @param {string} [options.suite] cipher suite name, see js/core/suites.js
 * @param {object|string} [options.kdf] passphrase KDF, see js/core/kdf.js
 * @param {number} [options.chunkSize]
 * @param {object} [options.limits] overrides for MANIFEST_LIMITS, applied to
 *   this file's own shape so the writer cannot exceed what the reader allows
 * @param {(done:number,total:number)=>void} [options.onProgress]
 * @returns {Promise<object>} a packed file, ready for the caller to upload
 */
export async function packFile(fileBytes, options = {}) {
  const {
    fileName = "document",
    mimeType = "application/octet-stream",
    passphrase = null,
    recipients = null,
    suite = DEFAULT_SUITE,
    chunkSize = DEFAULT_CHUNK_SIZE,
    kdf = DEFAULT_KDF,
    onProgress,
  } = options;

  const limits = options.limits || {};

  // Either route to the file key encrypts the file; a file may take both, so
  // that the person who uploaded it keeps a way in that does not depend on
  // still holding a device.
  const byPassphrase = shouldEncrypt(passphrase);
  const byRecipient = shouldSealToRecipients(recipients);
  const encrypted = byPassphrase || byRecipient;

  // Fail fast on an unknown suite, KDF or recipient key, before doing any
  // expensive work. A malformed key found after a gigabyte has been encrypted
  // is the same error reported at the worst possible moment.
  const kdfParams = byPassphrase ? kdfSpec(kdf) : null;
  if (encrypted) getSuite(suite);
  if (byRecipient) {
    const bounds = { ...MANIFEST_LIMITS, ...limits };
    if (recipients.length > bounds.maxRecipients) {
      throw new Error(
        `${recipients.length} recipients is above the maximum of ${bounds.maxRecipients}`
      );
    }
    recipients.forEach(parseRecipient);
  }

  // The writer is held to the same limits the reader enforces. Without this a
  // caller can pack, encrypt, upload and anchor a file whose manifest
  // validateManifestHeader() will reject forever — the bytes are in storage,
  // the root is on-chain, and nothing can open it again.
  assertPackable(fileBytes, chunkSize, limits);

  const plainChunks = splitIntoChunks(fileBytes, chunkSize);
  const totalChunks = plainChunks.length;

  const fileHash = await sha256(fileBytes);
  const fileHashHex = to0x(fileHash);

  const leaves = await hashChunks(plainChunks);
  const root = await merkleRoot(leaves);

  const fileKey = encrypted ? generateFileKey() : null;
  const fileSalt = encrypted ? generateSalt() : null;
  // Only the passphrase route stretches anything, so only it needs a KDF salt.
  const kdfSalt = byPassphrase ? generateSalt() : null;

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
    _passphrase: byPassphrase ? passphrase : null,
    _recipients: byRecipient ? [...recipients] : null,
    _limits: limits,
  };
}

/**
 * Build the final manifest once the caller knows where each chunk landed.
 *
 * @param {object} packed result of packFile
 * @param {string[]} locations storage id (e.g. IPFS CID) per chunk, in order
 */
export async function sealManifest(packed, locations) {
  if (packed === null || typeof packed !== "object") {
    throw new Error("sealManifest expects the result of packFile()");
  }
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
  const bodyJson = JSON.stringify(body);

  assertBodyNotAlreadySealed(packed, bodyJson);

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
    header.fileSalt = toBase64(packed._fileSalt);

    // Truthiness, not `!== null`: a passphrase is a non-empty string or null
    // and a recipient list a non-empty array or null, so this is exact — and it
    // does not mistake a `packed` missing the field entirely for one carrying it.
    if (packed._passphrase) {
      const wrapped = await wrapFileKey(
        packed._fileKey,
        packed._passphrase,
        packed._kdfSalt,
        packed._kdf
      );
      // The full parameter set travels with the file: a reader must reproduce the
      // derivation exactly, and hardcoding it would strand files on one setting.
      header.kdf = { ...packed._kdf, salt: toBase64(packed._kdfSalt) };
      header.wrappedKey = {
        iv: toBase64(wrapped.iv),
        ciphertext: toBase64(wrapped.ciphertext),
      };
    }

    if (packed._recipients) {
      // Re-sealing generates fresh ephemeral keys, so the wraps differ between
      // two seals of one packed file. That is the safe direction: the wrapping
      // key and its nonce are derived from the ephemeral key, so a reused one
      // would be a reused nonce.
      header.recipients = await wrapToRecipients(packed._fileKey, packed._recipients, {
        fileSalt: packed._fileSalt,
        fileHashHex: packed.fileHashHex,
        limits: packed._limits,
      });
    }

    const derived = await deriveManifestKey(packed._fileKey, packed._fileSalt);
    const sealed = await sealWithDerivedKey(utf8(bodyJson), derived, MANIFEST_AAD);
    header.body = toBase64(sealed);
  } else {
    header.body = body;
  }

  if (packed._fileKey instanceof Uint8Array) sealedBodies.set(packed._fileKey, bodyJson);
  return header;
}

/**
 * What one packed file has already been sealed as, so it is never sealed as
 * something else.
 *
 * The manifest body's key AND nonce both come out of one HKDF expansion over
 * (fileKey, fileSalt), which is safe precisely once: those two values are
 * generated inside packFile() and never reused, so one packed file means one
 * key/nonce pair. Seal the same packed file a second time with a different
 * chunk table — the obvious shape of an upload retry that lands on new CIDs —
 * and AES-GCM encrypts two different plaintexts under one key and one nonce.
 * That does not degrade the ciphertext, it removes it: XOR the two and the
 * keystream cancels, handing anyone who holds both manifests the file name,
 * the MIME type and every chunk location without the passphrase, plus the
 * material to forge the authentication tag.
 *
 * Keyed on the file key rather than on the packed object, because the file key
 * is what the nonce is derived from: a shallow copy of `packed` would slip past
 * an object-keyed guard while reusing the very same key and nonce. A WeakMap so
 * none of this bookkeeping reaches a caller that serialises what packFile()
 * returned.
 */
const sealedBodies = new WeakMap();

function assertBodyNotAlreadySealed(packed, bodyJson) {
  // An unencrypted manifest has no derived nonce, so nothing to reuse.
  if (!packed.encrypted || !(packed._fileKey instanceof Uint8Array)) return;

  const previous = sealedBodies.get(packed._fileKey);
  // Re-sealing after a transient failure, with the same locations, produces
  // the same plaintext and therefore the same ciphertext — no reuse, allowed.
  if (previous === undefined || previous === bodyJson) return;

  throw new Error(
    "this packed file has already been sealed with a different chunk table. " +
      "Re-sealing it would encrypt two manifests under one key and nonce and " +
      "expose both — call packFile() again to seal a different set of locations."
  );
}

/**
 * Recover the file key and the chunk table from a manifest.
 * For an encrypted manifest this is where a wrong passphrase is caught.
 *
 * @param {object} manifest
 * @param {string|null} [passphrase]
 * @param {object} [options]
 * @param {string} [options.identity] open the file with a recipient identity
 *   instead of a passphrase — see js/core/recipients.js
 * @param {object} [options.limits] overrides for MANIFEST_LIMITS
 */
export async function openManifest(manifest, passphrase = null, options = {}) {
  const { limits = {}, identity = null } = options;

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

  const usingIdentity = identity !== null && identity !== undefined;
  const hasPassphraseRoute = manifest.wrappedKey !== undefined && manifest.wrappedKey !== null;

  if (!usingIdentity) {
    // A file sealed only to recipient keys has no passphrase to ask for.
    // Asking for one anyway sends its recipient looking for a secret that was
    // never created, when what they need is the identity they already hold —
    // and checking it here rather than at the unwrap means a caller who does
    // supply a passphrase gets that sentence instead of a TypeError from the
    // missing KDF parameters.
    if (!hasPassphraseRoute) {
      throw new Error(
        "this file is sealed to recipient keys — open it with an identity " +
          "(options.identity), not a passphrase"
      );
    }
    if (typeof passphrase !== "string" || passphrase.length === 0) {
      throw new Error("this file is encrypted — a passphrase is required");
    }
  }

  getSuite(manifest.suite); // reject an unknown suite before doing PBKDF2 work

  const fileSalt = fromBase64(manifest.fileSalt);

  let fileKey;
  if (usingIdentity) {
    if (manifest.recipients === undefined || manifest.recipients === null) {
      throw new Error(
        "this file is not sealed to any recipient key — it can only be opened with its passphrase"
      );
    }
    // The file hash is bound into each wrap, so an entry lifted from another
    // file's manifest does not open here. It comes from the header that
    // validateManifestHeader() has already checked, and the Merkle root ties
    // that header to the on-chain record.
    fileKey = await unwrapWithIdentity(manifest.recipients, identity, {
      fileSalt,
      fileHashHex: manifest.fileHash,
      limits,
    });
  } else {
    const kdfSalt = fromBase64(manifest.kdf.salt);
    fileKey = await unwrapFileKey(
      {
        iv: fromBase64(manifest.wrappedKey.iv),
        ciphertext: fromBase64(manifest.wrappedKey.ciphertext),
      },
      passphrase,
      kdfSalt,
      manifest.kdf
    );
  }

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

  // concatAll, not concat(...plainChunks): a file restored at a small chunk
  // size runs to hundreds of thousands of chunks, and spreading that many
  // arguments overflows the call stack before a byte is copied.
  const bytes = concatAll(plainChunks);

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
  // openManifest() already enforces this, but restoreFileStream() also accepts
  // an `opened` a caller assembled itself — and the Merkle root is now checked
  // as the last entry is reached, so an empty or short table would otherwise
  // walk straight past the one check that ties these bytes to the chain.
  if (entries.length !== manifest.totalChunks) {
    throw new ManifestError(
      `chunk table has ${entries.length} entries but the header declares ${manifest.totalChunks}`
    );
  }
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

      // The root is checked before the last chunk is handed over, not after.
      // A consumer piping this into an HTTP response has already sent every
      // byte it received, so a root checked afterwards is a root checked too
      // late: for an unencrypted file the root is the *only* thing tying these
      // bytes to the on-chain record, and withholding one chunk is what turns
      // "we told you afterwards" into "you never got a complete file". The
      // cost is one chunk of delay at the very end.
      if (index === entries.length - 1) {
        const rootHex = to0x(await merkleRoot(leaves));
        if (rootHex !== manifest.merkleRoot) {
          throw new Error("reassembled Merkle root does not match the manifest");
        }
        if (expectedMerkleRoot && rootHex !== expectedMerkleRoot.toLowerCase()) {
          throw new Error(
            "reassembled Merkle root does not match the root recorded on-chain — this file is not the registered document"
          );
        }
      }

      yield { index, bytes: plain, entry: entries[index] };
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

/**
 * Returns false, rather than throwing, for a proof that is malformed as well as
 * one that simply does not verify — both are "no" to the only question a caller
 * asks here, and every field arrives from whoever served the proof.
 */
export async function checkChunkProof(leafHex, proof, rootHex) {
  try {
    if (!Array.isArray(proof)) return false;
    return await verifyMerkleProof(
      fromHex(leafHex),
      proof.map((step) => ({ hash: fromHex(step && step.hash), side: step && step.side })),
      fromHex(rootHex)
    );
  } catch {
    return false;
  }
}

export { toHex, to0x };
