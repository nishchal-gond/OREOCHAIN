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
  DEFAULT_PBKDF2_ITERATIONS,
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
 * @param {number} [options.chunkSize]
 * @param {number} [options.iterations] PBKDF2 iterations
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
    iterations = DEFAULT_PBKDF2_ITERATIONS,
    onProgress,
  } = options;

  const encrypted = typeof passphrase === "string" && passphrase.length > 0;
  if (encrypted) getSuite(suite); // fail fast on an unknown suite name

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
    _iterations: iterations,
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
      packed._iterations
    );
    header.kdf = {
      name: "PBKDF2-SHA256",
      iterations: packed._iterations,
      salt: toBase64(packed._kdfSalt),
    };
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
export async function openManifest(manifest, passphrase = null) {
  if (!manifest || manifest.version !== MANIFEST_VERSION) {
    throw new Error(`unsupported manifest version: ${manifest && manifest.version}`);
  }

  if (!manifest.encrypted) {
    return { fileKey: null, fileSalt: null, body: manifest.body };
  }

  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new Error("this file is encrypted — a passphrase is required");
  }

  const kdfSalt = fromBase64(manifest.kdf.salt);
  const fileKey = await unwrapFileKey(
    {
      iv: fromBase64(manifest.wrappedKey.iv),
      ciphertext: fromBase64(manifest.wrappedKey.ciphertext),
    },
    passphrase,
    kdfSalt,
    manifest.kdf.iterations
  );

  const fileSalt = fromBase64(manifest.fileSalt);
  const derived = await deriveManifestKey(fileKey, fileSalt);
  const plain = await openWithDerivedKey(fromBase64(manifest.body), derived, MANIFEST_AAD);

  return { fileKey, fileSalt, body: JSON.parse(fromUtf8(plain)) };
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
  const { expectedMerkleRoot, onProgress } = options;
  const entries = [...opened.body.chunks].sort((a, b) => a.index - b.index);

  if (entries.length !== manifest.totalChunks) {
    throw new Error(
      `manifest lists ${entries.length} chunks but declares ${manifest.totalChunks}`
    );
  }
  entries.forEach((entry, i) => {
    if (entry.index !== i) throw new Error(`chunk table has a gap at index ${i}`);
  });

  const plainChunks = [];
  for (const entry of entries) {
    const payload = await fetchChunk(entry.location, entry);

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

    plainChunks.push(plain);
    if (onProgress) onProgress(plainChunks.length, entries.length);
  }

  const leaves = await hashChunks(plainChunks);
  const root = await merkleRoot(leaves);
  const rootHex = to0x(root);

  if (rootHex !== manifest.merkleRoot) {
    throw new Error("reassembled Merkle root does not match the manifest");
  }
  if (expectedMerkleRoot && rootHex !== expectedMerkleRoot.toLowerCase()) {
    throw new Error(
      "reassembled Merkle root does not match the root recorded on-chain — this file is not the registered document"
    );
  }

  const bytes = concat(...plainChunks);
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
    merkleRoot: rootHex,
  };
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
