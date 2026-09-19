/**
 * Batch anchoring — proving many documents with one transaction.
 *
 * THE PROBLEM
 *
 * Registering each document on-chain costs one transaction. For a platform
 * that is fatal twice over:
 *
 *   1. Cost scales linearly with usage. Ten thousand uploads is ten thousand
 *      transactions, and the operator (or the user) pays for every one.
 *   2. Worse, it forces a wallet on every user. A person uploading a degree
 *      certificate does not have MetaMask, does not hold MATIC, and will not
 *      install a browser extension and buy cryptocurrency to file a document.
 *      That is not a fee problem, it is an adoption wall.
 *
 * THE FIX
 *
 * The same Merkle construction that proves a chunk belongs to a file proves a
 * file belongs to a batch. Collect every document registered during a window,
 * build a tree over them, and publish one root:
 *
 *      doc₁  doc₂  doc₃  …  doc₁₀₀₀₀      ← each an (already computed) leaf
 *        └──┬──┘     └──┬──┘
 *           └────┬──────┘
 *             batch root                   ← ONE transaction
 *
 * Every document still gets an independent, verifiable on-chain proof: its
 * inclusion path to the batch root. Ten thousand documents share the gas of a
 * single transaction, so per-document cost falls by four orders of magnitude
 * and keeps falling as volume grows — the opposite of the usual scaling curve.
 *
 * Combined with signed receipts (js/core/receipt.js), the user experience has
 * no wallet and no gas in it at all: they upload, they get a signed receipt
 * immediately, and the anchoring happens behind them on the operator's
 * schedule. The chain becomes a periodic public checkpoint rather than a
 * toll booth in front of every action.
 */

import { concat, fromHex, to0x, utf8 } from "./bytes.js";
import {
  buildMerkleTree,
  leafHash,
  merkleProof,
  merkleProofFromLevels,
  merkleRoot,
  verifyMerkleProof,
} from "./chunker.js";

export const ANCHOR_VERSION = "oreochain-anchor-v1";

/** Batches this large already amortise gas to near nothing; beyond it, proofs grow. */
export const MAX_BATCH_SIZE = 65536;

const HEX32 = /^0x[0-9a-f]{64}$/;

/**
 * Check that a document can be committed to, before anything depends on it.
 *
 * These rules used to live inside documentPreimage(), which meant they were
 * enforced at the moment the batch was built — long after the document had been
 * accepted, receipted and queued. A document that failed here then took every
 * document queued alongside it down with it. Exported so a caller can apply the
 * same rules at the door instead, where a rejection costs one request.
 */
export function assertAnchorableDocument(document) {
  if (document === null || typeof document !== "object") {
    throw new Error("a document must be an object");
  }
  const { fileHash, merkleRoot: root, fileSize, manifestCID } = document;

  if (typeof fileHash !== "string" || !HEX32.test(fileHash)) {
    throw new Error("fileHash must be 0x-prefixed 32-byte hex");
  }
  if (typeof root !== "string" || !HEX32.test(root)) {
    throw new Error("merkleRoot must be 0x-prefixed 32-byte hex");
  }
  if (!Number.isInteger(fileSize) || fileSize < 0) {
    throw new Error("fileSize must be a non-negative integer");
  }
  if (typeof manifestCID !== "string" || manifestCID.length === 0) {
    throw new Error("manifestCID must be a non-empty string");
  }
  return document;
}

/**
 * Canonical bytes committing to one document.
 *
 * Field order and widths are fixed because the Solidity side recomputes this
 * preimage byte-for-byte. `fileSize` is a big-endian uint64, matching
 * abi.encodePacked, so the two implementations cannot drift.
 */
export function documentPreimage(document) {
  assertAnchorableDocument(document);
  const { fileHash, merkleRoot: root, fileSize, manifestCID } = document;

  const size = new Uint8Array(8);
  new DataView(size.buffer).setBigUint64(0, BigInt(fileSize), false); // big-endian

  return concat(fromHex(fileHash), fromHex(root), size, utf8(manifestCID));
}

/** The batch-tree leaf for one document. */
export function documentLeaf(document) {
  return leafHash(documentPreimage(document));
}

/**
 * Build a batch from registered documents.
 *
 * @param {Array<{fileHash:string, merkleRoot:string, fileSize:number, manifestCID:string}>} documents
 * @returns {Promise<{root:string, size:number, leaves:Uint8Array[], documents:Array}>}
 */
export async function buildBatch(documents) {
  if (!Array.isArray(documents) || documents.length === 0) {
    throw new Error("a batch needs at least one document");
  }
  if (documents.length > MAX_BATCH_SIZE) {
    throw new Error(`a batch holds at most ${MAX_BATCH_SIZE} documents, got ${documents.length}`);
  }

  const seen = new Set();
  const leaves = [];
  for (const document of documents) {
    if (seen.has(document.fileHash)) {
      throw new Error(`document ${document.fileHash} appears twice in the batch`);
    }
    seen.add(document.fileHash);
    leaves.push(await documentLeaf(document));
  }

  return {
    version: ANCHOR_VERSION,
    root: to0x(await merkleRoot(leaves)),
    size: documents.length,
    leaves,
    documents,
  };
}

/**
 * The proof that one document is in a batch.
 *
 * Handed to the user at upload time, it is all they need — together with the
 * batch root read from the chain — to prove their document was anchored. The
 * proof is a few hundred bytes regardless of batch size: a 65,536-document
 * batch needs 16 sibling hashes.
 */
export async function proveInBatch(batch, fileHash) {
  const index = batch.documents.findIndex((document) => document.fileHash === fileHash);
  if (index === -1) throw new Error(`document ${fileHash} is not in this batch`);

  const proof = await merkleProof(batch.leaves, index);

  return {
    version: ANCHOR_VERSION,
    fileHash,
    batchRoot: batch.root,
    index,
    document: batch.documents[index],
    proof: proof.map((step) => ({ hash: to0x(step.hash), side: step.side })),
  };
}

/**
 * Every document's inclusion proof, from one pass over the batch.
 *
 * proveInBatch() rebuilds the whole tree per call, so proving a batch of n
 * documents one at a time costs n tree builds. Measured on a 500-document
 * batch that was 9.5 seconds; at the default batch size of 1000 it was around
 * 38. This builds the tree once and reads every path off it.
 *
 * @returns {Promise<Map<string, object>>} fileHash -> inclusion proof
 */
export async function proveWholeBatch(batch) {
  const levels = await buildMerkleTree(batch.leaves);
  const proofs = new Map();

  batch.documents.forEach((document, index) => {
    proofs.set(document.fileHash, {
      version: ANCHOR_VERSION,
      fileHash: document.fileHash,
      batchRoot: batch.root,
      index,
      document,
      proof: merkleProofFromLevels(levels, index).map((step) => ({
        hash: to0x(step.hash),
        side: step.side,
      })),
    });
  });

  return proofs;
}

/**
 * Verify an inclusion proof against a batch root read from the chain.
 *
 * Recomputes the leaf from the document's own fields rather than trusting a
 * supplied leaf — otherwise a proof could be valid for a leaf that has nothing
 * to do with the document it claims to describe.
 */
export async function verifyInBatch(inclusion, onChainBatchRoot) {
  // "This proof is invalid" is an answer a caller displays, not an exception it
  // handles, and every input here came from whoever served the proof — so a
  // malformed step, an over-long path or a bad hex digit is a reason, not a
  // throw.
  let expectedRoot;
  let ok;
  try {
    if (inclusion === null || typeof inclusion !== "object") {
      throw new Error("inclusion proof must be an object");
    }
    expectedRoot = (onChainBatchRoot || inclusion.batchRoot || "").toLowerCase();
    if (!HEX32.test(expectedRoot)) {
      throw new Error("batch root must be 0x-prefixed 32-byte hex");
    }
    if (!Array.isArray(inclusion.proof)) throw new Error("inclusion proof is missing its path");

    const leaf = await documentLeaf(inclusion.document);

    ok = await verifyMerkleProof(
      leaf,
      inclusion.proof.map((step) => ({
        hash: fromHex(step && step.hash),
        side: step && step.side,
      })),
      fromHex(expectedRoot)
    );
  } catch (error) {
    return { valid: false, reason: error.message };
  }

  if (!ok) return { valid: false, reason: "inclusion proof does not reach the batch root" };
  if (inclusion.document.fileHash !== inclusion.fileHash) {
    return { valid: false, reason: "proof names a different document than it carries" };
  }
  return { valid: true, fileHash: inclusion.fileHash, batchRoot: expectedRoot };
}

/**
 * Accumulates documents until it is worth anchoring.
 *
 * The operator decides the trade-off between cost and latency: a large batch
 * is cheaper per document, a short interval means a document is anchored
 * sooner. Nothing is lost while waiting — the signed receipt already proves
 * the service accepted the document, and the anchor upgrades that to a public,
 * independently checkable fact.
 */
export function createBatchQueue({ maxSize = 1000, maxAgeMs = 3600000, now = () => Date.now() } = {}) {
  let pending = [];
  let oldest = null;
  // A membership set beside the array: scanning `pending` on every add made
  // filling a queue quadratic, which at MAX_BATCH_SIZE is two billion string
  // comparisons on the request path.
  const queued = new Set();

  return {
    add(document) {
      if (pending.length >= MAX_BATCH_SIZE) throw new Error("batch queue is full");
      if (queued.has(document.fileHash)) return { queued: false, reason: "duplicate" };

      pending.push(document);
      queued.add(document.fileHash);
      if (oldest === null) oldest = now();
      return { queued: true, pending: pending.length };
    },

    /** True once the batch is large enough, or the oldest entry has waited long enough. */
    shouldFlush() {
      if (pending.length === 0) return false;
      return pending.length >= maxSize || now() - oldest >= maxAgeMs;
    },

    /**
     * Take pending documents and reset. The caller anchors what it receives.
     *
     * `count` takes only the oldest `count` entries, which is what lets a
     * caller build a batch first and remove exactly those documents afterwards
     * rather than emptying the queue before it knows the batch succeeded.
     * Entries are only ever appended, so the first `count` are always the ones
     * a preceding peek() returned.
     */
    drain(count = pending.length) {
      const taken = pending.slice(0, count);
      pending = pending.slice(count);
      for (const entry of taken) queued.delete(entry.fileHash);
      // Anything left was queued while the batch was being built, so its real
      // age is at most one build. Restarting the clock is a few seconds of
      // optimism, not a missed flush.
      oldest = pending.length === 0 ? null : now();
      return taken;
    },

    size: () => pending.length,
    peek: () => [...pending],
  };
}
