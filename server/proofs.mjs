/**
 * The proof service: signed receipts now, batched anchors later.
 *
 * This is what removes the wallet from the user's path. They upload, they get a
 * signed receipt immediately, and the operator anchors a Merkle root over many
 * documents in one periodic transaction. The user never installs an extension,
 * never holds a token, never pays gas — and still ends up with an independently
 * verifiable, public commitment to their document.
 *
 * State here is in memory. Anchoring is a durability mechanism, so a restart
 * before the next flush loses the pending queue, not the documents: the chunks
 * and manifests are already stored, and their receipts are already issued and
 * verifiable. Re-queue and anchor again. server/README.md says so plainly.
 */

import { buildBatch, createBatchQueue, proveInBatch } from "../js/core/anchor.js";
import {
  generateSigningKey,
  importPrivateKey,
  importPublicKey,
  issueReceipt,
  keyId,
} from "../js/core/receipt.js";

/**
 * @param {object} options
 * @param {object|null} [options.privateJwk] signing key; generated if absent
 * @param {object|null} [options.publicJwk]
 * @param {string} [options.issuer]
 */
export async function createProofService(options = {}) {
  const { privateJwk = null, publicJwk = null, issuer = "oreochain-gateway" } = options;

  let privateKey;
  let publicKey;
  let resolvedPublicJwk = publicJwk;
  let ephemeral = false;

  if (privateJwk && publicJwk) {
    privateKey = await importPrivateKey(privateJwk);
    publicKey = await importPublicKey(publicJwk);
  } else {
    // An ephemeral key means every restart invalidates previously issued
    // receipts, because nobody can verify them any more. Usable for local
    // development; never for a deployment.
    const generated = await generateSigningKey();
    privateKey = generated.privateKey;
    publicKey = generated.publicKey;
    resolvedPublicJwk = generated.exported.publicJwk;
    ephemeral = true;
  }

  const kid = await keyId(publicKey);

  const queue = createBatchQueue({
    maxSize: options.batchMaxSize ?? 1000,
    maxAgeMs: options.batchMaxAgeMs ?? 3600000,
  });

  // Batches that have been built and handed to the operator to anchor.
  const batches = new Map(); // batchRoot -> batch
  const proofsByDocument = new Map(); // fileHash -> inclusion proof

  return {
    kid,
    ephemeral,
    publicJwk: resolvedPublicJwk,

    /** Issue a receipt and queue the document for the next anchor. */
    async record(document) {
      const receipt = await issueReceipt(document, privateKey, { issuer, kid });
      const queued = queue.add({
        fileHash: document.fileHash,
        merkleRoot: document.merkleRoot,
        fileSize: document.fileSize,
        manifestCID: document.manifestCID,
      });
      return { receipt, queued: queued.queued, pending: queue.size() };
    },

    status() {
      return {
        kid,
        ephemeral,
        pending: queue.size(),
        shouldFlush: queue.shouldFlush(),
        anchoredBatches: batches.size,
      };
    },

    /**
     * Build a batch from everything pending.
     *
     * Returns the root for the operator to submit on-chain, plus an inclusion
     * proof for every document. The submission itself is deliberately not done
     * here: it needs a funded key, and a signing key with spending power does
     * not belong in the same process that accepts public uploads.
     */
    async buildPendingBatch() {
      if (queue.size() === 0) return null;

      const batch = await buildBatch(queue.drain());
      batches.set(batch.root, batch);

      for (const document of batch.documents) {
        proofsByDocument.set(document.fileHash, await proveInBatch(batch, document.fileHash));
      }

      return {
        root: batch.root,
        size: batch.size,
        documents: batch.documents.map((document) => document.fileHash),
      };
    },

    /** The inclusion proof a user needs to verify their document on-chain. */
    proofFor(fileHash) {
      return proofsByDocument.get(fileHash.toLowerCase()) || null;
    },

    listBatches() {
      return [...batches.values()].map((batch) => ({ root: batch.root, size: batch.size }));
    },
  };
}

/** Parse a signing key pair from the environment, if one is configured. */
export function readSigningKey(env = process.env) {
  const raw = env.OREOCHAIN_RECEIPT_KEY;
  if (!raw) return { privateJwk: null, publicJwk: null };

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`OREOCHAIN_RECEIPT_KEY is not valid JSON: ${error.message}`);
  }
  if (!parsed.privateJwk || !parsed.publicJwk) {
    throw new Error("OREOCHAIN_RECEIPT_KEY must be {\"privateJwk\":…,\"publicJwk\":…}");
  }
  return parsed;
}
