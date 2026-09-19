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

import {
  assertAnchorableDocument,
  buildBatch,
  createBatchQueue,
  proveInBatch,
} from "../js/core/anchor.js";
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
      // Reject anything that cannot be anchored before it is receipted, rather
      // than when the batch is built. issueReceipt() only asks for three
      // non-empty strings, so a document with a malformed fileHash used to be
      // signed and queued, and only failed later — taking the rest of the
      // pending queue with it.
      const anchorable = normalizeDocument(document);
      const receipt = await issueReceipt(anchorable, privateKey, { issuer, kid });
      const queued = queue.add({
        fileHash: anchorable.fileHash,
        merkleRoot: anchorable.merkleRoot,
        fileSize: anchorable.fileSize,
        manifestCID: anchorable.manifestCID,
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

      // Build from a copy, and only drain once the batch and every proof
      // exist. Draining as the argument to buildBatch() meant a rejection
      // emptied the queue on its way out: every document in it lost its anchor
      // having already been handed a receipt promising one.
      const documents = queue.peek();
      const batch = await buildBatch(documents);
      const proofs = [];
      for (const document of batch.documents) {
        proofs.push([document.fileHash, await proveInBatch(batch, document.fileHash)]);
      }

      // Past this point nothing can throw, so the queue and the proof table
      // move together. Documents recorded while the tree was being built are
      // not in `documents` and stay queued for the next batch.
      queue.drain(documents.length);
      batches.set(batch.root, batch);
      for (const [fileHash, proof] of proofs) proofsByDocument.set(fileHash, proof);

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

/**
 * Put a submitted document into the one shape the rest of the service assumes,
 * or reject it as a client error.
 *
 * Hex is lowercased first because that is the only spelling the anchor accepts
 * and the only one a receipt records — without this a caller writing `0xAB…`
 * would be receipted under one spelling and anchored under another, and
 * proofFor() would never find it again.
 */
function normalizeDocument(document) {
  if (document === null || typeof document !== "object" || Array.isArray(document)) {
    throw Object.assign(new Error("a document must be a JSON object"), { status: 400 });
  }

  const lower = (value) => (typeof value === "string" ? value.toLowerCase() : value);
  const normalized = {
    ...document,
    fileHash: lower(document.fileHash),
    merkleRoot: lower(document.merkleRoot),
  };

  try {
    assertAnchorableDocument(normalized);
  } catch (error) {
    throw Object.assign(error, { status: 400 });
  }
  return normalized;
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
