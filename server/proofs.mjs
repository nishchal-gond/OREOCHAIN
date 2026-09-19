/**
 * The proof service: signed receipts now, batched anchors later.
 *
 * This is what removes the wallet from the user's path. They upload, they get a
 * signed receipt immediately, and the operator anchors a Merkle root over many
 * documents in one periodic transaction. The user never installs an extension,
 * never holds a token, never pays gas — and still ends up with an independently
 * verifiable, public commitment to their document.
 *
 * State is durable (server/store.mjs). It has to be: a Merkle path depends on a
 * document's index in its batch, so the ordered document list behind an
 * anchored root is the only thing that can prove a document is in it. Held in
 * memory, that list did not survive a restart, and a document anchored on a
 * public chain became permanently unprovable while its receipt went on
 * claiming otherwise.
 *
 * Proofs are derived on demand rather than stored, because a stored proof is a
 * second copy of something the batch already determines, and two copies can
 * disagree.
 */

import {
  assertAnchorableDocument,
  buildBatch,
  proveWholeBatch,
} from "../js/core/anchor.js";
import { readSecret } from "./config.mjs";
import { openStore } from "./store.mjs";
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

  const store = options.store || openStore({ path: options.dbPath || ":memory:" });
  const batchMaxSize = options.batchMaxSize ?? 1000;
  const batchMaxAgeMs = options.batchMaxAgeMs ?? 3600000;
  const now = options.now || (() => Date.now());

  /**
   * Built proofs, keyed by batch root. Derived state only — dropping this
   * costs a tree rebuild, never a proof, which is the whole point of storing
   * the document order instead of the paths.
   */
  const proofCache = new Map();
  const PROOF_CACHE_BATCHES = options.proofCacheBatches ?? 8;

  async function proofsForBatch(stored) {
    const cached = proofCache.get(stored.root);
    if (cached) return cached;

    const documents = stored.documents.map((fileHash) => {
      const document = store.findDocument(fileHash);
      if (!document) {
        throw new Error(`batch ${stored.root} names document ${fileHash}, which is not stored`);
      }
      return {
        fileHash: document.fileHash,
        merkleRoot: document.merkleRoot,
        fileSize: document.fileSize,
        manifestCID: document.manifestCID,
      };
    });

    // Rebuilt from the stored order, so the root this produces must equal the
    // one that was anchored. If it does not, the log disagrees with the chain
    // and serving a proof from it would be worse than serving none.
    const batch = await buildBatch(documents);
    if (batch.root !== stored.root) {
      throw new Error(
        `rebuilt batch root ${batch.root} does not match the stored root ${stored.root}`
      );
    }

    const proofs = await proveWholeBatch(batch);
    proofCache.set(stored.root, proofs);
    if (proofCache.size > PROOF_CACHE_BATCHES) {
      proofCache.delete(proofCache.keys().next().value);
    }
    return proofs;
  }

  return {
    kid,
    ephemeral,
    publicJwk: resolvedPublicJwk,

    /** Issue a receipt and record the document for the next anchor. */
    async record(document) {
      // Reject anything that cannot be anchored before it is receipted, rather
      // than when the batch is built. issueReceipt() only asks for three
      // non-empty strings, so a document with a malformed fileHash used to be
      // signed and queued, and only failed later — taking the rest of the
      // pending queue with it.
      const anchorable = normalizeDocument(document);
      const receipt = await issueReceipt(anchorable, privateKey, { issuer, kid });

      // Persist before returning: the receipt is a promise in writing, and one
      // that outlives the process that made it only if the document does too.
      const { stored } = store.recordDocument(anchorable, receipt);

      return { receipt, queued: stored, pending: store.stats().pending };
    },

    status() {
      const stats = store.stats();
      const oldest = store.pendingDocuments(1)[0];
      return {
        kid,
        ephemeral,
        pending: stats.pending,
        shouldFlush:
          stats.pending > 0 &&
          (stats.pending >= batchMaxSize || now() - oldest.recordedAt >= batchMaxAgeMs),
        anchoredBatches: stats.batches,
        documents: stats.documents,
      };
    },

    /**
     * Build a batch from everything pending.
     *
     * Returns the root for the operator to submit on-chain. The submission
     * itself is deliberately not done here: it needs a funded key, and a
     * signing key with spending power does not belong in the same process that
     * accepts public uploads.
     */
    async buildPendingBatch() {
      const pending = store.pendingDocuments(batchMaxSize);
      if (pending.length === 0) return null;

      const batch = await buildBatch(
        pending.map((document) => ({
          fileHash: document.fileHash,
          merkleRoot: document.merkleRoot,
          fileSize: document.fileSize,
          manifestCID: document.manifestCID,
        }))
      );

      // One durable append records the batch and stamps its documents, so
      // there is no window where a document is in a batch but not marked, or
      // marked but not in one.
      store.saveBatch(batch);

      return {
        root: batch.root,
        size: batch.size,
        documents: batch.documents.map((document) => document.fileHash),
      };
    },

    /**
     * Note where a batch root landed on-chain, so verifiers can find it.
     *
     * Validated rather than trusted: this now arrives over HTTP from the
     * anchoring worker, and a malformed txHash written into the store would
     * be served to every verifier asking about that batch, pointing them at a
     * transaction that does not exist.
     */
    recordAnchor(root, { txHash, block }) {
      if (typeof root !== "string" || !/^0x[0-9a-f]{64}$/.test(root.toLowerCase())) {
        throw Object.assign(new Error("root must be 0x-prefixed 32-byte hex"), { status: 400 });
      }
      if (typeof txHash !== "string" || !/^0x[0-9a-f]{64}$/.test(txHash.toLowerCase())) {
        throw Object.assign(new Error("txHash must be 0x-prefixed 32-byte hex"), { status: 400 });
      }
      if (!Number.isInteger(block) || block < 0) {
        throw Object.assign(new Error("block must be a non-negative integer"), { status: 400 });
      }

      const known = store.findBatch(root.toLowerCase());
      if (!known) {
        throw Object.assign(new Error(`no batch ${root} to anchor`), { status: 404 });
      }
      if (known.txHash && known.txHash !== txHash.toLowerCase()) {
        // Two different transactions for one root means something is wrong
        // upstream; overwriting would hide it and break proofs already served.
        throw Object.assign(
          new Error(`batch ${root} is already anchored in ${known.txHash}`),
          { status: 409 }
        );
      }

      return store.anchorBatch(root.toLowerCase(), {
        txHash: txHash.toLowerCase(),
        block,
      });
    },

    /** The inclusion proof a user needs to verify their document on-chain. */
    async proofFor(fileHash) {
      const document = store.findDocument(String(fileHash).toLowerCase());
      if (!document || document.batchRoot === null) return null;

      const stored = store.findBatch(document.batchRoot);
      if (!stored) return null;

      const proof = (await proofsForBatch(stored)).get(document.fileHash);
      if (!proof) return null;

      // txHash and block are what lets a verifier find the transaction that
      // carries this root. Without them they hold a proof and no way to check
      // it against anything.
      return stored.txHash
        ? { ...proof, txHash: stored.txHash, block: stored.block }
        : proof;
    },

    listBatches() {
      return store.stats().batches;
    },

    /**
     * Batches built but not yet seen on-chain, oldest first.
     *
     * This is how the anchoring worker recovers: it owns the funded key and
     * the chain connection, but not the store, so after a crash between
     * building a batch and submitting it the gateway is the only thing that
     * knows the batch exists.
     */
    unanchoredBatches(limit) {
      return store.unanchoredBatches(limit).map((batch) => ({
        root: batch.root,
        size: batch.size,
        builtAt: batch.builtAt,
      }));
    },

    close() {
      store.close();
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
  // Also accepts OREOCHAIN_RECEIPT_KEY_FILE. This key signs every receipt the
  // service issues, so it is the one secret most worth keeping out of the
  // environment, where `docker inspect` and every child process can read it.
  const raw = readSecret(env, "OREOCHAIN_RECEIPT_KEY");
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
