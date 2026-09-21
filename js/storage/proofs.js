/**
 * The gateway's proof endpoints, and what a browser can prove with them.
 *
 * This is the client for the default anchoring path. The user uploads a
 * document, the gateway signs a statement that it accepted exactly that
 * document at that moment and hands it back, and some minutes later a batch
 * containing it is anchored on-chain in one transaction the operator pays for.
 * No wallet, no gas, no waiting for a block before the user has something in
 * their hand.
 *
 * What each half is worth, stated plainly because the UI has to say it:
 *
 *   the receipt   is the service's signature over what it accepted. It is
 *                 instant and free and it is exactly as trustworthy as the
 *                 service — a service that signs a receipt and anchors
 *                 nothing has still signed a receipt.
 *   the anchor    is the part no one can retract. Once the batch root is in a
 *                 transaction, anyone with the inclusion proof can check the
 *                 document against a public chain, with this gateway offline
 *                 or hostile.
 *
 * The cross-check is what makes the pair worth more than either: the receipt
 * and the anchor commit to the same fileHash, merkleRoot and manifestCID, so a
 * service that issued one receipt and quietly anchored a different document is
 * caught by comparing them — which is what checkAnchor() below does, in the
 * browser, against a root read from the chain.
 *
 * Nothing here accepts a verdict from the gateway. Every function returns
 * materials, and every judgement is made locally from a signature or a Merkle
 * path. A gateway saying "yes, that is anchored" proves nothing about a
 * gateway.
 */

import {
  importPublicKey,
  receiptMatchesAnchor,
  verifyReceipt,
} from "../core/receipt.js";
import { verifyInBatch } from "../core/anchor.js";
import { timedFetch, withRetry } from "./ipfs.js";

const DEFAULT_ENDPOINTS = Object.freeze({
  record: "/api/proofs/record",
  key: "/api/proofs/key",
  inclusion: "/api/proofs/inclusion/",
  verify: "/api/proofs/verify/",
});

const HEX32 = /^0x[0-9a-f]{64}$/;

/** A key id is an opaque short string; keep it inert before it reaches a URL. */
const SAFE_KID = /^[A-Za-z0-9_-]{1,64}$/;

function assertFileHash(fileHash) {
  const hash = String(fileHash || "").toLowerCase();
  if (!HEX32.test(hash)) throw new Error("file hash must be 0x-prefixed 32-byte hex");
  return hash;
}

export function createProofClient(options = {}) {
  const { endpoints = {}, retry, timeoutMs } = options;
  const route = { ...DEFAULT_ENDPOINTS, ...endpoints };

  async function getJson(url, callOptions = {}) {
    const response = await timedFetch(
      url,
      { method: "GET", headers: { Accept: "application/json" }, credentials: "same-origin" },
      { signal: callOptions.signal, timeoutMs }
    );
    return response.json();
  }

  return {
    /**
     * Ask the gateway to receipt a stored document and queue it for anchoring.
     *
     * Retried like any other request: record() is keyed on the fileHash, so a
     * response lost to a dropped connection costs a second attempt and not a
     * duplicate. What is never retried is a refusal the gateway meant — see
     * isRetryable() in ipfs.js.
     */
    async record(document, callOptions = {}) {
      return withRetry(
        async () => {
          const response = await timedFetch(
            route.record,
            {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(document),
              credentials: "same-origin",
            },
            { signal: callOptions.signal, timeoutMs }
          );
          const body = await response.json();
          if (!body || !body.receipt) throw new Error("the gateway returned no receipt");
          return body;
        },
        { ...retry, signal: callOptions.signal }
      );
    },

    /**
     * The public key a receipt was signed with.
     *
     * Asked for by id, not "whichever key you are using now". A gateway that
     * has rotated its key, or restarted with an ephemeral one, still holds the
     * old public key — and without naming the one that signed, every receipt
     * issued before the rotation is indistinguishable from a forgery.
     */
    async signingKey(kid = null, callOptions = {}) {
      let url = route.key;
      if (kid !== null && kid !== undefined) {
        if (!SAFE_KID.test(String(kid))) throw new Error("receipt names an unusable key id");
        url += `?kid=${encodeURIComponent(kid)}`;
      }
      try {
        return await getJson(url, callOptions);
      } catch (error) {
        // A key id the keyring has never held is not a lookup failure. The
        // gateway is saying it never signed anything with that key, which for
        // a receipt claiming otherwise means the receipt is fabricated.
        if (error && error.status === 404) return null;
        throw error;
      }
    },

    /**
     * The inclusion proof for a document, or null while it is still pending.
     *
     * A 404 here is the ordinary state between upload and the next batch, not
     * an error: the document is queued and the receipt already covers it.
     */
    async inclusion(fileHash, callOptions = {}) {
      const hash = assertFileHash(fileHash);
      try {
        return await getJson(`${route.inclusion}${hash}`, callOptions);
      } catch (error) {
        if (error && error.status === 404) return null;
        throw error;
      }
    },

    /**
     * Everything the gateway knows about a document, in one call.
     *
     * This exists for the deployment that has no `contract.rpcUrl` set. With
     * an RPC the browser reads the chain itself and needs none of this; with
     * none, the alternative is telling a visitor nothing at all, which is the
     * worse answer.
     *
     * Its `gatewayClaim` is the gateway's own verdict and is never used as
     * one. What is worth having is everything beside it: the receipt, the
     * inclusion proof, the batch root, the transaction. Those can be checked,
     * and checkVerifyResponse() below checks them.
     *
     * Two of its statuses are states rather than failures, so they come back
     * as answers: 404 is "no record of that document", and 503 is "the
     * gateway could not reach the chain" — which says nothing about the
     * document and must never read as "not anchored".
     */
    async verify(fileHash, callOptions = {}) {
      const hash = assertFileHash(fileHash);
      try {
        return await getJson(`${route.verify}${hash}`, callOptions);
      } catch (error) {
        const body = error && error.refusalBody;
        if (error && (error.status === 404 || error.status === 503) && body) return body;
        if (error && error.status === 404) return { fileHash: hash, gatewayClaim: { status: "unknown" } };
        if (error && error.status === 503) {
          return { fileHash: hash, gatewayClaim: { status: "unavailable" } };
        }
        throw error;
      }
    },
  };
}

/**
 * Check a held receipt's signature against the key that signed it.
 *
 * This is worth being precise about, because it is easy to oversell. Fetching
 * the key from the same gateway that issued the receipt does not prove the
 * gateway honest — it could serve a key for any statement it cares to sign.
 * What it does prove is that the bytes in hand are the bytes that gateway
 * signed: it catches a truncated download, a hand-edited field, a receipt
 * from somewhere else, and a gateway that quietly re-signs a different
 * document and hopes nobody kept the original.
 *
 * The proof that does not depend on the gateway's honesty is the anchor, and
 * checkAnchor() is where it happens. A receipt is the bridge until then.
 */
export async function checkReceipt(receipt, client, options = {}) {
  const statement = receipt && receipt.statement;
  if (!statement) return { valid: false, reason: "malformed receipt" };

  let served;
  try {
    served = await client.signingKey(statement.kid ?? null, options);
  } catch (error) {
    // The service could not be reached, or answered with something that is
    // not an answer. That says nothing about the receipt either way, and must
    // not be reported as though it did.
    return {
      valid: false,
      unavailable: true,
      reason: `could not fetch the signing key: ${error.message}`,
    };
  }

  /*
   * Three outcomes, and the difference between them is the whole point.
   *
   * The keyring keeps every key that has ever signed here, retired ones
   * included. So a `kid` it has never held is the forgery case: no key of that
   * id ever signed at this service, whatever the statement claims.
   */
  if (served === null) {
    return {
      valid: false,
      forged: true,
      reason:
        `no key with id ${statement.kid} has ever signed at this service, so this receipt ` +
        `was not issued by it.`,
    };
  }

  if (!served.publicJwk) {
    return { valid: false, unavailable: true, reason: "the gateway served no public key" };
  }

  /*
   * A gateway that answers a `kid` lookup with a different key is one that
   * predates the keyring and ignored the query — it has not caught a forgery,
   * it cannot look the key up at all. Calling that invalid would tell a user
   * holding a perfectly good receipt that it is fake, which is by some
   * distance the worse of the two mistakes.
   */
  if (statement.kid && served.kid && served.kid !== statement.kid) {
    return {
      valid: false,
      unavailable: true,
      reason:
        `this service cannot produce the key this receipt names (${statement.kid}); it ` +
        `offered ${served.kid} instead. The receipt cannot be checked here — its anchor ` +
        `on-chain still can.`,
    };
  }

  let publicKey;
  try {
    publicKey = await importPublicKey(served.publicJwk);
  } catch (error) {
    return { valid: false, reason: `the served key is unusable: ${error.message}` };
  }

  const result = await verifyReceipt(receipt, publicKey, options);
  return {
    ...result,
    ephemeral: Boolean(served.ephemeral),
    kid: served.kid ?? null,
    // A key retired after this receipt was issued does not weaken it: the
    // signature was good when it was made and the statement carries its own
    // date. Surfaced so a UI can say so rather than leaving it a mystery.
    retiredAt: served.retiredAt ?? null,
  };
}

/**
 * Check an inclusion proof against a batch root read from the chain.
 *
 * `onChainBatchRoot` must come from the chain, not from the proof and not from
 * the gateway. Verifying a Merkle path against the root that shipped with it
 * proves only that the server can do arithmetic.
 */
export async function checkAnchor(receipt, inclusion, onChainBatchRoot) {
  if (!inclusion) return { anchored: false, reason: "no inclusion proof yet" };

  const included = await verifyInBatch(inclusion, onChainBatchRoot);
  if (!included.valid) return { anchored: false, reason: included.reason };

  const consistent = receiptMatchesAnchor(receipt, inclusion);
  if (!consistent.consistent) {
    /*
     * The receipt and the anchor describe different documents. This is the one
     * outcome that is not a delay or a wobble: the service signed one thing
     * and committed another, and the user's copy is the evidence.
     */
    return { anchored: false, disputed: true, reason: consistent.reason };
  }

  return {
    anchored: true,
    fileHash: included.fileHash,
    batchRoot: included.batchRoot,
    txHash: inclusion.txHash || null,
    block: inclusion.block ?? null,
  };
}

export const _internals = { DEFAULT_ENDPOINTS, SAFE_KID, assertFileHash };

/**
 * Check what a verify response actually proves, in this browser.
 *
 * Used only where there is no way to read the chain — with an RPC configured
 * the page reads `findBatch()` itself and this whole path is skipped. The
 * question it answers is therefore narrower than it looks, and the narrowness
 * is the point.
 *
 * What can be settled here, from the materials alone:
 *
 *   - the receipt's signature, against the key that signed it;
 *   - that the inclusion proof's Merkle path reaches the batch root the
 *     gateway supplied;
 *   - that the receipt and the batch leaf describe the same document.
 *
 * What cannot, at all: whether that batch root is on the chain. That is one
 * fact and it needs a chain read. Everything above can be true of a gateway
 * that has anchored nothing — the arithmetic is its own, and so is the root.
 *
 * So `chainConfirmed` is false in every branch of this function. There is no
 * input that makes it true, deliberately: a caller that wants it has to do
 * the read. `gatewayClaim` is read for exactly one thing, the transaction and
 * block to point a person at, and never for its verdict.
 */
export async function checkVerifyResponse(body, client, options = {}) {
  const claim = (body && body.gatewayClaim) || {};
  const result = {
    chainConfirmed: false,
    gatewayStatus: typeof claim.status === "string" ? claim.status : "unknown",
    warnings: Array.isArray(claim.warnings) ? claim.warnings : [],
    chainRead: body && body.chainRead ? body.chainRead : null,
    receipt: null,
    inclusion: null,
    consistent: null,
    anchor: null,
  };

  if (!body || (!body.receipt && !body.batch)) return result;

  if (body.receipt) {
    /*
     * The verify response will carry the signing key itself as an additive
     * follow-up. Use it when it is there and fall back to the keyring lookup
     * when it is not, so this works against both and needs no change when the
     * field lands.
     */
    const inline = body.publicJwk || (body.receipt && body.receipt.publicJwk) || null;
    result.receipt = inline
      ? await checkReceiptWithJwk(body.receipt, inline, options)
      : await checkReceipt(body.receipt, client, options);
  }

  if (body.batch && Array.isArray(body.batch.proof)) {
    /*
     * The verify endpoint's `batch` is not an inclusion proof, though it
     * carries one. It has no top-level fileHash — that lives at the root of
     * the response — and verifyInBatch() checks the two against each other,
     * so the proof has to be assembled into the shape that function verifies
     * rather than handed over as it arrived.
     */
    const inclusion = {
      fileHash: body.fileHash,
      batchRoot: body.batch.root,
      index: body.batch.index,
      document: body.batch.document,
      proof: body.batch.proof,
    };

    // Against the root the gateway supplied, which proves internal
    // consistency and nothing about the chain. Said plainly by the caller.
    result.inclusion = await verifyInBatch(inclusion, body.batch.root);

    if (body.receipt) {
      const match = receiptMatchesAnchor(body.receipt, inclusion);
      result.consistent = match.consistent;
      if (!match.consistent) result.warnings = [...result.warnings, match.reason];
    }

    const onChain = body.batch.onChain || body.batch.recorded || null;
    if (onChain && onChain.txHash) {
      result.anchor = {
        txHash: onChain.txHash,
        block: onChain.block ?? null,
        // Where the gateway says the root is. A pointer for a person to
        // follow, not a confirmation — nothing here checked it.
        claimedOnly: true,
      };
    }
  }

  return result;
}

/** checkReceipt against a key already in hand, skipping the keyring lookup. */
async function checkReceiptWithJwk(receipt, publicJwk, options = {}) {
  let publicKey;
  try {
    publicKey = await importPublicKey(publicJwk);
  } catch (error) {
    return { valid: false, unavailable: true, reason: `the served key is unusable: ${error.message}` };
  }
  return verifyReceipt(receipt, publicKey, options);
}
