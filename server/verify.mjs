/**
 * Checking that a document is what the client says it is, before signing a
 * receipt for it.
 *
 * WHY THIS EXISTS
 *
 * A receipt states "this service accepted this exact document at this time"
 * (js/core/receipt.js). It did not. `record()` signed whatever three strings it
 * was handed: nothing checked that the manifestCID resolved to anything, that
 * the manifest it named described the file being receipted, or that the
 * document had any relationship to bytes this gateway had ever seen.
 *
 * So a client could obtain a validly signed receipt for a fileHash and
 * merkleRoot of its choosing, pointing at a manifest describing something else
 * entirely — and that receipt verifies, because the signature was never the
 * part that was lying. The batch built from it anchors the same fiction
 * on-chain.
 *
 * WHAT IT DOES NOT DO
 *
 * It does not decrypt anything, and it cannot. A manifest's header —
 * fileHash, merkleRoot, fileSize, totalChunks — is plaintext even for an
 * encrypted file; only the body, which holds the file name and the chunk
 * table, is sealed under the file key. The gateway reads the header and
 * nothing else, so the property that makes this service safe to operate for
 * other people is untouched: no plaintext, no passphrase, no file key.
 *
 * WHAT IT CANNOT PROVE
 *
 * That the manifest's own Merkle root is the root of the chunks it lists would
 * mean fetching and hashing every chunk — the whole file, on every upload, to
 * re-derive something the client already computed. This checks the cheap and
 * load-bearing thing instead: the document being receipted and the manifest it
 * names agree with each other. A client can still describe a file it made up,
 * but it can no longer be handed a receipt for one document while pointing at
 * a manifest for another.
 */

import { readManifest } from "../js/core/manifest.js";

/** The header fields a document and its manifest must agree on. */
const MUST_MATCH = ["fileHash", "merkleRoot", "fileSize"];

export class VerificationError extends Error {
  constructor(message, { status = 400, retryable = false } = {}) {
    super(message);
    this.name = "VerificationError";
    this.status = status;
    this.retryable = retryable;
  }
}

/**
 * @param {object} options
 * @param {{get: (cid: string) => Promise<Uint8Array>}} options.backend
 * @param {object} [options.limits] manifest bounds, passed to readManifest
 */
export function createManifestVerifier({ backend, limits = {} } = {}) {
  if (!backend || typeof backend.get !== "function") {
    throw new Error("createManifestVerifier needs a storage backend to read manifests through");
  }

  return {
    /**
     * @returns {Promise<{manifest: object}>} resolves when the document and its
     *   manifest agree; throws VerificationError otherwise.
     */
    async verify(document) {
      let bytes;
      try {
        bytes = await backend.get(document.manifestCID);
      } catch (error) {
        /*
         * Unfetchable is not the same as wrong, and the difference matters to
         * the caller: a freshly pinned manifest may not have propagated yet,
         * which a retry fixes, while a mismatch never will. Signing anyway
         * would defeat the point of checking, so this refuses — but says it is
         * worth trying again.
         */
        throw new VerificationError(
          `could not read manifest ${document.manifestCID} to verify this document: ${error.message}`,
          { status: 503, retryable: true }
        );
      }

      let manifest;
      try {
        // Header only. No passphrase is involved and none would help.
        manifest = readManifest(bytes, { limits });
      } catch (error) {
        throw new VerificationError(
          `manifest ${document.manifestCID} is not a valid manifest: ${error.message}`
        );
      }

      for (const field of MUST_MATCH) {
        const claimed = normalize(document[field]);
        const actual = normalize(manifest[field]);
        if (claimed !== actual) {
          throw new VerificationError(
            `document ${field} (${claimed}) does not match manifest ${document.manifestCID} ` +
              `(${actual}) — refusing to sign a receipt for a document this manifest does not describe`
          );
        }
      }

      return { manifest };
    },
  };
}

function normalize(value) {
  return typeof value === "string" ? value.toLowerCase() : value;
}

export const _internals = { MUST_MATCH, normalize };
