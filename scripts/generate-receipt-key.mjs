#!/usr/bin/env node
/**
 * Generate a receipt signing key for the gateway.
 *
 *   node scripts/generate-receipt-key.mjs
 *
 * Store the output in OREOCHAIN_RECEIPT_KEY. Keep it secret.
 *
 * Rotating it is supported: the gateway keeps a keyring of every public key
 * that has ever signed here, so receipts issued under the old key still
 * verify afterwards and GET /api/proofs/key?kid= still serves the key they
 * name. This file used to say rotating it left nobody able to verify them,
 * which stopped being true when the keyring landed — and this is the file an
 * operator reads just before rotating.
 *
 * *Losing* it is still unrecoverable, and it is a different thing from
 * rotating: a key the ring never saw signs nothing and verifies nothing.
 * Anchored batches are unaffected either way — they live on-chain and do not
 * depend on this key.
 */

import { generateSigningKey, keyId } from "../js/core/receipt.js";

const keys = await generateSigningKey();
const kid = await keyId(keys.publicKey);

console.error(`# key id: ${kid}`);
console.error("# Set this as OREOCHAIN_RECEIPT_KEY (keep it secret):");
console.log(JSON.stringify(keys.exported));
