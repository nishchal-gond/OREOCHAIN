#!/usr/bin/env node
/**
 * Generate a receipt signing key for the gateway.
 *
 *   node scripts/generate-receipt-key.mjs
 *
 * Store the output in OREOCHAIN_RECEIPT_KEY. Keep it secret and keep it stable:
 * rotating it invalidates every receipt issued under the old key, because
 * nobody can verify them any more. Anchored batches are unaffected — they live
 * on-chain and do not depend on this key.
 */

import { generateSigningKey, keyId } from "../js/core/receipt.js";

const keys = await generateSigningKey();
const kid = await keyId(keys.publicKey);

console.error(`# key id: ${kid}`);
console.error("# Set this as OREOCHAIN_RECEIPT_KEY (keep it secret):");
console.log(JSON.stringify(keys.exported));
