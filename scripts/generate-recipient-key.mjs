#!/usr/bin/env node
/**
 * Generate a recipient keypair, so documents can be shared with you without
 * anyone sharing a passphrase.
 *
 *   node scripts/generate-recipient-key.mjs > my-identity
 *
 * Two halves come out:
 *
 *   the identity   printed to stdout, so it can be redirected straight into a
 *                  file. This is the secret. Anyone holding it can open every
 *                  document ever sealed to the matching recipient key, and
 *                  there is no recovery if it is lost — the wrapped file keys
 *                  are the only copies, and nothing else can unwrap them.
 *
 *   the recipient  printed to stderr, so it stays on screen when stdout is
 *                  redirected. This is the public half: publish it, mail it,
 *                  put it in a signature. It is what a sender passes to
 *                  packFile({ recipients: [...] }).
 *
 * Rotating is re-sealing: a new keypair does not open documents sealed to the
 * old one, so keep the old identity until every document that matters has been
 * re-sealed to the new recipient key.
 */

import { generateIdentity } from "../js/core/recipients.js";

const { identity, recipient } = await generateIdentity();

console.error("# Your recipient key — give this out so people can seal files to you:");
console.error(recipient);
console.error("#");
console.error("# Your identity is on stdout. It is secret: keep it, back it up, and");
console.error("# never put it in a manifest or paste it where a recipient key is asked for.");
console.log(identity);
