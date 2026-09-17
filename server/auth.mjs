/**
 * API key authentication.
 *
 * Keys are compared in constant time. A naive `===` on secrets leaks their
 * contents through timing: an attacker who can measure response time learns how
 * many leading characters they guessed correctly, turning an infeasible search
 * over the whole key into a character-by-character walk.
 */

import { createHash, timingSafeEqual } from "node:crypto";

/**
 * Hash both sides to a fixed 32 bytes before comparing. timingSafeEqual throws
 * on length mismatch, which would itself leak the key's length; hashing removes
 * that entirely, since every digest is the same size.
 */
function constantTimeEquals(a, b) {
  const left = createHash("sha256").update(a, "utf8").digest();
  const right = createHash("sha256").update(b, "utf8").digest();
  return timingSafeEqual(left, right);
}

export function extractToken(req) {
  const header = req.headers.authorization;
  if (typeof header !== "string") return null;

  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match ? match[1].trim() : null;
}

/**
 * @returns {{ok: true, keyId: string} | {ok: false, reason: string}}
 */
export function authenticate(req, config) {
  if (config.allowAnonymous) return { ok: true, keyId: "anonymous" };

  const token = extractToken(req);
  if (!token) return { ok: false, reason: "missing bearer token" };

  // Every configured key is checked, with no early exit, so the time taken does
  // not reveal which key matched or how many keys exist.
  let matched = null;
  for (const key of config.apiKeys) {
    if (constantTimeEquals(token, key) && matched === null) matched = key;
  }
  if (!matched) return { ok: false, reason: "invalid api key" };

  // Identify the key in logs and rate limits without ever writing it down.
  return { ok: true, keyId: createHash("sha256").update(matched).digest("hex").slice(0, 12) };
}

export const _internals = { constantTimeEquals };
