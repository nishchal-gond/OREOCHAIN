import test from "node:test";
import assert from "node:assert/strict";

import {
  REFUSAL_CODES,
  isRetryableRefusal,
  parseRetryAfter,
  refusalAdvice,
} from "../js/core/refusals.js";
import * as gateway from "../server/gateway.mjs";

// ------------------------------------------------------------- the vocabulary

/*
 * The one test that matters here. The client switches on `code` with no
 * fall-through, which is only safe while it knows every code the gateway can
 * send — so the two lists are compared rather than trusted to stay in step.
 *
 * Skipped rather than failing while the gateway's half is still in review: a
 * red build would say this client is wrong, and it is not. It arms itself the
 * moment the export lands.
 */
test(
  "the client knows every refusal code the gateway can send",
  {
    skip: gateway.REFUSAL_CODES
      ? false
      : "server/gateway.mjs does not export REFUSAL_CODES yet",
  },
  () => {
    assert.deepEqual(
      Object.values(REFUSAL_CODES).sort(),
      Object.values(gateway.REFUSAL_CODES).sort()
    );
  }
);

test("every code has advice, and it is one of the three faults", () => {
  for (const code of Object.values(REFUSAL_CODES)) {
    const advice = refusalAdvice(code);
    assert.ok(advice, `no advice for ${code}`);
    assert.equal(typeof advice.retry, "boolean");
    assert.ok(["caller", "service", "transient"].includes(advice.fault), code);
    assert.ok(advice.message.length > 0, code);
  }
});

test("a code this client has never heard of gets no advice, not a guess", () => {
  assert.equal(refusalAdvice("teapot"), null);
  assert.equal(refusalAdvice(undefined), null);
  assert.equal(refusalAdvice(42), null);
  assert.equal(isRetryableRefusal("teapot"), null);
});

test("wobbles are retried and caps are not", () => {
  assert.equal(isRetryableRefusal(REFUSAL_CODES.RATE_LIMITED), true);
  assert.equal(isRetryableRefusal(REFUSAL_CODES.BUSY), true);

  // The two that a client must never retry through: both are limits that will
  // still be there four attempts later, and retrying them is a small attack on
  // a service that already said no.
  assert.equal(isRetryableRefusal(REFUSAL_CODES.CLIENT_QUOTA), false);
  assert.equal(isRetryableRefusal(REFUSAL_CODES.GATEWAY_BUDGET), false);

  assert.equal(isRetryableRefusal(REFUSAL_CODES.UNAUTHORIZED), false);
  assert.equal(isRetryableRefusal(REFUSAL_CODES.FORBIDDEN), false);
  assert.equal(isRetryableRefusal(REFUSAL_CODES.BAD_REQUEST), false);
});

test("a gateway-budget refusal is not blamed on the user", () => {
  const advice = refusalAdvice(REFUSAL_CODES.GATEWAY_BUDGET);
  assert.equal(advice.fault, "service");
  assert.match(advice.message, /not something you did/i);
  assert.match(advice.message, /nothing was stored/i);
  // Saying nothing is retrying in the background is the point: otherwise the
  // user closes the tab believing the upload will finish on its own.
  assert.match(advice.message, /nothing is retrying/i);
});

test("a client-quota refusal says the allowance comes back", () => {
  const advice = refusalAdvice(REFUSAL_CODES.CLIENT_QUOTA);
  assert.equal(advice.fault, "caller");
  assert.match(advice.message, /nothing was stored/i);
  assert.match(advice.message, /refreshes/i);
});

// ------------------------------------------------------------- Retry-After

test("Retry-After in delta-seconds", () => {
  assert.equal(parseRetryAfter("30"), 30_000);
  assert.equal(parseRetryAfter("  5 "), 5_000);
  assert.equal(parseRetryAfter("0"), 0);
});

test("Retry-After as an HTTP-date, relative to now", () => {
  const now = Date.parse("2026-09-19T10:00:00Z");
  const at = new Date(now + 45_000).toUTCString();
  assert.equal(parseRetryAfter(at, () => now), 45_000);
});

test("a date already past asks for no wait rather than a negative one", () => {
  const now = Date.parse("2026-09-19T10:00:00Z");
  const at = new Date(now - 60_000).toUTCString();
  assert.equal(parseRetryAfter(at, () => now), 0);
});

test("an unparseable Retry-After degrades to ordinary backoff", () => {
  // Every one of these would be a NaN-length sleep if it were trusted.
  assert.equal(parseRetryAfter("soon"), null);
  assert.equal(parseRetryAfter(""), null);
  assert.equal(parseRetryAfter("   "), null);
  assert.equal(parseRetryAfter(null), null);
  assert.equal(parseRetryAfter(undefined), null);
  assert.equal(parseRetryAfter("-5"), null);
});
