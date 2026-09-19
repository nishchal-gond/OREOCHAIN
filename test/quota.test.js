/**
 * What an anonymous visitor may cost.
 *
 * Anonymous access is a supported configuration here, not a development
 * shortcut — the premise is that a visitor needs no account — so what makes
 * it safe is not authentication but a ceiling on the spend. These tests are
 * about that ceiling, and about the thing that silently disables it: a proxy
 * in front of the gateway turning every visitor into one client.
 */

import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

import { assertSafeConfig, loadConfig } from "../server/config.mjs";
import { clientAddress } from "../server/clientaddr.mjs";
import { createHandler } from "../server/gateway.mjs";
import { createLogger } from "../server/log.mjs";
import { createMemoryBackend } from "../server/storage.mjs";
import { CLIENT_BYTES, DAILY_BYTES, createQuota } from "../server/quota.mjs";

const silent = createLogger({ level: "silent" });

const CAPS = {
  OREOCHAIN_CLIENT_BYTES_PER_WINDOW: "1000",
  OREOCHAIN_CLIENT_OBJECTS_PER_WINDOW: "5",
  OREOCHAIN_DAILY_BYTES: "10000",
  OREOCHAIN_DAILY_OBJECTS: "50",
};

// ------------------------------------------------------- the address itself

function request(remoteAddress, headers = {}) {
  return { socket: { remoteAddress }, headers };
}

test("X-Forwarded-For is believed exactly as far as it is trusted", () => {
  // Nothing is trusted by default, because anyone can send this header.
  assert.equal(
    clientAddress(request("10.0.0.1", { "x-forwarded-for": "1.2.3.4" }), 0),
    "10.0.0.1"
  );

  // One proxy of our own: it appended what it saw, and that is the client.
  assert.equal(
    clientAddress(request("10.0.0.1", { "x-forwarded-for": "1.2.3.4" }), 1),
    "1.2.3.4"
  );

  /*
   * The attack this defends against: a client sends its own X-Forwarded-For
   * to mint a fresh budget, and our proxy appends the real address to the
   * right of it. Counting from the right lands on the real one.
   */
  assert.equal(
    clientAddress(request("10.0.0.1", { "x-forwarded-for": "9.9.9.9, 1.2.3.4" }), 1),
    "1.2.3.4"
  );

  // Two proxies of our own, and a forged entry in front of them.
  assert.equal(
    clientAddress(request("10.0.0.1", { "x-forwarded-for": "9.9.9.9, 1.2.3.4, 10.0.0.2" }), 2),
    "1.2.3.4"
  );

  // Fewer entries than there are trusted proxies: the header is not what the
  // configuration says it is, so it is not evidence of anything.
  assert.equal(
    clientAddress(request("10.0.0.1", { "x-forwarded-for": "1.2.3.4" }), 3),
    "10.0.0.1"
  );

  // An IPv4 client on a dual-stack socket must not count as two clients.
  assert.equal(clientAddress(request("::ffff:1.2.3.4"), 0), "1.2.3.4");

  // Junk is not an address, and must not become a budget of its own.
  assert.equal(
    clientAddress(request("10.0.0.1", { "x-forwarded-for": "not an address" }), 1),
    "10.0.0.1"
  );
  assert.equal(clientAddress(request(undefined), 0), "unknown");
});

// -------------------------------------------------------------- the budgets

test("one client cannot spend everyone else's share", () => {
  let clock = 0;
  const quota = createQuota({ clientBytes: 1000, windowMs: 100, now: () => clock });

  assert.equal(quota.check("a", 600).allowed, true);
  quota.record("a", 600);

  const refused = quota.check("a", 600);
  assert.equal(refused.allowed, false);
  assert.equal(refused.scope, CLIENT_BYTES);
  assert.equal(refused.status, 429, "their window will roll over, so this is a 429");
  assert.ok(refused.retryAfterSeconds >= 1);

  // Another client is unaffected: this is a per-client cap, not a global one.
  assert.equal(quota.check("b", 900).allowed, true);

  // And the window rolls over.
  clock += 100;
  assert.equal(quota.check("a", 900).allowed, true);
});

test("the service as a whole has a daily ceiling, and it is a 503", () => {
  let clock = 0;
  const quota = createQuota({ dailyBytes: 1000, now: () => clock });

  // A thousand well-behaved clients still add up to the operator's bill.
  for (let i = 0; i < 10; i++) {
    assert.equal(quota.check(`client-${i}`, 100).allowed, true);
    quota.record(`client-${i}`, 100);
  }

  const refused = quota.check("client-11", 1);
  assert.equal(refused.allowed, false);
  assert.equal(refused.scope, DAILY_BYTES);
  assert.equal(refused.status, 503, "nothing the caller does will help until the day turns");
  assert.match(refused.message, /as much as it is allowed to today/);

  // The budget is a day, and the day turns.
  clock += 86_400_000;
  assert.equal(quota.check("client-11", 100).allowed, true);
});

test("objects are capped as well as bytes, because a million tiny pins still cost", () => {
  const quota = createQuota({ clientObjects: 2, windowMs: 1000 });

  quota.record("a", 1);
  quota.record("a", 1);

  const refused = quota.check("a", 1);
  assert.equal(refused.allowed, false);
  assert.match(refused.message, /as many objects/);
});

test("what is charged is what was stored, not what was declared", () => {
  const quota = createQuota({ clientBytes: 1000, windowMs: 1000 });

  // A client may declare 900 bytes and send 10. Only what reached the pinning
  // service costs anything.
  assert.equal(quota.check("a", 900).allowed, true);
  quota.record("a", 10);

  assert.equal(quota.check("a", 900).allowed, true, "the 900 was never spent");
  assert.equal(quota.snapshot().dailyBytes, 10);
});

test("the quota's memory follows live clients", () => {
  let clock = 0;
  const quota = createQuota({ clientBytes: 10, windowMs: 100, now: () => clock });
  for (let i = 0; i < 50; i++) quota.record(`client-${i}`, 1);
  assert.equal(quota.snapshot().clients, 50);

  clock += 100;
  assert.equal(quota.sweep(), 0, "windows that have rolled over are dropped");
});

// ------------------------------------------------------------ configuration

test("anonymous mode with a pinning account refuses to start without ceilings", () => {
  const env = { OREOCHAIN_ALLOW_ANONYMOUS: "true", PINATA_JWT: "jwt" };

  assert.throws(
    () => assertSafeConfig(loadConfig(env), { warn: () => {} }),
    /4 are unset/,
    "anonymous access without a ceiling is a bill with no ceiling"
  );

  // The message has to be actionable: every missing cap, by name, with a
  // number an operator can start from.
  try {
    assertSafeConfig(loadConfig(env), { warn: () => {} });
    assert.fail("should have thrown");
  } catch (error) {
    for (const name of Object.keys(CAPS)) assert.match(error.message, new RegExp(name));
    assert.match(error.message, /256 MiB per client per hour/);
    assert.match(error.message, /could afford to lose in a day/);
  }

  // With them set it starts, and warns about the one thing that silently
  // disables per-client caps.
  const warnings = [];
  const config = assertSafeConfig(loadConfig({ ...env, ...CAPS }), {
    warn: (message) => warnings.push(message),
  });
  assert.equal(config.dailyBytes, 10000);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /TRUSTED_PROXY_HOPS=0/);
  assert.match(warnings[0], /every visitor shares one budget/);

  // Behind a declared proxy there is nothing to warn about.
  const quiet = [];
  assertSafeConfig(loadConfig({ ...env, ...CAPS, OREOCHAIN_TRUSTED_PROXY_HOPS: "1" }), {
    warn: (message) => quiet.push(message),
  });
  assert.deepEqual(quiet, []);
});

test("a keyed gateway is not forced to set ceilings it does not need", () => {
  // The caps exist for the anonymous case. A private deployment that issues
  // keys to known clients is not made safer by being made harder to start.
  const config = assertSafeConfig(
    loadConfig({ OREOCHAIN_API_KEYS: "k".repeat(48), PINATA_JWT: "jwt" }),
    { warn: () => {} }
  );
  assert.equal(config.dailyBytes, null);
});

// -------------------------------------------------------------- end to end

async function startGateway(env = {}, deps = {}) {
  const config = assertSafeConfig(
    loadConfig({
      OREOCHAIN_ALLOW_ANONYMOUS: "true",
      OREOCHAIN_STORAGE: "memory",
      ...CAPS,
      ...env,
    }),
    { warn: () => {} }
  );

  const backend = createMemoryBackend();
  let stored = 0;
  const counting = {
    ...backend,
    put: async (bytes, name) => {
      stored++;
      return backend.put(bytes, name);
    },
  };

  const handler = createHandler(config, counting, {
    logger: silent,
    sweeper: false,
    proofs: null,
    ...deps,
  });
  const server = http.createServer((req, res) => {
    handler(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500).end();
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

  return {
    url: `http://127.0.0.1:${server.address().port}`,
    stored: () => stored,
    stop: () => new Promise((resolve) => server.close(resolve)),
  };
}

const pin = (gw, body, headers = {}) =>
  fetch(`${gw.url}/api/storage/pin`, { method: "POST", body, headers });

test("an upload past the ceiling is refused before its body is read", async () => {
  const gw = await startGateway({ OREOCHAIN_CLIENT_BYTES_PER_WINDOW: "100" });
  try {
    assert.equal((await pin(gw, "x".repeat(50))).status, 200);
    assert.equal(gw.stored(), 1);

    const refused = await pin(gw, "x".repeat(80));
    assert.equal(refused.status, 429);
    assert.equal(gw.stored(), 1, "nothing was sent to the pinning service");

    const body = await refused.json();
    assert.equal(body.scope, CLIENT_BYTES);
    assert.ok(Number(refused.headers.get("retry-after")) >= 1);
  } finally {
    await gw.stop();
  }
});

test("the daily ceiling stops the service, not just the client that hit it", async () => {
  const gw = await startGateway({
    OREOCHAIN_DAILY_BYTES: "100",
    OREOCHAIN_CLIENT_BYTES_PER_WINDOW: "1000",
    OREOCHAIN_TRUSTED_PROXY_HOPS: "1",
  });
  try {
    assert.equal((await pin(gw, "x".repeat(90), { "x-forwarded-for": "1.1.1.1" })).status, 200);

    // A different visitor entirely, and the answer is 503: this is the
    // operator's bill, not this client's share.
    const refused = await pin(gw, "x".repeat(90), { "x-forwarded-for": "2.2.2.2" });
    assert.equal(refused.status, 503);
    assert.match((await refused.json()).error, /allowed to today/);
  } finally {
    await gw.stop();
  }
});

test("behind a trusted proxy, visitors are metered apart; without one, together", async () => {
  // This is the failure worth catching: with hops at 0 behind a load
  // balancer, the first heavy visitor shuts out everyone else, and the
  // gateway looks perfectly healthy while doing it.
  const shared = await startGateway({ OREOCHAIN_CLIENT_BYTES_PER_WINDOW: "100" });
  try {
    assert.equal((await pin(shared, "x".repeat(90), { "x-forwarded-for": "1.1.1.1" })).status, 200);
    const second = await pin(shared, "x".repeat(90), { "x-forwarded-for": "2.2.2.2" });
    assert.equal(second.status, 429, "both arrived from the same socket, so both share a budget");
  } finally {
    await shared.stop();
  }

  const separate = await startGateway({
    OREOCHAIN_CLIENT_BYTES_PER_WINDOW: "100",
    OREOCHAIN_TRUSTED_PROXY_HOPS: "1",
  });
  try {
    assert.equal(
      (await pin(separate, "x".repeat(90), { "x-forwarded-for": "1.1.1.1" })).status,
      200
    );
    assert.equal(
      (await pin(separate, "x".repeat(90), { "x-forwarded-for": "2.2.2.2" })).status,
      200,
      "a second visitor has their own budget"
    );
    assert.equal(
      (await pin(separate, "x".repeat(90), { "x-forwarded-for": "1.1.1.1" })).status,
      429,
      "and the first is still held to theirs"
    );
  } finally {
    await separate.stop();
  }
});

test("the spend, and the proxy setting, are readable from /metrics", async () => {
  const gw = await startGateway({ OREOCHAIN_TRUSTED_PROXY_HOPS: "1" });
  try {
    await pin(gw, "x".repeat(40), { "x-forwarded-for": "1.1.1.1" });

    const metrics = await (await fetch(`${gw.url}/metrics`)).text();

    assert.match(metrics, /oreochain_daily_bytes_pinned 40/);
    assert.match(metrics, /oreochain_daily_bytes_budget 10000/);
    assert.match(metrics, /oreochain_daily_objects_pinned 1/);
    assert.match(metrics, /oreochain_quota_clients 1/);

    // The one an operator behind a load balancer needs to see before it
    // bites: 0 here means every visitor shares a budget.
    assert.match(metrics, /oreochain_trusted_proxy_hops 1/);
  } finally {
    await gw.stop();
  }
});

test("a forwarded header nobody trusts is counted, so a missing hop setting is visible", async () => {
  const gw = await startGateway();
  try {
    await pin(gw, "x", { "x-forwarded-for": "1.1.1.1" });
    await pin(gw, "x", { "x-forwarded-for": "2.2.2.2" });

    const metrics = await (await fetch(`${gw.url}/metrics`)).text();
    assert.match(metrics, /oreochain_forwarded_for_ignored_total [2-9]/);
    assert.match(metrics, /oreochain_trusted_proxy_hops 0/);
  } finally {
    await gw.stop();
  }
});
