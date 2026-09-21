/**
 * Receipts have to outlive the key that signed them.
 *
 * A receipt is portable by design — exportReceipt and importReceipt exist so
 * a holder can keep one and come back with it later. Verifying it needs the
 * public key it names in `statement.kid`, and the gateway used to serve only
 * the current key. So the day the signing key changed, every receipt issued
 * before it started failing to verify, with the same answer a forgery gets,
 * and the holder had no way to tell which had happened.
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

import { assertSafeConfig, loadConfig } from "../server/config.mjs";
import { createHandler } from "../server/gateway.mjs";
import { createLogger } from "../server/log.mjs";
import { createMemoryBackend } from "../server/storage.mjs";
import { createProofService } from "../server/proofs.mjs";
import { openKeyring } from "../server/keyring.mjs";
import { generateSigningKey, importPublicKey, verifyReceipt } from "../js/core/receipt.js";

const silent = createLogger({ level: "silent" });
const KEY = "r".repeat(48);

function scratch(name) {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), "oreochain-keyring-")), name);
}

const aDocument = (n) => ({
  fileHash: "0x" + n.toString(16).padStart(64, "0"),
  merkleRoot: "0x" + (n + 0x4000).toString(16).padStart(64, "0"),
  manifestCID: `bafyKeyring${n}`,
  fileSize: 100 + n,
});

// ------------------------------------------------------------- the ring itself

test("a keyring remembers every key and forgets none", () => {
  const file = scratch("keys.json");

  const first = openKeyring({ path: file });
  first.use("kid-one", { kty: "EC", x: "one" });
  assert.equal(first.current().kid, "kid-one");

  // Reopened: a restart must not start with an empty ring.
  const reopened = openKeyring({ path: file });
  assert.equal(reopened.current().kid, "kid-one");
  assert.deepEqual(reopened.find("kid-one").publicJwk, { kty: "EC", x: "one" });

  // Rotation: the new key signs, the old one is retired from signing and kept
  // for verifying.
  reopened.use("kid-two", { kty: "EC", x: "two" });
  assert.equal(reopened.current().kid, "kid-two");
  assert.ok(reopened.find("kid-one").retiredAt, "the old key is marked retired");
  assert.deepEqual(reopened.find("kid-one").publicJwk, { kty: "EC", x: "one" });

  const afterRotation = openKeyring({ path: file });
  assert.equal(afterRotation.size(), 2);
  assert.equal(afterRotation.find("kid-one").publicJwk.x, "one");

  // Restarting on the same key changes nothing.
  const before = fs.readFileSync(file, "utf8");
  afterRotation.use("kid-two", { kty: "EC", x: "two" });
  assert.equal(fs.readFileSync(file, "utf8"), before);

  // And rotating back is not an error either: a key already held is not added
  // twice, but it does become current again.
  afterRotation.use("kid-one", { kty: "EC", x: "one" });
  assert.equal(afterRotation.size(), 2);
  assert.equal(afterRotation.current().kid, "kid-one");
});

test("a keyring that cannot be read is a refusal, not an empty ring", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "oreochain-keyring-"));
  // Starting with an empty ring here would silently lose every historical key
  // and take every receipt issued under them with it.
  assert.throws(() => openKeyring({ path: directory }), /cannot read the keyring/);

  const corrupt = scratch("corrupt.json");
  fs.writeFileSync(corrupt, "{not json");
  assert.throws(() => openKeyring({ path: corrupt }), /not valid JSON/);

  const future = scratch("future.json");
  fs.writeFileSync(future, JSON.stringify({ v: 99, keys: [] }));
  assert.throws(() => openKeyring({ path: future }), /version 99/);
});

test("only public keys are written to disk", async () => {
  // The signing key comes from OREOCHAIN_RECEIPT_KEY precisely to keep it off
  // the data volume. A keyring that wrote private keys beside the proofs
  // would undo that to save a restart.
  const file = scratch("keys.json");
  const keys = await generateSigningKey();

  await createProofService({ ...keys.exported, keyringPath: file });

  const written = fs.readFileSync(file, "utf8");
  assert.match(written, /"kid"/);
  assert.doesNotMatch(written, /"d"/, "an EC private key's d parameter is in the file");

  // And not merely absent under that name: the secret itself is nowhere in it.
  assert.ok(keys.exported.privateJwk.d, "this key pair has a private component to look for");
  assert.equal(written.includes(keys.exported.privateJwk.d), false);
});

// --------------------------------------------------------- across a rotation

async function startGateway(proofs) {
  const config = assertSafeConfig(
    loadConfig({ OREOCHAIN_API_KEYS: KEY, OREOCHAIN_STORAGE: "memory" }),
    { warn: () => {} }
  );
  const handler = createHandler(config, createMemoryBackend(), {
    logger: silent,
    sweeper: false,
    proofs,
  });
  const server = http.createServer((req, res) => {
    handler(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500).end();
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    stop: () => new Promise((resolve) => server.close(resolve)),
  };
}

test("a receipt signed by a retired key still verifies after a rotation", async () => {
  const keyringPath = scratch("keys.json");
  const dbPath = scratch("proofs.log");

  const original = await generateSigningKey();
  const replacement = await generateSigningKey();

  // Day one: a receipt is issued and the holder walks away with it.
  const before = await createProofService({ ...original.exported, keyringPath, dbPath });
  const { receipt } = await before.record(aDocument(1));
  before.close();

  assert.equal(receipt.statement.kid, before.kid);

  // Some time later the operator rotates the signing key and restarts.
  const after = await createProofService({ ...replacement.exported, keyringPath, dbPath });
  assert.notEqual(after.kid, before.kid, "a new key is signing now");

  const gw = await startGateway(after);
  try {
    // The holder comes back with a receipt naming a key this gateway no
    // longer signs with, and asks for it by name.
    const response = await fetch(`${gw.url}/api/proofs/key?kid=${receipt.statement.kid}`);
    assert.equal(response.status, 200);
    const served = await response.json();
    assert.equal(served.kid, receipt.statement.kid);
    assert.ok(served.retiredAt, "and is told it is no longer the signing key");

    const checked = await verifyReceipt(receipt, await importPublicKey(served.publicJwk));
    assert.equal(checked.valid, true, "the receipt still verifies");

    // Without the keyring this is what a holder got instead, and it is the
    // same answer a forgery gets.
    const current = await (await fetch(`${gw.url}/api/proofs/key`)).json();
    const againstCurrent = await verifyReceipt(receipt, await importPublicKey(current.publicJwk));
    assert.equal(againstCurrent.valid, false);

    // The unrotated listing says what else can be asked for, so a client does
    // not have to guess.
    assert.equal(current.kid, after.kid);
    assert.equal(current.keys.length, 2);
    assert.deepEqual(
      current.keys.map((key) => key.current).sort(),
      [false, true]
    );

    const missing = await fetch(`${gw.url}/api/proofs/key?kid=never-signed-here`);
    assert.equal(missing.status, 404);
    assert.equal((await missing.json()).code, "bad_request");
  } finally {
    after.close();
    await gw.stop();
  }
});

test("historical keys are public, like the current one", async () => {
  // Verifying someone else's document is a public act; a court or an employer
  // checking a certificate has no account here, and a receipt whose key needs
  // one is not portable.
  const keyringPath = scratch("keys.json");
  const keys = await generateSigningKey();
  const proofs = await createProofService({ ...keys.exported, keyringPath });

  const gw = await startGateway(proofs);
  try {
    const response = await fetch(`${gw.url}/api/proofs/key?kid=${proofs.kid}`);
    assert.equal(response.status, 200, "asking for a key by name needs no credential");
    assert.equal((await response.json()).retiredAt, null);
  } finally {
    await gw.stop();
  }
});
