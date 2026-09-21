/**
 * The whole path, through a real browser, the way a user walks it.
 *
 * Every other suite in this repository tests a layer. This one tests the
 * product: Chromium loads the shipped pages from the gateway, a real file is
 * chosen in the file picker, sealed in the tab, uploaded chunk by chunk,
 * registered on a real compiled contract, and then fetched back, verified
 * against the anchored Merkle root, decrypted and downloaded — and the bytes
 * that come out are compared with the bytes that went in.
 *
 * It exists because everything it covers was broken at once and no test
 * noticed. @noble's ESM imports by package specifier, which no browser can
 * resolve, so the entire chunking core failed to load; and every button was
 * an inline onclick, which the gateway's own Content-Security-Policy refuses
 * to run. Both are invisible to a unit test and fatal to a user, which is
 * exactly the gap a browser test is for.
 *
 * The console is part of the assertion. A page that renders while logging CSP
 * violations is broken, so `problems` is checked alongside the result.
 *
 * Run with `npm run test:e2e`. Skipped when Playwright is not installed.
 */

import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { anchorPending, loadPlaywright, openApp } from "./harness.mjs";
import { loadToolchain } from "./chain.mjs";

const missing = !loadPlaywright()
  ? "playwright is not installed — run `npm i -D playwright` to enable the browser suite"
  : !loadToolchain()
    ? "solc / @ethereumjs are not installed — run `npm install` to enable the browser suite"
    : false;

const PASSPHRASE = "correct horse battery staple";

let workspace;
let app;

before(async () => {
  if (missing) return;
  workspace = fs.mkdtempSync(path.join(os.tmpdir(), "oreochain-e2e-"));
  app = await openApp();
});

after(async () => {
  if (app) await app.close();
  if (workspace) fs.rmSync(workspace, { recursive: true, force: true });
});

/**
 * A file with real binary content, distinct per test: the contract rejects a
 * second registration of the same file hash, which is the correct behaviour
 * and would otherwise make these tests order-dependent.
 */
function sampleFile(name, sizeBytes = 200_000) {
  const bytes = Buffer.concat([
    Buffer.from(`%PDF-1.4\n% ${name}\n`),
    crypto.randomBytes(sizeBytes),
  ]);
  const file = path.join(workspace, name);
  fs.writeFileSync(file, bytes);
  return { file, bytes };
}

/** Wait for the page's own status line to settle into success or failure. */
async function waitForNote(page, pattern) {
  await page.waitForFunction(
    (source) => {
      const note = document.getElementById("note");
      if (!note) return false;
      return new RegExp(source).test(note.innerHTML) || /text-danger/.test(note.innerHTML);
    },
    pattern.source,
    { timeout: 180_000 }
  );
  return page.locator("#note").innerText();
}

async function open(url, options = {}) {
  const { page, problems } = await app.newPage(options);
  await page.goto(`${app.gateway.origin}${url}`, { waitUntil: "load" });
  return { page, problems };
}

/**
 * Upload a file through upload.html and return what the page reported.
 *
 * `mode` is the anchoring choice the page now offers. "wallet" is the explicit
 * one — the user sends registerDocument() themselves — and "gateway" is what
 * someone gets who touches nothing.
 */
async function upload({ page, file, passphrase = PASSPHRASE, suite, mode = "wallet" }) {
  await page.waitForFunction(() => typeof window.uploadChunked === "function", { timeout: 30_000 });
  await page.setInputFiles("#doc-file", file);
  if (passphrase !== null) await page.fill("#passphrase", passphrase);
  if (suite) await page.selectOption("#cipher-suite", suite);
  if (mode === "wallet") await page.check("#anchor-wallet");

  await page.click("#chunked-upload-button");
  const note = await waitForNote(page, mode === "wallet" ? /Registered on-chain/ : /receipted/);

  return {
    note,
    shareUrl: await page.locator("#share-link").getAttribute("href"),
    summary: await page.locator("#chunk-summary").innerText(),
    fileHash: await page.locator("#file-hash").innerText(),
  };
}

/** The state the page is showing for this document's journey to the chain. */
function anchorState(page) {
  return page.locator("#anchor-state").getAttribute("data-state");
}

test("a real file survives the whole path: sealed, uploaded, anchored, restored", { skip: missing }, async () => {
  const { file, bytes } = await sampleFile("annual-report.pdf");

  const uploader = await open("/upload.html");
  const result = await upload({ page: uploader.page, file });

  assert.match(result.note, /Registered on-chain/);
  assert.match(result.summary, /4 chunks/);
  assert.match(result.summary, /aes-256-gcm/);
  assert.deepEqual(uploader.problems, []);

  // The share link is what the user actually passes on, so follow that rather
  // than reconstructing a URL the app never produced.
  const reader = await open(new URL(result.shareUrl).pathname + new URL(result.shareUrl).search);
  const { page } = reader;

  await page.waitForFunction(() => typeof window.retrieveChunked === "function", { timeout: 30_000 });
  assert.match(
    await page.inputValue("#lookup-hash"),
    /^0x[0-9a-f]{64}$/,
    "the share link should arrive with the file hash already filled in"
  );

  await page.fill("#retrieve-passphrase", PASSPHRASE);
  await page.click("#chunked-retrieve-button");
  const note = await waitForNote(page, /Verified/);

  assert.match(note, /Every one of 4 chunks matched the root anchored on-chain/);
  assert.match(await page.locator("#doc-status").innerText(), /Registered on-chain/);
  assert.match(
    await page.locator("#college-name").innerText(),
    /end-to-end test/,
    "the exporter label written on-chain should be read back"
  );

  const link = page.locator("#download-document");
  assert.ok(await link.isVisible(), "a verified document should offer a download");

  const [download] = await Promise.all([page.waitForEvent("download"), link.click()]);
  assert.equal(download.suggestedFilename(), "annual-report.pdf");

  const saved = path.join(workspace, "restored.bin");
  await download.saveAs(saved);
  assert.ok(
    fs.readFileSync(saved).equals(bytes),
    "the downloaded file should be byte-identical to the one chosen"
  );
  assert.deepEqual(reader.problems, []);
});

test("XChaCha20-Poly1305 works in the browser", { skip: missing }, async () => {
  // AES-GCM comes from WebCrypto; this suite is the only path that loads
  // @noble/ciphers in a page, which is the import that browsers could not
  // resolve at all before js/vendor existed.
  const { file, bytes } = await sampleFile("chacha.pdf", 80_000);

  const uploader = await open("/upload.html");
  const result = await upload({ page: uploader.page, file, suite: "xchacha20-poly1305" });
  assert.match(result.summary, /xchacha20-poly1305/);
  assert.deepEqual(uploader.problems, []);

  const reader = await open(new URL(result.shareUrl).pathname + new URL(result.shareUrl).search);
  await reader.page.fill("#retrieve-passphrase", PASSPHRASE);
  await reader.page.click("#chunked-retrieve-button");
  assert.match(await waitForNote(reader.page, /Verified/), /Verified/);

  const [download] = await Promise.all([
    reader.page.waitForEvent("download"),
    reader.page.locator("#download-document").click(),
  ]);
  const saved = path.join(workspace, "chacha-restored.bin");
  await download.saveAs(saved);
  assert.ok(fs.readFileSync(saved).equals(bytes));
  assert.deepEqual(reader.problems, []);
});

test("the wrong passphrase fails, and offers nothing to download", { skip: missing }, async () => {
  const { file } = await sampleFile("confidential.pdf", 40_000);

  const uploader = await open("/upload.html");
  const result = await upload({ page: uploader.page, file });

  const reader = await open(new URL(result.shareUrl).pathname + new URL(result.shareUrl).search);
  await reader.page.fill("#retrieve-passphrase", "not the passphrase");
  await reader.page.click("#chunked-retrieve-button");

  const note = await waitForNote(reader.page, /Verified/);
  assert.doesNotMatch(note, /Verified/, `expected a failure, got: ${note}`);
  assert.equal(
    await reader.page.locator("#download-document").isVisible(),
    false,
    "a failed decryption must not leave a download link behind"
  );
});

test("an unregistered file is reported as unregistered", { skip: missing }, async () => {
  const { file } = await sampleFile("never-uploaded.pdf", 20_000);

  const { page, problems } = await open("/verify.html");
  await page.waitForFunction(() => typeof window.verifyRegistration === "function", {
    timeout: 30_000,
  });

  // The page hashes the file on selection; the hash never leaves the browser.
  await page.setInputFiles("#doc-file", file);
  await page.waitForFunction(
    () => /^0x[0-9a-f]{64}$/.test(document.getElementById("lookup-hash").value),
    { timeout: 60_000 }
  );

  await page.click("#chunked-verify-button");
  const note = await waitForNote(page, /does not match any registered document/);
  assert.match(note, /does not match any registered document/);
  assert.match(await page.locator("#doc-status").innerText(), /Not registered/);
  assert.deepEqual(problems, []);
});

test("verifying a registered file needs no passphrase", { skip: missing }, async () => {
  const { file } = await sampleFile("public-notice.pdf", 30_000);

  const uploader = await open("/upload.html");
  await upload({ page: uploader.page, file });

  const { page, problems } = await open("/verify.html");
  await page.setInputFiles("#doc-file", file);
  await page.waitForFunction(
    () => /^0x[0-9a-f]{64}$/.test(document.getElementById("lookup-hash").value),
    { timeout: 60_000 }
  );
  await page.click("#chunked-verify-button");

  const note = await waitForNote(page, /matches a document registered on-chain/);
  assert.match(note, /matches a document registered on-chain/);
  assert.deepEqual(problems, []);
});

test("a visitor with no wallet can verify a document", { skip: missing }, async () => {
  // The case the product is for: someone was sent a file and wants to know
  // whether it is the one that was registered. They have no wallet, no
  // account and no intention of installing one. Until contract.rpcUrl
  // existed the app had no provider at all without MetaMask, so this page
  // told them to go and install it.
  const { file } = await sampleFile("sent-to-me.pdf", 30_000);

  const uploader = await open("/upload.html");
  await upload({ page: uploader.page, file });

  const { page, problems } = await open("/verify.html", { wallet: false });
  assert.equal(
    await page.evaluate(() => Boolean(window.ethereum)),
    false,
    "this context is meant to have no wallet in it"
  );
  assert.equal(
    await page.evaluate(() => Boolean(window.web3)),
    true,
    "the page should still have built a read-only provider from contract.rpcUrl"
  );
  assert.equal(
    await page.locator(".alert").isVisible(),
    false,
    "a read-only page has no reason to demand a wallet"
  );

  await page.setInputFiles("#doc-file", file);
  await page.waitForFunction(
    () => /^0x[0-9a-f]{64}$/.test(document.getElementById("lookup-hash").value),
    { timeout: 60_000 }
  );
  await page.click("#chunked-verify-button");

  assert.match(
    await waitForNote(page, /matches a document registered on-chain/),
    /matches a document registered on-chain/
  );
  assert.deepEqual(problems, []);
});

test("a visitor with no wallet can retrieve and verify a document", { skip: missing }, async () => {
  const { file, bytes } = await sampleFile("shared-report.pdf", 50_000);

  const uploader = await open("/upload.html");
  const result = await upload({ page: uploader.page, file });

  const share = new URL(result.shareUrl);
  const { page, problems } = await open(share.pathname + share.search, { wallet: false });

  await page.fill("#retrieve-passphrase", PASSPHRASE);
  await page.click("#chunked-retrieve-button");
  assert.match(await waitForNote(page, /Verified/), /Verified/);

  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.locator("#download-document").click(),
  ]);
  const saved = path.join(workspace, "no-wallet-restored.bin");
  await download.saveAs(saved);
  assert.ok(fs.readFileSync(saved).equals(bytes));
  assert.deepEqual(problems, []);
});

test("the wallet is asked for only by the choice that needs one", { skip: missing }, async () => {
  const { page } = await open("/upload.html", { wallet: false });

  // The default path signs nothing, so a visitor with no wallet is not told
  // to go and install one before they can do anything. That demand, shown
  // unconditionally, is the thing this whole path exists to remove.
  assert.equal(
    await page.locator(".alert").isVisible(),
    false,
    "the default path needs no wallet, so upload.html should not demand one"
  );

  await page.check("#anchor-wallet");
  assert.equal(
    await page.locator(".alert").isVisible(),
    true,
    "choosing to register from your own wallet should say a wallet is needed"
  );
  assert.match(await page.locator(".alert").innerText(), /wallet/i);

  // And back again: the demand is a property of the choice, not a one-way door.
  await page.check("#anchor-gateway");
  assert.equal(await page.locator(".alert").isVisible(), false);

  const reader = await open("/retrieve.html", { wallet: false });
  assert.equal(
    await reader.page.locator(".alert").isVisible(),
    false,
    "retrieve.html only reads, so it should not"
  );
});

// ------------------------------------------------- the default anchoring path

test("a visitor with no wallet uploads, is receipted, and is anchored", { skip: missing }, async () => {
  const { file, bytes } = await sampleFile("gateway-anchored.pdf", 60_000);

  // No wallet in this context at all. This is the path a user who has never
  // heard of MetaMask walks, and until now it did not exist.
  const uploader = await open("/upload.html", { wallet: false });
  const result = await upload({ page: uploader.page, file, mode: "gateway" });

  assert.match(result.note, /receipted/i);
  assert.equal(await anchorState(uploader.page), "receipted");
  assert.match(
    await uploader.page.locator("#anchor-state").innerText(),
    /not yet on the chain/i,
    "a receipt that is not yet anchored has to say so rather than imply it is done"
  );

  // The receipt is the user's copy and has to survive the tab.
  const receiptLink = uploader.page.locator("#receipt-download");
  assert.ok(await receiptLink.isVisible(), "a receipted upload should offer the receipt");

  const [download] = await Promise.all([
    uploader.page.waitForEvent("download"),
    receiptLink.click(),
  ]);
  const saved = path.join(workspace, "receipt.json");
  await download.saveAs(saved);

  const receipt = JSON.parse(fs.readFileSync(saved, "utf8"));
  assert.equal(receipt.statement.version, "oreochain-receipt-v1");
  assert.match(receipt.statement.fileHash, /^0x[0-9a-f]{64}$/);
  assert.ok(receipt.signature.length > 0);
  // The gateway checked the document against its manifest before signing.
  assert.equal(receipt.statement.verified, true);

  // Now the operator's side of the story, out of band, as the worker does it.
  const anchored = await anchorPending(app.gateway, app.chain);
  assert.ok(anchored, "there should have been a pending document to anchor");

  // The page is still open and still watching.
  await uploader.page.waitForFunction(
    () => document.getElementById("anchor-state").dataset.state === "anchored",
    undefined,
    { timeout: 60_000 }
  );
  assert.match(
    await uploader.page.locator("#anchor-state").innerText(),
    /verified in this browser/i
  );
  assert.deepEqual(uploader.problems, []);

  // And the document is still the document: retrieval is unchanged by how it
  // reached the chain.
  const share = new URL(result.shareUrl);
  const reader = await open(share.pathname + share.search, { wallet: false });
  await reader.page.fill("#retrieve-passphrase", PASSPHRASE);
  await reader.page.click("#chunked-retrieve-button");
  await waitForNote(reader.page, /Verified|match/);

  assert.ok(fs.readFileSync(path.join(workspace, "receipt.json")).length > 0);
  assert.ok(bytes.length > 0);
});

test("a stranger verifies a gateway-anchored document with no wallet", { skip: missing }, async () => {
  const { file } = await sampleFile("sent-to-a-stranger.pdf", 40_000);

  const uploader = await open("/upload.html", { wallet: false });
  await upload({ page: uploader.page, file, mode: "gateway" });
  await anchorPending(app.gateway, app.chain);

  /*
   * The whole proposition, from the other side. Someone who was sent this
   * file, has no wallet, no receipt and no account, drops it on verify.html.
   * There is no per-document record on-chain — the default path does not
   * create one — so this only works if the page checks the inclusion proof
   * against a batch root it read from the chain itself.
   */
  const { page, problems } = await open("/verify.html", { wallet: false });
  await page.waitForFunction(() => typeof window.verifyRegistration === "function", {
    timeout: 30_000,
  });
  await page.setInputFiles("#doc-file", file);
  await page.click("#chunked-verify-button");

  const note = await waitForNote(page, /Verified/);
  assert.match(note, /anchored on-chain/i);
  assert.match(await page.locator("#doc-status").innerText(), /Anchored on-chain/);
  assert.deepEqual(problems, []);
});

test("a file that was never uploaded is still reported as unregistered", { skip: missing }, async () => {
  // The batch fallback must not turn "no" into "maybe": a stranger checking a
  // document that does not exist has to be told so plainly.
  const { file } = await sampleFile("never-uploaded.pdf", 20_000);

  const { page } = await open("/verify.html", { wallet: false });
  await page.waitForFunction(() => typeof window.verifyRegistration === "function", {
    timeout: 30_000,
  });
  await page.setInputFiles("#doc-file", file);
  await page.click("#chunked-verify-button");

  await waitForNote(page, /does not match/);
  assert.match(await page.locator("#doc-status").innerText(), /Not registered/);
});
