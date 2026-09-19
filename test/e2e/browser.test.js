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

import { loadPlaywright, openApp } from "./harness.mjs";
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

/** Upload a file through upload.html and return what the page reported. */
async function upload({ page, file, passphrase = PASSPHRASE, suite }) {
  await page.waitForFunction(() => typeof window.uploadChunked === "function", { timeout: 30_000 });
  await page.setInputFiles("#doc-file", file);
  if (passphrase !== null) await page.fill("#passphrase", passphrase);
  if (suite) await page.selectOption("#cipher-suite", suite);

  await page.click("#chunked-upload-button");
  const note = await waitForNote(page, /Registered on-chain/);

  return {
    note,
    shareUrl: await page.locator("#share-link").getAttribute("href"),
    summary: await page.locator("#chunk-summary").innerText(),
    fileHash: await page.locator("#file-hash").innerText(),
  };
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

test("a page that signs asks for a wallet; a page that reads does not", { skip: missing }, async () => {
  const wallets = await open("/upload.html", { wallet: false });
  assert.equal(
    await wallets.page.locator(".alert").isVisible(),
    true,
    "upload.html signs a transaction, so it should say a wallet is needed"
  );
  assert.match(await wallets.page.locator(".alert").innerText(), /wallet/i);

  const reader = await open("/retrieve.html", { wallet: false });
  assert.equal(
    await reader.page.locator(".alert").isVisible(),
    false,
    "retrieve.html only reads, so it should not"
  );
});
