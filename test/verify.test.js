/**
 * Receipts asserting something the gateway checked.
 *
 * A receipt states "this service accepted this exact document at this time".
 * Before this, `record()` signed whatever three strings it was handed: nothing
 * confirmed the manifestCID resolved, or that the manifest it named described
 * the file being receipted. The signature was never the part that was lying,
 * which is what made it worth fixing — a forged claim came back validly
 * signed.
 *
 * These tests are written around that attack rather than around the happy
 * path, because the happy path passed before the fix too.
 */

import test from "node:test";
import assert from "node:assert/strict";

import { createManifestVerifier, VerificationError } from "../server/verify.mjs";
import { createProofService } from "../server/proofs.mjs";
import { generateSigningKey, importPublicKey, verifyReceipt } from "../js/core/receipt.js";
import { packFile, sealManifest } from "../js/core/manifest.js";
import { utf8 } from "../js/core/bytes.js";

const TEST_KDF = { name: "argon2id", memoryKiB: 8, iterations: 1, parallelism: 1 };
const TEST_LIMITS = { minArgon2MemoryKiB: 8 };

/**
 * A real manifest for real bytes, plus the document a well-behaved client
 * would send to /api/proofs/record for it.
 */
async function sealedDocument(text = "the actual contents", { passphrase = null } = {}) {
  const packed = await packFile(utf8(text), {
    fileName: "report.txt",
    mimeType: "text/plain",
    passphrase,
    kdf: passphrase ? TEST_KDF : undefined,
    limits: TEST_LIMITS,
  });
  const manifest = await sealManifest(
    packed,
    packed.chunks.map((_, i) => `bafyChunk${i}`)
  );
  const bytes = utf8(JSON.stringify(manifest));

  return {
    manifest,
    bytes,
    document: {
      fileHash: manifest.fileHash,
      merkleRoot: manifest.merkleRoot,
      fileSize: manifest.fileSize,
      manifestCID: "bafyManifestReal",
    },
  };
}

/** A backend serving exactly the manifests it is given. */
function backendServing(entries) {
  return {
    name: "test",
    async get(cid) {
      if (!(cid in entries)) throw new Error(`no such cid ${cid}`);
      const value = entries[cid];
      if (value instanceof Error) throw value;
      return value;
    },
  };
}

async function service(backend, options = {}) {
  const keys = await generateSigningKey();
  const verifier = backend ? createManifestVerifier({ backend, limits: TEST_LIMITS }) : null;
  return {
    keys,
    proofs: await createProofService({ ...keys.exported, verifier, ...options }),
  };
}

// ------------------------------------------------------------ the attack

test("a receipt is refused for a document the manifest does not describe", async () => {
  const real = await sealedDocument("the actual contents");
  const { proofs } = await service(backendServing({ bafyManifestReal: real.bytes }));

  // The manifest is genuine and resolves. The document points at it while
  // claiming a different file hash — which is exactly how you would obtain a
  // signed receipt, and then an on-chain anchor, for a document that does not
  // exist.
  const forged = { ...real.document, fileHash: "0x" + "11".repeat(32) };

  await assert.rejects(() => proofs.record(forged), /does not match manifest/);
  assert.equal(proofs.status().pending, 0, "a refused document was still queued for anchoring");
});

test("a mismatched merkleRoot is refused — it is the value that gets anchored", async () => {
  const real = await sealedDocument();
  const { proofs } = await service(backendServing({ bafyManifestReal: real.bytes }));

  await assert.rejects(
    () => proofs.record({ ...real.document, merkleRoot: "0x" + "22".repeat(32) }),
    /merkleRoot/
  );
});

test("a mismatched fileSize is refused", async () => {
  const real = await sealedDocument();
  const { proofs } = await service(backendServing({ bafyManifestReal: real.bytes }));

  await assert.rejects(() => proofs.record({ ...real.document, fileSize: 999999 }), /fileSize/);
});

test("a manifestCID that resolves to something that is not a manifest is refused", async () => {
  const { proofs } = await service(backendServing({ bafyManifestReal: utf8("hello, not json") }));
  const real = await sealedDocument();

  await assert.rejects(() => proofs.record(real.document), /not a valid manifest/);
});

test("a client cannot mark its own document verified", async () => {
  const real = await sealedDocument();
  const { proofs, keys } = await service(null); // no verifier configured

  // The flag is the service's assertion about the client, so a value from the
  // client is discarded. Honouring it would make the whole field worthless.
  const { receipt } = await proofs.record({ ...real.document, verified: true });

  assert.equal(receipt.statement.verified, false);
  const result = await verifyReceipt(receipt, await importPublicKey(keys.exported.publicJwk));
  assert.ok(result.valid, result.reason);
});

// ------------------------------------------------------- the honest path

test("a document that matches its manifest is receipted and marked verified", async () => {
  const real = await sealedDocument();
  const { proofs, keys } = await service(backendServing({ bafyManifestReal: real.bytes }));

  const { receipt, queued } = await proofs.record(real.document);

  assert.equal(queued, true);
  assert.equal(receipt.statement.verified, true);
  assert.equal(receipt.statement.fileHash, real.manifest.fileHash);

  const result = await verifyReceipt(receipt, await importPublicKey(keys.exported.publicJwk));
  assert.ok(result.valid, result.reason);
});

test("an encrypted file is verified without decrypting it", async () => {
  // The header is plaintext even when the body is sealed, so the gateway reads
  // fileHash and merkleRoot and never touches the passphrase or the file key.
  // This is the property that makes the service safe to run for other people.
  const real = await sealedDocument("secret contents", { passphrase: "correct horse" });
  assert.equal(real.manifest.encrypted, true);
  assert.equal(typeof real.manifest.body, "string", "the body should be sealed, not an object");

  const { proofs } = await service(backendServing({ bafyManifestReal: real.bytes }));
  const { receipt } = await proofs.record(real.document);

  assert.equal(receipt.statement.verified, true);
});

test("without a verifier the receipt says so rather than implying a check", async () => {
  const real = await sealedDocument();
  const { proofs } = await service(null);

  const { receipt } = await proofs.record(real.document);
  // Old receipts have no such field at all, so absent reads as "not
  // asserted" and false reads as "asserted, and no". Neither claims a check.
  assert.equal(receipt.statement.verified, false);
});

// ------------------------------------------------- unfetchable vs. wrong

test("an unreadable manifest is retryable, a mismatched one is not", async () => {
  const real = await sealedDocument();

  const unreachable = await service(
    backendServing({ bafyManifestReal: new Error("all gateways failed") })
  );
  const missing = await unreachable.proofs.record(real.document).catch((e) => e);

  // A freshly pinned manifest may not have propagated yet, which a retry
  // fixes. Signing anyway would defeat the check, so it still refuses — but a
  // client should be told to come back, not that its document is wrong.
  assert.equal(missing.status, 503);
  assert.equal(missing.retryable, true);

  const wrong = await service(backendServing({ bafyManifestReal: real.bytes }));
  const rejected = await wrong.proofs
    .record({ ...real.document, fileHash: "0x" + "33".repeat(32) })
    .catch((e) => e);

  assert.equal(rejected.status, 400);
  assert.equal(rejected.retryable, false);
});

test("nothing is stored or receipted when verification fails", async () => {
  const real = await sealedDocument();
  const { proofs } = await service(backendServing({ bafyManifestReal: real.bytes }));

  await proofs.record({ ...real.document, fileSize: 12345 }).catch(() => {});

  // The check runs before the signature and before the store, so a refused
  // document leaves nothing behind to be anchored later.
  assert.equal(proofs.status().documents, 0);
  assert.equal(await proofs.proofFor(real.document.fileHash), null);
});

// --------------------------------------------------------------- wiring

test("the verifier refuses to be built without a way to read manifests", () => {
  assert.throws(() => createManifestVerifier({}), /storage backend/);
});

test("a verification failure is a VerificationError with a client-safe message", async () => {
  const real = await sealedDocument();
  const verifier = createManifestVerifier({
    backend: backendServing({ bafyManifestReal: real.bytes }),
    limits: TEST_LIMITS,
  });

  const error = await verifier
    .verify({ ...real.document, fileHash: "0x" + "44".repeat(32) })
    .catch((e) => e);

  assert.ok(error instanceof VerificationError);
  assert.equal(error.status, 400);
  // It names what disagreed, so a client can fix it, without echoing anything
  // it did not already send.
  assert.match(error.message, /fileHash/);
});
