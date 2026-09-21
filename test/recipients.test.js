import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { equalBytes, fromBase64Url, toBase64Url, utf8 } from "../js/core/bytes.js";
import { generateFileKey, generateSalt } from "../js/core/crypto.js";
import { MANIFEST_LIMITS } from "../js/core/limits.js";
import {
  generateIdentity,
  IDENTITY_PREFIX,
  parseIdentity,
  parseRecipient,
  RECIPIENT_PREFIX,
  recipientOf,
  unwrapWithIdentity,
  wrapToRecipients,
} from "../js/core/recipients.js";
import { openManifest, packFile, restoreFile, sealManifest } from "../js/core/manifest.js";
import { ManifestError, validateManifestHeader } from "../js/core/validate.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// Argon2id at production settings costs seconds per derivation, and the tests
// that exercise both routes at once do not care how expensive the passphrase
// half is — only that it still works alongside recipients.
const TEST_KDF = { name: "argon2id", memoryKiB: 19456, iterations: 1, parallelism: 1 };

const FILE_HASH = "0x" + "ab".repeat(32);

function context(overrides = {}) {
  return { fileSalt: generateSalt(), fileHashHex: FILE_HASH, ...overrides };
}

/** Pack, "upload" to a Map, and seal — the whole writer path in one call. */
async function store(bytes, options) {
  const packed = await packFile(bytes, options);
  const blocks = new Map();
  const locations = packed.chunks.map((chunk, i) => {
    const id = `chunk${i}`;
    blocks.set(id, chunk.payload);
    return id;
  });
  const manifest = await sealManifest(packed, locations);
  return { manifest, fetch: (location) => blocks.get(location) };
}

// ---------------------------------------------------------------------------
// Key format
// ---------------------------------------------------------------------------

test("a generated identity carries the recipient key it belongs to", async () => {
  const { identity, recipient } = await generateIdentity();

  assert.ok(recipient.startsWith(RECIPIENT_PREFIX));
  assert.ok(identity.startsWith(IDENTITY_PREFIX));
  assert.equal(recipientOf(identity), recipient);

  const { publicKey } = parseIdentity(identity);
  assert.ok(equalBytes(publicKey, parseRecipient(recipient)));
});

test("every identity is different", async () => {
  const seen = new Set();
  for (let i = 0; i < 16; i++) {
    const { identity, recipient } = await generateIdentity();
    assert.ok(!seen.has(identity), "an identity repeated");
    assert.ok(!seen.has(recipient), "a recipient key repeated");
    seen.add(identity);
    seen.add(recipient);
  }
});

/**
 * The mistake this guards is not recoverable. An identity pasted where a
 * recipient key belongs is a private key published inside a manifest that
 * anyone can fetch, retroactively opening every file ever sealed to it — so
 * the refusal has to be by name, not a decoding error the user reads as a typo.
 */
test("an identity is refused where a recipient key is expected, by name", async () => {
  const { identity } = await generateIdentity();

  assert.throws(
    () => parseRecipient(identity),
    /that is a private identity, not a recipient key/
  );
});

test("a recipient key is refused where an identity is expected, by name", async () => {
  const { recipient } = await generateIdentity();

  assert.throws(
    () => parseIdentity(recipient),
    /that is a public recipient key, not an identity/
  );
});

test("a recipient key is refused if it is not a key at all", async () => {
  const { recipient } = await generateIdentity();

  for (const [label, value] of [
    ["empty", ""],
    ["unprefixed", recipient.slice(RECIPIENT_PREFIX.length)],
    ["wrong prefix", "ssh-ed25519 AAAA"],
    ["not base64url", RECIPIENT_PREFIX + "not base64!!"],
    ["truncated", recipient.slice(0, recipient.length - 8)],
    ["a number", 42],
    ["null", null],
  ]) {
    assert.throws(() => parseRecipient(value), Error, `accepted a ${label} recipient key`);
  }
});

test("surrounding whitespace is forgiven — keys arrive pasted", async () => {
  const { recipient, identity } = await generateIdentity();

  assert.ok(equalBytes(parseRecipient(`\n  ${recipient}\t `), parseRecipient(recipient)));
  assert.equal(recipientOf(`  ${identity}\n`), recipient);
});

test("a point that is not on the curve is refused rather than used", async () => {
  const { recipient } = await generateIdentity();
  const bytes = parseRecipient(recipient);

  // Still 65 bytes, still 0x04-prefixed, so it passes every structural check
  // and can only be caught by the curve equation itself.
  bytes[40] ^= 0xff;
  const bogus = RECIPIENT_PREFIX + toBase64Url(bytes);

  await assert.rejects(
    wrapToRecipients(generateFileKey(), [bogus], context()),
    /not a valid P-256 public key/
  );
});

// ---------------------------------------------------------------------------
// Wrapping
// ---------------------------------------------------------------------------

test("each recipient recovers exactly the file key that was wrapped", async () => {
  const fileKey = generateFileKey();
  const ctx = context();
  const people = await Promise.all([generateIdentity(), generateIdentity(), generateIdentity()]);

  const entries = await wrapToRecipients(fileKey, people.map((p) => p.recipient), ctx);
  assert.equal(entries.length, 3);

  for (const person of people) {
    const recovered = await unwrapWithIdentity(entries, person.identity, ctx);
    assert.ok(equalBytes(recovered, fileKey));
  }
});

test("someone who was not a recipient cannot open any entry", async () => {
  const ctx = context();
  const alice = await generateIdentity();
  const mallory = await generateIdentity();

  const entries = await wrapToRecipients(generateFileKey(), [alice.recipient], ctx);

  await assert.rejects(
    unwrapWithIdentity(entries, mallory.identity, ctx),
    /this file is not shared with your key/
  );
});

/**
 * The wrapping key AND the nonce are derived from the ephemeral key, so a
 * repeated ephemeral key is a repeated (key, nonce) pair for any recipient both
 * entries are addressed to — the AES-GCM failure that hands over the plaintext
 * of both. Nothing may produce one, including sealing the same file twice.
 */
test("no ephemeral key is ever used twice", async () => {
  const ctx = context();
  const people = await Promise.all([generateIdentity(), generateIdentity()]);
  const recipients = people.map((p) => p.recipient);
  const fileKey = generateFileKey();

  const seen = new Set();
  for (let round = 0; round < 8; round++) {
    for (const entry of await wrapToRecipients(fileKey, recipients, ctx)) {
      assert.ok(!seen.has(entry.ephemeral), "an ephemeral key was reused");
      seen.add(entry.ephemeral);
    }
  }
  assert.equal(seen.size, 16);
});

test("wrapping the same key to the same person twice never repeats a ciphertext", async () => {
  const ctx = context();
  const { recipient } = await generateIdentity();
  const fileKey = generateFileKey();

  const first = await wrapToRecipients(fileKey, [recipient], ctx);
  const second = await wrapToRecipients(fileKey, [recipient], ctx);

  assert.notEqual(first[0].ciphertext, second[0].ciphertext);
});

test("an entry cannot be lifted from one file's manifest into another's", async () => {
  const alice = await generateIdentity();
  const fileKey = generateFileKey();
  const fileSalt = generateSalt();

  const entries = await wrapToRecipients(fileKey, [alice.recipient], {
    fileSalt,
    fileHashHex: FILE_HASH,
  });

  // Same salt, same recipient, same entry — only the file it claims to belong
  // to differs, and the file hash is bound into the AEAD's additional data.
  await assert.rejects(
    unwrapWithIdentity(entries, alice.identity, {
      fileSalt,
      fileHashHex: "0x" + "cd".repeat(32),
    }),
    /not shared with your key/
  );
});

test("an entry does not survive being re-pointed at another ephemeral key", async () => {
  const ctx = context();
  const alice = await generateIdentity();
  const bob = await generateIdentity();
  const fileKey = generateFileKey();

  const [forAlice] = await wrapToRecipients(fileKey, [alice.recipient], ctx);
  const [forBob] = await wrapToRecipients(fileKey, [bob.recipient], ctx);

  // Both public keys are in the HKDF info, so a swapped ephemeral key derives
  // a different wrapping key and the tag fails.
  const spliced = [{ ephemeral: forBob.ephemeral, ciphertext: forAlice.ciphertext }];
  await assert.rejects(unwrapWithIdentity(spliced, alice.identity, ctx), /not shared with your key/);
});

test("a tampered wrapped key fails to open rather than yielding wrong bytes", async () => {
  const ctx = context();
  const alice = await generateIdentity();
  const [entry] = await wrapToRecipients(generateFileKey(), [alice.recipient], ctx);

  const bytes = fromBase64Url(entry.ciphertext);
  bytes[0] ^= 0x01;

  await assert.rejects(
    unwrapWithIdentity([{ ...entry, ciphertext: toBase64Url(bytes) }], alice.identity, ctx),
    /not shared with your key/
  );
});

test("a malformed entry is stepped over, not fatal, so one bad entry cannot deny the rest", async () => {
  const ctx = context();
  const alice = await generateIdentity();
  const fileKey = generateFileKey();
  const [good] = await wrapToRecipients(fileKey, [alice.recipient], ctx);

  const withJunk = [
    null,
    {},
    { ephemeral: "!!!", ciphertext: "!!!" },
    { ephemeral: good.ephemeral, ciphertext: "AAAA" },
    { ephemeral: toBase64Url(new Uint8Array(65)), ciphertext: good.ciphertext },
    good,
  ];

  assert.ok(equalBytes(await unwrapWithIdentity(withJunk, alice.identity, ctx), fileKey));
});

test("the same recipient listed twice is refused", async () => {
  const { recipient } = await generateIdentity();

  await assert.rejects(
    wrapToRecipients(generateFileKey(), [recipient, recipient], context()),
    /appears more than once/
  );
});

test("more recipients than the limit are refused before any key agreement", async () => {
  const many = [];
  const { recipient } = await generateIdentity();
  for (let i = 0; i <= MANIFEST_LIMITS.maxRecipients; i++) many.push(recipient);

  await assert.rejects(
    wrapToRecipients(generateFileKey(), many, context()),
    /above the maximum/
  );
});

test("a manifest cannot make a reader try an unbounded number of entries", async () => {
  const ctx = context();
  const alice = await generateIdentity();
  const [entry] = await wrapToRecipients(generateFileKey(), [alice.recipient], ctx);

  const flood = Array.from({ length: MANIFEST_LIMITS.maxRecipients + 1 }, () => entry);

  await assert.rejects(unwrapWithIdentity(flood, alice.identity, ctx), /above the maximum/);
});

// ---------------------------------------------------------------------------
// The manifest
// ---------------------------------------------------------------------------

test("a file sealed to recipients round-trips for each of them", async () => {
  const people = await Promise.all([generateIdentity(), generateIdentity()]);
  const bytes = utf8("minutes of the meeting\n".repeat(400));

  const { manifest, fetch } = await store(bytes, {
    fileName: "minutes.txt",
    mimeType: "text/plain",
    recipients: people.map((p) => p.recipient),
    chunkSize: 1024,
  });

  assert.equal(manifest.encrypted, true);
  assert.equal(manifest.recipients.length, 2);

  for (const person of people) {
    const opened = await openManifest(manifest, null, { identity: person.identity });
    const restored = await restoreFile(manifest, opened, fetch);
    assert.ok(equalBytes(restored.bytes, bytes));
    assert.equal(restored.fileName, "minutes.txt");
  }
});

/**
 * The header is public — anyone who can fetch the CID can read it. A recipient
 * list that named its recipients would therefore publish who a document was
 * shared with, which is usually the more sensitive of the two facts.
 */
test("the public header does not say who the file was shared with", async () => {
  const alice = await generateIdentity();
  const { manifest } = await store(utf8("x"), {
    fileName: "x",
    recipients: [alice.recipient],
  });

  const header = JSON.stringify(manifest);
  const publicKey = alice.recipient.slice(RECIPIENT_PREFIX.length);

  assert.ok(!header.includes(publicKey), "the manifest names a recipient's public key");
  assert.ok(!header.includes(alice.identity), "the manifest contains an identity");

  for (const entry of manifest.recipients) {
    assert.deepEqual(Object.keys(entry).sort(), ["ciphertext", "ephemeral"]);
  }
});

test("a file sealed to recipients has no passphrase parameters at all", async () => {
  const alice = await generateIdentity();
  const { manifest } = await store(utf8("x"), {
    fileName: "x",
    recipients: [alice.recipient],
  });

  assert.equal(manifest.wrappedKey, undefined);
  assert.equal(manifest.kdf, undefined);
  validateManifestHeader(manifest);
});

test("a file can take both routes, and both reach the same file key", async () => {
  const alice = await generateIdentity();
  const bytes = utf8("shared and kept");

  const { manifest, fetch } = await store(bytes, {
    fileName: "both.txt",
    passphrase: "correct horse battery staple",
    recipients: [alice.recipient],
    kdf: TEST_KDF,
  });

  const viaPassphrase = await openManifest(manifest, "correct horse battery staple");
  const viaIdentity = await openManifest(manifest, null, { identity: alice.identity });

  assert.ok(equalBytes(viaPassphrase.fileKey, viaIdentity.fileKey));
  assert.ok(equalBytes((await restoreFile(manifest, viaIdentity, fetch)).bytes, bytes));
});

test("opening a recipient-only file says what it needs, rather than asking for a passphrase", async () => {
  const alice = await generateIdentity();
  const { manifest } = await store(utf8("x"), { fileName: "x", recipients: [alice.recipient] });

  for (const attempt of [
    openManifest(manifest, null),
    openManifest(manifest, "a guess"),
  ]) {
    await assert.rejects(attempt, /sealed to recipient keys — open it with an identity/);
  }
});

test("an identity offered for a passphrase-only file says so", async () => {
  const alice = await generateIdentity();
  const { manifest } = await store(utf8("x"), {
    fileName: "x",
    passphrase: "pw",
    kdf: TEST_KDF,
  });

  await assert.rejects(
    openManifest(manifest, null, { identity: alice.identity }),
    /not sealed to any recipient key/
  );
});

test("a non-recipient cannot open the file even holding the manifest and every chunk", async () => {
  const alice = await generateIdentity();
  const mallory = await generateIdentity();
  const { manifest } = await store(utf8("confidential"), {
    fileName: "c.txt",
    recipients: [alice.recipient],
  });

  await assert.rejects(
    openManifest(manifest, null, { identity: mallory.identity }),
    /not shared with your key/
  );
});

/**
 * Revocation is re-sealing. There is no entry to delete from a manifest already
 * published, so what has to hold is that the new manifest does not open for the
 * dropped recipient — a fresh file key, not the old one re-wrapped.
 */
test("re-sealing without a recipient shuts them out of the new manifest", async () => {
  const alice = await generateIdentity();
  const bob = await generateIdentity();
  const bytes = utf8("board pack");

  const first = await store(bytes, { fileName: "p.txt", recipients: [alice.recipient, bob.recipient] });
  const second = await store(bytes, { fileName: "p.txt", recipients: [alice.recipient] });

  const stillIn = await openManifest(second.manifest, null, { identity: alice.identity });
  assert.ok(equalBytes((await restoreFile(second.manifest, stillIn, second.fetch)).bytes, bytes));

  await assert.rejects(
    openManifest(second.manifest, null, { identity: bob.identity }),
    /not shared with your key/
  );

  // Two files, two file keys — the second is not the first re-wrapped.
  const asAlice = await openManifest(first.manifest, null, { identity: alice.identity });
  assert.ok(!equalBytes(asAlice.fileKey, stillIn.fileKey));
});

test("an empty recipient list is refused rather than quietly storing plaintext", async () => {
  await assert.rejects(
    packFile(utf8("x"), { fileName: "x", recipients: [] }),
    /omit it to store a file without recipients/
  );
});

test("a recipient list of the wrong type is refused", async () => {
  for (const value of ["oreo-recipient-v1:abc", 7, {}]) {
    await assert.rejects(
      packFile(utf8("x"), { fileName: "x", recipients: value }),
      /recipients must be an array/
    );
  }
});

test("a bad recipient key is caught before the file is encrypted", async () => {
  const onProgress = () => assert.fail("encryption started despite a malformed recipient key");

  await assert.rejects(
    packFile(utf8("x".repeat(4096)), {
      fileName: "x",
      recipients: ["not-a-key"],
      chunkSize: 16,
      onProgress,
    }),
    /recipient key must start with/
  );
});

// ---------------------------------------------------------------------------
// Validation of a hostile manifest
// ---------------------------------------------------------------------------

async function recipientManifest() {
  const alice = await generateIdentity();
  const { manifest } = await store(utf8("x"), { fileName: "x", recipients: [alice.recipient] });
  return manifest;
}

test("an encrypted manifest offering no way to the file key is refused", async () => {
  const manifest = await recipientManifest();
  delete manifest.recipients;

  assert.throws(
    () => validateManifestHeader(manifest),
    (error) => error instanceof ManifestError && /wrappedKey, recipients, or both/.test(error.message)
  );
});

test("a recipients field that is present but empty is refused", async () => {
  const manifest = await recipientManifest();
  manifest.recipients = [];

  assert.throws(() => validateManifestHeader(manifest), /present but empty/);
});

test("recipient entries are checked for shape before an EC point is imported", async () => {
  const manifest = await recipientManifest();
  const good = manifest.recipients[0];

  for (const [label, entries] of [
    ["not an array", { 0: good }],
    ["an entry that is not an object", [good, "x"]],
    ["a null entry", [good, null]],
    ["a nested array", [[good]]],
    ["a missing ephemeral", [{ ciphertext: good.ciphertext }]],
    ["a missing ciphertext", [{ ephemeral: good.ephemeral }]],
    ["a non-string field", [{ ephemeral: 1, ciphertext: good.ciphertext }]],
    ["standard base64 rather than base64url", [{ ...good, ciphertext: "ab+/cd==" }]],
    ["an oversized ephemeral", [{ ...good, ephemeral: good.ephemeral + "AAAA" }]],
    ["an oversized ciphertext", [{ ...good, ciphertext: good.ciphertext + "AAAA" }]],
  ]) {
    assert.throws(
      () => validateManifestHeader({ ...manifest, recipients: entries }),
      ManifestError,
      `accepted ${label}`
    );
  }
});

test("a manifest reusing one ephemeral key across two entries is refused", async () => {
  const manifest = await recipientManifest();
  const [entry] = manifest.recipients;

  assert.throws(
    () => validateManifestHeader({ ...manifest, recipients: [entry, { ...entry }] }),
    /reuses the ephemeral key of an earlier entry/
  );
});

test("a manifest listing more recipients than the limit is refused", async () => {
  const manifest = await recipientManifest();
  const [entry] = manifest.recipients;

  const flood = Array.from({ length: MANIFEST_LIMITS.maxRecipients + 1 }, (_, i) => ({
    ...entry,
    // Distinct, so the count is what rejects this rather than the reuse check.
    ephemeral: toBase64Url(Uint8Array.from({ length: 65 }, (_, b) => (b === 64 ? i : entry.ephemeral.charCodeAt(0)))),
  }));

  assert.throws(
    () => validateManifestHeader({ ...manifest, recipients: flood }),
    /above the maximum/
  );
});

test("a file shared to recipients survives a round trip through JSON", async () => {
  const alice = await generateIdentity();
  const bytes = utf8("over the wire");
  const { manifest, fetch } = await store(bytes, {
    fileName: "w.txt",
    recipients: [alice.recipient],
  });

  const reparsed = JSON.parse(JSON.stringify(manifest));
  validateManifestHeader(reparsed);

  const opened = await openManifest(reparsed, null, { identity: alice.identity });
  assert.ok(equalBytes((await restoreFile(reparsed, opened, fetch)).bytes, bytes));
});

// ---------------------------------------------------------------------------
// The script an operator actually runs
// ---------------------------------------------------------------------------

test("generate-recipient-key.mjs prints a usable pair, secret half on stdout", async () => {
  const identity = execFileSync(
    process.execPath,
    [path.join(ROOT, "scripts", "generate-recipient-key.mjs")],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
  ).trim();

  assert.ok(identity.startsWith(IDENTITY_PREFIX));

  // It opens a real file, which is the only claim that matters about it.
  const recipient = recipientOf(identity);
  const { manifest, fetch } = await store(utf8("from the CLI"), {
    fileName: "cli.txt",
    recipients: [recipient],
  });
  const opened = await openManifest(manifest, null, { identity });
  assert.equal(
    new TextDecoder().decode((await restoreFile(manifest, opened, fetch)).bytes),
    "from the CLI"
  );
});
