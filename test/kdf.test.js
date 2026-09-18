/**
 * Passphrase key derivation.
 *
 * This is the weakest link in the whole system: the wrapped file key travels in
 * the manifest, so an attacker who fetches one can guess passphrases offline at
 * hardware speed with nobody watching. The cost of a single guess is the real
 * security parameter, which is what Argon2id raises and PBKDF2 barely does.
 */

import test from "node:test";
import assert from "node:assert/strict";

import { argon2id } from "../node_modules/@noble/hashes/esm/argon2.js";
import { equalBytes, randomBytes, toHex, utf8 } from "../js/core/bytes.js";
import {
  ARGON2ID_DEFAULTS,
  DEFAULT_KDF,
  deriveKeyEncryptionKey,
  describeKdf,
  KDF_ARGON2ID,
  KDF_PBKDF2,
  kdfSpec,
  normalizeKdfName,
  PBKDF2_DEFAULTS,
} from "../js/core/kdf.js";
import { validateKdfParameters, ManifestError } from "../js/core/validate.js";
import { MANIFEST_LIMITS } from "../js/core/limits.js";
import { openManifest, packFile, restoreFile, sealManifest } from "../js/core/manifest.js";

const TEST_KDF = { name: "argon2id", memoryKiB: 8, iterations: 1, parallelism: 1 };
const TEST_LIMITS = { minArgon2MemoryKiB: 8 };

// ------------------------------------------------------ known-answer testing

test("Argon2id matches the RFC 9106 test vector", () => {
  /*
   * RFC 9106 §5.3. A key-derivation function that has not been checked against
   * a published vector is worth nothing: a subtly wrong implementation still
   * produces plausible-looking bytes, encrypts happily, and silently provides a
   * fraction of the intended strength.
   */
  const tag = argon2id(new Uint8Array(32).fill(1), new Uint8Array(16).fill(2), {
    t: 3,
    m: 32,
    p: 4,
    dkLen: 32,
    key: new Uint8Array(8).fill(3),
    personalization: new Uint8Array(12).fill(4),
  });

  assert.equal(
    toHex(tag),
    "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
  );
});

// ---------------------------------------------------------------- parameters

test("Argon2id is the default for new files", () => {
  assert.equal(DEFAULT_KDF, KDF_ARGON2ID);
  assert.equal(kdfSpec().name, KDF_ARGON2ID);
});

test("the shipped Argon2id parameters clear the OWASP floor with room to spare", () => {
  // m >= 19456 KiB with t >= 1, p = 1 is OWASP's minimum recommended profile.
  assert.ok(
    ARGON2ID_DEFAULTS.memoryKiB >= 19456,
    `expected >= 19456 KiB, got ${ARGON2ID_DEFAULTS.memoryKiB}`
  );
  assert.ok(ARGON2ID_DEFAULTS.iterations >= 1);
  assert.ok(ARGON2ID_DEFAULTS.parallelism >= 1);
  assert.ok(ARGON2ID_DEFAULTS.memoryKiB >= MANIFEST_LIMITS.minArgon2MemoryKiB);

  // Attacker cost scales roughly with memory x passes. Pin the intended
  // profile so a future edit cannot quietly weaken it: a one-character change
  // to either number is invisible in review and halves the cost of an attack.
  assert.equal(ARGON2ID_DEFAULTS.memoryKiB, 65536);
  assert.equal(ARGON2ID_DEFAULTS.iterations, 2);
  assert.ok(
    ARGON2ID_DEFAULTS.memoryKiB * ARGON2ID_DEFAULTS.iterations >= 47104,
    "the default must never cost an attacker less than the profile it replaced"
  );
});

test("the legacy PBKDF2 floor is still the OWASP recommendation", () => {
  assert.ok(PBKDF2_DEFAULTS.iterations >= 600000);
});

test("partial parameter sets are filled in from the defaults", () => {
  const spec = kdfSpec({ name: "argon2id", memoryKiB: 65536 });
  assert.equal(spec.memoryKiB, 65536);
  assert.equal(spec.iterations, ARGON2ID_DEFAULTS.iterations);
  assert.equal(spec.parallelism, ARGON2ID_DEFAULTS.parallelism);
});

test("legacy KDF names are normalised", () => {
  // Manifests written before Argon2id spell it "PBKDF2-SHA256".
  assert.equal(normalizeKdfName("PBKDF2-SHA256"), KDF_PBKDF2);
  assert.equal(normalizeKdfName("pbkdf2"), KDF_PBKDF2);
  assert.equal(normalizeKdfName("Argon2id"), KDF_ARGON2ID);
  assert.throws(() => normalizeKdfName("scrypt"), /unsupported key-derivation/);
  assert.throws(() => normalizeKdfName(""), /unsupported key-derivation/);
});

test("a bare number is rejected rather than silently meaning defaults", () => {
  // The old API took a PBKDF2 iteration count positionally. Spreading a number
  // yields {}, which would quietly hand back Argon2id defaults and change an
  // upgrading caller's security parameters without a word.
  assert.throws(() => kdfSpec(1000), /must be a name or a parameter object/);
  assert.throws(() => kdfSpec(600000), /received number/);
  assert.throws(() => kdfSpec(null), /received object|must be a name/);
  assert.throws(() => kdfSpec(true), /received boolean/);
});

test("describeKdf states the parameters a user is relying on", () => {
  assert.match(describeKdf("argon2id"), /Argon2id \(65536 KiB, 2 passes, p=1\)/);
  assert.match(describeKdf({ name: "argon2id", iterations: 3 }), /3 passes/);
  assert.match(describeKdf({ name: "argon2id", iterations: 1 }), /1 pass,/);
  assert.match(describeKdf({ name: "pbkdf2-sha256" }), /PBKDF2-SHA256 \(600000/);
});

// ---------------------------------------------------------------- derivation

test("derivation is deterministic and salt-dependent", async () => {
  const salt = randomBytes(16);
  const a = await deriveKeyEncryptionKey("passphrase", salt, TEST_KDF);
  const b = await deriveKeyEncryptionKey("passphrase", salt, TEST_KDF);
  assert.ok(equalBytes(a, b));

  const other = await deriveKeyEncryptionKey("passphrase", randomBytes(16), TEST_KDF);
  assert.ok(!equalBytes(a, other), "a different salt must give a different key");
});

test("the two KDFs produce different keys from identical inputs", async () => {
  // Otherwise a file could be opened under whichever is cheaper to attack.
  const salt = randomBytes(16);
  const argon = await deriveKeyEncryptionKey("same passphrase", salt, TEST_KDF);
  const pbkdf2 = await deriveKeyEncryptionKey("same passphrase", salt, {
    name: KDF_PBKDF2,
    iterations: 1000,
  });
  assert.notEqual(toHex(argon), toHex(pbkdf2));
});

test("changing any Argon2id parameter changes the key", async () => {
  const salt = randomBytes(16);
  // 32 KiB rather than 8, so that raising parallelism still satisfies
  // Argon2's requirement of at least 8 KiB per lane.
  const base = { name: "argon2id", memoryKiB: 32, iterations: 1, parallelism: 1 };
  const baseline = await deriveKeyEncryptionKey("pw", salt, base);

  for (const override of [{ memoryKiB: 64 }, { iterations: 2 }, { parallelism: 2 }]) {
    const changed = await deriveKeyEncryptionKey("pw", salt, { ...base, ...override });
    assert.ok(!equalBytes(baseline, changed), `parameter ${Object.keys(override)[0]} was ignored`);
  }
});

test("Argon2's memory-per-lane requirement is enforced with a clear message", () => {
  // Without this check the failure comes out of the hash internals as
  // "memory should be at least 8*p bytes", far from where it was configured.
  assert.throws(
    () => kdfSpec({ name: "argon2id", memoryKiB: 8, parallelism: 2 }),
    /memoryKiB >= 8 \* parallelism/
  );
  assert.throws(
    () =>
      validateKdfParameters(
        { name: "argon2id", memoryKiB: 8, iterations: 1, parallelism: 4 },
        { minArgon2MemoryKiB: 8 }
      ),
    /memoryKiB >= 8 \* parallelism/
  );
});

test("derivation refuses an empty passphrase or a short salt", async () => {
  await assert.rejects(
    () => deriveKeyEncryptionKey("", randomBytes(16), TEST_KDF),
    /passphrase is required/
  );
  await assert.rejects(
    () => deriveKeyEncryptionKey("pw", randomBytes(4), TEST_KDF),
    /salt of at least 8 bytes/
  );
  await assert.rejects(() => deriveKeyEncryptionKey("pw", "not bytes", TEST_KDF), /salt/);
});

test("the derived key is 256 bits", async () => {
  const key = await deriveKeyEncryptionKey("pw", randomBytes(16), TEST_KDF);
  assert.equal(key.length, 32);
  assert.ok(utf8("sanity").length === 6);
});

// ---------------------------------------------------------------- validation

test("a manifest weakening Argon2id below the floor is rejected", () => {
  /*
   * The central attack this defends against. Whoever serves the manifest picks
   * these numbers; memoryKiB: 8 would make cracking the passphrase as cheap as
   * it was before Argon2id was adopted, and the file would still open normally,
   * so nothing would look wrong.
   */
  assert.throws(
    () => validateKdfParameters({ name: "argon2id", memoryKiB: 8, iterations: 1, parallelism: 1 }),
    /kdf.memoryKiB must be at least 19456/
  );
});

test("a manifest demanding absurd Argon2id work is rejected", () => {
  // The reverse attack: a manifest that makes opening a file a denial of
  // service against the reader, who would dutifully allocate the memory.
  assert.throws(
    () =>
      validateKdfParameters({
        name: "argon2id",
        memoryKiB: 8_589_934_592,
        iterations: 1,
        parallelism: 1,
      }),
    /kdf.memoryKiB exceeds the maximum/
  );
  assert.throws(
    () => validateKdfParameters({ name: "argon2id", memoryKiB: 65536, iterations: 1e6, parallelism: 1 }),
    /kdf.iterations exceeds the maximum/
  );
});

test("Argon2id parameters must all be present and integral", () => {
  for (const bad of [
    { name: "argon2id", iterations: 1, parallelism: 1 },
    { name: "argon2id", memoryKiB: 65536, parallelism: 1 },
    { name: "argon2id", memoryKiB: 65536, iterations: 1 },
    { name: "argon2id", memoryKiB: 65536.5, iterations: 1, parallelism: 1 },
  ]) {
    assert.throws(() => validateKdfParameters(bad), ManifestError);
  }
});

test("legacy PBKDF2 parameters are still validated against their own floor", () => {
  assert.doesNotThrow(() =>
    validateKdfParameters({ name: "PBKDF2-SHA256", iterations: 600000 })
  );
  assert.throws(
    () => validateKdfParameters({ name: "PBKDF2-SHA256", iterations: 1 }),
    /kdf.iterations must be at least 600000/
  );
});

test("an unknown KDF name in a manifest is rejected", () => {
  assert.throws(() => validateKdfParameters({ name: "md5" }), /unsupported key-derivation/);
});

test("the floor can be lowered deliberately, but not by the manifest", () => {
  // Callers choose their own bounds; a manifest never gets to.
  assert.doesNotThrow(() =>
    validateKdfParameters(
      { name: "argon2id", memoryKiB: 8, iterations: 1, parallelism: 1 },
      { minArgon2MemoryKiB: 8 }
    )
  );
});

// -------------------------------------------------------------- end-to-end

async function roundTrip(kdf, limits) {
  const data = randomBytes(2048);
  const blocks = new Map();
  let n = 0;

  const packed = await packFile(data, {
    fileName: "kdf.bin",
    passphrase: "an end to end passphrase",
    chunkSize: 1024,
    kdf,
  });
  const locations = packed.chunks.map((chunk) => {
    const id = `b${n++}`;
    blocks.set(id, chunk.payload);
    return id;
  });

  const manifest = await sealManifest(packed, locations);
  const opened = await openManifest(manifest, "an end to end passphrase", { limits });
  const restored = await restoreFile(manifest, opened, (loc) => blocks.get(loc), { limits });

  return { manifest, restored, data };
}

test("a file sealed with Argon2id round-trips, and records its parameters", async () => {
  const { manifest, restored, data } = await roundTrip(TEST_KDF, TEST_LIMITS);

  assert.ok(equalBytes(restored.bytes, data));
  assert.equal(manifest.kdf.name, KDF_ARGON2ID);
  assert.equal(manifest.kdf.memoryKiB, 8);
  assert.equal(manifest.kdf.iterations, 1);
  assert.equal(manifest.kdf.parallelism, 1);
  assert.match(manifest.kdf.salt, /^[A-Za-z0-9+/]+=*$/);
});

test("files sealed with the legacy PBKDF2 still open", async () => {
  // Backward compatibility is not optional: a KDF change that stranded existing
  // files would destroy them, since there is no recovery path without the key.
  const { manifest, restored, data } = await roundTrip({
    name: KDF_PBKDF2,
    iterations: 600000,
  });

  assert.ok(equalBytes(restored.bytes, data));
  assert.equal(manifest.kdf.name, KDF_PBKDF2);
  assert.equal(manifest.kdf.iterations, 600000);
});

test("a wrong passphrase still fails cleanly under Argon2id", async () => {
  const { manifest } = await roundTrip(TEST_KDF, TEST_LIMITS);
  await assert.rejects(
    () => openManifest(manifest, "not the passphrase", { limits: TEST_LIMITS }),
    /wrong passphrase/
  );
});

test("a manifest with tampered KDF parameters does not open", async () => {
  // Changing the parameters changes the derived key, so the wrapped file key
  // fails to unwrap — the tampering is caught by the AEAD tag, not just by
  // validation.
  const { manifest } = await roundTrip(TEST_KDF, TEST_LIMITS);
  const tampered = { ...manifest, kdf: { ...manifest.kdf, iterations: 2 } };

  await assert.rejects(
    () => openManifest(tampered, "an end to end passphrase", { limits: TEST_LIMITS }),
    /wrong passphrase/
  );
});

test("packFile rejects an unusable kdf before doing any work", async () => {
  await assert.rejects(
    () => packFile(randomBytes(64), { passphrase: "pw", kdf: "scrypt" }),
    /unsupported key-derivation/
  );
  await assert.rejects(
    () => packFile(randomBytes(64), { passphrase: "pw", kdf: 1000 }),
    /must be a name or a parameter object/
  );
});

test("a file sealed under the previous default profile still opens", async () => {
  /*
   * The parameters that sealed a file travel with it, so raising the default
   * must not strand anything already stored. If it did, those files would be
   * destroyed outright — there is no path to the plaintext without the key.
   *
   * This uses the real profile that shipped before the raise (46 MiB, one
   * pass), not a cheap stand-in, because the point is that genuine older
   * files open.
   */
  const previousDefault = { name: "argon2id", memoryKiB: 47104, iterations: 1, parallelism: 1 };

  const { manifest, restored, data } = await roundTrip(previousDefault);

  assert.ok(equalBytes(restored.bytes, data));
  assert.equal(manifest.kdf.memoryKiB, 47104);
  assert.equal(manifest.kdf.iterations, 1);

  // And the current default really is different, so this is a real regression
  // guard rather than a test that would pass either way.
  assert.notEqual(manifest.kdf.memoryKiB, ARGON2ID_DEFAULTS.memoryKiB);
});

test("a new file is sealed with the current default, not a stale one", async () => {
  // packFile with no kdf option must pick up ARGON2ID_DEFAULTS. Cheap
  // parameters cannot verify this, so it derives at full cost once.
  const { manifest } = await roundTrip(undefined);

  assert.equal(manifest.kdf.name, KDF_ARGON2ID);
  assert.equal(manifest.kdf.memoryKiB, ARGON2ID_DEFAULTS.memoryKiB);
  assert.equal(manifest.kdf.iterations, ARGON2ID_DEFAULTS.iterations);
  assert.equal(manifest.kdf.parallelism, ARGON2ID_DEFAULTS.parallelism);
});
