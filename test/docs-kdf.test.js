/**
 * The documentation agrees with the code about key derivation.
 *
 * The Argon2id profile is a security parameter a reader is invited to check:
 * docs/SECURITY.md §2.5 says how much memory a guess costs an attacker, and
 * somebody deciding whether that is enough has no way to tell a stale figure
 * from a current one. Before this, the numbers were copied by hand into two
 * documents, the Readme, the example config and the tests, and a change that
 * touched only js/core/kdf.js left every copy quietly lying.
 *
 * So the prose is generated from the code by scripts/sync-kdf-docs.mjs, and this
 * is the part that makes it stick: generation only helps if somebody runs it.
 * The equivalent for the contract ABI lives in CI, where it catches a stale file
 * after the push; here it runs in `npm test`, so the answer arrives while the
 * change is still in a working tree.
 */

import test from "node:test";
import assert from "node:assert/strict";

import { ARGON2ID_DEFAULTS, ARGON2ID_PROFILE, argon2idCost } from "../js/core/kdf.js";
import { kdfFacts, regions, syncKdfDocs } from "../scripts/sync-kdf-docs.mjs";

test("the generated key-derivation documentation is up to date", () => {
  // write: false — a test that fixed the drift would report success and leave
  // the repository in a state nobody chose.
  const { stale } = syncKdfDocs({ write: false });

  assert.deepEqual(
    stale,
    [],
    `${stale.join(", ")} no longer matches js/core/kdf.js. Run \`npm run kdf-docs\`.`
  );
});

test("every marked region is present in the file it belongs to", () => {
  // syncKdfDocs throws on a missing marker, so this is really a check that the
  // markers survive editing: a document whose markers were deleted looks
  // up-to-date forever, which is the one failure the check above cannot see.
  assert.doesNotThrow(() => syncKdfDocs({ write: false }));

  const ids = Object.values(regions()).flatMap((spans) => Object.keys(spans));
  assert.ok(ids.length >= 9, `expected the generated regions, found ${ids.length}`);
});

test("the documented figures are the ones the code will actually use", () => {
  const facts = kdfFacts();

  assert.equal(facts.memoryKiB, ARGON2ID_DEFAULTS.memoryKiB);
  assert.equal(facts.iterations, ARGON2ID_DEFAULTS.iterations);
  assert.equal(facts.parallelism, ARGON2ID_DEFAULTS.parallelism);

  // The attack-cost ratio is the one figure in the prose that is computed rather
  // than copied, so it is worth checking the arithmetic rather than trusting the
  // number that comes out of it.
  const expected = argon2idCost(ARGON2ID_DEFAULTS) / argon2idCost(ARGON2ID_PROFILE.costFloor);
  assert.equal(facts.costRatio, expected.toFixed(1));
  assert.ok(Number(facts.costRatio) >= 1, "the shipped profile cannot be weaker than the floor");
});

test("no generated region is left holding a stale number after the profile moves", () => {
  /*
   * The real test of a generator is what it does when the source changes, and
   * nothing here can change ARGON2ID_DEFAULTS — it is frozen, and a test that
   * mutated it would poison every other file in the suite. So this renders the
   * regions and checks that each one that should carry a number does, which is
   * what fails if a template is ever flattened into a hard-coded string.
   */
  const { memoryKiB } = ARGON2ID_DEFAULTS;

  const security = regions()["docs/SECURITY.md"];
  assert.match(security.profile, new RegExp(`m=${memoryKiB} KiB`));
  assert.match(security.envelope, new RegExp(`m=${memoryKiB}KiB`));
  assert.match(security.primitive, /Argon2id \(\d+(\.\d+)? MiB, \d+ passe?s?\)/);

  const sealing = regions()["docs/SEALING.md"];
  assert.match(sealing.settings, new RegExp(`\\| Memory \\| ${memoryKiB} KiB`));
  assert.match(sealing.bounds, /\| Min Argon2 memory \| [\d,]+ KiB \|/);

  const readme = regions()["Readme.md"];
  assert.match(readme.memory, /MiB/);
  assert.match(readme.cost, /^~[\d.]+s$/);
});
