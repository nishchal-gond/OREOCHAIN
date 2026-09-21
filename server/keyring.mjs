/**
 * Every public key that has ever signed a receipt here.
 *
 * A receipt is portable and long-lived by design: someone can come back a
 * year later with one and expect it to check out. Verifying it needs the
 * public key that signed it, and the receipt names that key by `kid` — but
 * the gateway only ever served the *current* key. So the moment the signing
 * key changed, every receipt issued under the old one failed to verify, with
 * the same answer a forgery gets. A holder could not tell a rotation from a
 * lie.
 *
 * This is the missing half: a small file beside the proof store listing every
 * public key that has signed, so a rotation adds a key and never forgets one.
 *
 * **Only public keys are stored here.** The signing key still comes from
 * OREOCHAIN_RECEIPT_KEY, which is the whole point of that setting: it keeps
 * the one secret worth stealing out of the environment and off the data
 * volume. A keyring that wrote private keys next to the proofs would undo
 * that to save a restart.
 */

import { readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";

const VERSION = 1;

/**
 * @param {object} options
 * @param {string} options.path where to keep it; ":memory:" for tests
 * @param {object} [options.log]
 * @param {Function} [options.now]
 */
export function openKeyring(options = {}) {
  const filePath = options.path || ":memory:";
  const persistent = filePath !== ":memory:";
  const now = options.now || (() => new Date().toISOString());
  const log = options.log;

  /** kid -> { kid, publicJwk, firstSeen, retiredAt } */
  let keys = new Map();
  let current = null;

  if (persistent) {
    let raw = null;
    try {
      raw = readFileSync(filePath, "utf8");
    } catch (error) {
      // A keyring that does not exist yet is the normal first start. Anything
      // else — a directory, a permissions problem — is not, and starting with
      // an empty ring would quietly lose every historical key.
      if (error.code !== "ENOENT") {
        throw new Error(`cannot read the keyring at ${filePath}: ${error.message}`);
      }
    }

    if (raw) {
      let parsed;
      try {
        parsed = JSON.parse(raw);
      } catch (error) {
        throw new Error(`the keyring at ${filePath} is not valid JSON: ${error.message}`);
      }
      if (parsed.v !== VERSION) {
        throw new Error(
          `the keyring at ${filePath} is version ${parsed.v}, this build writes ${VERSION}`
        );
      }
      for (const key of parsed.keys || []) keys.set(key.kid, key);
      current = parsed.current || null;
    }
  }

  function persist() {
    if (!persistent) return;
    const document = {
      v: VERSION,
      current,
      keys: [...keys.values()],
    };
    // Written whole and renamed into place: a keyring truncated by a crash
    // mid-write would lose the history it exists to keep.
    const temporary = path.join(
      path.dirname(filePath),
      `.${path.basename(filePath)}.${process.pid}.tmp`
    );
    writeFileSync(temporary, JSON.stringify(document, null, 2) + "\n", { mode: 0o600 });
    renameSync(temporary, filePath);
  }

  return {
    /**
     * Record the key that is signing now, retiring whichever was before.
     *
     * Idempotent: restarting with the same key changes nothing. Starting with
     * a different one adds it and marks the previous as retired — retired
     * from *signing*, never forgotten for verifying.
     */
    use(kid, publicJwk) {
      let added = false;

      if (!keys.has(kid)) {
        keys.set(kid, { kid, publicJwk, firstSeen: now(), retiredAt: null });
        added = true;
      }

      if (current !== kid) {
        const previous = current ? keys.get(current) : null;
        if (previous && !previous.retiredAt) previous.retiredAt = now();
        current = kid;
        added = true;

        if (previous && log) {
          log.info("receipt signing key rotated", {
            from: previous.kid,
            to: kid,
            keysHeld: keys.size,
          });
        }
      }

      if (added) persist();
      return keys.get(kid);
    },

    current: () => (current ? keys.get(current) : null),

    /** The public key for a kid, retired or not, or null. */
    find: (kid) => keys.get(kid) || null,

    /** Every kid held, for a client that wants to know what it can ask for. */
    list: () =>
      [...keys.values()].map((key) => ({
        kid: key.kid,
        firstSeen: key.firstSeen,
        retiredAt: key.retiredAt,
        current: key.kid === current,
      })),

    size: () => keys.size,
  };
}
