import test from "node:test";
import assert from "node:assert/strict";

import { buildBatch, proveInBatch } from "../js/core/anchor.js";
import { generateSigningKey, issueReceipt, keyId } from "../js/core/receipt.js";
import { checkAnchor, checkReceipt, createProofClient } from "../js/storage/proofs.js";

/** Swap in a fake fetch for the duration of one call. */
async function withFetch(impl, fn) {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  try {
    return await fn();
  } finally {
    globalThis.fetch = original;
  }
}

function json(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => "application/json" },
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

const DOCUMENT = {
  fileHash: `0x${"11".repeat(32)}`,
  merkleRoot: `0x${"22".repeat(32)}`,
  manifestCID: "bafyManifestOne",
  fileSize: 4096,
  totalChunks: 2,
  encrypted: true,
  suite: "aes-256-gcm",
};

/** A gateway's key, and a receipt it signed, as the browser would receive them. */
async function issue(document = DOCUMENT) {
  const key = await generateSigningKey();
  const kid = await keyId(key.publicKey);
  const receipt = await issueReceipt(document, key.privateKey, { kid });
  return { key, kid, receipt };
}

/** A keyring that serves any key it has ever held, and 404s for the rest. */
function keyring(entries) {
  return async (url) => {
    const asked = new URL(url, "https://gateway.test").searchParams.get("kid");
    if (asked === null) return json(entries[0]);
    const found = entries.find((entry) => entry.kid === asked);
    return found ? json(found) : json({ error: "no such key" }, 404);
  };
}

// ------------------------------------------------------------------ recording

test("recording a document returns the receipt the gateway signed", async () => {
  const { receipt } = await issue();
  let sent = null;

  await withFetch(
    async (url, init) => {
      sent = { url, body: JSON.parse(init.body) };
      return json({ receipt, queued: true, pending: 3 });
    },
    async () => {
      const result = await createProofClient().record(DOCUMENT);
      assert.equal(result.pending, 3);
      assert.deepEqual(result.receipt.statement, receipt.statement);
    }
  );

  assert.equal(sent.url, "/api/proofs/record");
  assert.equal(sent.body.fileHash, DOCUMENT.fileHash);
});

test("a response with no receipt in it is a failure, not a success", async () => {
  await withFetch(
    async () => json({ queued: true }),
    async () => {
      const client = createProofClient({ retry: { maxAttempts: 1 } });
      await assert.rejects(() => client.record(DOCUMENT), /no receipt/);
    }
  );
});

test("recording is not retried when the gateway meant its refusal", async () => {
  let calls = 0;
  await withFetch(
    async () => {
      calls++;
      return json({ code: "gateway_budget", error: "spent for today" }, 503);
    },
    async () => {
      const client = createProofClient({ retry: { backoffBaseMs: 1 } });
      await assert.rejects(() => client.record(DOCUMENT), /gateway_budget/);
    }
  );
  assert.equal(calls, 1);
});

// ---------------------------------------------------------------------- keys

test("the key is asked for by the id the receipt names", async () => {
  const { kid, key, receipt } = await issue();
  const asked = [];

  await withFetch(
    async (url) => {
      asked.push(url);
      return json({ kid, publicJwk: key.exported.publicJwk });
    },
    async () => {
      const result = await checkReceipt(receipt, createProofClient());
      assert.equal(result.valid, true);
    }
  );

  // Not "whichever key you are using now": a gateway that has rotated still
  // holds the old public key, and asking for the current one would make every
  // receipt issued before the rotation look like a forgery.
  assert.equal(asked.length, 1);
  assert.match(asked[0], new RegExp(`kid=${kid}$`));
});

test("a receipt verifies against a key the gateway has since retired", async () => {
  const older = await issue();
  const current = await issue();

  await withFetch(
    keyring([
      { kid: current.kid, publicJwk: current.key.exported.publicJwk },
      {
        kid: older.kid,
        publicJwk: older.key.exported.publicJwk,
        retiredAt: "2026-09-01T00:00:00.000Z",
      },
    ]),
    async () => {
      const result = await checkReceipt(older.receipt, createProofClient());
      // A key retired after the receipt was signed does not weaken it.
      assert.equal(result.valid, true);
      assert.equal(result.retiredAt, "2026-09-01T00:00:00.000Z");
    }
  );
});

test("a key id the gateway has never held reads as a forgery", async () => {
  const real = await issue();
  const stranger = await issue();

  await withFetch(
    keyring([{ kid: real.kid, publicJwk: real.key.exported.publicJwk }]),
    async () => {
      const result = await checkReceipt(stranger.receipt, createProofClient());
      assert.equal(result.valid, false);
      assert.equal(result.forged, true);
      assert.match(result.reason, /has ever signed at this service/);
    }
  );
});

test("a gateway that cannot be reached is not evidence of a forgery", async () => {
  const { receipt } = await issue();

  await withFetch(
    async () => {
      throw new Error("connection reset");
    },
    async () => {
      const result = await checkReceipt(receipt, createProofClient());
      assert.equal(result.valid, false);
      // The distinction the user's trust rests on: this receipt is unchecked,
      // not disproved.
      assert.equal(result.unavailable, true);
      assert.notEqual(result.forged, true);
    }
  );
});

test("a gateway that ignores the kid query is unavailable, not accusing", async () => {
  const older = await issue();
  const current = await issue();

  await withFetch(
    // A gateway from before the keyring: it answers every lookup with today's
    // key, whatever was asked for.
    async () => json({ kid: current.kid, publicJwk: current.key.exported.publicJwk }),
    async () => {
      const result = await checkReceipt(older.receipt, createProofClient());
      assert.equal(result.valid, false);
      assert.equal(result.unavailable, true);
      assert.notEqual(result.forged, true);
      assert.match(result.reason, /cannot produce the key/);
    }
  );
});

test("an edited statement fails the signature it no longer matches", async () => {
  const { kid, key, receipt } = await issue();
  const tampered = {
    ...receipt,
    statement: { ...receipt.statement, manifestCID: "bafySomethingElse" },
  };

  await withFetch(
    async () => json({ kid, publicJwk: key.exported.publicJwk }),
    async () => {
      const result = await checkReceipt(tampered, createProofClient());
      assert.equal(result.valid, false);
      assert.match(result.reason, /signature does not verify/);
    }
  );
});

test("a gateway running on a throwaway key says so", async () => {
  const { kid, key, receipt } = await issue();

  await withFetch(
    async () => json({ kid, publicJwk: key.exported.publicJwk, ephemeral: true }),
    async () => {
      const result = await checkReceipt(receipt, createProofClient());
      assert.equal(result.valid, true);
      // The UI needs this: the receipt stops being checkable at the next
      // restart, so the anchor is the part that will last.
      assert.equal(result.ephemeral, true);
    }
  );
});

// ----------------------------------------------------------------- inclusion

test("no inclusion proof yet is a state, not an error", async () => {
  await withFetch(
    async () => json({ error: "no inclusion proof for that document yet" }, 404),
    async () => {
      assert.equal(await createProofClient().inclusion(DOCUMENT.fileHash), null);
    }
  );
});

test("a file hash that is not a file hash never reaches the network", async () => {
  await withFetch(
    async () => {
      throw new Error("should not have been called");
    },
    async () => {
      const client = createProofClient();
      await assert.rejects(() => client.inclusion("../../etc/passwd"), /32-byte hex/);
    }
  );
});

// -------------------------------------------------------------------- anchors

test("an inclusion proof verifies against the root read from the chain", async () => {
  const { receipt } = await issue();
  const batch = await buildBatch([DOCUMENT]);
  const inclusion = await proveInBatch(batch, DOCUMENT.fileHash);

  const result = await checkAnchor(receipt, { ...inclusion, txHash: `0x${"ab".repeat(32)}`, block: 91 }, batch.root);
  assert.equal(result.anchored, true);
  assert.equal(result.block, 91);
});

test("a proof checked against the wrong root does not pass", async () => {
  const { receipt } = await issue();
  const batch = await buildBatch([DOCUMENT]);
  const inclusion = await proveInBatch(batch, DOCUMENT.fileHash);

  // The whole reason the root has to come from the chain: verifying the
  // gateway's path against the gateway's own root proves only arithmetic.
  const result = await checkAnchor(receipt, inclusion, `0x${"99".repeat(32)}`);
  assert.equal(result.anchored, false);
});

test("a service that receipts one document and anchors another is caught", async () => {
  // The receipt says one manifest; the batch commits to a different one.
  const { receipt } = await issue({ ...DOCUMENT, manifestCID: "bafyWhatTheUserWasPromised" });
  const batch = await buildBatch([{ ...DOCUMENT, manifestCID: "bafyWhatWasActuallyAnchored" }]);
  const inclusion = await proveInBatch(batch, DOCUMENT.fileHash);

  const result = await checkAnchor(receipt, inclusion, batch.root);
  assert.equal(result.anchored, false);
  assert.equal(result.disputed, true);
  assert.match(result.reason, /manifestCID differs/);
});

test("no inclusion proof is pending, not disputed", async () => {
  const { receipt } = await issue();
  const result = await checkAnchor(receipt, null, null);
  assert.equal(result.anchored, false);
  assert.notEqual(result.disputed, true);
});
