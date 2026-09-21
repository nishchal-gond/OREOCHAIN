#!/usr/bin/env node
/**
 * Drive a running gateway through the whole path a user takes.
 *
 *   node scripts/smoke.mjs --url http://localhost:8787 --key "$OREOCHAIN_API_KEYS"
 *   node scripts/smoke.mjs --url https://gateway.example --key "$KEY" --anchor-key "$ANCHOR_KEY"
 *
 * Not a test of the code — `npm test` does that, against mocks and an EVM.
 * This is a test of a *deployment*: the image, the compose file, the
 * environment, the volume, the reverse proxy in front of it. Those are the
 * things `npm test` cannot see, and they are what actually breaks. A default
 * in docker-compose.yml drifting from what the code now refuses to start
 * without is invisible to every other check in this repository.
 *
 * So it uses the same client code the browser uses (js/core), speaks to the
 * service over HTTP exactly as a visitor would, and checks the answers the way
 * a sceptical user should: the receipt's signature against the published key,
 * the inclusion proof against the batch root, the restored bytes against the
 * bytes that went in.
 *
 * Read-only in the sense that matters: it pins a small file and records it,
 * which is what the service is for, and it anchors nothing on a chain. Safe
 * against a real deployment, at the cost of one small pinned file.
 *
 * Exit 0 if every step passed, 1 on the first that did not.
 */

import { equalBytes, randomBytes, utf8 } from "../js/core/bytes.js";
import { openManifest, packFile, restoreFile, sealManifest } from "../js/core/manifest.js";
import { putAll } from "../js/storage/ipfs.js";
import { verifyInBatch } from "../js/core/anchor.js";
import { importPublicKey, verifyReceipt } from "../js/core/receipt.js";

function arg(name, fallback = null) {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? fallback : process.argv[index + 1];
}

const url = (arg("url") || process.env.OREOCHAIN_GATEWAY_URL || "http://127.0.0.1:8787").replace(
  /\/$/,
  ""
);
const key = arg("key") || process.env.OREOCHAIN_API_KEY || "";
const anchorKey = arg("anchor-key") || process.env.OREOCHAIN_ANCHOR_API_KEY || "";
const size = Number(arg("size", "40960"));
const chunkSize = Number(arg("chunk-size", "4096"));
const readyTimeoutMs = Number(arg("ready-timeout-ms", "60000"));

// A key issued to one client is sent on every call; without one the gateway is
// either anonymous or about to answer 401, and the step that fails says so.
const auth = key ? { Authorization: `Bearer ${key}` } : {};

let step = 0;
const ok = (message) => console.log(`  ok  ${++step}. ${message}`);

function fail(message, detail) {
  console.error(`  FAIL ${step + 1}. ${message}`);
  if (detail) console.error(`       ${detail}`);
  process.exit(1);
}

async function json(path, init = {}) {
  const response = await fetch(`${url}${path}`, {
    ...init,
    headers: { ...auth, ...(init.headers || {}) },
  });
  const text = await response.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch {
    /* a non-JSON body is itself the diagnosis, reported below */
  }
  return { response, body, text };
}

/**
 * Storage through the gateway, which is what a browser does in backend mode.
 *
 * Written here rather than reusing createPinataAdapter() because that one
 * reads back from public IPFS gateways, and a smoke test that falls through to
 * the wider internet would pass while the deployment's own retrieval path was
 * broken.
 */
function gatewayStorage() {
  return {
    readOnly: false,
    async put(bytes, name = "chunk") {
      const response = await fetch(`${url}/api/storage/pin`, {
        method: "POST",
        headers: {
          ...auth,
          "Content-Type": "application/octet-stream",
          "X-Chunk-Name": encodeURIComponent(name),
        },
        body: bytes,
      });
      if (!response.ok) {
        fail(`pinning "${name}" returned ${response.status}`, await response.text());
      }
      const { cid } = await response.json();
      if (!cid) fail("the pin endpoint returned no cid");
      return cid;
    },
    async get(cid) {
      const response = await fetch(`${url}/api/storage/${cid}`, { headers: auth });
      if (!response.ok) fail(`reading ${cid} returned ${response.status}`);
      return new Uint8Array(await response.arrayBuffer());
    },
  };
}

console.log(`Smoke test against ${url}`);

// 1. Up, and willing to take traffic. /ready rather than /health: a container
//    that is alive but draining should not be declared good.
const deadline = Date.now() + readyTimeoutMs;
let ready = false;
while (Date.now() < deadline) {
  try {
    if ((await fetch(`${url}/ready`)).ok) {
      ready = true;
      break;
    }
  } catch {
    /* not listening yet */
  }
  await new Promise((resolve) => setTimeout(resolve, 500));
}
if (!ready) fail(`/ready did not answer within ${readyTimeoutMs}ms`);
ok("the gateway is ready");

// 2. A real file, chunked and hashed by the same code the browser runs.
const original = randomBytes(size);
const packed = await packFile(original, {
  fileName: "smoke-test.bin",
  mimeType: "application/octet-stream",
  chunkSize,
});
ok(`packed ${size} bytes into ${packed.totalChunks} chunks`);

// 3. Every chunk and the manifest through the service's own storage.
const storage = gatewayStorage();
const locations = await putAll(storage, packed.chunks, { concurrency: 4 });
const manifest = await sealManifest(packed, locations);
const manifestCID = await storage.put(utf8(JSON.stringify(manifest)), "manifest.json");
ok(`pinned ${locations.length} chunks and the manifest (${manifestCID})`);

// 4. The receipt. This is the step that fails when the gateway cannot read
//    back the manifest it was just given, which is a propagation problem in
//    production and a misconfigured backend in a rehearsal.
const record = await json("/api/proofs/record", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    fileHash: packed.fileHashHex,
    merkleRoot: packed.merkleRootHex,
    manifestCID,
    fileSize: packed.fileSize,
    totalChunks: packed.totalChunks,
    encrypted: false,
  }),
});
if (!record.response.ok) {
  fail(`recording the document returned ${record.response.status}`, record.text);
}
const receipt = record.body.receipt;
if (!receipt) fail("no receipt in the response", record.text);
ok(`receipted, verified=${receipt.statement.verified}, kid=${receipt.statement.kid}`);

// 5. The receipt checked the way its holder should check it, against the
//    published key rather than against the service's word.
const published = await json("/api/proofs/key");
if (!published.response.ok) fail(`the key endpoint returned ${published.response.status}`);
const publicJwk = published.body.publicJwk || published.body.key || published.body;
const verdict = await verifyReceipt(receipt, await importPublicKey(publicJwk));
if (!verdict.valid) fail("the receipt does not verify against the published key", verdict.reason);
ok("the receipt verifies against the key the service publishes");

// 6. The bytes come back. Chunks are read through the gateway, so a broken
//    retrieval path fails here rather than in front of a user.
const opened = await openManifest(manifest, null);
const restored = await restoreFile(manifest, opened, (location) => storage.get(location), {
  expectedMerkleRoot: packed.merkleRootHex,
});
if (!equalBytes(restored.bytes, original)) fail("the restored file is not the file that went in");
ok(`restored ${restored.bytes.length} bytes, identical to the original`);

// 7. With an anchoring key: batch, then prove the document is in the batch.
//    Nothing here submits a transaction — the root is returned for the worker
//    to anchor, and the proof is verifiable against it either way.
if (anchorKey) {
  const batch = await fetch(`${url}/api/proofs/batch`, {
    method: "POST",
    headers: { Authorization: `Bearer ${anchorKey}` },
  });
  if (!batch.ok) fail(`building a batch returned ${batch.status}`, await batch.text());
  const built = (await batch.json()).batch;
  if (!built || !built.root) fail("nothing was batched, so there is no root to prove against");
  ok(`batched ${built.size} document(s) under ${built.root}`);

  const inclusion = await json(`/api/proofs/inclusion/${packed.fileHashHex}`);
  if (!inclusion.response.ok) {
    fail(`the inclusion proof returned ${inclusion.response.status}`, inclusion.text);
  }
  /*
   * Against the root the batch call returned, not against inclusion.batchRoot
   * — verifyInBatch falls back to the root carried in the proof itself when
   * it is given nothing, and a proof checked against its own claim is not a
   * check at all. In production this argument is the root read from the
   * contract.
   */
  const proven = await verifyInBatch(inclusion.body, built.root);
  if (!proven.valid) fail("the inclusion proof does not verify against the batch root", proven.reason);
  ok("the inclusion proof verifies against the batch root");
} else {
  console.log("  --  skipping the batch and proof: no --anchor-key given");
}

console.log(`\nAll ${step} step(s) passed.`);
