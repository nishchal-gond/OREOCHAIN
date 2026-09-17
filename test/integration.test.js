/**
 * End-to-end: the same sequence js/chunked-app.js performs in the browser,
 * against an in-memory store, finishing with a real ABI-encoded contract call.
 *
 * This is the test that would catch an argument-type mistake — a chunk count
 * that does not fit uint32, a hash that is not a valid bytes32 — which would
 * otherwise only surface when a user's transaction reverted.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

import { equalBytes, fromUtf8, randomBytes, utf8 } from "../js/core/bytes.js";
import { openManifest, packFile, restoreFile, sealManifest } from "../js/core/manifest.js";
import { putAll } from "../js/storage/ipfs.js";
import { CHUNKED_VERIFICATION_ABI } from "../js/contract-abi.js";

const require = createRequire(import.meta.url);
const TEST_LIMITS = { minIterations: 1000 };

function memoryIpfs() {
  const blocks = new Map();
  let n = 0;
  return {
    blocks,
    readOnly: false,
    async put(bytes) {
      const cid = `bafkTest${String(n++).padStart(4, "0")}`;
      blocks.set(cid, bytes.slice());
      return cid;
    },
    async get(cid) {
      if (!blocks.has(cid)) throw new Error(`no such block: ${cid}`);
      return blocks.get(cid);
    },
  };
}

/** Everything uploadChunked() does, minus the DOM and the wallet. */
async function upload(data, { fileName, mimeType, passphrase, suite }) {
  const adapter = memoryIpfs();

  const packed = await packFile(data, {
    fileName,
    mimeType,
    passphrase,
    suite,
    chunkSize: 1024,
    iterations: 1000,
  });

  const locations = await putAll(adapter, packed.chunks, { concurrency: 4 });
  const manifest = await sealManifest(packed, locations);
  const manifestCID = await adapter.put(utf8(JSON.stringify(manifest)));

  return { adapter, packed, manifest, manifestCID };
}

/** Everything retrieveChunked() does, given what the chain would return. */
async function retrieve(adapter, onChain, passphrase) {
  const manifest = JSON.parse(fromUtf8(await adapter.get(onChain.manifestCID)));

  assert.equal(
    manifest.merkleRoot.toLowerCase(),
    onChain.merkleRoot.toLowerCase(),
    "manifest root must match the on-chain root"
  );

  const opened = await openManifest(manifest, passphrase, { limits: TEST_LIMITS });
  return restoreFile(manifest, opened, (location) => adapter.get(location), {
    expectedMerkleRoot: onChain.merkleRoot,
    limits: TEST_LIMITS,
  });
}

test("a document survives the full upload and retrieval round trip", async () => {
  const data = randomBytes(9000); // 9 chunks at 1 KiB
  const passphrase = "an-end-to-end-passphrase";

  const { adapter, packed, manifestCID } = await upload(data, {
    fileName: "degree-certificate.pdf",
    mimeType: "application/pdf",
    passphrase,
    suite: "aes-256-gcm",
  });

  // What registerDocument() would have written.
  const onChain = {
    merkleRoot: packed.merkleRootHex,
    manifestCID,
    totalChunks: packed.totalChunks,
    fileSize: packed.fileSize,
    encrypted: true,
  };

  const restored = await retrieve(adapter, onChain, passphrase);

  assert.ok(equalBytes(restored.bytes, data));
  assert.equal(restored.fileName, "degree-certificate.pdf");
  assert.equal(restored.mimeType, "application/pdf");
  assert.equal(packed.totalChunks, 9);
  // 9 chunks + 1 manifest.
  assert.equal(adapter.blocks.size, 10);
});

test("a substituted manifest is rejected against the on-chain root", async () => {
  const passphrase = "pass";
  const genuine = await upload(randomBytes(3000), { fileName: "a.bin", passphrase });
  const forged = await upload(randomBytes(3000), { fileName: "b.bin", passphrase });

  // The attacker swaps in their own manifest but cannot change the chain.
  const tamperedChain = {
    merkleRoot: genuine.packed.merkleRootHex,
    manifestCID: await genuine.adapter.put(
      utf8(JSON.stringify(forged.manifest))
    ),
  };

  await assert.rejects(
    () => retrieve(genuine.adapter, tamperedChain, passphrase),
    /must match the on-chain root/
  );
});

test("the registerDocument arguments encode against the generated ABI", async () => {
  let Web3;
  try {
    ({ Web3 } = require("web3"));
  } catch {
    return; // web3 not installed; the rest of the suite still covers the pipeline
  }

  const { packed, manifestCID } = await upload(randomBytes(5000), {
    fileName: "x.bin",
    passphrase: "pass",
  });

  const web3 = new Web3();
  const contract = new web3.eth.Contract(
    CHUNKED_VERIFICATION_ABI,
    "0x000000000000000000000000000000000000dEaD"
  );

  const encoded = contract.methods
    .registerDocument(
      packed.fileHashHex,
      packed.merkleRootHex,
      manifestCID,
      packed.totalChunks,
      packed.fileSize,
      packed.encrypted
    )
    .encodeABI();

  assert.match(encoded, /^0x[0-9a-f]+$/);
  // The two hashes must appear verbatim in the calldata.
  assert.ok(encoded.includes(packed.fileHashHex.slice(2)), "file hash missing from calldata");
  assert.ok(encoded.includes(packed.merkleRootHex.slice(2)), "merkle root missing from calldata");
});

test("the on-chain integer types are wide enough for real files", async () => {
  // totalChunks is uint32 and fileSize is uint64 in the contract.
  const packed = await packFile(randomBytes(2048), { chunkSize: 1024 });

  assert.ok(Number.isInteger(packed.totalChunks) && packed.totalChunks > 0);
  assert.ok(packed.totalChunks <= 0xffffffff);
  assert.ok(packed.fileSize <= Number.MAX_SAFE_INTEGER);

  // At the 256 KiB default, a uint32 chunk count covers ~1.1 petabytes, and
  // uint64 fileSize covers far more than that — so the chunk count is the
  // binding limit, and it is comfortably beyond any real document.
  const maxBytes = 0xffffffff * 262144;
  assert.ok(maxBytes > 1e15, "uint32 chunk count should cover petabyte-scale files");
  assert.ok(maxBytes < 2 ** 64, "fileSize as uint64 must cover the largest addressable file");
});

test("hashes are always valid bytes32 hex", async () => {
  for (const size of [0, 1, 1024, 5000]) {
    const packed = await packFile(randomBytes(size), { chunkSize: 1024 });
    assert.match(packed.fileHashHex, /^0x[0-9a-f]{64}$/);
    assert.match(packed.merkleRootHex, /^0x[0-9a-f]{64}$/);
  }
});
