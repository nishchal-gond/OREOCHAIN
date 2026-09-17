import test from "node:test";
import assert from "node:assert/strict";

import { equalBytes, randomBytes, toHex } from "../js/core/bytes.js";
import {
  buildMerkleTree,
  hashChunks,
  joinChunks,
  merkleProof,
  merkleRoot,
  splitIntoChunks,
  verifyMerkleProof,
} from "../js/core/chunker.js";

test("splitting and rejoining is lossless for sizes around the chunk boundary", () => {
  const chunkSize = 1024;
  for (const size of [0, 1, 1023, 1024, 1025, 2048, 4097, 65536]) {
    const data = randomBytes(size);
    const chunks = splitIntoChunks(data, chunkSize);
    assert.equal(
      chunks.length,
      Math.max(1, Math.ceil(size / chunkSize)),
      `wrong chunk count for ${size} bytes`
    );
    assert.ok(equalBytes(joinChunks(chunks), data), `round trip failed for ${size} bytes`);
  }
});

test("an empty file still produces one chunk", () => {
  const chunks = splitIntoChunks(new Uint8Array(0), 1024);
  assert.equal(chunks.length, 1);
  assert.equal(chunks[0].length, 0);
});

test("chunkSize must be a positive integer", () => {
  assert.throws(() => splitIntoChunks(randomBytes(10), 0), /positive integer/);
  assert.throws(() => splitIntoChunks(randomBytes(10), -1), /positive integer/);
  assert.throws(() => splitIntoChunks(randomBytes(10), 1.5), /positive integer/);
});

test("the Merkle root changes if any single chunk changes", async () => {
  const chunks = [randomBytes(64), randomBytes(64), randomBytes(64), randomBytes(64)];
  const before = await merkleRoot(await hashChunks(chunks));

  const tampered = chunks.map((c) => c.slice());
  tampered[2][0] ^= 0x01; // flip one bit in one chunk
  const after = await merkleRoot(await hashChunks(tampered));

  assert.notEqual(toHex(before), toHex(after));
});

test("the Merkle root changes if chunks are reordered", async () => {
  const chunks = [randomBytes(64), randomBytes(64), randomBytes(64)];
  const before = await merkleRoot(await hashChunks(chunks));
  const after = await merkleRoot(await hashChunks([chunks[1], chunks[0], chunks[2]]));
  assert.notEqual(toHex(before), toHex(after));
});

test("leaves and internal nodes are domain-separated", async () => {
  // A leaf hash must never equal the internal-node hash of the same bytes,
  // otherwise a chunk could be substituted for a subtree.
  const chunks = [randomBytes(32), randomBytes(32)];
  const leaves = await hashChunks(chunks);
  const levels = await buildMerkleTree(leaves);
  const root = levels[1][0];
  for (const leaf of leaves) {
    assert.notEqual(toHex(leaf), toHex(root));
  }
});

test("Merkle proofs verify for every chunk, at every tree shape", async () => {
  for (const count of [1, 2, 3, 4, 5, 7, 8, 9, 16, 17]) {
    const chunks = Array.from({ length: count }, () => randomBytes(48));
    const leaves = await hashChunks(chunks);
    const root = await merkleRoot(leaves);

    for (let i = 0; i < count; i++) {
      const proof = await merkleProof(leaves, i);
      assert.ok(
        await verifyMerkleProof(leaves[i], proof, root),
        `proof failed for chunk ${i} of ${count}`
      );
    }
  }
});

test("a proof for the wrong chunk is rejected", async () => {
  const chunks = Array.from({ length: 8 }, () => randomBytes(48));
  const leaves = await hashChunks(chunks);
  const root = await merkleRoot(leaves);

  const proof = await merkleProof(leaves, 3);
  assert.equal(await verifyMerkleProof(leaves[4], proof, root), false);
});

test("a forged leaf is rejected", async () => {
  const chunks = Array.from({ length: 4 }, () => randomBytes(48));
  const leaves = await hashChunks(chunks);
  const root = await merkleRoot(leaves);

  const proof = await merkleProof(leaves, 1);
  const forged = leaves[1].slice();
  forged[0] ^= 0xff;
  assert.equal(await verifyMerkleProof(forged, proof, root), false);
});

test("proof index must be in range", async () => {
  const leaves = await hashChunks([randomBytes(10), randomBytes(10)]);
  await assert.rejects(() => merkleProof(leaves, 2), /out of range/);
  await assert.rejects(() => merkleProof(leaves, -1), /out of range/);
});
