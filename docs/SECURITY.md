# OREOCHAIN security design

This document describes what the system protects, how, and — just as importantly
— what it does not protect against. Read the limitations section before
describing OREOCHAIN as secure to anyone.

---

## 1. Why there is no new cipher here

A reasonable instinct when building a security product is to invent a new
encryption algorithm, on the theory that something nobody has seen cannot be
broken. In cryptography this instinct is backwards, and it is worth being
precise about why.

The security of AES is not a property of its design document. It is the
accumulated result of roughly twenty-five years of public cryptanalysis: every
academic group with an interest has attacked it, published what they found, and
failed to break the full-round cipher. That body of failed attacks *is* the
evidence. ChaCha20 has a comparable, somewhat shorter record.

A cipher written this month has none of that. It is not "unbroken" — it is
unexamined, which is a different thing that looks identical from the inside.
Historically, new ciphers from non-specialists are broken quickly once anyone
looks, and the author is the person least able to find the flaw, because the
same blind spot that produced it hides it.

This applies to *modifying* a standard cipher too. Changing AES's round count,
S-box or key schedule does not produce "AES, improved". It produces a new,
unanalyzed cipher wearing a trusted name — the worst of both worlds, because it
invites the trust without earning it.

So OREOCHAIN uses standard primitives, from the platform's own implementation:

| Purpose | Primitive |
|---|---|
| Chunk encryption | AES-256-GCM, XChaCha20-Poly1305, or both |
| Key derivation | HKDF-SHA256 |
| Passphrase stretching | PBKDF2-HMAC-SHA256, 600,000 iterations |
| Content hashing | SHA-256 |
| Integrity commitment | Merkle tree, domain-separated |

**The engineering novelty is in the composition, not the primitives.** That is
where real improvement is available, and the rest of this document is about it.

---

## 2. What is actually new here

### 2.1 Per-chunk key isolation

Most "encrypt the file then store it" systems use one key and one nonce for the
whole object. OREOCHAIN derives an independent key *and* nonce for every chunk:

```
chunkKey(i), chunkNonce(i) = HKDF-SHA256(
    ikm  = fileKey,
    salt = fileSalt,
    info = "oreochain-envelope-v1/<suite>/chunk/<i>"
)
```

Two consequences:

1. **Blast radius.** Recovering one chunk's key — through a memory disclosure, a
   side channel, a bad random number on one device — reveals that chunk and
   nothing else. There is no single key whose loss decrypts the archive.

2. **Nonce reuse becomes structurally impossible.** Reusing a nonce under the
   same key is the failure that destroys AES-GCM completely: it leaks the
   authentication subkey and lets an attacker forge arbitrary messages. Because
   every chunk key here is used for exactly one encryption, the condition cannot
   arise, no matter how many chunks a file has or how many files share a
   passphrase.

### 2.2 Position-bound authenticated encryption

Every chunk's AEAD tag covers additional authenticated data naming the file, the
chunk's index and the total chunk count:

```
AAD = "oreochain-envelope-v1|<fileHash>|<index>|<totalChunks>"
```

The reader reconstructs this independently from the manifest. That converts a
whole class of attacks from "silently succeeds" into "fails to decrypt":

| Attack | Result |
|---|---|
| Reorder two chunks | Both fail authentication |
| Duplicate a chunk | Fails at the duplicated position |
| Truncate the file and adjust the count | Every chunk fails |
| Splice in a chunk from another file | Fails |

Without position binding, an attacker who cannot read your data can still
*rearrange* it — reordering the pages of a contract, say — and the file still
decrypts cleanly. Here it does not decrypt at all.

### 2.3 Merkle commitment anchored on-chain

Chunk hashes are folded into a Merkle tree whose root goes on-chain. The tree is
domain-separated:

```
leaf(chunk)       = SHA-256(0x00 || chunk)
node(left, right) = SHA-256(0x01 || left || right)
```

The `0x00`/`0x01` prefixes prevent an attacker from presenting a chunk hash as
an internal node and substituting a whole subtree for a single chunk — the
standard second-preimage attack on naive Merkle trees. A level with an odd
number of nodes promotes its last node unchanged rather than hashing it against
a copy of itself, which would make two different chunk lists collide.

This buys something a plain file hash cannot: **per-chunk proof**. One 256 KiB
block can be proven to belong to a registered document, on-chain, via
`verifyChunk`, without downloading, decrypting or disclosing the rest. Proving a
block of a 10 GB file costs the same as proving a block of a 1 MB file.

`test/contract.test.js` compiles the contract and runs it in a real EVM to check
the Solidity tree and the JavaScript tree produce identical roots for every tree
shape. A silent divergence there would break proofs only in production.

### 2.4 Cipher agility and cascade

Three suites are available, selected per file and recorded in the manifest:

- **`aes-256-gcm`** — hardware-accelerated wherever AES-NI exists, which is most
  machines. Default.
- **`xchacha20-poly1305`** — faster in pure software (older phones, embedded
  targets, WASM), and free of the cache-timing side channels that table-driven
  AES implementations exhibit. Its 192-bit nonce makes random nonces safe at any
  volume.
- **`cascade-aes-xchacha`** — inner AES-256-GCM, then outer XChaCha20-Poly1305,
  under independently derived keys. Plaintext stays sealed unless **both**
  ciphers are broken. Roughly double the CPU cost.

Agility is the part that matters long-term. Because the suite is recorded per
file, the format can adopt a post-quantum AEAD later without invalidating
anything already stored. **A format that can migrate is worth more than any
single cipher choice** — and it is the improvement a bespoke cipher actively
prevents, since a proprietary format has nowhere to migrate to.

The cascade is a genuine hedge, but be honest about the threat it addresses: a
catastrophic break of AES-256, which no serious cryptographer expects. It is the
right default for data that must stay secret for decades; it is overkill for a
routine document.

### 2.5 Envelope encryption

The passphrase never encrypts data. It derives a key-encryption key that wraps a
random per-file key:

```
fileKey        = 32 random bytes
KEK            = PBKDF2-SHA256(passphrase, kdfSalt, 600000)
wrappedFileKey = AES-256-GCM(KEK, fileKey)
```

Changing a passphrase rewraps ~60 bytes instead of re-encrypting the archive.
Two uploads of the same document produce completely different ciphertext (fresh
random file key), so identical documents are not linkable in storage — while the
public file hash and Merkle root still match, so the chain recognises them as
the same document.

### 2.6 Manifest confidentiality

The manifest splits into a public header and an encrypted body:

- **Header** (public): version, KDF parameters, wrapped key, file hash, Merkle
  root, chunk count, size. This is what the chain commits to.
- **Body** (encrypted): file name, MIME type, and the chunk table — index,
  storage location, plaintext hash, ciphertext hash, size.

Chunk locations and the file name are themselves sensitive. `payroll-2026.pdf`
leaks its contents from the name alone, and an enumerable chunk list tells an
observer exactly which blocks to target. Without the passphrase, neither is
visible.

---

## 3. Verification layers on retrieval

Each downloaded chunk passes three independent checks:

1. **Stored-hash check** — the bytes match the ciphertext hash in the manifest.
   Cheap, runs before any crypto, and rejects corrupted or substituted blocks
   without spending CPU on them.
2. **AEAD authentication** — the chunk decrypts under its position-bound key, or
   it does not decrypt at all.
3. **Merkle reconstruction** — the reassembled chunk hashes must rebuild the
   root recorded on-chain. This is the check that ties the bytes in your hands to
   the blockchain record.

Then the reassembled file's SHA-256 and length are compared to the manifest.
Any mismatch raises; partial or "best effort" output is never returned.

---

## 4. Threat model

### Defended

| Threat | Mechanism |
|---|---|
| Storage provider alters stored bytes | Stored-hash check, AEAD tag, Merkle root |
| Storage provider reads documents | Client-side encryption; only ciphertext is uploaded |
| Chunks reordered, duplicated, dropped or spliced | Position-bound AAD |
| Manifest substituted | On-chain Merkle root compared against the manifest |
| Document backdated or its history disputed | On-chain block number and timestamp |
| Unauthorised registration | `onlyExporter`, controlled by the contract owner |
| One exporter revoking another's record | `revokeDocument` checks the registering address |
| Chunk hash replayed as a subtree | Domain-separated Merkle tree |
| Correlating two uploads of the same file in storage | Random per-file key |

### Not defended

These are real limitations. State them plainly rather than discovering them in
an audit.

- **A lost passphrase means lost data.** There is no recovery, no reset and no
  backdoor. That is the design, and it is the most common way users lose files.
- **A compromised browser or device defeats everything.** Encryption happens in
  the page; malware or a malicious extension sees plaintext and the passphrase.
- **Weak passphrases fall to offline attack.** PBKDF2 raises the cost per guess,
  it does not make a six-character passphrase safe. The wrapped key is public.
- **PBKDF2 is memory-cheap**, so a GPU or ASIC attacker gets far more guesses per
  dollar than your CPU does. Argon2id is the correct primitive; WebCrypto does
  not expose it, so adopting it needs an audited WASM build. This is the single
  most valuable upgrade to the current design — see below.
- **Revocation does not delete anything.** `revokeDocument` clears the on-chain
  record. Chunks already pinned remain wherever they were pinned. Treat any
  upload as permanent.
- **Availability depends on pinning.** If nothing pins the chunks, the chain
  still says "registered" while the bytes are gone. Chunked storage helps
  (chunks can be re-pinned and replicated independently) but guarantees nothing
  on its own.
- **Chunk sizes and counts leak metadata.** An observer sees roughly how large a
  file is and when it was registered. There is no padding.
- **Not formally audited.** The composition is built from standard primitives
  and is tested, but it has not been reviewed by a professional cryptographer.
  Do not describe it as audited.
- **The contract has not been audited either.** It is deliberately small and
  uses no external calls, but the same caveat applies before it holds anything
  valuable.

---

## 5. Operational rules

1. **Never put credentials in client-side JavaScript.** An earlier version of
   this project embedded a live Pinata API key and secret in `js/App.js`, where
   every visitor could read them. Credentials belong on a server, reached
   through the `backend` storage mode. Anything committed to git must be
   treated as public forever — rotate it, don't just delete it.
2. **Keep `js/config.js` out of version control.** It is gitignored. Only
   `js/config.example.js` is committed.
3. **Do not lower `iterations` below 600,000.** It is the OWASP floor for
   PBKDF2-HMAC-SHA256 and the only thing standing between a weak passphrase and
   an offline attacker.
4. **Deploy the contract yourself and set the owner to a wallet you control.**
   The owner controls the exporter allowlist.
5. **Serve over HTTPS.** WebCrypto is unavailable on insecure origins, and the
   page's integrity is what everything else rests on.

---

## 6. Roadmap, in priority order

1. **Argon2id for passphrase stretching** (via an audited WASM build), keeping
   PBKDF2 for backward compatibility. Highest-value change: it directly
   addresses the weakest link, which is human-chosen passphrases.
2. **A backend pinning proxy** so credentials leave the browser entirely, plus
   rate limiting and per-user quotas.
3. **Multi-recipient key wrapping** — wrap the file key to several public keys so
   a document can be shared without sharing a passphrase.
4. **Hybrid post-quantum key wrapping** (ML-KEM alongside the classical wrap) for
   documents that must stay confidential for decades. "Harvest now, decrypt
   later" is a real concern for long-lived records.
5. **Replication across independent pinning providers**, with on-chain challenges
   using `verifyChunk` to prove a provider still holds a given block.
6. **A professional cryptographic review** before this protects anything that
   matters.
