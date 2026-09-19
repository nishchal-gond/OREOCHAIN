<div align="center">

# OREOCHAIN

**Verifiable storage infrastructure.**

Files are split, encrypted and committed to cryptographically — so any part of a
document can prove itself, years later, without revealing the rest.

[Architecture](#architecture) · [How it works](#how-it-works) · [Quick start](#quick-start) · [Gateway](#the-gateway) · [Security](docs/SECURITY.md)

</div>

---

## What this is

Most "blockchain document storage" stores a hash of a file and calls it proof.
That answers exactly one question — *is this byte-for-byte the file I registered?*
— and it answers it only if you already hold the whole file in the clear.

OREOCHAIN is built around a different primitive. A file becomes a **tree of
independently encrypted, independently verifiable chunks**, and what goes on the
ledger is the root of that tree. From that single 32-byte value you can prove
any individual chunk belongs to the registered document, without downloading it,
decrypting it, or disclosing anything else.

That shift is what turns a verification demo into infrastructure:

|  | Hash-and-store | OREOCHAIN |
|---|---|---|
| On-chain footprint | one hash | file hash + Merkle root |
| Prove one section of a file | impossible | one proof, a few hundred bytes |
| Cost of proving part of a 10 GB file | download 10 GB | a handful of hashes |
| Confidentiality | none | per-chunk encryption, client-side |
| Reordering / splicing detection | none | fails to decrypt |
| Cost per document | one transaction | amortised across a batch |
| User needs a wallet | yes | **no** |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  BROWSER                                                            │
│  splits · encrypts · signs nothing away                             │
│                                                                     │
│  file ─► 256 KB chunks ─► per-chunk key ─► ciphertext               │
│              │                                                      │
│              └─► SHA-256 each ─► Merkle tree ─► root                │
└──────────────────────────┬──────────────────────────────────────────┘
                           │  ciphertext only
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  GATEWAY            holds the pinning credential, never a key       │
│  authenticates · meters · issues signed receipts · batches anchors  │
└──────────────┬────────────────────────────────┬─────────────────────┘
               │                                │
               ▼                                ▼
      ┌────────────────┐            ┌──────────────────────────┐
      │  IPFS storage  │            │  Ledger                  │
      │  chunk blocks  │            │  one root per batch      │
      └────────────────┘            └──────────────────────────┘
```

The passphrase and the file key never leave the browser. The gateway handles
ciphertext exclusively — **a total compromise of our servers exposes no
documents**, only file sizes and timing.

---

## How it works

### 1. Chunking and commitment

A file is split into 256 KB chunks. Each chunk is hashed and the hashes are
folded into a Merkle tree:

```
      chunk₀   chunk₁   chunk₂   chunk₃
        │        │        │        │
      hash₀    hash₁    hash₂    hash₃      leaf = SHA-256(0x00 ‖ chunk)
        └───┬────┘        └───┬────┘
          node₀              node₁          node = SHA-256(0x01 ‖ L ‖ R)
            └────────┬─────────┘
                   root                     ← this is what gets anchored
```

The `0x00`/`0x01` prefixes are not decoration. Without them a chunk hash could
be presented as an internal node and an entire subtree swapped for a single
chunk — the classic second-preimage attack on naive Merkle trees.

### 2. Encryption

Envelope encryption, with one key per chunk:

```
passphrase ──Argon2id──► KEK ──wraps──► file key ──HKDF──► key₀, key₁, key₂ …
   (memory-hard)                                            nonce₀, nonce₁ …
```

The passphrase step is memory-hard on purpose. The wrapped file key travels in
the manifest, so anyone who fetches one can guess passphrases offline at
hardware speed — the cost of a single guess is the whole defence, and it is the
parameter an attacker cannot buy their way around. Argon2id forces every guess
to allocate and traverse <!-- kdf:memory -->64 MiB twice over<!-- /kdf:memory -->, which is exactly what a GPU or ASIC
cannot cheaply multiply. PBKDF2, which needs almost no memory, remains readable
so files sealed before this change still open.

That derivation runs in a dedicated worker — a `Worker` in the browser, a
`worker_threads` thread on Node — so the <!-- kdf:cost -->~2.2s<!-- /kdf:cost --> it costs does not
freeze the page or stall a server. Where no worker is available it falls back to the calling
thread — slower and visibly so, but still correct.

Two properties follow that a single-key design cannot offer:

- **Blast radius.** Compromising one chunk's key reveals that chunk and nothing
  else. There is no master key whose loss decrypts an archive.
- **Nonce reuse becomes impossible.** Reusing a nonce under one key destroys
  AES-GCM completely — it leaks the authentication subkey and permits arbitrary
  forgery. Here every key is used exactly once, so the condition cannot arise
  regardless of file size or how many files share a passphrase.

Each chunk's authentication tag also covers *where it sits*:

```
AAD = version ‖ fileHash ‖ chunkIndex ‖ totalChunks
```

So reordering chunks, duplicating one, truncating the file, or splicing in a
chunk from a different file all **fail to decrypt** rather than quietly
producing the wrong document. An attacker who cannot read your contract still
cannot silently reshuffle its pages.

### 3. Anchoring — without wallets or gas

Registering each document on-chain individually is fatal to a platform twice
over: cost grows linearly with usage, and every user needs a wallet, an
extension and a token balance. That is not a fee problem, it is an adoption wall.

So the same Merkle construction is applied one level up:

```
doc₁   doc₂   doc₃   …   doc₁₀₀₀₀        ← a day of uploads
  └──┬───┘      └──┬───┘
     └──────┬──────┘
        batch root                        ← ONE transaction
```

Users receive a **signed receipt** the instant their file is stored — no wallet,
no gas, no waiting for a block. Batches anchor on the operator's schedule, and
every document keeps an independent inclusion proof of a few hundred bytes
regardless of batch size.

Cost per document falls as volume rises. That is the opposite of the usual
blockchain scaling curve, and it is what makes the economics work.

| | Per-document | Batched (10,000) |
|---|---|---|
| Transactions | 10,000 | 1 |
| User needs a wallet | yes | no |
| Proof size | — | ~14 sibling hashes |
| Marginal cost trend | flat | **falls with scale** |

### 4. Verification

Three independent layers run on every chunk retrieved:

1. **Stored-hash check** — the bytes match the recorded ciphertext hash. Cheap,
   pre-decryption, rejects altered blocks before spending CPU on them.
2. **Authenticated decryption** — the chunk opens under its position-bound key,
   or it does not open at all.
3. **Merkle reconstruction** — the rebuilt root must equal the root anchored
   publicly. This is the step that ties bytes in your hand to the ledger.

Any mismatch aborts. Partial or best-effort output is never returned.

---

## Cipher suites

Selected per file and recorded in the manifest, so the format can migrate
without invalidating anything already stored.

| Suite | Use it when |
|---|---|
| `aes-256-gcm` | Default. Hardware-accelerated on essentially any modern CPU. |
| `xchacha20-poly1305` | Faster in pure software; no cache-timing exposure. |
| `cascade-aes-xchacha` | Both, independent keys. Survives a break of *either* cipher, at ~2× CPU. |

There is deliberately **no custom cipher here**, and the standard ones are used
unmodified. [`docs/SECURITY.md` §1](docs/SECURITY.md) explains why that is a
security decision rather than a lack of ambition — in short, a cipher's strength
is the public cryptanalysis it has survived, and a new one has survived none.

The migration path is the real engineering win. A proprietary cipher would have
nowhere to migrate *to*.

---

## Quick start

```bash
git clone https://github.com/nishchal-gond/OREOCHAIN.git
cd OREOCHAIN
npm install            # also what puts web3.min.js where the pages load it from

# Everything in memory, no accounts, no chain — just to see it work
npm run dev            # http://127.0.0.1:8787
```

For a real deployment:

```bash
# 1. Deploy Contract/ChunkedVerification.sol (Remix, Hardhat or Foundry).
#    The deploying wallet becomes the owner.

# 2. Point the frontend at it
cp js/config.example.js js/config.js     # gitignored; set contract.address

# 3. Generate credentials for the gateway
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"   # API key
node scripts/generate-receipt-key.mjs                                      # receipt key

# 4. Run it
PINATA_JWT=… OREOCHAIN_API_KEYS=… OREOCHAIN_RECEIPT_KEY=… npm start
```

Serve over HTTPS or `localhost` — WebCrypto is unavailable on other insecure
origins, and every guarantee above rests on the page's integrity.

---

## The gateway

`server/` is a zero-dependency Node service that sits between your users and
your storage provider.

A browser cannot keep a secret: any pinning credential shipped to the page is
readable by every visitor. The gateway holds it instead, and adds what only a
server can enforce — API key authentication, per-key rate limiting, request
bodies capped as bytes arrive, and a single audit point where every upload is
logged.

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /health` | — | Liveness |
| `POST /api/storage/pin` | key | Store one encrypted chunk |
| `GET /api/storage/<cid>` | key | Retrieve one chunk |
| `POST /api/proofs/record` | key | Issue a signed receipt, queue for anchoring |
| `POST /api/proofs/batch` | key | Build a batch, return the root to anchor |
| `GET /api/proofs/key` | **public** | Receipt verification key |
| `GET /api/proofs/inclusion/<hash>` | **public** | Inclusion proof for a document |

Verification endpoints are deliberately public. A court, an employer or a
regulator checking a certificate has no account here and should not need one.

See [`server/README.md`](server/README.md) for configuration, deployment notes,
and an honest list of what it does not do yet.

---

## Layout

```
Contract/ChunkedVerification.sol   on-chain anchor, chunk proofs, batch anchors

js/core/chunker.js                 chunking + Merkle tree
js/core/crypto.js                  envelope encryption, key derivation
js/core/suites.js                  cipher suite registry
js/core/manifest.js                the pipeline: pack, seal, open, restore, stream
js/core/anchor.js                  batch trees and inclusion proofs
js/core/kdf.js                     Argon2id passphrase stretching (+ legacy PBKDF2)
js/core/kdf-worker.js              runs derivation off the page's thread
js/core/receipt.js                 signed receipts
js/core/validate.js                strict validation of untrusted manifests
js/core/limits.js                  resource limits, all caller-overridable
js/storage/ipfs.js                 storage adapters, retry/backoff, resume

server/gateway.mjs                 HTTP handler: auth, limits, routing
server/proofs.mjs                  receipts + batch queue
server/storage.mjs                 server-side pinning; holds the credential
server/auth.mjs                    constant-time API key checks
server/ratelimit.mjs               per-key token bucket

test/                              435 tests, including EVM cross-checks
docs/SECURITY.md                   design rationale and threat model
docs/SEALING.md                    chunking, sealing and key-derivation settings
```

`js/core/` and `js/storage/` have no DOM and no network dependency, so the same
modules run unchanged in the browser, in the gateway, or in a CLI. There is
exactly one implementation of the chunking and the cryptography — client and
server cannot drift into disagreeing about what a valid file is.

---

## Robustness

Chunking multiplies every per-request failure by the number of chunks. A
400-chunk upload at a 1% failure rate fails outright 98% of the time without
retries. So the network layer assumes failure is the normal case:

- **Retry with exponential backoff and full jitter** on transient failures;
  permanent ones (400/401/403/404) are never retried. Without jitter, chunks
  that fail together retry together and recreate the burst that caused it.
- **Gateway failover** — each read gateway is retried, then the next is tried.
- **Resumable uploads** — hand back the locations from an interrupted run and
  only the missing chunks upload again.
- **Cancellation** — every network path accepts an `AbortSignal`.
- **Streaming retrieval** — `restoreFileStream()` yields verified chunks in
  order with bounded look-ahead, so a server can pipe a multi-gigabyte file
  without buffering it. Verification is identical to the buffered path.

Manifests are treated as hostile input, because whoever can serve a CID controls
every field in one before a single cryptographic check runs:

| Hostile field | Effect without validation | Defence |
|---|---|---|
| `totalChunks: 4e9` | restore loop hangs | bounded chunk count |
| `fileSize: 1e15` | allocation kills the process | bounded size + consistency check |
| `kdf.memoryKiB: 8` | passphrase cracking becomes cheap again | floor of 19,456 KiB enforced |
| `__proto__` | prototype pollution | rejected outright, not sanitised |
| `location: "../../etc/passwd"` | traversal / request forgery | strict pattern |

---

## Tests

```bash
npm test           # 435 tests
npm run test:e2e   # the pages driven in a real browser (needs Playwright)
npm run abi        # regenerate js/contract-abi.js after changing the contract
npm run vendor     # regenerate js/vendor/noble after changing a @noble version
npm run kdf-docs   # rewrite the key-derivation numbers in the docs from js/core/kdf.js
npm run test-count # rewrite the counts above from a real run of the suite
```

Coverage includes the RFC 9106 known-answer vector for Argon2id, the derivation
worker executed in a real thread, chunk round-trips at every boundary size, Merkle proofs across
every tree shape, tamper/reorder/splice/truncation detection, all three cipher
suites, retry and resume behaviour, hostile manifests, streaming and
cancellation, batch anchoring and receipt forgery, and the gateway's auth, rate
limiting, body caps and traversal defences.

Two test files matter more than the rest:

- **`test/contract.test.js`** compiles the contract and executes it in a real
  EVM, confirming the Solidity and JavaScript Merkle implementations agree
  byte-for-byte. A silent divergence there would break on-chain proofs *only in
  production*.
- **`test/gateway.test.js`** runs against a real HTTP server on an ephemeral
  port, because body caps and traversal defences are properties of actual socket
  handling, not of a mocked object.
- **`test/e2e/browser.test.js`** opens the shipped pages in Chromium, served by
  a real gateway, and walks the path a user walks: choose a file, seal it,
  upload every chunk, register it on the compiled contract, then fetch it back,
  verify it against the anchored Merkle root and compare the downloaded bytes
  with the original. It covers what only a browser can fail at — module
  resolution, the Content-Security-Policy the gateway sends, the wallet round
  trip — and every one of those had a live bug when it was written. It needs
  Playwright, so it runs on its own (`npm run test:e2e`) and skips when
  Playwright is absent:

  ```bash
  npm i --no-save playwright && npx playwright install chromium
  npm run test:e2e
  ```

---

## Security

Read [`docs/SECURITY.md`](docs/SECURITY.md) before relying on this. The short
version:

- Encryption happens in the browser. Only ciphertext is uploaded.
- Every chunk has its own key and nonce; reordering and splicing are detectable.
- **A lost passphrase means lost data.** There is no recovery and no backdoor.
- Revocation clears the on-chain record. It does **not** delete pinned chunks.
  Treat every upload as permanent.
- **Not audited.** The composition uses standard primitives and is extensively
  tested, but no professional cryptographer has reviewed it. Do not claim
  otherwise.

`docs/SECURITY.md` §4 carries the full list of what this does not defend
against. Publishing that list is the point — a security system whose limits are
undocumented is a security system nobody can evaluate.

> **If you cloned this repository before this change:** earlier commits contain
> a live Pinata API key and secret. They are gone from the code but remain in
> git history, so treat them as compromised and rotate them at the provider.

---

## Roadmap

In priority order, with reasoning rather than dates:

1. **Automated batch submission**, so anchoring needs no operator action.
2. **Multi-recipient key wrapping** — share a document without sharing a
   passphrase.
3. **Hybrid post-quantum key wrapping** (ML-KEM alongside the classical wrap)
   for records that must stay confidential for decades. "Harvest now, decrypt
   later" is a real concern for long-lived documents.
4. **Replication across independent pinning providers**, with on-chain
   challenges proving a provider still holds a given block.
5. **A professional cryptographic review**, before this protects anything that
   matters.

---

## License

MIT — see [LICENSE](LICENSE).
