# 🍪 OREOCHAIN

> **Chunked, encrypted, blockchain-anchored document storage**

OREOCHAIN splits a file into fixed-size chunks, encrypts each chunk under its
own key in the browser, stores the chunks on IPFS, and anchors a single Merkle
root on-chain that commits to every chunk. Retrieval fetches the chunks back,
verifies each one against that root, decrypts them and rebuilds the file.

Nothing readable leaves your browser, and nothing but two hashes and a manifest
pointer goes on-chain.

---

## How it works

### Upload

```
file
 └─ split into 256 KiB chunks
     ├─ SHA-256 each chunk ──► Merkle tree ──► root ─────────────┐
     └─ encrypt each chunk with its own derived key + nonce      │
         └─ upload ciphertext chunks to IPFS ──► one CID each    │
             └─ manifest (chunk table, encrypted) ──► CID ───┐   │
                                                             ▼   ▼
                                    registerDocument(fileHash, merkleRoot,
                                                     manifestCID, chunkCount,
                                                     size, encrypted)
```

### Retrieve

```
file hash ──► findDocument() ──► merkleRoot + manifestCID
                                       │
              fetch manifest ──────────┘
                    │  (root must match the chain, or stop)
              unlock with passphrase ──► chunk table
                    │
              for each chunk:  fetch ──► hash check ──► authenticated decrypt
                    │
              rebuild ──► Merkle root must equal the on-chain root
                    │
                    └──► file
```

Three independent checks run on every chunk, and the reassembled file's hash and
length are checked against the manifest. Any mismatch aborts; partial output is
never returned.

---

## What makes this different from "hash a file and store the hash"

| | Hash-only | OREOCHAIN |
|---|---|---|
| On-chain data | one hash | file hash + Merkle root |
| Prove one part of a file | impossible | `verifyChunk`, on-chain, no download |
| Detect chunk reordering | n/a | yes — position-bound AEAD |
| Confidentiality | none | per-chunk encryption, client-side |
| Parallel fetch | no | yes, chunk by chunk |
| Cost of proving a block of a 10 GB file | download 10 GB | a few hashes |

See [`docs/SECURITY.md`](docs/SECURITY.md) for the full design and threat model,
including an explicit list of what this does **not** protect against.

---

## Cipher suites

Chosen per file and recorded in the manifest, so the format can migrate later
without invalidating stored files.

| Suite | When to use it |
|---|---|
| `aes-256-gcm` | Default. Hardware-accelerated on almost any modern CPU. |
| `xchacha20-poly1305` | Faster in pure software; no cache-timing exposure. |
| `cascade-aes-xchacha` | Both, independent keys. Survives a break of either cipher, at ~2x CPU cost. |

There is deliberately **no custom cipher** here, and the standard ones are used
unmodified. [`docs/SECURITY.md §1`](docs/SECURITY.md) explains why that is a
security decision rather than a lack of ambition.

---

## Tech stack

- **Chain:** any EVM network (Polygon by default)
- **Contract:** Solidity `^0.8.20` — `Contract/ChunkedVerification.sol`
- **Storage:** IPFS via Pinata, behind a swappable adapter
- **Crypto:** WebCrypto (AES-GCM, HKDF, PBKDF2, SHA-256) + `@noble/ciphers`
- **Frontend:** plain ES modules, no build step
- **Wallet:** MetaMask via web3.js v4

---

## Layout

```
Contract/ChunkedVerification.sol   on-chain anchor + on-chain chunk proofs
Contract/Verfication.sol           the original contract, kept for reference

js/core/bytes.js                   encoding helpers
js/core/chunker.js                 chunking + Merkle tree
js/core/crypto.js                  envelope encryption, key derivation
js/core/suites.js                  cipher suite registry
js/core/manifest.js                the pipeline: pack, seal, open, restore
js/storage/ipfs.js                 storage adapters (gateway / Pinata)
js/chunked-app.js                  browser controller for upload + retrieval
js/App.js                          wallet session, chain helpers, admin
js/contract-abi.js                 generated — see `npm run abi`

test/                              81 tests, including EVM cross-checks
docs/SECURITY.md                   design rationale and threat model
```

`js/core/` and `js/storage/` have no DOM or network dependencies, so the same
modules run unchanged in a Node server or a CLI.

---

## Setup

### 1. Install

```bash
git clone https://github.com/nishchal-gond/OREOCHAIN.git
cd OREOCHAIN
npm install
```

### 2. Deploy the contract

Compile and deploy `Contract/ChunkedVerification.sol` (Remix, Hardhat or
Foundry). The deploying wallet becomes the owner. Note the address.

### 3. Configure

```bash
cp js/config.example.js js/config.js
```

Set `contract.address`, `contract.chainId`, and your storage settings.
`js/config.js` is gitignored.

For local development you may set `storage.mode` to `"direct"` and paste a
Pinata JWT — but understand that **any visitor can read that token out of the
page**. For anything deployed, use `"backend"` mode and keep credentials on your
server; the endpoint takes `multipart/form-data` with a `file` field and returns
`{ "cid": "..." }`.

### 4. Authorise an exporter

Open `admin.html` as the contract owner and add the wallet that will register
documents.

### 5. Run

Serve the directory over HTTP — opening the files directly with `file://` will
not work, because ES modules and WebCrypto both require a real origin:

```bash
npx serve .          # or: python3 -m http.server 8080
```

Use HTTPS or `localhost`; WebCrypto is unavailable on other insecure origins.

---

## Usage

**Upload** — `upload.html`: choose a file, set a passphrase (blank publishes it
unencrypted), pick a suite, upload. You get back the file hash, the Merkle root,
the manifest CID and a shareable retrieval link.

**Retrieve** — `retrieve.html`: paste the document hash (or select the file to
compute it), enter the passphrase, retrieve. Every chunk is verified before the
download is offered.

**Verify** — `verify.html`: check whether a file is registered on-chain. No
passphrase and no download needed, so it works for encrypted documents you are
not entitled to read.

**Revoke** — `delete.html`: clears the on-chain record. It does **not** delete
chunks already pinned off-chain.

---

## Tests

```bash
npm test
```

81 tests covering chunk round-trips at every boundary size, Merkle proofs across
every tree shape, tamper/reorder/splice/truncation detection, wrong-passphrase
handling, all three cipher suites, and storage adapter failover.

`test/contract.test.js` compiles the contract and executes it in a real EVM to
confirm the Solidity Merkle implementation matches the JavaScript one
byte-for-byte — if those ever drift, on-chain proofs would silently stop
verifying.

```bash
npm run abi    # regenerate js/contract-abi.js after changing the contract
```

---

## Security

Read [`docs/SECURITY.md`](docs/SECURITY.md) before relying on this. In short:

- Encryption happens in the browser; only ciphertext is uploaded.
- Every chunk gets its own key and nonce; reordering and splicing are detectable.
- **A lost passphrase means lost data.** There is no recovery.
- Revocation does not delete pinned chunks. Treat every upload as permanent.
- This has not been audited by a professional cryptographer. Do not claim it has.

> **Note for anyone who cloned this repository before this change:** earlier
> commits contain a live Pinata API key and secret. They are removed from the
> code but remain in git history, so they must be treated as compromised and
> rotated at the provider.

---

## License

MIT — see [LICENSE](LICENSE).
