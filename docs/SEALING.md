# How a file is chunked and sealed

A short reference for the settings that decide how OREOCHAIN splits a file,
encrypts it, and stretches the passphrase that protects it — plus what changed
in the key-derivation profile recently and why older files still open.

`docs/SECURITY.md` carries the full rationale and threat model. This document
is the settings sheet.

## 1. Chunking

`js/core/chunker.js` splits the plaintext into fixed-size chunks before anything
is encrypted.

| Setting | Value | Where |
|---|---|---|
| Chunk size | 262144 bytes (256 KiB) | `DEFAULT_CHUNK_SIZE`, overridable per call and via `crypto.chunkSize` in config |
| Max chunk size | 64 MiB | `MANIFEST_LIMITS.maxChunkSize` |
| Max chunks per file | 4,000,000 | `MANIFEST_LIMITS.maxTotalChunks` |
| Max file size | 1 TiB | `MANIFEST_LIMITS.maxFileSize` |

256 KiB is the IPFS block size, so a chunk maps onto one block without
re-splitting. An empty file still yields one chunk, so every file has at least
one Merkle leaf.

Each chunk is hashed with SHA-256 and the hashes are folded into a Merkle tree,
whose root is the single 32-byte value anchored on-chain. The tree is
domain-separated — leaves are hashed as `SHA256(0x00 ‖ chunk)` and internal
nodes as `SHA256(0x01 ‖ left ‖ right)` — so a chunk hash can never be replayed
as an internal node. A level with an odd node count promotes that node
unchanged rather than hashing it with itself, which would let two different
chunk lists collide.

## 2. Sealing

Encryption is an envelope, in `js/core/crypto.js`:

```
fileKey        = 32 random bytes                     (per file)
KEK            = Argon2id(passphrase, kdfSalt, ...)  (see §3)
wrappedFileKey = AES-256-GCM(KEK, fileKey)           (travels in the manifest)
chunk key/nonce= HKDF-SHA256(fileKey, fileSalt, "<envelope>/<suite>/chunk/<i>")
```

The passphrase never encrypts data directly — it only wraps the file key, so
changing a passphrase rewraps 60 bytes instead of re-encrypting the whole file.

Every chunk gets its own key and nonce from HKDF, so each key is used exactly
once and the nonce reuse that breaks AES-GCM cannot occur. Each chunk is sealed
with additional authenticated data naming the envelope version, the file hash,
the chunk index and the total chunk count:

```
<envelope-version>|<fileHashHex>|<index>|<totalChunks>
```

Position is therefore part of what the tag covers: reordering, duplicating,
truncating, or splicing in a chunk from another file fails authentication
rather than producing wrong plaintext.

### Cipher suites

Selected per file and recorded in the manifest (`js/core/suites.js`):

| Suite | Overhead | Notes |
|---|---|---|
| `aes-256-gcm` (default) | 16 B | Hardware-accelerated where AES-NI exists; available from WebCrypto alone |
| `xchacha20-poly1305` | 16 B | Faster in pure software, no cache-timing exposure, 192-bit nonce |
| `cascade-aes-xchacha` | 32 B | Both in sequence under independently derived keys; ~2× the CPU cost |

### The manifest

Split into a public header and an encrypted body (`js/core/manifest.js`):

- **Header** — version, KDF parameters and salt, the wrapped file key, the file
  salt, the plaintext file hash, the Merkle root, chunk size, chunk count and
  file size. Readable by anyone; this is what the on-chain record commits to.
- **Body** — file name, MIME type, and the per-chunk table (index, storage
  location, plaintext hash, ciphertext hash, sizes). Encrypted under a key
  derived from the file key, because chunk locations and the file name are
  themselves sensitive.

## 3. Key-derivation settings

`js/core/kdf.js`. New files use Argon2id; PBKDF2-SHA256 is readable but never
written.

| Setting | Value |
|---|---|
| Default KDF | `argon2id` (`DEFAULT_KDF`) |
| Memory | 47104 KiB (46 MiB) |
| Passes | 1 |
| Parallelism | 1 |
| Derived key | 256 bits |
| KDF salt | 16 random bytes, unique per file |
| Legacy PBKDF2 | 600,000 iterations, SHA-256 — read-only |

Argon2id rather than Argon2i or Argon2d: the hybrid RFC 9106 recommends by
default. The implementation is checked against the RFC 9106 §5.3 known-answer
vector in `test/kdf.test.js`, because a subtly wrong KDF still produces
plausible bytes and encrypts happily, with no symptom to notice.

Derivation runs in `js/core/kdf-worker.js` so the page stays responsive. The
worker is terminated after every request rather than pooled — it holds the
passphrase and tens of megabytes of Argon2 state that cannot be scrubbed — and
the derived key is transferred rather than copied. If no `Worker` exists or the
script fails to load, derivation falls back to the calling thread; a worker that
ran and failed, or timed out, propagates instead, since retrying inline would
block for the same reason and fail identically.

### Bounds on parameters read from a manifest

Parameters travel with the file, so whoever serves a manifest picks them. Both
directions are bounded in `js/core/limits.js` and enforced by
`validateKdfParameters`:

| Bound | Value | Stops |
|---|---|---|
| Min Argon2 memory | 19,456 KiB | A manifest setting memory to 8 KiB, making cracking as cheap as before Argon2id, with the file still opening normally |
| Max Argon2 memory | 2 GiB | A manifest demanding 8 GiB to open — denial of service against the reader |
| Argon2 passes | 1–16 | |
| Argon2 parallelism | 1–16 | |
| PBKDF2 iterations | 600,000–50,000,000 | A legacy manifest claiming fewer than the OWASP floor |

`assertArgon2Shape` additionally requires `memoryKiB >= 8 * parallelism`, which
Argon2 needs per lane, turning a cryptic failure inside the hash into a clear
one where the parameters were chosen.

## 4. How the settings changed recently

| PR | Date | Change | Status |
|---|---|---|---|
| [#5](https://github.com/nishchal-gond/OREOCHAIN/pull/5) | 2026-09-17 | Argon2id (m=47104 KiB, t=1, p=1) replaces PBKDF2 for new files; PBKDF2 kept readable; parameter bounds added | Merged |
| [#6](https://github.com/nishchal-gond/OREOCHAIN/pull/6) | 2026-09-18 | Derivation moved into a worker so the ~0.7s no longer freezes the page; `worker-src 'self' blob:` added to the gateway CSP | Merged |
| [#7](https://github.com/nishchal-gond/OREOCHAIN/pull/7) | 2026-09-18 | Raises the default to m=65536 KiB, t=2 — about 2.78× as expensive to attack, ~2.2s to derive | **Open, not merged** |

The ordering was deliberate. PBKDF2 is memory-cheap, so a GPU runs thousands of
guesses in parallel; Argon2id forces each guess to allocate and traverse tens of
megabytes, which is what parallel hardware cannot cheaply multiply. That made
derivation slow enough to freeze the tab, so #6 moved it off the page's thread,
and only then was the stronger profile in #7 affordable — 2.2 seconds on the
main thread would have been unusable jank, worst on the low-end phones where it
is slowest.

The values in §3 are what master ships today. If #7 merges, memory becomes
65536 KiB and passes become 2, and `js/config.example.js`, `docs/SECURITY.md`
and the Readme change with it.

Neither raise helps a genuinely weak passphrase. They multiply the cost per
guess; they do not make `password1` safe. The worker is not a security boundary
either — same origin, same process — so anything that can run script on the page
can still reach the derived key.

## 5. How older files stay readable

Three things keep already-sealed files opening:

1. **The parameters travel with the file.** `sealManifest` writes the full
   parameter set into the manifest header (`header.kdf`, including the salt), and
   `openManifest` derives from what the manifest says, not from the current
   default. Hardcoding the default would strand every file sealed under any
   other setting.
2. **PBKDF2 stays implemented.** `normalizeKdfName` accepts the older spellings
   a pre-Argon2id manifest may carry — `PBKDF2-SHA256`, `pbkdf2`,
   `pbkdf2-hmac-sha256` — and maps them onto one internal name. It is never
   chosen for new files.
3. **There is a test that proves it.** `test/kdf.test.js` round-trips a file
   sealed under the real previous profile (46 MiB, one pass), not a cheap
   stand-in, and asserts that profile differs from the current default so the
   test cannot pass vacuously. The defaults are also pinned by assertion,
   including a floor on `memory × passes`, because a one-character edit to
   either number is invisible in review and would halve the cost of an attack.

This matters more than a usual compatibility guarantee: if a KDF change
stranded a stored file, the file would be destroyed outright. There is no path
to the plaintext without the key.
