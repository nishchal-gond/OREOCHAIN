# OREOCHAIN gateway

A small HTTP service that sits between your users and your pinning provider.

```
browser (encrypts)  ──►  gateway (authenticates, meters)  ──►  IPFS / Pinata
       │                        │
       │                        └── holds the pinning credential
       └── holds the passphrase and the file key
```

**The gateway never sees plaintext.** Chunks arrive already encrypted, and no
passphrase or file key is ever sent to it. A full compromise of this server
exposes ciphertext, chunk sizes and traffic timing — not documents. That
property is what makes it safe to run this on someone else's behalf, and it is
worth protecting in any change you make here.

## Why it exists

A browser cannot keep a secret. Any pinning credential shipped to the page is
readable by every visitor. The gateway moves that credential server-side and
adds the things only a server can enforce:

- authentication, so uploads are attributable
- rate limiting and burst control, so one client cannot exhaust your quota
- request size caps, so a client cannot exhaust your memory
- a single audit point where every upload is logged

## Run it

```bash
# Generate an API key for a client
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

PINATA_JWT="your-pinata-jwt" \
OREOCHAIN_API_KEYS="the-key-you-just-generated" \
npm start
```

For local development with no pinning account, `OREOCHAIN_STORAGE=memory` keeps
everything in process memory:

```bash
OREOCHAIN_STORAGE=memory OREOCHAIN_API_KEYS="$(node -e "console.log('k'.repeat(48))")" npm start
```

The process refuses to start if it is misconfigured — no API keys, no pinning
credential, a wildcard CORS origin — rather than running in a state you did not
intend.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8787` | Listen port |
| `HOST` | `127.0.0.1` | Listen address. Keep it loopback behind a reverse proxy. |
| `OREOCHAIN_API_KEYS` | — | Comma-separated client keys, each ≥32 characters |
| `OREOCHAIN_ALLOW_ANONYMOUS` | `false` | Disable auth entirely. Only for a genuinely public gateway. |
| `PINATA_JWT` | — | Pinning credential. Never leaves this process. |
| `OREOCHAIN_STORAGE` | `pinata` | `memory` for local testing |
| `OREOCHAIN_MAX_CHUNK_BYTES` | `1048576` | Hard cap per request body |
| `OREOCHAIN_MAX_CONCURRENT_UPLOADS` | `32` | Request bodies buffered at once, process-wide. Past this, 503. |
| `OREOCHAIN_RATE_LIMIT_PER_MINUTE` | `600` | Sustained rate per key |
| `OREOCHAIN_RATE_LIMIT_BURST` | `120` | Burst allowance per key |
| `OREOCHAIN_ALLOWED_ORIGINS` | none | Browser origins permitted via CORS. `*` is refused. |
| `OREOCHAIN_READ_TIMEOUT_MS` | `30000` | Request body timeout |
| `OREOCHAIN_UPSTREAM_TIMEOUT_MS` | `60000` | Timeout for calls to the pinning service |
| `OREOCHAIN_SERVE_STATIC` | `false` | Also serve the frontend, so there is no CORS at all |
| `OREOCHAIN_RECEIPT_KEY` | — | Receipt signing key pair. Generate with `node scripts/generate-receipt-key.mjs`. |
| `OREOCHAIN_DB_PATH` | `./oreochain-proofs.log` | Recorded documents and anchored batches. `:memory:` for tests only. |

## API

### `GET /health`

Unauthenticated liveness check.

```json
{ "status": "ok", "storage": "pinata", "uptime": 1234.5 }
```

### `POST /api/storage/pin`

Stores one encrypted chunk. The body is **raw bytes**, not multipart — the
gateway needs no multipart parser (a perennial source of parsing bugs) and the
body size is trivially bounded.

```
Authorization: Bearer <api-key>
Content-Type: application/octet-stream
X-Chunk-Name: chunk-000042        (optional, sanitised, for upstream metadata)
```

```json
{ "cid": "bafy…" }
```

### `GET /api/storage/<cid>`

Returns the stored bytes. The CID is validated against a strict alphanumeric
pattern before it is used, so it can never traverse a path or switch protocol.

### `POST /api/proofs/record`

Issues a signed receipt for a stored document and queues it for the next batch
anchor. This is what lets a user register a document with no wallet and no gas.

```json
{ "fileHash": "0x…", "merkleRoot": "0x…", "manifestCID": "bafy…",
  "fileSize": 4096, "totalChunks": 1, "encrypted": true, "suite": "aes-256-gcm" }
```

### `POST /api/proofs/batch`

Builds a batch from everything pending and returns the Merkle root for the
operator to anchor on-chain, plus the list of documents it covers.

Submission is deliberately **not** done here: it needs a funded key, and a key
with spending power does not belong in the same process that accepts public
uploads. Take the root and submit it with `anchorBatch(root, size, uri)` from
wherever you keep that key.

### `GET /api/proofs/key` — public

The receipt verification key, as a JWK, plus its key id.

### `GET /api/proofs/inclusion/<fileHash>` — public

The inclusion proof for one document, checkable against the anchored batch root.

Both of these are unauthenticated on purpose: verifying someone else's document
is a public act, and a court, employer or regulator checking a certificate has
no account here.

## Point the frontend at it

In `js/config.js`:

```js
storage: {
  provider: "pinata",
  mode: "backend",
  endpoint: "https://gateway.example.com/api/storage/pin",
  gateways: ["https://gateway.example.com/api/storage/"],
}
```

Serving the frontend from the gateway itself (`OREOCHAIN_SERVE_STATIC=true`)
removes cross-origin requests entirely, which is the simplest deployment.

The static root is the repository, so what may be served is an explicit
allowlist rather than everything in it — otherwise `.git`, the server sources
and `js/config.js` would all be URLs. Served: `.html` pages at the root, and
`css/`, `js/`, `assets/`, `files/`, plus `node_modules/web3/dist/` and
`node_modules/@noble/{hashes,ciphers}/esm/`, which the pages load directly. A
file must also have an extension the frontend actually uses, so source maps and
`.ts` sources stay unreachable. Anything else is a 404. **If you add a
directory the frontend needs, add it to `STATIC_DIRECTORIES` in
`server/gateway.mjs`.**

## Deployment notes

1. **Run a supported Node.** The code works on Node 18, but 18 is past
   end-of-life and receives no security patches — use 20 or newer for anything
   deployed.
2. **Put TLS in front of it.** The gateway speaks plain HTTP by design; end it
   at a reverse proxy or load balancer. WebCrypto in the browser requires a
   secure origin anyway.
3. **Bind to loopback** and let the proxy handle the internet.
4. **One API key per client**, so a leaked key can be revoked without disrupting
   everyone. Revoking means removing it from `OREOCHAIN_API_KEYS` and restarting.
5. **Ship the logs somewhere.** Each line is JSON with an event, a key digest
   (never the key), byte counts and CIDs.
6. **Set `OREOCHAIN_RECEIPT_KEY` before going live.** Without it the gateway
   signs receipts with a throwaway key and warns at startup — every restart
   then invalidates every receipt previously issued, because nobody can verify
   them any more. Anchored batches are unaffected; they live on-chain.
7. Rate limits are per process and in memory. Behind multiple instances each
   enforces its own share; move to a shared store if you need a global limit.
   Authenticated callers are bucketed by key, anonymous ones by source address
   — which behind a reverse proxy is the proxy's address, so every anonymous
   caller shares one bucket unless the proxy enforces its own limits.
8. `SIGTERM` drains in-flight requests before exiting, so a deploy does not
   drop an upload mid-chunk.
9. **Put `OREOCHAIN_DB_PATH` on persistent storage and back it up.** It holds
   every recorded document and the ordered document list behind every anchored
   batch. That order is the only thing that can prove a document belongs to a
   root once the root is on-chain: lose the file and those documents stay
   anchored forever with no recoverable inclusion proof. A document is written
   and flushed to disk before its receipt is returned, so a receipt always has
   a stored document behind it. The file is append-only JSON lines, so `wc -l`
   counts records and `tail` shows the most recent.

## What is not here yet

Honest list, so nobody assumes otherwise:

- **No per-user quota or billing.** Rate limiting bounds the *rate*, not the
  total. A client within its rate limit can still pin indefinitely.
- **Rate-limit buckets and the memory backend still reset on restart.** Neither
  matters: a bucket refills anyway, and the memory backend is for local
  development. Recorded documents and anchored batches *are* persisted — see
  `OREOCHAIN_DB_PATH` and the deployment note below.
- **Anchor submission is manual.** The gateway builds the batch; something with
  a funded key has to send the transaction.
- **No key rotation without a restart.** Keys are read once at startup.
- **No upload deduplication.** The same chunk pinned twice is pinned twice.
  (A document recorded twice is now deduplicated; chunks are not.)
