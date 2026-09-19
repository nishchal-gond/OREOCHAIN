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
| `OREOCHAIN_VERIFY_MANIFESTS` | `true` | Check a document against its manifest before signing a receipt for it |
| `OREOCHAIN_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` or `silent` |
| `OREOCHAIN_SHUTDOWN_DELAY_MS` | `0` | Keep serving this long after SIGTERM, so a load balancer notices `/ready` first |

Any of `OREOCHAIN_API_KEYS`, `PINATA_JWT` and `OREOCHAIN_RECEIPT_KEY` can be
given as `<NAME>_FILE` pointing at a file instead — the form Docker secrets,
Kubernetes secret mounts and systemd `LoadCredential` all use. A value in the
environment is visible in `docker inspect`, in `/proc`, and to every child
process; a file is not. Setting both a variable and its `_FILE` twin is an
error rather than a guess about which one you meant, and a trailing newline is
stripped so a credential written with `echo` still works.

## Logs

One JSON object per line on stdout, with a timestamp, a level, and — for
anything inside a request — the request id:

```json
{"time":"2026-09-19T08:10:19.191Z","level":"info","msg":"pinned","reqId":"9e1c…","keyId":"a3f0c1d2e4b5","bytes":262144,"cid":"bafy…","ms":412}
```

The id comes back to the client in the `X-Request-Id` header and in the body of
any error, so a user reporting a failure can quote something that finds the
exact line. An incoming `X-Request-Id` is reused when it is short and
alphanumeric, so a trace started at your edge proxy carries through.

Field names that name a credential are never printed, and a value shaped like a
JWT or an `Authorization` header is truncated even under a field nobody thought
to list. That is a backstop, not a licence.

## API

### `GET /health`

Unauthenticated liveness check: is the process running? Nothing more. Point a
liveness probe here — a liveness probe that checks a dependency restarts the
container every time the dependency is down, turning an outage into a crash
loop.

```json
{ "status": "ok", "storage": "pinata", "uptime": 1234.5, "inFlightUploads": 3 }
```

### `GET /ready`

Unauthenticated readiness check: should this instance be sent traffic? A
different question, and the one a load balancer should ask.

```json
{ "status": "ready", "draining": false, "store": "ok" }
```

`503` when the process is shutting down, or when the proof store cannot answer
— it must be writable before a receipt can honestly be issued.

It deliberately does not probe Pinata. An upstream wobble would fail readiness
on every replica at once and take the whole service out over a dependency that
only affects one endpoint.

On SIGTERM the gateway fails readiness *first*, keeps serving for
`OREOCHAIN_SHUTDOWN_DELAY_MS`, and only then stops listening and drains
in-flight requests. Set that to a little more than your readiness probe
interval, or the probe never observes the 503 and requests arrive at a socket
that has already closed.

### `GET /metrics`

Prometheus exposition format, behind the same bearer token as the API — request
volume and queue depth are operational shape, not public information.

```
oreochain_requests_total{route="pin",status="2xx"} 14203
oreochain_uploads_shed_total 4
oreochain_documents_pending 17
oreochain_uploads_in_flight 3
```

`oreochain_documents_pending` is the one to alert on: it grows silently when
documents are being receipted and nothing is anchoring them, and nothing else
in the system says so.

Routes are labelled by shape (`pin`, `fetch`, `inclusion`), never by cid or file
hash — one time series per document is how a metrics backend is destroyed.

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

Before signing, the gateway fetches `manifestCID` through its own storage
backend and checks that the manifest's `fileHash`, `merkleRoot` and `fileSize`
match what is being receipted. Without that, a receipt said "this service
accepted this exact document" about three strings nobody had checked: a client
could obtain a validly signed receipt — and then an on-chain anchor — for a
document of its choosing, pointing at a manifest describing something else. The
signature was never the part that was lying.

Only the manifest *header* is read. `fileHash`, `merkleRoot`, `fileSize` and
`totalChunks` are plaintext even for an encrypted file; the body holding the
file name and chunk table stays sealed. No passphrase and no file key is
involved, so this does not weaken the property that the gateway cannot read
your documents.

Two failures, deliberately distinguished:

| Situation | Status | Meaning |
|---|---|---|
| Manifest disagrees with the document | `400` | Will never succeed; fix the request |
| Manifest could not be read | `503` + `Retry-After` | A freshly pinned manifest may not have propagated; retry |

The receipt records what was done, as `"verified": true` or `false` in the
signed statement. The field is additive: receipts issued before it existed have
no such key, so *absent* means "not asserted" rather than false, and every
previously issued receipt still verifies. `OREOCHAIN_VERIFY_MANIFESTS=false`
turns the check off and the process warns at startup; receipts then say
`"verified": false`.

**What this does not prove:** that the manifest's Merkle root is genuinely the
root of the chunks it lists. That would mean fetching and hashing the whole
file on every upload to re-derive what the client already computed. A client
can still describe a file it invented — but it can no longer be handed a
receipt for one document while pointing at a manifest for another.

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
5. **Ship the logs somewhere.** Each line is JSON with a time, a level, a
   request id, a key digest (never the key), byte counts and CIDs. Scrape
   `/metrics` too, and alert on `oreochain_documents_pending`.
6. **Set `OREOCHAIN_RECEIPT_KEY` before going live.** Without it the gateway
   signs receipts with a throwaway key and warns at startup — every restart
   then invalidates every receipt previously issued, because nobody can verify
   them any more. Anchored batches are unaffected; they live on-chain.
7. Rate limits are per process and in memory. Behind multiple instances each
   enforces its own share; move to a shared store if you need a global limit.
   Authenticated callers are bucketed by key, anonymous ones by source address
   — which behind a reverse proxy is the proxy's address, so every anonymous
   caller shares one bucket unless the proxy enforces its own limits.
8. `SIGTERM` fails `/ready`, keeps serving for `OREOCHAIN_SHUTDOWN_DELAY_MS`,
   then stops listening and drains in-flight requests, so a deploy does not
   drop an upload mid-chunk. Give the orchestrator a termination grace period
   longer than that delay plus your slowest upload, or it will `SIGKILL`
   mid-drain and undo the point of it.
9. **Run exactly one instance against a given `OREOCHAIN_DB_PATH`.** The store
   has a single writer and takes a lock file beside it to enforce that: a
   second process refuses to start and says which host holds it. Two appending
   to one file would interleave records, so a batch written by one names
   documents the other cannot produce — an inclusion proof that cannot be
   rebuilt for a document already anchored on-chain, discovered long after the
   fact. The lock is advisory and built on exclusive file creation, which NFS
   does not implement reliably; on NFS-backed storage do not rely on it. To run
   several gateways today, give each its own store on storage it does not
   share. Running them against *one* store needs a backend that supports
   concurrent writers.
10. **Put `OREOCHAIN_DB_PATH` on persistent storage and back it up.** It holds
   every recorded document and the ordered document list behind every anchored
   batch. That order is the only thing that can prove a document belongs to a
   root once the root is on-chain: lose the file and those documents stay
   anchored forever with no recoverable inclusion proof. A document is written
   and flushed to disk before its receipt is returned, so a receipt always has
   a stored document behind it. The file is append-only JSON lines, so `wc -l`
   counts records and `tail` shows the most recent.

## Running it in a container

```bash
cp .env.example .env            # fill in OREOCHAIN_API_KEYS
mkdir -p secrets
printf %s "$PINATA_JWT" > secrets/pinata_jwt
node scripts/generate-receipt-key.mjs > secrets/receipt_key
docker compose up --build
```

`docker-compose.yml` is the reference for how this service expects to be
operated, not just a convenience: credentials as mounted files rather than
environment values, the proof store on a named volume that outlives the
container, a read-only root filesystem, and a grace period long enough for the
shutdown window plus a drain. `secrets/` is gitignored.

Two defaults change inside a container, and both are set in the image:

- `HOST=0.0.0.0`. The default is loopback, which in a container's own network
  namespace means nothing outside it can connect.
- The entrypoint is `dumb-init`, so `SIGTERM` reaches the gateway. A process
  running as PID 1 gets no default signal handling, and without this the
  graceful shutdown never runs.

CI builds the image, starts it, round-trips a chunk through it, stops it and
checks it exited cleanly — so these stay true rather than rotting quietly.

### Kubernetes

The pieces that matter, given the above:

```yaml
# One writer, and the gateway enforces it: the proof store is a single
# appended file with its index in memory, so a second replica refuses to
# start rather than interleaving appends and leaving anchored documents
# unprovable. Raising this needs a store that supports concurrent writers
# (Postgres behind the same interface), not a bigger number here.
replicas: 1
strategy:
  # And with one writer, the new pod must not start before the old one has
  # released the store.
  type: Recreate
livenessProbe:
  httpGet: { path: /health, port: 8787 }
readinessProbe:
  httpGet: { path: /ready, port: 8787 }
  periodSeconds: 3
env:
  # Longer than the readiness period, so the probe observes the 503 before
  # the listener closes.
  - name: OREOCHAIN_SHUTDOWN_DELAY_MS
    value: "5000"
  - name: PINATA_JWT_FILE
    value: /run/secrets/pinata_jwt
# Longer than the delay plus the slowest upload you allow.
terminationGracePeriodSeconds: 60
```

Liveness must stay on `/health`. Pointing it at `/ready` restarts the pod for
draining, which is the thing it was asked to do.

## What is not here yet

Honest list, so nobody assumes otherwise:

- **One instance per proof store.** Enforced at startup rather than left to
  documentation, but it is still a ceiling: horizontal scaling needs a store
  with concurrent writers behind the same interface.
- **No per-user quota or billing.** Rate limiting bounds the *rate*, not the
  total. A client within its rate limit can still pin indefinitely.
- **Rate-limit buckets and the memory backend still reset on restart.** Neither
  matters: a bucket refills anyway, and the memory backend is for local
  development. Recorded documents and anchored batches *are* persisted — see
  `OREOCHAIN_DB_PATH` and the deployment note below.
- **Anchor submission is manual.** The gateway builds the batch; something with
  a funded key has to send the transaction. Until that is automated, a
  document is anchored only when someone remembers — which for a service is
  the gap that matters most.
- **A receipt proves the document matches its manifest, not that the manifest
  is honest.** See `POST /api/proofs/record` above for exactly where that line
  falls.
- **No key rotation without a restart.** Keys are read once at startup, from
  the environment or from a `_FILE` mount. A rolling restart is graceful, so
  rotation costs a deploy rather than an outage.
- **No upload deduplication.** The same chunk pinned twice is pinned twice.
  (A document recorded twice is now deduplicated; chunks are not.)
