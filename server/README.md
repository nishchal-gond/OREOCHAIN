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

# And the key that signs receipts. The gateway will not start without one,
# because a throwaway key would disown every receipt at the next restart.
node scripts/generate-receipt-key.mjs

PINATA_JWT="your-pinata-jwt" \
OREOCHAIN_API_KEYS="the-key-you-just-generated" \
OREOCHAIN_RECEIPT_KEY='{"privateJwk":…,"publicJwk":…}' \
npm start
```

For local development with no pinning account, `OREOCHAIN_STORAGE=memory` keeps
everything in process memory:

```bash
OREOCHAIN_STORAGE=memory OREOCHAIN_EPHEMERAL_RECEIPT_KEY=true \
  OREOCHAIN_API_KEYS="$(node -e "console.log('k'.repeat(48))")" npm start
```

`OREOCHAIN_EPHEMERAL_RECEIPT_KEY` signs with a throwaway key so there is
nothing to generate first, and the log says so every time it signs that way.
It is for development only: every restart invalidates every receipt issued
before it, and a holder cannot tell that from a forgery. `npm run dev` sets it
too, along with the in-memory store, static file serving and anonymous access.
In a deployment, generate a key.

The process refuses to start if it is misconfigured — no API keys, no pinning
credential, no receipt key, a wildcard CORS origin — rather than running in a
state you did not intend.

**A deployment is two processes.** This one issues receipts promising that a
document will be anchored; [the anchoring worker](#the-anchoring-worker) is
what makes that true. Running the gateway alone is fine for development and
leaves every receipt an unkept promise in production. The gateway says so at
startup when no anchoring key is configured.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8787` | Listen port |
| `HOST` | `127.0.0.1` | Listen address. Keep it loopback behind a reverse proxy. |
| `OREOCHAIN_API_KEYS` | — | Comma-separated client keys, each ≥32 characters |
| `OREOCHAIN_ANCHOR_API_KEYS` | — | The subset of the above allowed to drive anchoring. Unset means nothing may anchor. |
| `OREOCHAIN_ALLOW_ANONYMOUS` | `false` | Serve anyone, with no key. Supported in production — see below. |
| `OREOCHAIN_TRUSTED_PROXY_HOPS` | `0` | Proxies of your own in front of this process. Required behind one. |
| `OREOCHAIN_CLIENT_BYTES_PER_WINDOW` | — | Bytes one client may pin per window |
| `OREOCHAIN_CLIENT_OBJECTS_PER_WINDOW` | — | Objects one client may pin per window |
| `OREOCHAIN_QUOTA_WINDOW_MS` | `3600000` | The window those two are measured over |
| `OREOCHAIN_DAILY_BYTES` | — | Bytes the whole service may pin per day |
| `OREOCHAIN_DAILY_OBJECTS` | — | Objects the whole service may pin per day |
| `PINATA_JWT` | — | Pinning credential. Never leaves this process. |
| `OREOCHAIN_STORAGE` | `pinata` | `memory` for local testing |
| `OREOCHAIN_MAX_CHUNK_BYTES` | `1048576` | Hard cap per request body |
| `OREOCHAIN_MAX_CONCURRENT_UPLOADS` | `32` | Request bodies buffered at once, process-wide. Past this, 503. |
| `OREOCHAIN_RATE_LIMIT_PER_MINUTE` | `600` | Sustained rate per key |
| `OREOCHAIN_RATE_LIMIT_BURST` | `120` | Burst allowance per key |
| `OREOCHAIN_ALLOWED_ORIGINS` | none | Browser origins permitted via CORS. `*` is refused. |
| `OREOCHAIN_READ_TIMEOUT_MS` | `30000` | Request body timeout |
| `OREOCHAIN_UPSTREAM_TIMEOUT_MS` | `60000` | Timeout for calls to the pinning service |
| `OREOCHAIN_IPFS_GATEWAYS` | three public ones | Comma-separated IPFS gateways to read a CID back through, tried in order |
| `OREOCHAIN_SERVE_STATIC` | `false` | Also serve the frontend, so there is no CORS at all |
| `OREOCHAIN_RECEIPT_KEY` | — | Receipt signing key pair. Generate with `node scripts/generate-receipt-key.mjs`. Required. |
| `OREOCHAIN_EPHEMERAL_RECEIPT_KEY` | `false` | Sign with a throwaway key instead. Development only; see below. |
| `OREOCHAIN_KEYRING_PATH` | beside the store | Every public key that has signed a receipt here |
| `OREOCHAIN_DB_PATH` | `./oreochain-proofs.log` | Recorded documents and anchored batches. `:memory:` for tests only. |
| `OREOCHAIN_STORE_CHECK` | `full` | How hard to check the proof store at startup: `full` rebuilds every batch root, `structural` only cross-references, `off` skips it |
| `OREOCHAIN_ALLOW_DAMAGED_STORE` | `false` | Start anyway when that check finds damage, serving the intact batches |
| `OREOCHAIN_VERIFY_MANIFESTS` | `true` | Check a document against its manifest before signing a receipt for it |
| `OREOCHAIN_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` or `silent` |
| `OREOCHAIN_SHUTDOWN_DELAY_MS` | `0` | Keep serving this long after SIGTERM, so a load balancer notices `/ready` first |
| `OREOCHAIN_CHAIN_RPC` | — | Read-only RPC endpoint, so the gateway can confirm anchors itself |
| `OREOCHAIN_CONTRACT_ADDRESS` | — | The deployed contract to read. Set with the line above or not at all. |
| `OREOCHAIN_CHAIN_CACHE_MS` | `3600000` | How long a confirmed anchor is trusted from cache |
| `OREOCHAIN_VERIFY_RATE_LIMIT_PER_MINUTE` | `30` | Public verification, per source address |
| `OREOCHAIN_VERIFY_RATE_LIMIT_BURST` | `10` | Burst for the same |

The anchoring worker is a second process with its own settings — see
[The anchoring worker](#the-anchoring-worker).

Any of `OREOCHAIN_API_KEYS`, `OREOCHAIN_ANCHOR_API_KEYS`, `PINATA_JWT` and
`OREOCHAIN_RECEIPT_KEY` can be given as `<NAME>_FILE` pointing at a file
instead — the form Docker secrets,
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

Every refusal carries a `code`: one stable token from a closed set, so a
client can decide what to do without matching on prose. It matters most where
one status means two things — a `429` is "slow down" from the rate limiter and
"not until your window rolls" from a byte cap, and a `503` is "try in a
second" from load shedding and "not today" from the daily budget.

| `code` | Typical status | What a client should do |
|---|---|---|
| `rate_limited` | 429 | Back off and retry; `Retry-After` says how long |
| `client_quota` | 429 | Stop retrying until the window rolls over |
| `busy` | 503 | Retry shortly; the gateway is at its concurrency ceiling |
| `gateway_budget` | 503 | Stop for today; the service has spent its daily budget |
| `unauthorized` | 401 | Fix the credential |
| `forbidden` | 403 | The key is valid but not for this; see the message |
| `bad_request` | 400 | Fix the request |

The prose in `error` is for people and may change. The `code` will not.

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

Builds a batch from everything pending and returns the Merkle root to anchor
on-chain, plus the list of documents it covers.

Submission is deliberately **not** done here: it needs a funded key, and a key
with spending power does not belong in the same process that accepts public
uploads. The anchoring worker calls this and sends the transaction — see
[The anchoring worker](#the-anchoring-worker). Calling it by hand still works
if you would rather submit anchors yourself.

### `GET /api/proofs/unanchored`

Batches that were built but never confirmed on-chain, oldest first, at most
100 at a time. Needs an anchoring key — see below.

This is how the worker recovers. It owns the funded key and the chain
connection but not the store, so after a crash between building a batch and
submitting it, the gateway is the only thing that knows the batch exists —
its documents are already stamped, so they never come back as pending.

### `POST /api/proofs/anchored`

```json
{ "root": "0x…", "txHash": "0x…", "block": 21000000 }
```

Records where a batch root landed, so inclusion proofs can carry the
transaction a verifier checks them against.

Validated rather than trusted, because this is the one place a client's claim
ends up inside something the gateway serves to everyone:

| Situation | Status |
|---|---|
| Malformed root, txHash or block | `400` |
| No such batch | `404` |
| Already anchored in a *different* transaction | `409` |
| Already anchored in the *same* transaction | `200` |

The last two matter together: a worker that crashed after sending and before
recording will report again on restart, and that has to be accepted or the
batch deadlocks. Two different transactions for one root means something
upstream is wrong, and overwriting would hide it while breaking proofs already
served.

### Anchoring is a separate privilege

`OREOCHAIN_ANCHOR_API_KEYS` names the subset of `OREOCHAIN_API_KEYS` allowed to
call `/api/proofs/batch`, `/api/proofs/unanchored` and `/api/proofs/anchored`.
Every other key gets a `403`, however valid it is for uploading.

The reason is `/api/proofs/anchored`. The transaction hash it records is served
to everyone who asks for a proof in that batch, so a client that could post a
well-formed fictitious one would send every verifier to a transaction that does
not exist — and the real anchor would then be rejected as a conflict, leaving
the batch permanently misreported. Uploading and anchoring are different jobs;
they get different keys.

It fails closed. With `OREOCHAIN_ANCHOR_API_KEYS` unset nothing may anchor, and
the gateway warns at startup that batches will be built and never anchored. An
entry that is not also in `OREOCHAIN_API_KEYS` is refused at startup, since
that key could never authenticate in the first place.

`OREOCHAIN_ALLOW_ANONYMOUS=true` grants it to everyone, because an anonymous
gateway has no boundary to be inside of — anyone who can reach the port can
already upload and record. That is for local development, not for a
deployment.

### `GET /api/proofs/key` — public

The current verification key as a JWK, its key id, and `keys`: every key id
this gateway has ever signed with, each marked current or retired.

`GET /api/proofs/key?kid=<kid>` serves one of them by name, including retired
ones, with the `retiredAt` timestamp. `404` if this gateway has never signed
with it.

That parameter is the whole point. A receipt names the key that signed it in
`statement.kid`, and receipts are portable and long-lived — someone can come
back a year later with one. Serving only the current key meant every receipt
issued before a rotation failed to verify, giving the holder the same answer a
forgery gets, with no way to tell which.

### `GET /api/proofs/verify/<fileHash>` — public

Everything needed to establish whether a document is anchored, for someone
with no account here, no wallet and no RPC endpoint of their own.

It answers for **both** ways a document reaches the contract: a batch anchor,
where this gateway receipted the document and the worker anchored its batch's
root, and a per-document registration written from the uploader's own wallet.
A verifier does not know which was used, so both are looked up.

```json
{
  "fileHash": "0x…",
  "receipt":  { … },          // the signed receipt, or null
  "batch":    { "root": "0x…", "index": 3, "size": 12, "document": {…},
                "proof": [ … ],
                "recorded": { "txHash": "0x…", "block": 21000000 },
                "onChain":  { "block": 21000000, "size": 12,
                              "txHash": "0x…", "confirmations": 45 } },
  "registration": { "block": …, "merkleRoot": "0x…", "exporter": "0x…", … },
  "chainRead":    { "contract": "0x…", "chainId": 1 },
  "gatewayClaim": { "verified": true, "status": "verified",
                    "anchoredBy": ["batch"], "explain": "…" },
  "howToCheck": "…"
}
```

**The verdict is fenced off on purpose.** Asking this service "is this
verified?" and believing the answer reinstates exactly the party a signed
receipt exists to bound. So the body leads with the materials — the receipt,
the inclusion proof, the root, the transaction, the on-chain record, and which
contract on which chain was read — and the conclusion sits in `gatewayClaim`,
which a caller is free to ignore and redo. A browser client should verify
locally with `verifyReceipt` and `verifyInBatch` from `js/core/` and use this
endpoint only as a chain read it cannot perform itself.

`gatewayClaim.status` is one of:

| Status | Meaning | HTTP |
|---|---|---|
| `verified` | anchored, by whichever paths `anchoredBy` names | 200 |
| `not-anchored` | recorded here, proof valid, not yet on-chain by either path | 200 |
| `disputed` | the chain disagrees with this gateway; see `warnings` | 200 |
| `unchecked` | this gateway is not configured to read the chain | 200 |
| `unavailable` | the chain could not be reached — **not** a negative | 503 + `Retry-After` |
| `unknown` | neither this gateway nor the contract has heard of it | 404 |
| `internal` | this gateway could not reproduce its own proof | 500 |

`unavailable` exists because a regulator acting on a false "this document is
not anchored" is the worst thing this endpoint can produce. An RPC that is
down says so; it never becomes a "no".

**Cost control.** This is the only public route that does outside work per
call, so: a confirmed anchor is cached for `OREOCHAIN_CHAIN_CACHE_MS` (an
anchored root does not change), "not there" is cached briefly so a scan of
unknown hashes is not a scan of your RPC quota, "could not check" is never
cached, and the route has its own rate limit — `OREOCHAIN_VERIFY_RATE_LIMIT_*`,
much tighter than uploads and keyed by source address. A per-document
registration is cached for a shorter time than an anchor, because unlike an
anchor a registration can be revoked.

**What a null registration cannot tell you:** `revokeDocument` deletes the
record outright, so a revoked document and one that was never registered read
identically. The `DocumentRevoked` event is the audit trail for that, and
finding it means a log scan over an unbounded block range, which this
deliberately does not do on an unauthenticated request.

### When the chain disagrees: what this gateway does

Decided deliberately, because the alternatives are all worse:

- **A read never writes.** If the contract does not hold a root this gateway
  recorded as anchored, the store is not corrected, marked or cleared. The
  recorded transaction is the only evidence linking that batch to a
  submission, and a read path that can erase it turns a misconfigured RPC into
  data loss.
- **It is reported as `disputed`, never as "not anchored".** The response
  carries both what was recorded and the fact that the contract does not show
  it, the gateway logs it at `error`, and
  `oreochain_anchor_discrepancies_total` increments. Alert on that metric.
- **Nothing re-anchors automatically.** The worker anchors what the gateway
  lists as unanchored, and a batch with a recorded anchor is not on that list.
  Letting a read-path disagreement feed the write path would mean an RPC
  pointed at the wrong network could spend money anchoring batches that are
  already anchored.

So recovering from a genuine reorg is a deliberate human act:

1. Confirm the transaction is really gone — a second RPC endpoint, or a block
   explorer. An RPC serving a fork, or pointed at the wrong network, looks
   exactly like a reorg from here.
2. Stop the gateway.
3. Remove that batch's anchor line from the store. It is append-only JSON
   lines, so this is the single line reading
   `{"t":"anchor","root":"0x…",…}` for that root.
4. Start the gateway. The batch is unanchored again, and the worker anchors it
   on its next tick.

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

## The anchoring worker

The gateway builds batches. Something has to put their roots on-chain, and
until now that was a person with a wallet. `server/anchor-worker.mjs` is that
something.

```bash
OREOCHAIN_CHAIN_RPC=https://rpc.example \
OREOCHAIN_CONTRACT_ADDRESS=0x… \
OREOCHAIN_ANCHOR_KEY_FILE=/run/secrets/anchor_key \
OREOCHAIN_ANCHOR_API_KEY_FILE=/run/secrets/anchor_api_key \
OREOCHAIN_GATEWAY_URL=http://gateway:8787 \
node server/anchor-worker.mjs
```

### What the operator has to supply

| Setting | Required | What it is |
|---|---|---|
| `OREOCHAIN_CHAIN_RPC` | yes | JSON-RPC endpoint to submit through |
| `OREOCHAIN_CONTRACT_ADDRESS` | yes | the deployed `ChunkedVerification` |
| `OREOCHAIN_ANCHOR_KEY` / `_FILE` | yes | funded private key, `0x` + 64 hex |
| `OREOCHAIN_ANCHOR_API_KEY` / `_FILE` | yes | a key in the gateway's `OREOCHAIN_ANCHOR_API_KEYS` |
| `OREOCHAIN_GATEWAY_URL` | no | default `http://127.0.0.1:8787` |
| `OREOCHAIN_ANCHOR_INTERVAL_MS` | no | default `60000` |
| `OREOCHAIN_ANCHOR_CONFIRMATIONS` | no | default `3` |
| `OREOCHAIN_ANCHOR_URI` | no | proof URL written into the anchor; `{root}` is substituted |
| `OREOCHAIN_ANCHOR_PENDING_TIMEOUT_MS` | no | default `600000`, when to resend a transaction that never mined |

Note the two different keys. `OREOCHAIN_ANCHOR_KEY` is the chain key that pays
for transactions; `OREOCHAIN_ANCHOR_API_KEY` is how the worker authenticates to
the gateway, and the gateway must list it in its own
`OREOCHAIN_ANCHOR_API_KEYS`. Issue it to the worker alone, so it can be revoked
without touching any client.

Three things are true of the chain key beyond holding it: the address must be
**funded**, it must be an **authorised exporter** on the contract, and it must
be **nowhere near the gateway**. Authorising it is one command from a dev
checkout, run with the contract owner's key:

```bash
OREOCHAIN_CHAIN_RPC=… OREOCHAIN_DEPLOY_KEY_FILE=… OREOCHAIN_CONTRACT_ADDRESS=… \
npm run add-exporter -- 0x<the worker's address> "anchor worker" --confirm
```

Without `--confirm` it checks the owner, checks whether the address is already
authorised, and sends nothing. The worker is a separate process
precisely so a key that can spend is not in the process that parses public
uploads.

None of the required settings has a default, and the worker names every one
that is missing in a single line before exiting:

```
the anchoring worker cannot start, 2 setting(s) are missing:
  OREOCHAIN_ANCHOR_KEY — the funded private key that signs anchor transactions (or OREOCHAIN_ANCHOR_KEY_FILE)
  OREOCHAIN_ANCHOR_API_KEY — an OREOCHAIN_API_KEYS entry the worker authenticates to the gateway with
```

That is deliberate. The failure this replaces is the silent one: a worker that
starts happily with no key, polls for ever, anchors nothing, and leaves every
receipt it issued promising an anchor that is never coming.

It then refuses to start if the contract address has no code on that chain, if
its address is not an authorised exporter, or if the address holds no balance —
each of which would otherwise show up only as a stream of reverted
transactions you paid gas for.

### Trying it before it costs anything

There is no local chain in this repository, so the first anchor you send goes
to a real one. Send it to a testnet: deploy the contract there, fund the
anchoring address from that network's faucet, authorise it, and run the worker
against it end to end. Everything behaves identically — the same contract, the
same confirmations, the same failure messages — and a mistake costs test
currency.

Worth doing at least once before the mainnet or L2 deployment, because the two
failures most likely to be waiting (the address was never authorised, or the
contract address and the RPC endpoint are for different networks) are both
caught by the worker's preflight on the first run rather than by a support
request three weeks later.

### How a tick works

1. Ask the gateway what is unanchored. Anchor those first, oldest first.
2. Only when nothing is outstanding, build a new batch if the gateway says the
   queue should flush. Adding to a queue that is not draining turns one stuck
   batch into a pile of them.
3. For each batch: ask the **contract** whether that root is already anchored.
   If it is and it is `OREOCHAIN_ANCHOR_CONFIRMATIONS` deep, recover the
   transaction hash from the `BatchAnchored` log in that block and report it
   back. If it is not anchored, send the transaction and return.

No step waits for a transaction to mine. A submitted batch stays unanchored
until it has confirmed, so the next tick picks it up, and a worker that dies in
between recovers by asking the contract rather than by remembering anything.

Confirmations are not decoration: a receipt records the transaction its proof
points at, and a user does not come back to re-check. Reporting one block deep
means a reorg can leave a whole batch of receipts pointing at a transaction
that no longer exists. Three is a floor for a fast chain; a public L1 wants
more.

### When it goes wrong

| Symptom | What it means | What to do |
|---|---|---|
| `cannot anchor against this chain` at startup | preflight failed | read the message: wrong address, unauthorised exporter, or no balance |
| `cannot read unanchored batches` | the gateway is unreachable or the API key is wrong | the worker keeps ticking; fix and it catches up |
| `returned 403` from the gateway | the worker's API key is not in `OREOCHAIN_ANCHOR_API_KEYS` | add it there and restart the gateway |
| `a sent anchor never mined, resubmitting` | the transaction was dropped | usually gas; the contract rejects a duplicate anchor, so a resend is safe |
| `anchored batch has no recoverable transaction hash` | the batch **is** anchored, but the RPC has pruned the log | `POST /api/proofs/anchored` with the hash by hand, from a block explorer |
| `oreochain_documents_pending` climbing | nothing is being anchored | check the worker is running at all |

Running two workers against one gateway is harmless but pointless: they race,
the loser's transaction reverts with `AlreadyExists`, and gas is wasted. Run
one.

## Running it open to the public

A visitor needs no account. That is the product, not a shortcut: someone
sealing a document in their browser should not have to sign up first, and
accounts would be the wrong shape for it. So `OREOCHAIN_ALLOW_ANONYMOUS=true`
is a supported production configuration, and keyed mode is for private
deployments.

What makes it safe is not authentication. It is a ceiling on what it can cost.

| Layer | Setting | What it stops |
|---|---|---|
| Per request | `OREOCHAIN_MAX_CHUNK_BYTES` | One body exhausting memory |
| In flight | `OREOCHAIN_MAX_CONCURRENT_UPLOADS` | Many bodies at once doing the same |
| Per client, per minute | `OREOCHAIN_RATE_LIMIT_*` | One visitor calling constantly |
| Per client, per window | `OREOCHAIN_CLIENT_BYTES_PER_WINDOW`, `..._OBJECTS_...` | One visitor spending everyone's share |
| Per day, service-wide | `OREOCHAIN_DAILY_BYTES`, `OREOCHAIN_DAILY_OBJECTS` | A thousand polite visitors adding up to a bill |

The last two have no defaults, and with `OREOCHAIN_ALLOW_ANONYMOUS=true` and a
pinning account the gateway **refuses to start** until all four are set,
naming each one and suggesting a number. The right numbers depend on what your
pinning plan costs; pick what you could afford to lose in a day.

A client that hits its own ceiling gets `429` with `Retry-After` — its window
will roll over. A request refused by the daily budget gets `503`, because
nothing the caller does will help until the day turns. The daily counter
resets at 00:00 UTC, and it lives in memory: **a restart starts the day's
budget again.** That is deliberate — persisting it means another durable
store, and this is a guard rail on a bill rather than a ledger — but it means
a crash-looping gateway is not protected by it.

Everything is in `/metrics`: `oreochain_daily_bytes_pinned` against
`oreochain_daily_bytes_budget`, the same for objects,
`oreochain_quota_clients`, and `oreochain_quota_rejections_total` by scope.
Alert on the budget ones before they bite.

### Behind a proxy, set `OREOCHAIN_TRUSTED_PROXY_HOPS`

Every one of those per-client limits is keyed on the client's address, and
behind a reverse proxy every request arrives from the proxy. Left at `0`, all
your visitors share one rate limit and one byte budget, and the first heavy
one shuts out the rest — on a gateway that looks perfectly healthy.

Set it to the number of proxies of your own that a request passes through
(usually `1`). The gateway then reads `X-Forwarded-For` counting that many
entries from the right, which is the only part of it your own infrastructure
wrote. It is `0` by default because trusting that header unconditionally is
worse than ignoring it: anyone could then send one and mint a fresh budget per
request.

It applies to the public verification route as well. That one is
unauthenticated, so the address is the only thing metering it: behind a proxy
with hops at `0`, every verifier in the world shares one
`OREOCHAIN_VERIFY_RATE_LIMIT_PER_MINUTE`, and one person checking a batch of
certificates locks out everyone else.

Two things make a missing setting visible rather than mysterious:
`oreochain_trusted_proxy_hops` in `/metrics`, and
`oreochain_forwarded_for_ignored_total`, which counts requests that arrived
with the header while nothing was trusted. A non-zero count there with hops at
`0` means there is a proxy in front of this gateway that the configuration
does not know about.

### Rotating the receipt key

Receipts already issued must keep verifying, so rotation adds a key rather
than replacing one:

1. Generate a new pair: `node scripts/generate-receipt-key.mjs`.
2. Put it in `OREOCHAIN_RECEIPT_KEY` (or the file `OREOCHAIN_RECEIPT_KEY_FILE`
   points at) and restart. The drain is graceful, so this is a deploy rather
   than an outage.
3. That is all. The new key signs from now on; the old public key stays in the
   keyring and `GET /api/proofs/key?kid=<old>` keeps serving it, so every
   receipt already in someone's hands still verifies. The log says
   `receipt signing key rotated` with both key ids.

The keyring lives beside the proof store — `<OREOCHAIN_DB_PATH>.keys.json`
unless `OREOCHAIN_KEYRING_PATH` says otherwise — and **belongs in the same
backup**. Losing it means losing the ability to verify every receipt signed by
a key you have since rotated away from. It holds public keys only: the signing
key stays in the environment or a secret mount, which is what
`OREOCHAIN_RECEIPT_KEY` is for.

It is not a secret. Serving it is the point.

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
6. **Set `OREOCHAIN_RECEIPT_KEY`.** Without it the gateway refuses to start,
   because the alternative is signing receipts with a throwaway key and
   disowning every one of them at the next restart — and a holder cannot tell
   that from a forgery. `OREOCHAIN_EPHEMERAL_RECEIPT_KEY=true` opts into it
   for development, and says so in the log every time. Anchored batches are
   unaffected either way; they live on-chain.
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
10. **Deploy the anchoring worker too, and only one of it.** The gateway
   issues receipts that promise an anchor; the worker is what makes that true.
   It needs no persistent storage of its own — everything it would remember,
   it can ask the contract for — so it restarts and redeploys freely. See
   [The anchoring worker](#the-anchoring-worker).
11. **Put `OREOCHAIN_DB_PATH` on persistent storage and back it up.** It holds
   every recorded document and the ordered document list behind every anchored
   batch. That order is the only thing that can prove a document belongs to a
   root once the root is on-chain: lose the file and those documents stay
   anchored forever with no recoverable inclusion proof. A document is written
   and flushed to disk before its receipt is returned, so a receipt always has
   a stored document behind it. The file is append-only JSON lines, so `wc -l`
   counts records and `tail` shows the most recent. Backing it up is a `cp`
   while the gateway runs, and a restore is only done when the copy has been
   checked — see [Backing up the proof store](#backing-up-the-proof-store-and-restoring-it).
12. **Check the store after every restore**, with `npm run verify-store`. A log
   that lost records still parses; only rebuilding each batch root from the
   documents under it says whether the store can still prove what it claims.
   The gateway runs that check at startup and refuses a damaged store, which is
   a backstop rather than the plan.

## Backing up the proof store, and restoring it

The store is the one thing a deployment cannot recreate. Everything else can be
rebuilt: keys reissued, containers redeployed, the frontend reserved from a CDN.
An anchored batch's ordered document list cannot — once the root is on-chain,
that order is the only thing that turns "this root is anchored" into "your
document is in it". There is no upstream copy to fetch it back from.

### Taking a backup

Copy the file. That is the whole procedure, and it is safe while the gateway is
running:

```bash
cp "$OREOCHAIN_DB_PATH" "/backups/proofs-$(date -u +%Y%m%dT%H%M%SZ).log"
```

Three properties make that true, and all three are deliberate. The log is
append-only, so a copy can never miss a record that was there when it started.
Each record is one `write` followed by an `fsync` before the request that
caused it returns, so a record in the file is a record the client was already
told about. And a copy caught mid-append can only ever catch a half-written
*final* line, which a reader drops — the store tolerates a torn tail by design
because a crash produces the same thing.

What that costs you is the tail: a copy taken at time T holds everything
receipted before T and nothing after. Take one often enough that the gap is a
gap you can live with, remembering that a document in the gap has a signed
receipt in a user's hands and no record here.

Do not back up the `.lock` file beside it, and do not restore one — it names
the process that held the store, and a stale one is exactly what the lock's
liveness check exists to clear.

### Checking a backup

A copy that parses is not a copy that proves anything. Records lost in transit,
a truncated transfer, a partial restore from two snapshots: all of these leave
a log whose every line is valid JSON and whose batches no longer hash to the
roots that were anchored. Rebuilding each root from the documents under it is
what tells them apart, because the root *is* a hash of exactly that order.

```bash
npm run verify-store -- /backups/proofs-20260919T120000Z.log
```

```
/backups/proofs-20260919T120000Z.log
18422 document(s), 19 batch(es), 19 anchored — full check in 140ms
no problems found
```

Exit code 0 means intact, 1 means damaged, 2 means it could not be read, so it
drops straight into a cron job or a monitoring check. `--json` gives the whole
report. It takes no lock and opens no write handle, so it is safe to point at a
live store as well as at a backup — the worst it can see is that torn final
line, which it reports rather than removes.

Put it in cron. The startup check happens once: a process running for months
is reporting on the store as it was when it opened, and this is the only thing
that would notice bit rot or a stray edit in between. Out of process is the
right place for it, because a rehash of a large store inside the gateway would
stall the event loop.

```cron
17 * * * * cd /srv/oreochain && npm run verify-store -- /data/oreochain-proofs.log --json > /var/log/oreochain-store-check.json
```

Two gauges carry the startup result into `/metrics`:
`oreochain_store_damaged_batches`, which is what to alert on, and
`oreochain_store_check_timestamp_seconds`, which distinguishes "nothing is
wrong" from "nothing has looked".

The gateway runs the same check at startup and refuses to serve a store that
fails it. That is the backstop, not the plan: by the time the gateway refuses,
the restore has already been declared done. Check the backup first, while the
copy you restored *from* is still around.

`OREOCHAIN_STORE_CHECK=structural` skips the rehash for a store large enough
that startup time matters — it cross-references batches and documents without
hashing, which catches lost records but not a reordering. For scale: 20,000
documents rebuild in about 140 ms, so `full` is the right default for almost
everyone.

### The restore

```bash
# 1. Stop the gateway. One writer, and the restore is a write.
docker compose stop gateway

# 2. Check the backup before it becomes the live store.
npm run verify-store -- /backups/proofs-20260919T120000Z.log

# 3. Put it in place, without deleting what is there.
mv /data/oreochain-proofs.log /data/oreochain-proofs.log.suspect
cp /backups/proofs-20260919T120000Z.log /data/oreochain-proofs.log

# 4. Remove a stale lock only if one is left and no gateway is running.
rm -f /data/oreochain-proofs.log.lock

# 5. Start. It checks the store again and refuses if anything is wrong.
docker compose start gateway
```

Keep the suspect file. If the backup turns out to be older than you thought,
the records in the gap exist only there, and a store can be repaired by
appending the missing `doc` lines in their original order — the later records
are position-dependent, so order is not negotiable and this is a job to do
carefully, not a script to run.

Practise this. A backup nobody has restored is a hypothesis; the test suite
runs the same cycle (back up, destroy, restore, serve a proof, verify it
against the on-chain root) but it cannot tell you that *your* backup job is
writing to the volume you think it is.

And read the check for what it says. A clean report means this store agrees
with itself — its batches rebuild to the roots that were anchored, and nothing
references a record that is missing. It does **not** mean it is *your* store.
Another deployment's backup, restored over yours, passes every check perfectly,
because it was written by the same code and is internally sound; it simply
contains none of your documents. Nothing in the log identifies the deployment
it belongs to, so there is nothing for the checker to compare against. Confirm
the file you restored is the right one before you trust the green tick — the
document count and the anchored-batch count in the report are the quickest
sanity check against what you know your deployment holds.

The failure mode if you get this wrong is at least the right shape: a proof
request for one of your documents finds no such document and answers "not
found", rather than returning a proof against a root that is not yours.

### When the check finds damage

Every problem is reported with the batch it belongs to:

```
14 document(s), 3 batch(es), 3 anchored — full check in 2ms
1 problem(s) across 1 batch(es):
  [root_mismatch] batch rebuilds to 0x0b49…, not the recorded 0x7abb… — its
  documents are not the documents that were anchored
```

| Kind | What happened |
|---|---|
| `missing_document` | A batch names a document that is not in the store. Records were lost. |
| `root_mismatch` | A batch's documents no longer hash to its recorded root. Its contents changed. |
| `missing_batch` | A document is in a batch the store does not have. The batch record was lost. |
| `wrong_batch_index` | A document is listed at a position it does not record itself at. |
| `unbuildable_batch` | A batch's documents cannot be hashed at all: a field is malformed. |

The answer to all of them is a restore, not a repair. Nothing in this codebase
will edit a proof store to make it self-consistent, because "consistent" would
mean agreeing with whatever survived rather than with what was anchored.

If no good backup exists, the damaged batches' documents are unprovable and
saying so is the only honest option — the anchors stay on-chain, and the
receipts the gateway issued for them are still valid signatures over what was
accepted. `OREOCHAIN_ALLOW_DAMAGED_STORE=true` starts the gateway anyway so the
intact batches keep serving; the damaged ones refuse individually either way,
because the same rebuild guards every proof the gateway hands out.

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
- **The daily spend budget resets on restart.** It is a guard rail on a bill,
  not a ledger; a crash-looping gateway is not protected by it. Persisting it
  means a second durable store, which is a larger change than the protection
  is worth today.
- **Rate-limit buckets and the memory backend still reset on restart.** Neither
  matters: a bucket refills anyway, and the memory backend is for local
  development. Recorded documents and anchored batches *are* persisted — see
  `OREOCHAIN_DB_PATH` and the deployment note below.
- **Anchoring is one worker, and a batch is anchored a minute or so after it
  is built.** `OREOCHAIN_ANCHOR_INTERVAL_MS` plus the confirmation wait is the
  delay between a receipt being issued and a transaction existing to back it.
  That is the design — batching is what removes per-user gas — but a receipt
  says nothing about *when* its anchor lands, so do not promise a user one.
- **The worker does not manage gas.** It uses the RPC's estimate with a
  margin. A chain in the middle of a fee spike may see the transaction sit in
  the mempool until `OREOCHAIN_ANCHOR_PENDING_TIMEOUT_MS` expires and it is
  resent at the price of the day. There is no bump-and-replace.
- **A receipt proves the document matches its manifest, not that the manifest
  is honest.** See `POST /api/proofs/record` above for exactly where that line
  falls.
- **Rotating the receipt key costs a restart.** Keys are read once at startup,
  from the environment or a `_FILE` mount. A rolling restart is graceful, so
  rotation costs a deploy rather than an outage — and receipts issued under
  the old key keep verifying, because the keyring keeps it.
- **No upload deduplication.** The same chunk pinned twice is pinned twice.
  (A document recorded twice is now deduplicated; chunks are not.)
