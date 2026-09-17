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
| `OREOCHAIN_RATE_LIMIT_PER_MINUTE` | `600` | Sustained rate per key |
| `OREOCHAIN_RATE_LIMIT_BURST` | `120` | Burst allowance per key |
| `OREOCHAIN_ALLOWED_ORIGINS` | none | Browser origins permitted via CORS. `*` is refused. |
| `OREOCHAIN_READ_TIMEOUT_MS` | `30000` | Request body timeout |
| `OREOCHAIN_UPSTREAM_TIMEOUT_MS` | `60000` | Timeout for calls to the pinning service |
| `OREOCHAIN_SERVE_STATIC` | `false` | Also serve the frontend, so there is no CORS at all |

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

## Deployment notes

1. **Put TLS in front of it.** The gateway speaks plain HTTP by design; end it
   at a reverse proxy or load balancer. WebCrypto in the browser requires a
   secure origin anyway.
2. **Bind to loopback** and let the proxy handle the internet.
3. **One API key per client**, so a leaked key can be revoked without disrupting
   everyone. Revoking means removing it from `OREOCHAIN_API_KEYS` and restarting.
4. **Ship the logs somewhere.** Each line is JSON with an event, a key digest
   (never the key), byte counts and CIDs.
5. Rate limits are per process and in memory. Behind multiple instances each
   enforces its own share; move to a shared store if you need a global limit.
   Authenticated callers are bucketed by key, anonymous ones by source address
   — which behind a reverse proxy is the proxy's address, so every anonymous
   caller shares one bucket unless the proxy enforces its own limits.
6. `SIGTERM` drains in-flight requests before exiting, so a deploy does not
   drop an upload mid-chunk.

## What is not here yet

Honest list, so nobody assumes otherwise:

- **No per-user quota or billing.** Rate limiting bounds the *rate*, not the
  total. A client within its rate limit can still pin indefinitely.
- **No persistence.** Rate-limit buckets and the memory backend reset on restart.
- **No key rotation without a restart.** Keys are read once at startup.
- **No upload deduplication.** The same chunk pinned twice is pinned twice.
