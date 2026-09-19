/**
 * Copy this file to js/config.js and fill it in. js/config.js is gitignored, so
 * your settings never reach the repository.
 *
 *     cp js/config.example.js js/config.js
 */
window.OREOCHAIN_CONFIG = {
  contract: {
    // Address of the deployed ChunkedVerification contract.
    address: "0x0000000000000000000000000000000000000000",
    // Chain the contract is deployed on (137 = Polygon mainnet, 80002 = Amoy testnet).
    chainId: 137,
    explorer: "https://polygonscan.com",
  },

  storage: {
    provider: "pinata",

    // "backend": your server holds the Pinata credentials and proxies uploads.
    //            The browser never sees a token. Use this in production.
    // "direct":  the browser calls Pinata with the JWT below. That token is
    //            readable by anyone who opens the page — local development only.
    mode: "backend",

    // backend mode: your gateway's upload endpoint. It receives raw bytes
    // (application/octet-stream) and responds with { "cid": "..." }.
    // Run one with `npm start` — see server/README.md.
    endpoint: "/api/storage/pin",

    // direct mode only. Leave null in any deployed environment.
    jwt: null,

    // Read gateways, tried in order. Each is retried on transient failures
    // before moving to the next. Point these at your own gateway
    // ("/api/storage/") to keep every request on one origin.
    gateways: [
      "https://ipfs.io/ipfs/",
      "https://cloudflare-ipfs.com/ipfs/",
      "https://gateway.pinata.cloud/ipfs/",
    ],

    // Retry policy for transient network failures.
    retry: { maxAttempts: 4, backoffBaseMs: 250 },
  },

  crypto: {
    // "aes-256-gcm"         fastest where AES-NI exists (most machines)
    // "xchacha20-poly1305"  fastest in pure software; no cache-timing exposure
    // "cascade-aes-xchacha" both, independent keys — survives a break of either
    suite: "aes-256-gcm",

    // Bytes per chunk. 256 KiB matches the IPFS block size.
    chunkSize: 262144,

    // Passphrase key derivation.
    //
    // This is the setting that actually protects a weak passphrase. The wrapped
    // file key travels in the manifest, so an attacker who fetches one guesses
    // offline at hardware speed — the cost of a single guess is the whole
    // defence. Argon2id is memory-hard: every guess must allocate and traverse
    // the profile's full memory cost, which is what a GPU or ASIC cannot cheaply
    // multiply.
    //
    // The name alone means "use the profile this version of OREOCHAIN ships",
    // which is defined once in js/core/kdf.js as ARGON2ID_DEFAULTS and written
    // up in docs/SEALING.md §3. Deliberately no numbers here: spelling them out
    // pins them, so a copy of this file made today would keep today's profile
    // after an upgrade raised it, silently and with nothing to notice.
    //
    // To override deliberately — a server, where nobody is watching a spinner,
    // can afford much more memory — give the parameters you want and they win:
    //
    //     kdf: { name: "argon2id", memoryKiB: 262144, iterations: 3, parallelism: 1 }
    //
    // "pbkdf2-sha256" is still readable so files sealed before Argon2id still
    // open, but it is memory-cheap and should not be chosen for new files.
    kdf: "argon2id",
  },
};
