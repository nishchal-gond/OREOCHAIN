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
    // This is the setting that actually protects a weak passphrase. The
    // wrapped file key travels in the manifest, so an attacker who fetches one
    // guesses offline at hardware speed — the cost of a single guess is the
    // whole defence.
    //
    // Argon2id is memory-hard: every guess must allocate and traverse this
    // much memory, which is what a GPU or ASIC cannot cheaply multiply.
    // 47104 KiB / 1 pass is an OWASP-recommended profile and costs roughly
    // 0.7s in the browser. Raise memoryKiB on a server, where blocking a
    // thread for longer is acceptable.
    //
    // "pbkdf2-sha256" is still readable so files sealed before this change
    // still open, but it is memory-cheap and should not be chosen for new files.
    kdf: {
      name: "argon2id",
      memoryKiB: 47104,
      iterations: 1,
      parallelism: 1,
    },
  },
};
