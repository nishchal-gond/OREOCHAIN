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

    // backend mode: your upload endpoint. It should accept multipart/form-data
    // with a "file" field and respond with { "cid": "..." }.
    endpoint: "/api/storage/pin",

    // direct mode only. Leave null in any deployed environment.
    jwt: null,

    // Read gateways, tried in order.
    gateways: [
      "https://ipfs.io/ipfs/",
      "https://cloudflare-ipfs.com/ipfs/",
      "https://gateway.pinata.cloud/ipfs/",
    ],
  },

  crypto: {
    // "aes-256-gcm"         fastest where AES-NI exists (most machines)
    // "xchacha20-poly1305"  fastest in pure software; no cache-timing exposure
    // "cascade-aes-xchacha" both, independent keys — survives a break of either
    suite: "aes-256-gcm",

    // Bytes per chunk. 256 KiB matches the IPFS block size.
    chunkSize: 262144,

    // PBKDF2 iterations for passphrase stretching. Higher is slower to attack
    // and slower to unlock. Do not reduce below 600000.
    iterations: 600000,
  },
};
