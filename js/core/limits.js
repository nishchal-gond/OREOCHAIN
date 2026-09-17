/**
 * Resource limits.
 *
 * Every limit here exists to turn an unbounded operation into a bounded one.
 * They are exported so a caller with different constraints — a server with
 * 16 GB of RAM, a phone browser with 300 MB — can raise or lower them
 * deliberately, instead of discovering the machine's limit by hitting it.
 */

export const MANIFEST_LIMITS = {
  /** At the 256 KiB default this covers a 1 TB file. */
  maxTotalChunks: 4_000_000,

  /** Largest file the format will describe. */
  maxFileSize: 1_099_511_627_776, // 1 TiB

  /** Largest permitted chunk size. */
  maxChunkSize: 67_108_864, // 64 MiB

  /** Largest AEAD expansion any suite adds (the cascade's two tags). */
  maxAeadOverhead: 64,

  /** A manifest is a chunk table; this bounds how large that JSON may be. */
  maxManifestBytes: 134_217_728, // 128 MiB

  /** PBKDF2 bounds. The floor is the OWASP recommendation. */
  minIterations: 600_000,
  maxIterations: 50_000_000,

  /**
   * Above this, restoreFile() refuses rather than assembling in memory.
   * Callers that can stream should use restoreFileStream() instead.
   */
  maxInMemoryBytes: 536_870_912, // 512 MiB
};

export const NETWORK_LIMITS = {
  /** Attempts per block, including the first. */
  maxAttempts: 4,
  /** Backoff base in milliseconds; doubles each retry with jitter. */
  backoffBaseMs: 250,
  maxBackoffMs: 8_000,
  /** Per-request timeout. */
  requestTimeoutMs: 60_000,
  /** Concurrent chunk transfers. */
  concurrency: 4,
};
