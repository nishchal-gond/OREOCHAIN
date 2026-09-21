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

  /**
   * PBKDF2 bounds, for legacy manifests. The floor is the OWASP
   * recommendation; a manifest claiming fewer is either broken or hostile.
   */
  minIterations: 600_000,
  maxIterations: 50_000_000,

  /**
   * Argon2id bounds.
   *
   * The floor matters as much as the ceiling: an attacker who can serve a
   * manifest could otherwise set memory to 8 KiB and make cracking the
   * passphrase as cheap as it was before Argon2id was adopted. The ceiling
   * stops the reverse attack — a manifest demanding 8 GiB to open.
   */
  minArgon2MemoryKiB: 19_456, // OWASP's floor: 19 MiB
  maxArgon2MemoryKiB: 2_097_152, // 2 GiB
  minArgon2Iterations: 1,
  maxArgon2Iterations: 16,
  minArgon2Parallelism: 1,
  maxArgon2Parallelism: 16,

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
  /**
   * The longest `Retry-After` worth sleeping through rather than reporting.
   *
   * A gateway asking for thirty seconds is a wobble to wait out. One asking
   * for ten minutes is telling the client a window has to roll, and holding a
   * browser tab silently for that is worse for the user than saying so.
   */
  maxRetryAfterMs: 30_000,
  /** Per-request timeout. */
  requestTimeoutMs: 60_000,
  /** Concurrent chunk transfers. */
  concurrency: 4,
};
