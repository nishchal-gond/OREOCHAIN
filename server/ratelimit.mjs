/**
 * Token-bucket rate limiting, per API key.
 *
 * A bucket refills at a steady rate up to a burst ceiling. That shape suits
 * chunked uploads: a client legitimately sends a few hundred requests back to
 * back for one file, then goes quiet. A fixed per-second cap would reject
 * normal traffic; a pure quota would let one client monopolise the service.
 */

export function createRateLimiter({ perMinute, burst, now = () => Date.now() } = {}) {
  const ratePerMs = perMinute / 60000;
  const buckets = new Map();

  function take(key, cost = 1) {
    const timestamp = now();
    let bucket = buckets.get(key);

    if (!bucket) {
      bucket = { tokens: burst, updated: timestamp };
      buckets.set(key, bucket);
    }

    bucket.tokens = Math.min(burst, bucket.tokens + (timestamp - bucket.updated) * ratePerMs);
    bucket.updated = timestamp;

    if (bucket.tokens < cost) {
      const deficit = cost - bucket.tokens;
      return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil(deficit / ratePerMs / 1000)) };
    }

    bucket.tokens -= cost;
    return { allowed: true, remaining: Math.floor(bucket.tokens) };
  }

  /** Drop idle buckets so a long-running process does not grow without bound. */
  function sweep(maxIdleMs = 3600000) {
    const timestamp = now();
    for (const [key, bucket] of buckets) {
      if (timestamp - bucket.updated > maxIdleMs) buckets.delete(key);
    }
    return buckets.size;
  }

  return { take, sweep, size: () => buckets.size };
}
