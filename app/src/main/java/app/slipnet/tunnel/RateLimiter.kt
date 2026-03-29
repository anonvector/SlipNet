package app.slipnet.tunnel

/**
 * Token-bucket rate limiter for bandwidth limiting.
 * Thread-safe — multiple copyStream threads share a single instance.
 *
 * Tokens can go negative: a large read (e.g., 64KB buffer) at a low rate
 * (e.g., 32 KB/s) immediately deducts the full amount, then sleeps for the
 * debt. This avoids deadlock when a single read exceeds the per-second rate.
 *
 * @param bytesPerSecond Maximum throughput in bytes/sec. 0 = unlimited.
 */
class RateLimiter(bytesPerSecond: Long) {
    @Volatile
    var bytesPerSecond: Long = bytesPerSecond
        set(value) {
            field = value
            synchronized(lock) {
                tokens = value.toDouble()
                lastRefillNanos = System.nanoTime()
            }
        }

    private val lock = Any()
    private var tokens: Double = bytesPerSecond.toDouble()
    private var lastRefillNanos: Long = System.nanoTime()

    /**
     * Blocks until [byteCount] bytes are permitted. Does nothing if rate is 0 (unlimited).
     */
    fun acquire(byteCount: Int) {
        val rate = bytesPerSecond
        if (rate <= 0 || byteCount <= 0) return

        val sleepMs: Long
        synchronized(lock) {
            refill()
            tokens -= byteCount
            if (tokens >= 0) return  // enough tokens, no wait
            // Tokens are negative — sleep for the debt to recover.
            sleepMs = ((-tokens / rate) * 1000).toLong().coerceAtLeast(1)
        }
        try {
            Thread.sleep(sleepMs)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    private fun refill() {
        val now = System.nanoTime()
        val elapsed = now - lastRefillNanos
        if (elapsed <= 0) return
        val rate = bytesPerSecond
        val newTokens = (elapsed.toDouble() / 1_000_000_000.0) * rate
        // Cap at 1 second of burst to prevent accumulating huge allowances during idle.
        // Negative tokens (debt from large reads) are recovered naturally through refill.
        tokens = (tokens + newTokens).coerceAtMost(rate.toDouble())
        lastRefillNanos = now
    }
}
