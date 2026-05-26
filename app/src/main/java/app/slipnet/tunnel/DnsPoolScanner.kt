package app.slipnet.tunnel

import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.repository.ResolverScannerRepository
import app.slipnet.util.AppLog as Log
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit

/**
 * Distilled view of an in-flight pool scan. Exposed via VpnRepositoryImpl so
 * the main screen can render a progress strip without knowing per-resolver
 * details.
 */
data class DnsPoolScanState(
    val isRunning: Boolean = false,
    /** Pool size (denominator for the prefilter progress). */
    val total: Int = 0,
    /** Phase-1 entries that have finished the `isResolverAlive` check. */
    val probed: Int = 0,
    /** Phase-1 entries that came back alive — these get queued for E2E. */
    val alive: Int = 0,
    /** Phase-2 successes (full E2E with HTTP/SSH verification). */
    val verified: Int = 0,
)

/** A parsed entry from the user's per-profile pool text. */
data class PoolEntry(val host: String, val port: Int) {
    /** Reconstruct the address in the same `host` or `host:port` form. */
    fun asAddress(): String = if (port == 53) host else "$host:$port"
}

/**
 * Scans a per-profile pool of DNS resolvers using the existing isolated E2E
 * tunnel probe and returns the [TOP_N] entries with the lowest tunnel-setup
 * latency.
 *
 * "Like simple mode" means we use the same E2E test the scanner UI uses
 * (testResolverE2eIsolated, fullVerification=false). Transport is taken from
 * `profile.dnsTransport`, so a TCP-config pool is probed over TCP and a UDP
 * pool over UDP without extra wiring.
 */
object DnsPoolScanner {
    private const val TAG = "DnsPoolScanner"
    private const val TIMEOUT_FULL_VERIFICATION_MS = 18_000L
    private const val TIMEOUT_HANDSHAKE_ONLY_MS = 10_000L
    const val TOP_N = 10
    const val MAX_POOL_SIZE = 1000

    /**
     * Test URL used by the HTTP-verification phase for non-SSH tunnel
     * variants. Matches the on-screen DNS scanner's default
     * (`PreferencesDataStore.scannerTestUrl`). `generate_204` returns a 204
     * with an empty body — zero bytes after headers and no TLS handshake,
     * so the verification adds minimal overhead on top of the tunnel
     * handshake. SSH variants ignore this and verify with a banner read.
     */
    private const val VERIFICATION_URL = "http://www.gstatic.com/generate_204"

    /**
     * Pool-scan concurrency. Higher than the on-screen scanner's
     * [ResolverScannerRepository.maxE2eConcurrency] (10) because here the user
     * is waiting on a single connect — the throughput win outweighs the
     * extra memory pressure from 20 concurrent DNSTT/Noise/KCP/smux clients.
     * Slipstream stays at 1 (native singleton).
     */
    private const val POOL_CONCURRENCY = 20

    /**
     * Phase 1 (isResolverAlive prefilter) concurrency. A single UDP/TCP DNS
     * query is much cheaper than a full DNSTT tunnel session, so we can run
     * far more in parallel — purpose is to weed out dead / censored IPs in a
     * few seconds so phase 2 only spends its 12 s probe budget on resolvers
     * that have at least a pulse.
     */
    private const val PHASE1_CONCURRENCY = 70
    private const val PHASE1_TIMEOUT_MS = 3_000L

    /**
     * Parse the user-entered pool text into validated entries. One IP/host
     * per line; blanks and `#` comments are skipped; `host:port` form is
     * recognized; capped at [MAX_POOL_SIZE].
     */
    fun parsePool(text: String): List<PoolEntry> {
        return text.split('\n', ',')
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .mapNotNull { parseEntry(it) }
            .distinctBy { "${it.host}:${it.port}" }
            .take(MAX_POOL_SIZE)
            .toList()
    }

    private fun parseEntry(entry: String): PoolEntry? {
        if (entry.isEmpty()) return null
        // IPv6 bracketed form: [::1]:53
        if (entry.startsWith("[")) {
            val close = entry.indexOf(']')
            if (close <= 1) return null
            val host = entry.substring(1, close)
            val rest = entry.substring(close + 1)
            val port = if (rest.startsWith(":")) rest.substring(1).toIntOrNull() ?: 53 else 53
            return PoolEntry(host, port)
        }
        // Single colon → host:port. Multiple colons → bare IPv6 (no port).
        val firstColon = entry.indexOf(':')
        val lastColon = entry.lastIndexOf(':')
        if (firstColon > 0 && firstColon == lastColon) {
            val host = entry.substring(0, firstColon)
            val port = entry.substring(firstColon + 1).toIntOrNull() ?: 53
            return PoolEntry(host, port)
        }
        return PoolEntry(entry, 53)
    }

    /**
     * Streaming two-phase pool scan (producer/consumer pipeline):
     *
     * **Phase 1 — `isResolverAlive` prefilter** runs all entries in parallel
     * at concurrency 50, 3 s each. As soon as an entry comes back alive it
     * is **immediately** queued for phase 2 — no waiting for the whole
     * prefilter to finish.
     *
     * **Phase 2 — full E2E** workers (20 of them) pull survivors from the
     * survivor channel and run `testResolverE2eIsolated(fullVerification=true)`:
     * Noise/KCP/smux handshake + HTTP `generate_204` (or SSH banner) through
     * the tunnel. Each success counts toward the [TOP_N] early-exit target.
     *
     * Both phases run concurrently, so the user usually sees the first ✓ a
     * few seconds in — well before the prefilter has even scanned half the
     * pool.
     *
     * Progress is reported via [onProgress] with running totals:
     *   - probed: phase-1 entries finished
     *   - alive:  phase-1 survivors so far (= phase-2 queue + done)
     *   - verified: phase-2 successes so far (the ✓ count)
     */
    suspend fun scan(
        scanner: ResolverScannerRepository,
        profile: ServerProfile,
        entries: List<PoolEntry>,
        fullVerification: Boolean = false,
        onProgress: (probed: Int, alive: Int, verified: Int) -> Unit,
        onJobStart: (kotlinx.coroutines.Job) -> Unit = {},
    ): List<Pair<PoolEntry, Long>> {
        if (entries.isEmpty()) return emptyList()

        val shuffled = entries.shuffled()

        // Detached SupervisorJob (see earlier comment): structured
        // concurrency with the caller would force startDnsttProxy to wait
        // for every probe's Go cleanup before returning.
        val probesJob = kotlinx.coroutines.SupervisorJob()
        onJobStart(probesJob)
        val probeScope = kotlinx.coroutines.CoroutineScope(
            kotlin.coroutines.coroutineContext + probesJob
        )

        val perResolverTimeoutMs = if (fullVerification) TIMEOUT_FULL_VERIFICATION_MS else TIMEOUT_HANDSHAKE_ONLY_MS
        val scannerCap = scanner.maxE2eConcurrency(profile).coerceAtLeast(1)
        val phase2Concurrency = if (scannerCap == 1) 1 else POOL_CONCURRENCY
        Log.i(TAG, "[Pool] scan start: ${shuffled.size} entries (shuffled), phase1=$PHASE1_CONCURRENCY, phase2=$phase2Concurrency, fullVerification=$fullVerification, timeoutMs=$perResolverTimeoutMs, exitAt=$TOP_N successes")

        // Pipeline: phase 1 → survivorChannel → phase 2 workers → resultChannel → collector
        val survivorChannel = kotlinx.coroutines.channels.Channel<PoolEntry>(
            kotlinx.coroutines.channels.Channel.UNLIMITED
        )
        val resultChannel = kotlinx.coroutines.channels.Channel<Pair<PoolEntry, app.slipnet.domain.model.E2eTestResult>>(
            kotlinx.coroutines.channels.Channel.UNLIMITED
        )

        val probed = java.util.concurrent.atomic.AtomicInteger(0)
        val alive = java.util.concurrent.atomic.AtomicInteger(0)
        val verified = java.util.concurrent.atomic.AtomicInteger(0)
        val testDomain = profile.domain.ifBlank { "example.com" }

        // ─── Phase 1: launch all probes, stream survivors out ─────
        // We wrap them in a coroutineScope so this coroutine waits for all
        // 500 launches to complete before closing survivorChannel. Cancel-
        // lation via probesJob.cancel() short-circuits the wait.
        probeScope.launch {
            val phase1Sem = Semaphore(PHASE1_CONCURRENCY)
            try {
                kotlinx.coroutines.coroutineScope {
                    shuffled.forEach { entry ->
                        launch {
                            val ok = phase1Sem.withPermit {
                                scanner.isResolverAlive(
                                    host = entry.host,
                                    // DoT defaults to 853; for phase 1 we
                                    // always probe UDP/53 since IP liveness
                                    // is what we're checking.
                                    port = if (entry.port == 853) 53 else entry.port,
                                    testDomain = testDomain,
                                    timeoutMs = PHASE1_TIMEOUT_MS,
                                    transport = app.slipnet.domain.model.DnsTransport.UDP,
                                )
                            }
                            val p = probed.incrementAndGet()
                            val a = if (ok) alive.incrementAndGet() else alive.get()
                            onProgress(p, a, verified.get())
                            if (ok) survivorChannel.trySend(entry)
                        }
                    }
                }
            } finally {
                survivorChannel.close()  // signal phase-2 workers no more survivors coming
                Log.i(TAG, "[Pool] phase 1 done: ${alive.get()}/${shuffled.size} alive")
            }
        }

        // ─── Phase 2: workers pull from survivorChannel, run E2E ──
        // Each worker processes one entry at a time, so phase2Concurrency
        // workers ≡ at most phase2Concurrency concurrent E2E tests.
        probeScope.launch {
            try {
                kotlinx.coroutines.coroutineScope {
                    repeat(phase2Concurrency) {
                        launch {
                            for (entry in survivorChannel) {
                                val r = scanner.testResolverE2eIsolated(
                                    resolverHost = entry.host,
                                    resolverPort = entry.port,
                                    profile = profile,
                                    testUrl = VERIFICATION_URL,
                                    timeoutMs = perResolverTimeoutMs,
                                    fullVerification = fullVerification,
                                    onPhaseUpdate = {}
                                )
                                resultChannel.trySend(entry to r)
                            }
                        }
                    }
                }
            } finally {
                resultChannel.close()  // signal collector no more results coming
            }
        }

        // ─── Collector: stop at TOP_N successes or when pipeline drains ──
        val collected = mutableListOf<Pair<PoolEntry, app.slipnet.domain.model.E2eTestResult>>()
        var earlyExit = false
        try {
            for ((entry, result) in resultChannel) {
                collected.add(entry to result)
                if (result.success) {
                    val v = verified.incrementAndGet()
                    onProgress(probed.get(), alive.get(), v)
                    if (v >= TOP_N) {
                        Log.i(TAG, "[Pool] early-exit: $TOP_N verified after probed=${probed.get()}/${shuffled.size} alive=${alive.get()}")
                        earlyExit = true
                        break
                    }
                }
            }
        } finally {
            probesJob.cancel()  // fire-and-forget cleanup
        }

        val top = collected
            .filter { (_, r) -> r.success && r.totalMs > 0 }
            .sortedBy { (_, r) -> r.totalMs }
            .take(TOP_N)
            .map { (e, r) -> e to r.totalMs }
        Log.i(TAG, "[Pool] scan done: probed=${probed.get()}/${shuffled.size} alive=${alive.get()} verified=${verified.get()} earlyExit=$earlyExit top=${top.map { "${it.first.asAddress()}@${it.second}ms" }}")
        return top
    }
}
