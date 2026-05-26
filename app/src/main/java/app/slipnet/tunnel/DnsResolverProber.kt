package app.slipnet.tunnel

import app.slipnet.util.AppLog as Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlin.math.max
import kotlin.math.min
import kotlin.random.Random

/**
 * Probe the configured DNS resolver(s) at connect time to pick the DNS query
 * length and (for VayDNS) outbound rate limit, replacing the user-set values.
 *
 * The probe talks to the real tunnel server via the configured resolver using
 * the protocol's actual record type. We only check that *a* DNS response
 * round-trips — RCODE doesn't matter, since the server answers `*.<domain>`
 * queries with either forged-stats payload or a session error and either
 * proves the path delivered.
 */
data class ProbeResult(
    val maxQnameLen: Int,
    val maxPayload: Int,
    val rpsLimit: Double,
    val probed: Boolean,  // false → fallback values, e.g. unsupported transport or full failure
)

object DnsResolverProber {
    private const val TAG = "DnsResolverProber"

    // DNS RR type codes (a subset matching the VayDNS UI picker).
    private val rrTypes = mapOf(
        "txt" to 16,
        "cname" to 5,
        "a" to 1,
        "aaaa" to 28,
        "mx" to 15,
        "ns" to 2,
        "srv" to 33,
        "null" to 10,
        "caa" to 257,
    )

    /**
     * Probe a resolver and return the chosen values.
     *
     * [resolvers] is a comma-separated list (the same format the user types in
     * the DNS Resolver field). Each entry can be `host`, `host:port`, or a
     * URL with `tls://` / `https://` / `tcp://` scheme. Non-UDP entries cause
     * the prober to fall back to a static preset (see [staticPreset]).
     *
     * [authoritative] true → DNSTT/NoizDNS authoritative mode is on. The probe
     * is skipped and a result with rpsLimit=0 / large qname is returned.
     */
    fun probe(
        resolvers: String,
        tunnelDomain: String,
        recordType: String,
        authoritative: Boolean,
        timeoutMs: Int = 1500,
    ): ProbeResult {
        val t0 = System.currentTimeMillis()
        Log.i(TAG, "[Auto] probe start: resolvers=$resolvers domain=$tunnelDomain rrtype=$recordType authoritative=$authoritative")
        if (authoritative) {
            val r = ProbeResult(maxQnameLen = 253, maxPayload = 0, rpsLimit = 0.0, probed = false)
            Log.i(TAG, "[Auto] result: authoritative mode → skip probe → $r (${System.currentTimeMillis() - t0}ms)")
            return r
        }

        val entries = resolvers.split(",").map { it.trim() }.filter { it.isNotEmpty() }
        if (entries.isEmpty() || tunnelDomain.isBlank()) {
            val r = safeDefaults()
            Log.w(TAG, "[Auto] no resolver or tunnel domain → $r (${System.currentTimeMillis() - t0}ms)")
            return r
        }

        // Any non-UDP entry → static preset (no real probe).
        val allUdp = entries.all { isPlainUdp(it) }
        if (!allUdp) {
            val preset = staticPreset(recordType)
            Log.i(TAG, "[Auto] non-UDP resolver(s) — static preset → $preset (${System.currentTimeMillis() - t0}ms)")
            return preset
        }

        val rrType = rrTypes[recordType.lowercase()] ?: 16  // default TXT
        val candidates = qnameCandidatesFor(tunnelDomain, recordType)
        Log.i(TAG, "[Auto] qname candidates: $candidates")

        // Probe all resolvers in parallel — each probe is ~2 s of blocking I/O so
        // running N resolvers sequentially used to add N×2 s of dead time before
        // the tunnel started. With a thread per resolver the whole set finishes in
        // roughly one resolver's time regardless of pool size.
        val executor = java.util.concurrent.Executors.newFixedThreadPool(entries.size.coerceIn(1, 16))
        val futures = entries.map { entry ->
            val (host, port) = parseHostPort(entry)
            Log.i(TAG, "[Auto] probing $host:$port …")
            executor.submit<Pair<Int, Double>?> {
                probeOne(host, port, tunnelDomain, rrType, candidates, timeoutMs)
            }
        }
        executor.shutdown()

        var minQname = Int.MAX_VALUE
        var minRps = Double.MAX_VALUE
        var anySucceeded = false

        entries.zip(futures).forEach { (entry, future) ->
            val (host, port) = parseHostPort(entry)
            val result = runCatching { future.get() }.getOrNull()
            if (result == null) {
                Log.w(TAG, "[Auto] $host:$port — no responses at any qname length")
                return@forEach
            }
            Log.i(TAG, "[Auto] $host:$port → qname=${result.first} rps=${result.second}")
            anySucceeded = true
            minQname = min(minQname, result.first)
            minRps = min(minRps, result.second)
        }

        if (!anySucceeded) {
            val r = safeDefaults()
            Log.w(TAG, "[Auto] all resolvers silent → $r (${System.currentTimeMillis() - t0}ms)")
            return r
        }

        val payload = dnsNameCapacity(tunnelDomain, minQname)
        val r = ProbeResult(
            maxQnameLen = minQname,
            maxPayload = payload,
            rpsLimit = if (minRps == Double.MAX_VALUE) 0.0 else minRps,
            probed = true,
        )
        Log.i(TAG, "[Auto] result: $r (${System.currentTimeMillis() - t0}ms)")
        return r
    }

    // --- internals ----

    private fun safeDefaults() = ProbeResult(maxQnameLen = 80, maxPayload = 0, rpsLimit = 2.0, probed = false)

    private fun staticPreset(recordType: String): ProbeResult {
        val rt = recordType.lowercase()
        val qname = if (rt == "txt") 120 else 100
        return ProbeResult(maxQnameLen = qname, maxPayload = 0, rpsLimit = 0.0, probed = false)
    }

    private fun isPlainUdp(entry: String): Boolean {
        val lower = entry.lowercase()
        return !lower.startsWith("https://") && !lower.startsWith("tls://") && !lower.startsWith("tcp://")
    }

    private fun parseHostPort(entry: String): Pair<String, Int> {
        // IPv6 bracketed
        if (entry.startsWith("[")) {
            val close = entry.indexOf(']')
            if (close > 0) {
                val host = entry.substring(1, close)
                val rest = entry.substring(close + 1)
                val port = if (rest.startsWith(":")) rest.substring(1).toIntOrNull() ?: 53 else 53
                return host to port
            }
        }
        // host:port (only one colon allowed; IPv6 must use brackets)
        val colon = entry.lastIndexOf(':')
        if (colon > 0 && entry.indexOf(':') == colon) {
            val host = entry.substring(0, colon)
            val port = entry.substring(colon + 1).toIntOrNull() ?: 53
            return host to port
        }
        return entry to 53
    }

    /**
     * Candidate QNAME lengths to probe. Generated from a coarse ladder, clamped
     * to the protocol-maximum (253 bytes including label headers) and to a
     * conservative floor.
     */
    private fun qnameCandidatesFor(tunnelDomain: String, recordType: String): List<Int> {
        // Resolvers may rewrite long QNAMEs for A/AAAA more aggressively than
        // for TXT, so cap A/AAAA a little tighter.
        val cap = when (recordType.lowercase()) {
            "a", "aaaa" -> 200
            else -> 240
        }
        val baseDomainLen = tunnelDomain.length + 2  // crude: dot + null terminator
        val minQname = max(60, baseDomainLen + 16)
        return listOf(minQname, 100, 150, 200, cap).distinct().sorted().filter { it <= 253 }
    }

    /**
     * Probe one resolver. Returns (maxQnameLen, rpsLimit) on success, null if
     * every length and the rate probe failed.
     */
    private fun probeOne(
        host: String,
        port: Int,
        tunnelDomain: String,
        rrType: Int,
        candidates: List<Int>,
        timeoutMs: Int,
    ): Pair<Int, Double>? {
        // 1) QNAME length scan: find the largest length where ≥1/2 queries
        //    got a DNS response.
        var bestQname = -1
        for (qname in candidates) {
            var hits = 0
            for (attempt in 0 until 2) {
                if (sendOne(host, port, makeProbeName(tunnelDomain, qname), rrType, timeoutMs)) {
                    hits++
                }
                if (attempt == 0) Thread.sleep(100)
            }
            Log.i(TAG, "[Auto]   qname=$qname → $hits/2 responses")
            if (hits >= 1) bestQname = qname
            // Don't stop early — a longer length might still work even if a
            // shorter one didn't on this round; but practically we expect
            // monotonic behavior. Stop at first failure to save time.
            else if (bestQname > 0) break
        }
        if (bestQname < 0) return null

        // 2) Rate probe at the chosen length. Send 10 queries at 50 q/s.
        val rate = rateProbe(host, port, tunnelDomain, rrType, bestQname, timeoutMs)
        return bestQname to rate
    }

    private fun rateProbe(
        host: String,
        port: Int,
        tunnelDomain: String,
        rrType: Int,
        qnameLen: Int,
        timeoutMs: Int,
    ): Double {
        val total = 10
        val gapMs = 20L  // 50 q/s
        var ok = 0
        for (i in 0 until total) {
            if (sendOne(host, port, makeProbeName(tunnelDomain, qnameLen), rrType, timeoutMs)) ok++
            Thread.sleep(gapMs)
        }
        val rps = when {
            ok >= 8 -> 0.0       // unlimited
            ok >= 4 -> 10.0
            else -> 2.0
        }
        Log.i(TAG, "[Auto]   rate probe @50q/s: $ok/$total responded → rps=$rps")
        return rps
    }

    /**
     * Build a probe QNAME `<random base32 padding>.<tunnelDomain>` padded to
     * approximately [targetTotalLen] wire bytes.
     */
    private fun makeProbeName(tunnelDomain: String, targetTotalLen: Int): String {
        val suffix = ".$tunnelDomain"
        // Each label is at most 63 chars; chain them if needed.
        val padBytes = max(8, targetTotalLen - suffix.length - 2)  // -2 for first label header + trailing dot
        val labels = mutableListOf<String>()
        var remaining = padBytes
        while (remaining > 0) {
            val take = min(remaining, 60)
            labels.add(randomBase32(take))
            remaining -= take
        }
        return labels.joinToString(".") + suffix
    }

    private fun randomBase32(n: Int): String {
        val alphabet = "abcdefghijklmnopqrstuvwxyz234567"
        val sb = StringBuilder(n)
        for (i in 0 until n) sb.append(alphabet[Random.nextInt(alphabet.length)])
        return sb.toString()
    }

    /** Send one UDP DNS query. Returns true iff *any* response came back. */
    private fun sendOne(host: String, port: Int, qname: String, rrType: Int, timeoutMs: Int): Boolean {
        var socket: DatagramSocket? = null
        return try {
            val query = buildDnsQuery(qname, rrType)
            socket = DatagramSocket()
            socket.soTimeout = timeoutMs.coerceIn(500, 5000)
            val addr = InetAddress.getByName(host)
            socket.send(DatagramPacket(query, query.size, addr, port))
            val buf = ByteArray(1500)
            val pkt = DatagramPacket(buf, buf.size)
            socket.receive(pkt)
            pkt.length >= 12  // at least a valid DNS header
        } catch (_: Exception) {
            false
        } finally {
            socket?.close()
        }
    }

    private fun buildDnsQuery(qname: String, rrType: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val txid = Random.nextInt(65536)
        out.write(txid shr 8); out.write(txid and 0xFF)
        // Flags: standard query, recursion desired
        out.write(0x01); out.write(0x00)
        // QDCOUNT=1, ANCOUNT/NSCOUNT/ARCOUNT=0
        out.write(0); out.write(1)
        out.write(0); out.write(0)
        out.write(0); out.write(0)
        out.write(0); out.write(0)
        // QNAME labels
        for (label in qname.split(".")) {
            val len = label.length.coerceAtMost(63)
            out.write(len)
            for (i in 0 until len) out.write(label[i].code)
        }
        out.write(0)  // root
        out.write(rrType shr 8); out.write(rrType and 0xFF)
        out.write(0); out.write(1)  // class IN
        return out.toByteArray()
    }

    /**
     * Mirror of the Go-side `dnsNameCapacity` (dnstt) / `DNSNameCapacity`
     * (vaydns) helpers. Approximates the bytes of binary payload that fit in
     * a QNAME of [qnameLen] wire bytes after base32 encoding (5 bytes →
     * 8 chars), label overhead (1 byte per 63 chars), and the trailing
     * tunnel-domain suffix.
     */
    private fun dnsNameCapacity(tunnelDomain: String, qnameLen: Int): Int {
        val suffixWire = tunnelDomain.length + 2  // each label header byte ≈ accounted for
        val available = qnameLen - suffixWire
        if (available <= 0) return 0
        // Subtract label headers: 1 byte per 63-char label
        val labels = (available + 62) / 63
        val charsForPayload = available - labels
        if (charsForPayload <= 0) return 0
        // base32: 8 chars carry 5 bytes
        return (charsForPayload * 5) / 8
    }
}
