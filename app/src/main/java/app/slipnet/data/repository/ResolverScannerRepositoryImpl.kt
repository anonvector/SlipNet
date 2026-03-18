package app.slipnet.data.repository

import android.content.Context
import android.os.SystemClock
import android.util.Log
import app.slipnet.R
import app.slipnet.domain.model.DnsTransport
import app.slipnet.domain.model.DnsTunnelTestResult
import app.slipnet.domain.model.E2eTestPhase
import app.slipnet.domain.model.E2eTestResult
import app.slipnet.domain.model.ResolverScanResult
import app.slipnet.domain.model.ResolverStatus
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TunnelType
import app.slipnet.domain.repository.ResolverScannerRepository
import app.slipnet.domain.model.SshAuthType
import app.slipnet.tunnel.DnsttBridge
import app.slipnet.tunnel.DnsttSocksBridge
import app.slipnet.tunnel.ResolverConfig
import app.slipnet.tunnel.SlipstreamBridge
import com.jcraft.jsch.JSch
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.async
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import app.slipnet.tunnel.DomainRouter
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.net.URL
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.random.Random

@Singleton
class ResolverScannerRepositoryImpl @Inject constructor(
    @ApplicationContext private val context: Context
) : ResolverScannerRepository {

    private var cachedResolvers: List<String>? = null
    private var cachedTierBoundaries: List<Int> = emptyList()

    override fun getDefaultResolvers(): List<String> {
        cachedResolvers?.let { return it }

        // Load from raw resource file; supports N "# SHUFFLE_BELOW" markers:
        // - Before first marker: top priority resolvers (not shuffled, scanned first)
        // - Between consecutive markers: independent tiers (each shuffled separately)
        // - After last marker: remaining resolvers (shuffled, scanned last)
        val resolvers = mutableListOf<String>()
        val seen = mutableSetOf<String>()
        val boundaries = mutableListOf<Int>()
        try {
            context.resources.openRawResource(R.raw.resolvers).bufferedReader().useLines { lines ->
                for (line in lines) {
                    val trimmed = line.trim()
                    if (trimmed == "# SHUFFLE_BELOW") {
                        boundaries.add(resolvers.size)
                        continue
                    }
                    if (trimmed.isNotBlank() && !trimmed.startsWith("#") && isValidIpAddress(trimmed) && seen.add(trimmed)) {
                        resolvers.add(trimmed)
                    }
                }
            }
        } catch (e: Exception) {
            return listOf("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1")
        }

        cachedTierBoundaries = boundaries
        cachedResolvers = resolvers
        Log.d("ResolverScanner", "Parsed ${resolvers.size} resolvers, tiers=${boundaries.size + 1}, boundaries=$boundaries, first5=${resolvers.take(5)}")
        return resolvers
    }

    override fun getDefaultResolverTierBoundaries(): List<Int> {
        if (cachedResolvers == null) getDefaultResolvers()
        return cachedTierBoundaries
    }

    override fun parseResolverList(content: String): List<String> {
        return parseResolverList(java.io.BufferedReader(java.io.StringReader(content)))
    }

    override fun parseResolverList(reader: java.io.BufferedReader): List<String> {
        val seen = mutableSetOf<String>()
        val result = mutableListOf<String>()
        reader.forEachLine { line ->
            extractIpsFromLine(line, seen, result)
        }
        return result
    }

    /**
     * Extract all valid IPv4 addresses from a single line without regex.
     * Scans for digit sequences separated by dots (e.g. "1.2.3.4").
     */
    private fun extractIpsFromLine(line: String, seen: MutableSet<String>, out: MutableList<String>) {
        var i = 0
        val len = line.length
        while (i < len) {
            // Skip to the start of a potential IP (first digit not preceded by a word char)
            if (!line[i].isDigit()) { i++; continue }
            if (i > 0 && (line[i - 1].isLetterOrDigit() || line[i - 1] == '.')) { i++; continue }

            val start = i
            var dots = 0
            var octetStart = i
            var valid = true

            while (i < len && (line[i].isDigit() || line[i] == '.')) {
                if (line[i] == '.') {
                    if (!validateOctet(line, octetStart, i)) { valid = false; break }
                    dots++
                    if (dots > 3) { valid = false; break }
                    octetStart = i + 1
                }
                i++
            }

            // Check trailing char isn't a word char (boundary check)
            if (i < len && (line[i].isLetterOrDigit())) { valid = false }

            if (valid && dots == 3 && octetStart < i && validateOctet(line, octetStart, i)) {
                val ip = normalizeIp(line, start, i)
                if (seen.add(ip)) out.add(ip)
            }
        }
    }

    /** Validate an octet substring [from, to) is 0-255. Allows leading zeros (e.g. "006"). */
    private fun validateOctet(s: String, from: Int, to: Int): Boolean {
        val len = to - from
        if (len == 0 || len > 3) return false
        var num = 0
        for (j in from until to) {
            num = num * 10 + (s[j] - '0')
        }
        return num in 0..255
    }

    /** Normalize an IP substring by stripping leading zeros from each octet (e.g. "006.132.048.001" → "6.132.48.1"). */
    private fun normalizeIp(s: String, from: Int, to: Int): String {
        val raw = s.substring(from, to)
        val parts = raw.split(".")
        return parts.joinToString(".") { it.trimStart('0').ifEmpty { "0" } }
    }

    private fun isValidIpAddress(ip: String): Boolean {
        val parts = ip.split(".")
        if (parts.size != 4) return false
        return parts.all { part ->
            val num = part.toIntOrNull() ?: return@all false
            num in 0..255
        }
    }

    /**
     * Generate random subdomain to avoid DNS caching
     */
    private fun generateRandomSubdomain(): String {
        val chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        return (1..8).map { chars[Random.nextInt(chars.length)] }.joinToString("")
    }

    override suspend fun scanResolver(
        host: String,
        port: Int,
        testDomain: String,
        timeoutMs: Long
    ): ResolverScanResult = withContext(Dispatchers.IO) {
        val startTime = SystemClock.elapsedRealtime()

        try {
            scanResolverDnsTunnel(host, port, testDomain, timeoutMs, startTime)
        } catch (e: Exception) {
            val responseTime = SystemClock.elapsedRealtime() - startTime
            ResolverScanResult(
                host = host,
                port = port,
                status = ResolverStatus.ERROR,
                responseTimeMs = responseTime,
                errorMessage = e.message ?: "Unknown error"
            )
        }
    }

    /**
     * DNS Tunnel compatibility scan - tests NS, TXT records and random subdomain support
     */
    private suspend fun scanResolverDnsTunnel(
        host: String,
        port: Int,
        testDomain: String,
        timeoutMs: Long,
        startTime: Long
    ): ResolverScanResult = withContext(Dispatchers.IO) {
        // For tunnel subdomains like "t.example.com", queries hit the DNSTT server
        // which can't answer generic DNS queries. Use the parent zone for basic/NS/TXT
        // tests and the actual tunnel domain for random subdomain tests (which prove
        // the delegation chain works).
        val parentDomain = getParentDomain(testDomain)

        // First, do a basic connectivity check (against the parent zone)
        val basicCheck = withTimeoutOrNull(timeoutMs) {
            val randSub = generateRandomSubdomain()
            performDnsQuery(host, port, "$randSub.$parentDomain", DNS_TYPE_A, timeoutMs)
        }

        if (basicCheck == null) {
            val responseTime = SystemClock.elapsedRealtime() - startTime
            return@withContext ResolverScanResult(
                host = host,
                port = port,
                status = ResolverStatus.TIMEOUT,
                responseTimeMs = responseTime
            )
        }

        // Run all tunnel compatibility tests in parallel
        val nsDeferred = async { testNsDelegation(host, port, testDomain, timeoutMs) }
        val txtDeferred = async { testRecordType(host, port, parentDomain, DNS_TYPE_TXT, timeoutMs) }
        val rndDeferred = async {
            testRandomSubdomain(host, port, testDomain, timeoutMs)
                || testRandomSubdomain(host, port, testDomain, timeoutMs)
        }
        val tunnelRealismDeferred = async { testTunnelRealism(host, port, testDomain, timeoutMs) }
        val ednsDeferred = async { probeEdnsMaxPayload(host, port, testDomain, timeoutMs) }
        val nxdomainDeferred = async { testNxdomainCorrect(host, port, timeoutMs) }

        val nsSupport = nsDeferred.await()
        val txtSupport = txtDeferred.await()
        val randomSubdomain = rndDeferred.await()
        val tunnelRealism = tunnelRealismDeferred.await()
        val ednsMaxPayload = ednsDeferred.await()
        val edns0Support = ednsMaxPayload > 0
        val nxdomainCorrect = nxdomainDeferred.await()

        val responseTime = SystemClock.elapsedRealtime() - startTime

        val tunnelResult = DnsTunnelTestResult(
            nsSupport = nsSupport,
            txtSupport = txtSupport,
            randomSubdomain = randomSubdomain,
            tunnelRealism = tunnelRealism,
            edns0Support = edns0Support,
            ednsMaxPayload = ednsMaxPayload,
            nxdomainCorrect = nxdomainCorrect
        )

        // Mark as WORKING if resolver responded (basic check passed above)
        // Score indicates tunnel compatibility quality (5/5 = fully compatible)
        ResolverScanResult(
            host = host,
            port = port,
            status = ResolverStatus.WORKING,
            responseTimeMs = responseTime,
            tunnelTestResult = tunnelResult
        )
    }

    /**
     * Test if a specific DNS record type is supported
     */
    private suspend fun testRecordType(
        host: String,
        port: Int,
        testDomain: String,
        recordType: Int,
        timeoutMs: Long
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            val randSub = generateRandomSubdomain()
            val queryDomain = "$randSub.$testDomain"
            val result = withTimeoutOrNull(timeoutMs) {
                performDnsQuery(host, port, queryDomain, recordType, timeoutMs)
            }
            // Success if we got a response OR if we got NXDOMAIN/NOERROR
            // (NXDOMAIN is acceptable - means server queried properly)
            result != null
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Test random nested subdomain resolution
     */
    private suspend fun testRandomSubdomain(
        host: String,
        port: Int,
        testDomain: String,
        timeoutMs: Long
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            val randSub1 = generateRandomSubdomain()
            val randSub2 = generateRandomSubdomain()
            val queryDomain = "$randSub1.$randSub2.$testDomain"
            val result = withTimeoutOrNull(timeoutMs) {
                performDnsQuery(host, port, queryDomain, DNS_TYPE_A, timeoutMs)
            }
            // Any response (including NXDOMAIN) means the resolver processed the query
            result != null
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Tunnel realism test — sends a query that mimics real dnstt/Slipstream wire
     * format: a long base32-encoded random payload as the subdomain with QTYPE=TXT.
     * DPI systems that fingerprint DNS tunnels by entropy/length/record-type will
     * drop this query while allowing the shorter random-subdomain tests above.
     * Getting a response (even NXDOMAIN) means the resolver passes tunnel traffic.
     */
    private suspend fun testTunnelRealism(
        host: String,
        port: Int,
        testDomain: String,
        timeoutMs: Long
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            // Generate a random payload roughly the size dnstt/Slipstream would use
            // (80-120 bytes → ~130-192 base32 chars, split into 57-char DNS labels).
            val payloadBytes = ByteArray(100).also { Random.nextBytes(it) }
            val base32Sub = base32Encode(payloadBytes)
            val dotified = dotifyBase32(base32Sub)
            val queryDomain = "$dotified.$testDomain"

            val result = withTimeoutOrNull(timeoutMs) {
                performDnsQuery(host, port, queryDomain, DNS_TYPE_TXT, timeoutMs)
            }
            // Any response (including NXDOMAIN/SERVFAIL) means the query survived DPI
            result != null
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Probe the maximum EDNS payload size the resolver supports.
     * Tests sizes 512, 900, 1232 in order; returns the largest that works.
     * 1232 is ideal for DNS tunnels (matches dnsflagday.net recommendation).
     * Returns 0 if no EDNS support detected.
     */
    private suspend fun probeEdnsMaxPayload(
        host: String,
        port: Int,
        testDomain: String,
        timeoutMs: Long
    ): Int = withContext(Dispatchers.IO) {
        val sizes = intArrayOf(512, 900, 1232)
        var maxWorking = 0

        for (size in sizes) {
            try {
                val queryDomain = "${generateRandomSubdomain()}.$testDomain"
                val dnsQuery = buildDnsQueryWithEdns0(queryDomain, DNS_TYPE_TXT, size)
                val serverAddress = InetAddress.getByName(host)

                val socket = DatagramSocket()
                socket.soTimeout = timeoutMs.toInt().coerceIn(500, 30000)
                try {
                    val requestPacket = DatagramPacket(dnsQuery, dnsQuery.size, serverAddress, port)
                    socket.send(requestPacket)

                    val responseBuffer = ByteArray(4096)
                    val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
                    socket.receive(responsePacket)

                    val len = responsePacket.length
                    if (len >= 12) {
                        // Check RCODE isn't FORMERR (1) — some resolvers reject unknown EDNS sizes
                        val rcode = responseBuffer[3].toInt() and 0x0F
                        if (rcode != 1 && hasOptRecord(responseBuffer, len)) {
                            maxWorking = size
                        }
                    }
                } finally {
                    socket.close()
                }
            } catch (_: Exception) {
                // This size failed; try next
            }
        }

        maxWorking
    }

    /**
     * Test NXDOMAIN correctness: query a guaranteed non-existent domain and check
     * that the resolver returns RCODE=NXDOMAIN (3). Hijacking resolvers return
     * NOERROR with spoofed answers, which breaks DNS tunnel protocols.
     * Tests 3 times, passes if at least 2 return proper NXDOMAIN.
     */
    private suspend fun testNxdomainCorrect(
        host: String,
        port: Int,
        timeoutMs: Long
    ): Boolean = withContext(Dispatchers.IO) {
        var nxdomainCount = 0
        val attempts = 3

        for (i in 0 until attempts) {
            try {
                // Query a domain under .invalid (RFC 6761 — guaranteed non-existent)
                val randomLabel = generateRandomSubdomain()
                val queryDomain = "nxd-$randomLabel.invalid"

                val result = withTimeoutOrNull(timeoutMs) {
                    performDnsQuery(host, port, queryDomain, DNS_TYPE_A, timeoutMs)
                }

                if (result != null && result.responseCode == 3) {
                    // RCODE 3 = NXDOMAIN — correct behavior
                    nxdomainCount++
                }
                // RCODE 0 with no answer = also acceptable (some resolvers)
                // RCODE 0 with an answer IP = hijacking
                if (result != null && result.responseCode == 0 && result.resolvedIp != null) {
                    // Resolver returned a fake answer — hijacking detected
                    // Don't increment nxdomainCount
                }
            } catch (_: Exception) {
                // Timeout or error — don't count
            }
        }

        // Pass if at least 2 out of 3 returned proper NXDOMAIN
        nxdomainCount >= 2
    }

    /**
     * Build a DNS query with EDNS0 OPT record in the additional section.
     * The OPT record advertises the given UDP payload size to the resolver.
     */
    private fun buildDnsQueryWithEdns0(domain: String, recordType: Int, udpPayloadSize: Int): ByteArray {
        val buffer = mutableListOf<Byte>()

        // Transaction ID (random)
        val transactionId = Random.nextInt(65536)
        buffer.add((transactionId shr 8).toByte())
        buffer.add((transactionId and 0xFF).toByte())

        // Flags: Standard query, RD=1 (0x0100)
        buffer.add(0x01.toByte())
        buffer.add(0x00.toByte())

        // Questions: 1
        buffer.add(0x00.toByte())
        buffer.add(0x01.toByte())

        // Answer RRs: 0
        buffer.add(0x00.toByte())
        buffer.add(0x00.toByte())

        // Authority RRs: 0
        buffer.add(0x00.toByte())
        buffer.add(0x00.toByte())

        // Additional RRs: 1 (OPT record)
        buffer.add(0x00.toByte())
        buffer.add(0x01.toByte())

        // Query name
        domain.split(".").forEach { label ->
            buffer.add(label.length.toByte())
            label.forEach { buffer.add(it.code.toByte()) }
        }
        buffer.add(0x00.toByte()) // Null terminator

        // Query type
        buffer.add((recordType shr 8).toByte())
        buffer.add((recordType and 0xFF).toByte())

        // Query class: IN (0x0001)
        buffer.add(0x00.toByte())
        buffer.add(0x01.toByte())

        // --- OPT pseudo-RR (RFC 6891) ---
        buffer.add(0x00.toByte())                            // Name: root (empty)
        buffer.add(0x00.toByte()); buffer.add(0x29.toByte()) // Type: OPT (41)
        buffer.add((udpPayloadSize shr 8).toByte())          // Class = UDP payload size (high)
        buffer.add((udpPayloadSize and 0xFF).toByte())       // Class = UDP payload size (low)
        buffer.add(0x00.toByte())                            // Extended RCODE: 0
        buffer.add(0x00.toByte())                            // EDNS version: 0
        buffer.add(0x00.toByte()); buffer.add(0x00.toByte()) // Flags: 0 (no DO bit)
        buffer.add(0x00.toByte()); buffer.add(0x00.toByte()) // RDATA length: 0

        return buffer.toByteArray()
    }

    /**
     * Check if the DNS response contains an OPT record (type 41) in the additional section.
     */
    private fun hasOptRecord(response: ByteArray, length: Int): Boolean {
        if (length < 12) return false

        val qdCount = ((response[4].toInt() and 0xFF) shl 8) or (response[5].toInt() and 0xFF)
        val anCount = ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)
        val nsCount = ((response[8].toInt() and 0xFF) shl 8) or (response[9].toInt() and 0xFF)
        val arCount = ((response[10].toInt() and 0xFF) shl 8) or (response[11].toInt() and 0xFF)

        if (arCount == 0) return false

        // Skip past header
        var offset = 12

        // Skip question section
        for (i in 0 until qdCount) {
            offset = skipDnsName(response, offset, length) ?: return false
            offset += 4 // QTYPE + QCLASS
            if (offset > length) return false
        }

        // Skip answer + authority sections
        for (i in 0 until (anCount + nsCount)) {
            offset = skipDnsName(response, offset, length) ?: return false
            if (offset + 10 > length) return false
            val rdLength = ((response[offset + 8].toInt() and 0xFF) shl 8) or (response[offset + 9].toInt() and 0xFF)
            offset += 10 + rdLength
            if (offset > length) return false
        }

        // Parse additional section looking for OPT (type 41)
        for (i in 0 until arCount) {
            offset = skipDnsName(response, offset, length) ?: return false
            if (offset + 10 > length) return false
            val rrType = ((response[offset].toInt() and 0xFF) shl 8) or (response[offset + 1].toInt() and 0xFF)
            if (rrType == 41) return true // Found OPT record
            val rdLength = ((response[offset + 8].toInt() and 0xFF) shl 8) or (response[offset + 9].toInt() and 0xFF)
            offset += 10 + rdLength
            if (offset > length) return false
        }

        return false
    }

    /**
     * Skip a DNS name (handles both labels and compression pointers).
     * Returns the offset after the name, or null on error.
     */
    private fun skipDnsName(data: ByteArray, startOffset: Int, length: Int): Int? {
        var offset = startOffset
        while (offset < length) {
            val labelLen = data[offset].toInt() and 0xFF
            if (labelLen == 0) {
                return offset + 1 // End of name
            }
            if ((labelLen and 0xC0) == 0xC0) {
                return offset + 2 // Compression pointer (2 bytes)
            }
            offset += 1 + labelLen
        }
        return null // Ran past end
    }

    /**
     * RFC 4648 base32 encode (A-Z 2-7, no padding) — matches dnstt/Slipstream alphabet.
     */
    private fun base32Encode(data: ByteArray): String {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        val sb = StringBuilder((data.size * 8 + 4) / 5)
        var buffer = 0
        var bitsLeft = 0
        for (byte in data) {
            buffer = (buffer shl 8) or (byte.toInt() and 0xFF)
            bitsLeft += 8
            while (bitsLeft >= 5) {
                bitsLeft -= 5
                sb.append(alphabet[(buffer shr bitsLeft) and 0x1F])
            }
        }
        if (bitsLeft > 0) {
            sb.append(alphabet[(buffer shl (5 - bitsLeft)) and 0x1F])
        }
        return sb.toString()
    }

    /**
     * Insert dots every 57 characters from the right so each DNS label stays ≤ 57 chars,
     * matching the Slipstream dotify convention.
     */
    private fun dotifyBase32(encoded: String): String {
        if (encoded.length <= 57) return encoded
        val sb = StringBuilder(encoded.length + encoded.length / 57)
        var remaining = encoded.length
        var pos = 0
        // First label gets the remainder length, subsequent labels are 57 chars
        val firstLabelLen = remaining % 57
        if (firstLabelLen > 0) {
            sb.append(encoded, 0, firstLabelLen)
            pos = firstLabelLen
            remaining -= firstLabelLen
            if (remaining > 0) sb.append('.')
        }
        while (remaining > 0) {
            val end = pos + minOf(57, remaining)
            sb.append(encoded, pos, end)
            remaining -= (end - pos)
            pos = end
            if (remaining > 0) sb.append('.')
        }
        return sb.toString()
    }

    override fun expandIpRanges(ranges: List<Pair<Long, Long>>): List<String> {
        val seen = mutableSetOf<Long>()
        val result = mutableListOf<String>()
        for ((start, end) in ranges) {
            var ip = start
            while (ip <= end) {
                if (seen.add(ip)) result.add(longToIp(ip))
                ip++
            }
        }
        return result
    }

    override fun loadCountryCidrRanges(
        context: android.content.Context,
        countryCode: String
    ): List<Pair<Long, Long>> {
        return loadCidrRanges(context, countryCode)
    }

    override fun generateFromRanges(ranges: List<Pair<Long, Long>>, count: Int): List<String> {
        if (ranges.isEmpty()) return emptyList()

        val cumulativeSizes = LongArray(ranges.size)
        var cumulative = 0L
        for (i in ranges.indices) {
            val (start, end) = ranges[i]
            cumulative += (end - start + 1)
            cumulativeSizes[i] = cumulative
        }
        val totalIps = cumulative

        val result = mutableSetOf<String>()
        val maxAttempts = count * 3
        var attempts = 0

        while (result.size < count && attempts < maxAttempts) {
            attempts++
            val pos = (Random.nextLong(totalIps) and 0x7FFFFFFFFFFFFFFFL) % totalIps

            var lo = 0
            var hi = ranges.size - 1
            while (lo < hi) {
                val mid = (lo + hi) / 2
                if (cumulativeSizes[mid] <= pos) lo = mid + 1 else hi = mid
            }

            val (start, _) = ranges[lo]
            val offset = pos - (if (lo > 0) cumulativeSizes[lo - 1] else 0L)
            val ip = start + offset
            result.add(longToIp(ip))
        }

        return result.toList()
    }

    override fun generateCountryRangeIps(
        context: android.content.Context,
        countryCode: String,
        count: Int
    ): List<String> {
        val ranges = loadCidrRanges(context, countryCode)
        return generateFromRanges(ranges, count)
    }

    private fun loadCidrRanges(context: android.content.Context, countryCode: String): List<Pair<Long, Long>> {
        val ranges = mutableListOf<Pair<Long, Long>>()
        try {
            context.assets.open("geo/$countryCode.cidr").use { stream ->
                BufferedReader(InputStreamReader(stream)).use { reader ->
                    reader.forEachLine { line ->
                        val trimmed = line.trim()
                        if (trimmed.isNotEmpty()) {
                            val range = DomainRouter.parseCidr(trimmed)
                            if (range != null) {
                                ranges.add(range)
                            }
                        }
                    }
                }
            }
        } catch (_: Exception) {
            // Asset file not found
        }
        return ranges
    }

    private fun longToIp(ip: Long): String {
        return "${(ip shr 24) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 8) and 0xFF}.${ip and 0xFF}"
    }

    override suspend fun detectTransparentProxy(
        testDomain: String,
        timeoutMs: Long
    ): Boolean = withContext(Dispatchers.IO) {
        // RFC 5737 TEST-NET addresses — documentation-only, should never host DNS servers
        val testNetIps = listOf("192.0.2.1", "198.51.100.1", "203.0.113.1")

        for (ip in testNetIps) {
            try {
                val result = withTimeoutOrNull(timeoutMs) {
                    performDnsQuery(ip, 53, testDomain, DNS_TYPE_A, timeoutMs)
                }
                if (result != null) {
                    // A TEST-NET IP responded — ISP is intercepting DNS traffic
                    return@withContext true
                }
            } catch (_: Exception) {
                // Expected: no response from documentation-only addresses
            }
        }
        false
    }

    override fun scanResolvers(
        hosts: List<String>,
        port: Int,
        testDomain: String,
        timeoutMs: Long,
        concurrency: Int
    ): Flow<ResolverScanResult> = channelFlow {
        val semaphore = Semaphore(concurrency)

        hosts.forEach { host ->
            launch {
                semaphore.acquire()
                try {
                    val result = scanResolver(host, port, testDomain, timeoutMs)
                    send(result)
                } finally {
                    semaphore.release()
                }
            }
        }
    }

    // ---- E2E tunnel testing ----

    override suspend fun testResolverE2e(
        resolverHost: String,
        resolverPort: Int,
        profile: ServerProfile,
        testUrl: String,
        timeoutMs: Long,
        fullVerification: Boolean,
        onPhaseUpdate: (String) -> Unit
    ): E2eTestResult = withContext(Dispatchers.IO) {
        when (profile.tunnelType) {
            TunnelType.SLIPSTREAM, TunnelType.SLIPSTREAM_SSH ->
                testResolverSlipstream(resolverHost, resolverPort, profile, testUrl, timeoutMs, onPhaseUpdate, fullVerification)
            TunnelType.DNSTT, TunnelType.DNSTT_SSH ->
                testResolverDnstt(resolverHost, resolverPort, profile, testUrl, timeoutMs, onPhaseUpdate, fullVerification = fullVerification)
            TunnelType.NOIZDNS, TunnelType.NOIZDNS_SSH ->
                testResolverDnstt(resolverHost, resolverPort, profile, testUrl, timeoutMs, onPhaseUpdate, noizMode = true, fullVerification = fullVerification)
            else ->
                E2eTestResult(errorMessage = "Unsupported tunnel type: ${profile.tunnelType.displayName}")
        }
    }

    override fun testResolversE2e(
        resolvers: List<Pair<String, Int>>,
        profile: ServerProfile,
        testUrl: String,
        timeoutMs: Long,
        fullVerification: Boolean,
        onPhaseUpdate: (String, String) -> Unit
    ): Flow<Pair<String, E2eTestResult>> = channelFlow {
        for ((host, port) in resolvers) {
            val result = testResolverE2e(host, port, profile, testUrl, timeoutMs, fullVerification) { phase ->
                onPhaseUpdate(host, phase)
            }
            send(host to result)
        }
    }

    override suspend fun testResolverE2eIsolated(
        resolverHost: String,
        resolverPort: Int,
        profile: ServerProfile,
        testUrl: String,
        timeoutMs: Long,
        fullVerification: Boolean,
        onPhaseUpdate: (String) -> Unit
    ): E2eTestResult = withContext(Dispatchers.IO) {
        when (profile.tunnelType) {
            TunnelType.SLIPSTREAM, TunnelType.SLIPSTREAM_SSH ->
                // Slipstream native lib is singleton — fall back to shared bridge
                testResolverSlipstream(resolverHost, resolverPort, profile, testUrl, timeoutMs, onPhaseUpdate, fullVerification)
            TunnelType.DNSTT, TunnelType.DNSTT_SSH ->
                testResolverDnsttIsolated(resolverHost, resolverPort, profile, testUrl, timeoutMs, onPhaseUpdate, fullVerification = fullVerification)
            TunnelType.NOIZDNS, TunnelType.NOIZDNS_SSH ->
                testResolverDnsttIsolated(resolverHost, resolverPort, profile, testUrl, timeoutMs, onPhaseUpdate, noizMode = true, fullVerification = fullVerification)
            else ->
                E2eTestResult(errorMessage = "Unsupported tunnel type: ${profile.tunnelType.displayName}")
        }
    }

    override fun maxE2eConcurrency(profile: ServerProfile): Int = when (profile.tunnelType) {
        TunnelType.SLIPSTREAM, TunnelType.SLIPSTREAM_SSH -> 1
        else -> 3
    }

    /** Format resolver address for DNSTT/NoizDNS based on DNS transport. Returns null for DoH.
     *  Resolves domain names to IPs since Go on Android cannot resolve hostnames. */
    private fun formatDnsServer(host: String, port: Int, transport: DnsTransport): String? {
        val resolvedHost = VpnRepositoryImpl.resolveHost(host)
        return when (transport) {
            DnsTransport.UDP -> "$resolvedHost:$port"
            DnsTransport.TCP -> "tcp://$resolvedHost:$port"
            DnsTransport.DOT -> "tls://$resolvedHost:$port"
            DnsTransport.DOH -> null
        }
    }

    /**
     * Test a single resolver using an ephemeral DNSTT/NoizDNS Go client.
     * Creates its own DnsttClient on a unique port — safe for concurrent use.
     * Does NOT touch the singleton DnsttBridge or DnsttSocksBridge.
     */
    private suspend fun testResolverDnsttIsolated(
        resolverHost: String,
        resolverPort: Int,
        profile: ServerProfile,
        testUrl: String,
        timeoutMs: Long,
        onPhaseUpdate: (String) -> Unit,
        noizMode: Boolean = false,
        fullVerification: Boolean = false
    ): E2eTestResult = withContext(Dispatchers.IO) {
        val totalStart = SystemClock.elapsedRealtime()
        val tunnelName = if (noizMode) "NoizDNS" else "DNSTT"
        val dnsttPort = findFreePort()
        var client: mobile.DnsttClient? = null
        try {
            val result = withTimeoutOrNull(timeoutMs) {
                // Phase 1: Start tunnel
                onPhaseUpdate("Starting $tunnelName...")

                val dnsServer = formatDnsServer(resolverHost, resolverPort, profile.dnsTransport)
                    ?: return@withTimeoutOrNull E2eTestResult(
                        errorMessage = "DoH transport uses URL, not per-resolver IP",
                        phase = E2eTestPhase.TUNNEL_SETUP
                    )

                val listenAddr = "127.0.0.1:$dnsttPort"
                val newClient = mobile.Mobile.newClient(dnsServer, profile.domain, profile.dnsttPublicKey, listenAddr)
                newClient.setAuthoritativeMode(profile.dnsttAuthoritative)
                if (profile.dnsPayloadSize > 0) {
                    newClient.setMaxPayload(profile.dnsPayloadSize.toLong())
                }
                if (noizMode) {
                    newClient.setNoizMode(true)
                    newClient.setDeviceManufacturer(android.os.Build.MANUFACTURER)
                }
                client = newClient
                newClient.start()

                // Phase 2: Wait for DNSTT running
                onPhaseUpdate("Waiting for $tunnelName...")
                var remaining = timeoutMs - (SystemClock.elapsedRealtime() - totalStart)
                val readyTimeout = minOf(remaining, 10000L)
                val readyStart = SystemClock.elapsedRealtime()
                var running = false
                while (SystemClock.elapsedRealtime() - readyStart < readyTimeout) {
                    if (newClient.isRunning) {
                        running = true
                        break
                    }
                    delay(100)
                }

                if (!running) {
                    return@withTimeoutOrNull E2eTestResult(
                        totalMs = SystemClock.elapsedRealtime() - totalStart,
                        errorMessage = "$tunnelName startup timeout",
                        phase = E2eTestPhase.TUNNEL_SETUP
                    )
                }

                // Phase 2b: Warm up tunnel (Noise/KCP/smux handshake)
                onPhaseUpdate("Tunnel handshake...")
                remaining = timeoutMs - (SystemClock.elapsedRealtime() - totalStart)
                if (remaining <= 0) {
                    return@withTimeoutOrNull E2eTestResult(
                        totalMs = SystemClock.elapsedRealtime() - totalStart,
                        errorMessage = "Timeout before tunnel handshake",
                        phase = E2eTestPhase.TUNNEL_SETUP
                    )
                }
                val warmupOk = warmupDnsttTunnel(dnsttPort, remaining, profile.socksUsername, profile.socksPassword)
                if (!warmupOk) {
                    return@withTimeoutOrNull E2eTestResult(
                        totalMs = SystemClock.elapsedRealtime() - totalStart,
                        errorMessage = "$tunnelName tunnel handshake timeout (resolver may not work)",
                        phase = E2eTestPhase.TUNNEL_SETUP
                    )
                }

                val isSshVariant = profile.tunnelType == TunnelType.DNSTT_SSH || profile.tunnelType == TunnelType.NOIZDNS_SSH
                val tunnelSetupMs = SystemClock.elapsedRealtime() - totalStart

                // Fast scan mode: SOCKS5 handshake already proved bidirectional
                // tunnel data flow — skip HTTP/SSH verification.
                if (!fullVerification) {
                    return@withTimeoutOrNull E2eTestResult(
                        tunnelSetupMs = tunnelSetupMs,
                        totalMs = SystemClock.elapsedRealtime() - totalStart,
                        success = true,
                        phase = E2eTestPhase.COMPLETED
                    )
                }

                // Phase 3: Full verification — HTTP/SSH through tunnel
                remaining = timeoutMs - (SystemClock.elapsedRealtime() - totalStart)
                if (remaining <= 0) {
                    return@withTimeoutOrNull E2eTestResult(
                        tunnelSetupMs = tunnelSetupMs,
                        totalMs = SystemClock.elapsedRealtime() - totalStart,
                        errorMessage = "Timeout after tunnel setup",
                        phase = E2eTestPhase.HTTP_REQUEST
                    )
                }

                if (isSshVariant) {
                    onPhaseUpdate("SSH connect...")
                    val bannerResult = verifySshConnection(dnsttPort, profile, remaining)
                    E2eTestResult(
                        tunnelSetupMs = tunnelSetupMs,
                        httpLatencyMs = bannerResult.latencyMs,
                        totalMs = SystemClock.elapsedRealtime() - totalStart,
                        httpStatusCode = if (bannerResult.success) 200 else 0,
                        success = bannerResult.success,
                        errorMessage = bannerResult.errorMessage,
                        phase = E2eTestPhase.COMPLETED
                    )
                } else {
                    // Non-SSH: connect directly to the DNSTT port (Dante SOCKS5 on remote side)
                    onPhaseUpdate("HTTP request...")
                    val httpResult = performHttpThroughSocks(dnsttPort, profile, testUrl, remaining)
                    E2eTestResult(
                        tunnelSetupMs = tunnelSetupMs,
                        httpLatencyMs = httpResult.latencyMs,
                        totalMs = SystemClock.elapsedRealtime() - totalStart,
                        httpStatusCode = httpResult.statusCode,
                        success = httpResult.success,
                        errorMessage = httpResult.errorMessage,
                        phase = E2eTestPhase.COMPLETED
                    )
                }
            }
            result ?: E2eTestResult(
                totalMs = SystemClock.elapsedRealtime() - totalStart,
                errorMessage = "E2E test timed out (${timeoutMs}ms)",
                phase = E2eTestPhase.TUNNEL_SETUP
            )
        } catch (e: Exception) {
            E2eTestResult(
                totalMs = SystemClock.elapsedRealtime() - totalStart,
                errorMessage = e.message ?: "Unknown error",
                phase = E2eTestPhase.TUNNEL_SETUP
            )
        } finally {
            try { client?.stop() } catch (_: Exception) {}
        }
    }

    private suspend fun testResolverSlipstream(
        resolverHost: String,
        resolverPort: Int,
        profile: ServerProfile,
        testUrl: String,
        timeoutMs: Long,
        onPhaseUpdate: (String) -> Unit,
        fullVerification: Boolean = false
    ): E2eTestResult = withContext(Dispatchers.IO) {
        val totalStart = SystemClock.elapsedRealtime()
        val tunnelPort = findFreePort()
        try {
            val result = withTimeoutOrNull(timeoutMs) {
                // Phase 1: Start tunnel
                onPhaseUpdate("Starting tunnel...")
                SlipstreamBridge.proxyOnlyMode = true

                val resolver = ResolverConfig(
                    host = resolverHost,
                    port = resolverPort,
                    authoritative = profile.authoritativeMode
                )

                val startResult = SlipstreamBridge.startClient(
                    domain = profile.domain,
                    resolvers = listOf(resolver),
                    congestionControl = profile.congestionControl.value,
                    keepAliveInterval = profile.keepAliveInterval,
                    tcpListenPort = tunnelPort,
                    tcpListenHost = "127.0.0.1"
                )

                if (startResult.isFailure) {
                    return@withTimeoutOrNull E2eTestResult(
                        totalMs = SystemClock.elapsedRealtime() - totalStart,
                        errorMessage = "Bridge start failed: ${startResult.exceptionOrNull()?.message}",
                        phase = E2eTestPhase.TUNNEL_SETUP
                    )
                }

                // Phase 2: Wait for QUIC handshake
                onPhaseUpdate("QUIC handshake...")
                val quicTimeout = minOf(timeoutMs / 2, 10000L)
                val quicStart = SystemClock.elapsedRealtime()
                var quicReady = false
                while (SystemClock.elapsedRealtime() - quicStart < quicTimeout) {
                    if (SlipstreamBridge.isQuicReady()) {
                        quicReady = true
                        break
                    }
                    delay(100)
                }

                if (!quicReady) {
                    return@withTimeoutOrNull E2eTestResult(
                        totalMs = SystemClock.elapsedRealtime() - totalStart,
                        errorMessage = "QUIC handshake timeout",
                        phase = E2eTestPhase.QUIC_HANDSHAKE
                    )
                }

                val tunnelSetupMs = SystemClock.elapsedRealtime() - totalStart
                val actualPort = SlipstreamBridge.getClientPort()

                // Fast scan mode: QUIC handshake proves tunnel connectivity
                if (!fullVerification) {
                    return@withTimeoutOrNull E2eTestResult(
                        tunnelSetupMs = tunnelSetupMs,
                        totalMs = SystemClock.elapsedRealtime() - totalStart,
                        success = true,
                        phase = E2eTestPhase.COMPLETED
                    )
                }

                // Phase 3: Full verification — HTTP/SSH through tunnel
                val isSshVariant = profile.tunnelType == TunnelType.SLIPSTREAM_SSH
                if (isSshVariant) {
                    onPhaseUpdate("SSH connect...")
                    val remaining = timeoutMs - tunnelSetupMs
                    val bannerResult = verifySshConnection(actualPort, profile, remaining)
                    E2eTestResult(
                        tunnelSetupMs = tunnelSetupMs,
                        httpLatencyMs = bannerResult.latencyMs,
                        totalMs = SystemClock.elapsedRealtime() - totalStart,
                        httpStatusCode = if (bannerResult.success) 200 else 0,
                        success = bannerResult.success,
                        errorMessage = bannerResult.errorMessage,
                        phase = E2eTestPhase.COMPLETED
                    )
                } else {
                    onPhaseUpdate("HTTP request...")
                    val httpResult = performHttpThroughSocks(
                        actualPort, profile, testUrl,
                        timeoutMs - tunnelSetupMs
                    )
                    E2eTestResult(
                        tunnelSetupMs = tunnelSetupMs,
                        httpLatencyMs = httpResult.latencyMs,
                        totalMs = SystemClock.elapsedRealtime() - totalStart,
                        httpStatusCode = httpResult.statusCode,
                        success = httpResult.success,
                        errorMessage = httpResult.errorMessage,
                        phase = E2eTestPhase.COMPLETED
                    )
                }
            }
            result ?: E2eTestResult(
                totalMs = SystemClock.elapsedRealtime() - totalStart,
                errorMessage = "E2E test timed out (${timeoutMs}ms)",
                phase = E2eTestPhase.TUNNEL_SETUP
            )
        } catch (e: Exception) {
            E2eTestResult(
                totalMs = SystemClock.elapsedRealtime() - totalStart,
                errorMessage = e.message ?: "Unknown error",
                phase = E2eTestPhase.TUNNEL_SETUP
            )
        } finally {
            try {
                SlipstreamBridge.stopClient()
            } catch (_: Exception) {}
            SlipstreamBridge.proxyOnlyMode = false
        }
    }

    private suspend fun testResolverDnstt(
        resolverHost: String,
        resolverPort: Int,
        profile: ServerProfile,
        testUrl: String,
        timeoutMs: Long,
        onPhaseUpdate: (String) -> Unit,
        noizMode: Boolean = false,
        fullVerification: Boolean = false
    ): E2eTestResult = withContext(Dispatchers.IO) {
        val totalStart = SystemClock.elapsedRealtime()
        val tunnelName = if (noizMode) "NoizDNS" else "DNSTT"
        // Same two-layer stack as VPN: DnsttBridge on one port, DnsttSocksBridge on another
        val dnsttPort = findFreePort()
        val bridgePort = findFreePort()
        try {
            val result = withTimeoutOrNull(timeoutMs) {
                // Phase 1: Start tunnel
                onPhaseUpdate("Starting $tunnelName...")

                val dnsServer = formatDnsServer(resolverHost, resolverPort, profile.dnsTransport)
                    ?: return@withTimeoutOrNull E2eTestResult(
                        errorMessage = "DoH transport uses URL, not per-resolver IP",
                        phase = E2eTestPhase.TUNNEL_SETUP
                    )

                val startResult = DnsttBridge.startClient(
                    dnsServer = dnsServer,
                    tunnelDomain = profile.domain,
                    publicKey = profile.dnsttPublicKey,
                    listenPort = dnsttPort,
                    listenHost = "127.0.0.1",
                    authoritativeMode = profile.dnsttAuthoritative,
                    noizMode = noizMode
                )

                if (startResult.isFailure) {
                    return@withTimeoutOrNull E2eTestResult(
                        totalMs = SystemClock.elapsedRealtime() - totalStart,
                        errorMessage = "$tunnelName start failed: ${startResult.exceptionOrNull()?.message}",
                        phase = E2eTestPhase.TUNNEL_SETUP
                    )
                }

                // Phase 2: Wait for DNSTT running
                onPhaseUpdate("Waiting for DNSTT...")
                var remaining = timeoutMs - (SystemClock.elapsedRealtime() - totalStart)
                val readyTimeout = minOf(remaining, 10000L)
                val readyStart = SystemClock.elapsedRealtime()
                var running = false
                while (SystemClock.elapsedRealtime() - readyStart < readyTimeout) {
                    if (DnsttBridge.isRunning()) {
                        running = true
                        break
                    }
                    delay(100)
                }

                if (!running) {
                    return@withTimeoutOrNull E2eTestResult(
                        totalMs = SystemClock.elapsedRealtime() - totalStart,
                        errorMessage = "DNSTT startup timeout",
                        phase = E2eTestPhase.TUNNEL_SETUP
                    )
                }

                // Phase 2b: Warm up the DNS tunnel.
                // DnsttBridge.isRunning() returns true before the Go code finishes
                // KCP/Noise/smux setup — it only means the goroutine started.
                // The Go Accept() loop doesn't run until Noise handshake completes
                // (3-15s of DNS round-trips). A warm-up connection forces this setup
                // and blocks until the tunnel is actually functional.
                onPhaseUpdate("Tunnel handshake...")
                remaining = timeoutMs - (SystemClock.elapsedRealtime() - totalStart)
                if (remaining <= 0) {
                    return@withTimeoutOrNull E2eTestResult(
                        totalMs = SystemClock.elapsedRealtime() - totalStart,
                        errorMessage = "Timeout before tunnel handshake",
                        phase = E2eTestPhase.TUNNEL_SETUP
                    )
                }
                val warmupOk = warmupDnsttTunnel(dnsttPort, remaining, profile.socksUsername, profile.socksPassword)
                if (!warmupOk) {
                    return@withTimeoutOrNull E2eTestResult(
                        totalMs = SystemClock.elapsedRealtime() - totalStart,
                        errorMessage = "DNSTT tunnel handshake timeout (resolver may not work)",
                        phase = E2eTestPhase.TUNNEL_SETUP
                    )
                }

                val isSshVariant = profile.tunnelType == TunnelType.DNSTT_SSH || profile.tunnelType == TunnelType.NOIZDNS_SSH

                if (!isSshVariant) {
                    // Non-SSH: start DnsttSocksBridge (same as VPN flow) to handle
                    // SOCKS5 auth with Dante and DNS worker pool.
                    onPhaseUpdate("Starting bridge...")
                    DnsttSocksBridge.authoritativeMode = profile.dnsttAuthoritative
                    val bridgeResult = DnsttSocksBridge.start(
                        dnsttPort = dnsttPort,
                        dnsttHost = "127.0.0.1",
                        listenPort = bridgePort,
                        listenHost = "127.0.0.1",
                        socksUsername = profile.socksUsername,
                        socksPassword = profile.socksPassword
                    )

                    if (bridgeResult.isFailure) {
                        return@withTimeoutOrNull E2eTestResult(
                            totalMs = SystemClock.elapsedRealtime() - totalStart,
                            errorMessage = "Bridge start failed: ${bridgeResult.exceptionOrNull()?.message}",
                            phase = E2eTestPhase.TUNNEL_SETUP
                        )
                    }
                }

                val tunnelSetupMs = SystemClock.elapsedRealtime() - totalStart

                // Fast scan mode: warmup handshake already proved tunnel works
                if (!fullVerification) {
                    return@withTimeoutOrNull E2eTestResult(
                        tunnelSetupMs = tunnelSetupMs,
                        totalMs = SystemClock.elapsedRealtime() - totalStart,
                        success = true,
                        phase = E2eTestPhase.COMPLETED
                    )
                }

                // Phase 3: Full verification — HTTP/SSH through tunnel
                remaining = timeoutMs - (SystemClock.elapsedRealtime() - totalStart)
                if (remaining <= 0) {
                    return@withTimeoutOrNull E2eTestResult(
                        tunnelSetupMs = tunnelSetupMs,
                        totalMs = SystemClock.elapsedRealtime() - totalStart,
                        errorMessage = "Timeout after tunnel setup",
                        phase = E2eTestPhase.HTTP_REQUEST
                    )
                }

                if (isSshVariant) {
                    onPhaseUpdate("SSH connect...")
                    val bannerResult = verifySshConnection(dnsttPort, profile, remaining)
                    E2eTestResult(
                        tunnelSetupMs = tunnelSetupMs,
                        httpLatencyMs = bannerResult.latencyMs,
                        totalMs = SystemClock.elapsedRealtime() - totalStart,
                        httpStatusCode = if (bannerResult.success) 200 else 0,
                        success = bannerResult.success,
                        errorMessage = bannerResult.errorMessage,
                        phase = E2eTestPhase.COMPLETED
                    )
                } else {
                    onPhaseUpdate("HTTP request...")
                    val httpResult = performHttpThroughSocks(
                        bridgePort, profile, testUrl,
                        remaining
                    )
                    E2eTestResult(
                        tunnelSetupMs = tunnelSetupMs,
                        httpLatencyMs = httpResult.latencyMs,
                        totalMs = SystemClock.elapsedRealtime() - totalStart,
                        httpStatusCode = httpResult.statusCode,
                        success = httpResult.success,
                        errorMessage = httpResult.errorMessage,
                        phase = E2eTestPhase.COMPLETED
                    )
                }
            }
            result ?: E2eTestResult(
                totalMs = SystemClock.elapsedRealtime() - totalStart,
                errorMessage = "E2E test timed out (${timeoutMs}ms)",
                phase = E2eTestPhase.TUNNEL_SETUP
            )
        } catch (e: Exception) {
            E2eTestResult(
                totalMs = SystemClock.elapsedRealtime() - totalStart,
                errorMessage = e.message ?: "Unknown error",
                phase = E2eTestPhase.TUNNEL_SETUP
            )
        } finally {
            try {
                DnsttSocksBridge.stop()
            } catch (_: Exception) {}
            try {
                DnsttBridge.stopClient()
            } catch (_: Exception) {}
        }
    }

    /**
     * Verify the DNSTT tunnel works by sending a SOCKS5 CONNECT through it.
     *
     * Step 1: SOCKS5 auth (local to dnstt-client — does NOT test the tunnel)
     * Step 2: SOCKS5 CONNECT to example.com:80 — this travels through the DNS
     *         tunnel to the remote SOCKS5 server (Dante) and the reply comes back.
     *         Any SOCKS5 reply (even failure) proves bidirectional tunnel data flow.
     *
     * The Go listener starts before the Noise handshake completes, so isRunning()
     * returns true prematurely. The TCP accept blocks until Noise finishes, then
     * the CONNECT request provides the actual tunnel proof.
     */
    private fun warmupDnsttTunnel(
        dnsttPort: Int,
        timeoutMs: Long,
        username: String? = null,
        password: String? = null
    ): Boolean {
        var sock: Socket? = null
        return try {
            val warmupTimeout = timeoutMs.toInt().coerceAtLeast(1)
            sock = Socket()
            sock.connect(java.net.InetSocketAddress("127.0.0.1", dnsttPort), warmupTimeout)
            sock.soTimeout = warmupTimeout

            val input = sock.getInputStream()
            val output = sock.getOutputStream()

            // SOCKS5 auth with remote Dante (bytes travel through DNS tunnel).
            // performSocksAuth handles both no-auth and username/password methods,
            // exactly matching what performHttpThroughSocks does.
            if (!performSocksAuth(input, output, username, password)) return false

            // SOCKS5 CONNECT to example.com:80 — proves bidirectional tunnel data flow.
            // VER=5, CMD=1(CONNECT), RSV=0, ATYP=3(domain), LEN, DOMAIN, PORT_HI, PORT_LO
            val domain = "example.com"
            val connectReq = byteArrayOf(
                0x05, 0x01, 0x00, 0x03,
                domain.length.toByte()
            ) + domain.toByteArray() + byteArrayOf(0x00, 0x50) // port 80
            output.write(connectReq)
            output.flush()

            // Read first 4 bytes of SOCKS5 CONNECT reply (VER REP RSV ATYP).
            // Any valid reply (even REP != 0) proves data traveled through the tunnel and back.
            val connectResp = ByteArray(4)
            input.readFully(connectResp)
            connectResp[0] == 0x05.toByte()
        } catch (e: Exception) {
            false
        } finally {
            try { sock?.close() } catch (_: Exception) {}
        }
    }

    private data class SshBannerResult(
        val success: Boolean = false,
        val latencyMs: Long = 0,
        val errorMessage: String? = null
    )

    /**
     * Wait for the local tunnel port to accept TCP connections.
     * Same check as VPN service's waitForProxyReady — connect-and-close.
     */
    private fun waitForPortListening(port: Int, maxAttempts: Int = 20, delayMs: Long = 150): Boolean {
        repeat(maxAttempts) {
            try {
                Socket().use { socket ->
                    socket.connect(java.net.InetSocketAddress("127.0.0.1", port), 300)
                    return true
                }
            } catch (_: Exception) {
                Thread.sleep(delayMs)
            }
        }
        return false
    }

    /**
     * Verify SSH tunnel connectivity by performing a real JSch SSH handshake —
     * exactly replicating what VPN service's SshTunnelBridge.startOverProxy() does.
     * JSch connects directly to the local tunnel port (raw TCP), the tunnel
     * forwards to the remote SSH server, and JSch does the full SSH negotiation.
     */
    private fun verifySshConnection(
        localPort: Int,
        profile: ServerProfile,
        timeoutMs: Long
    ): SshBannerResult {
        // Step 1: Wait for TCP listener (same as VPN service's waitForProxyReady)
        if (!waitForPortListening(localPort)) {
            return SshBannerResult(errorMessage = "Port $localPort not listening")
        }

        // Step 2: Real SSH handshake — same as SshTunnelBridge.startOverProxy()
        var session: com.jcraft.jsch.Session? = null
        return try {
            val start = SystemClock.elapsedRealtime()
            val jsch = JSch()
            if (profile.sshAuthType == SshAuthType.KEY && profile.sshPrivateKey.isNotBlank()) {
                jsch.addIdentity(
                    "e2e-test-key",
                    profile.sshPrivateKey.toByteArray(Charsets.UTF_8),
                    null,
                    if (profile.sshKeyPassphrase.isNotBlank())
                        profile.sshKeyPassphrase.toByteArray(Charsets.UTF_8) else null
                )
            }
            // Connect directly to the tunnel's local port — same as VPN service
            val newSession = jsch.getSession(profile.sshUsername, "127.0.0.1", localPort)
            if (profile.sshAuthType == SshAuthType.KEY) {
                newSession.setConfig("PreferredAuthentications", "publickey")
            } else {
                newSession.setPassword(profile.sshPassword)
            }
            newSession.setConfig("StrictHostKeyChecking", "no")
            newSession.connect(timeoutMs.toInt().coerceAtLeast(1))
            session = newSession

            val latencyMs = SystemClock.elapsedRealtime() - start
            if (newSession.isConnected) {
                SshBannerResult(success = true, latencyMs = latencyMs)
            } else {
                SshBannerResult(latencyMs = latencyMs, errorMessage = "SSH session not connected")
            }
        } catch (e: Exception) {
            SshBannerResult(errorMessage = "SSH connect: ${e.message}")
        } finally {
            try { session?.disconnect() } catch (_: Exception) {}
        }
    }

    private data class HttpThroughSocksResult(
        val success: Boolean = false,
        val statusCode: Int = 0,
        val latencyMs: Long = 0,
        val errorMessage: String? = null
    )

    private fun performHttpThroughSocks(
        localPort: Int,
        profile: ServerProfile,
        testUrl: String,
        remainingTimeoutMs: Long
    ): HttpThroughSocksResult {
        val socketTimeout = remainingTimeoutMs.toInt()
        if (socketTimeout <= 0) {
            return HttpThroughSocksResult(errorMessage = "No time remaining for HTTP")
        }

        var socket: Socket? = null
        return try {
            val url = URL(testUrl)
            val host = url.host
            val port = if (url.port != -1) url.port else if (url.protocol == "https") 443 else 80
            val path = if (url.path.isNullOrBlank()) "/" else url.path

            socket = Socket()
            socket.connect(java.net.InetSocketAddress("127.0.0.1", localPort), socketTimeout)
            socket.soTimeout = socketTimeout

            val input = socket.getInputStream()
            val output = socket.getOutputStream()

            // SOCKS5 auth with remote Dante server (through tunnel)
            if (!performSocksAuth(input, output, profile.socksUsername, profile.socksPassword)) {
                return HttpThroughSocksResult(errorMessage = "SOCKS5 auth failed")
            }

            // SOCKS5 CONNECT
            val domainBytes = host.toByteArray()
            val connectReq = ByteArray(7 + domainBytes.size)
            connectReq[0] = 0x05 // version
            connectReq[1] = 0x01 // CONNECT
            connectReq[2] = 0x00 // reserved
            connectReq[3] = 0x03 // domain
            connectReq[4] = domainBytes.size.toByte()
            System.arraycopy(domainBytes, 0, connectReq, 5, domainBytes.size)
            connectReq[5 + domainBytes.size] = (port shr 8).toByte()
            connectReq[6 + domainBytes.size] = (port and 0xFF).toByte()
            output.write(connectReq)
            output.flush()

            if (!readSocksConnectResponse(input)) {
                return HttpThroughSocksResult(errorMessage = "SOCKS5 CONNECT failed")
            }

            // HTTP HEAD request
            val httpStart = SystemClock.elapsedRealtime()
            val httpReq = "HEAD $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n"
            output.write(httpReq.toByteArray())
            output.flush()

            // Read status line
            val responseBuilder = StringBuilder()
            var b: Int
            while (input.read().also { b = it } != -1) {
                responseBuilder.append(b.toChar())
                if (responseBuilder.endsWith("\r\n")) break
            }
            val latencyMs = SystemClock.elapsedRealtime() - httpStart

            val statusLine = responseBuilder.toString().trim()
            val statusCode = statusLine.split(" ").getOrNull(1)?.toIntOrNull() ?: 0

            HttpThroughSocksResult(
                success = statusCode in 200..299,
                statusCode = statusCode,
                latencyMs = latencyMs
            )
        } catch (e: Exception) {
            HttpThroughSocksResult(errorMessage = "HTTP failed: ${e.message}")
        } finally {
            try { socket?.close() } catch (_: Exception) {}
        }
    }

    private fun performSocksAuth(
        input: InputStream,
        output: OutputStream,
        username: String?,
        password: String?
    ): Boolean {
        val hasAuth = !username.isNullOrBlank() && !password.isNullOrBlank()
        if (hasAuth) {
            output.write(byteArrayOf(0x05, 0x01, 0x02))
        } else {
            output.write(byteArrayOf(0x05, 0x01, 0x00))
        }
        output.flush()

        val greetResp = ByteArray(2)
        input.readFully(greetResp)
        if (greetResp[0] != 0x05.toByte() || (greetResp[1].toInt() and 0xFF) == 0xFF) return false

        if ((greetResp[1].toInt() and 0xFF) == 0x02) {
            val user = username!!.toByteArray()
            val pass = password!!.toByteArray()
            val authReq = ByteArray(3 + user.size + pass.size)
            authReq[0] = 0x01
            authReq[1] = user.size.toByte()
            System.arraycopy(user, 0, authReq, 2, user.size)
            authReq[2 + user.size] = pass.size.toByte()
            System.arraycopy(pass, 0, authReq, 3 + user.size, pass.size)
            output.write(authReq)
            output.flush()

            val authResp = ByteArray(2)
            input.readFully(authResp)
            if (authResp[1] != 0x00.toByte()) return false
        }
        return true
    }

    private fun readSocksConnectResponse(input: InputStream): Boolean {
        val connResp = ByteArray(4)
        input.readFully(connResp)
        if (connResp[1] != 0x00.toByte()) return false
        when (connResp[3].toInt() and 0xFF) {
            0x01 -> { val r = ByteArray(6); input.readFully(r) }
            0x03 -> { val l = input.read(); val r = ByteArray(l + 2); input.readFully(r) }
            0x04 -> { val r = ByteArray(18); input.readFully(r) }
        }
        return true
    }

    private fun InputStream.readFully(buffer: ByteArray) {
        var offset = 0
        while (offset < buffer.size) {
            val bytesRead = this.read(buffer, offset, buffer.size - offset)
            if (bytesRead == -1) throw java.io.IOException("Unexpected end of stream")
            offset += bytesRead
        }
    }

    companion object {
        private const val DNS_TYPE_A = 1      // A record (IPv4 address)
        private const val DNS_TYPE_NS = 2     // NS record (Name server)
        private const val DNS_TYPE_TXT = 16   // TXT record (Text)

        /** Find a free port by binding to port 0 and immediately releasing it. */
        fun findFreePort(): Int {
            return java.net.ServerSocket(0).use { it.localPort }
        }
    }

    private data class DnsQueryResult(
        val success: Boolean,
        val resolvedIp: String? = null,
        val isCensored: Boolean = false,
        val error: String? = null,
        val responseCode: Int = 0,
        val rawResponse: ByteArray? = null,
        val rawLength: Int = 0
    )

    private suspend fun performDnsQuery(
        host: String,
        port: Int,
        domain: String,
        recordType: Int = DNS_TYPE_A,
        timeoutMs: Long = 3000
    ): DnsQueryResult = withContext(Dispatchers.IO) {
        var socket: DatagramSocket? = null
        try {
            socket = DatagramSocket()
            socket.soTimeout = timeoutMs.toInt().coerceIn(500, 30000)

            val dnsQuery = buildDnsQuery(domain, recordType)
            val serverAddress = InetAddress.getByName(host)
            val requestPacket = DatagramPacket(dnsQuery, dnsQuery.size, serverAddress, port)

            socket.send(requestPacket)

            val responseBuffer = ByteArray(512)
            val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
            socket.receive(responsePacket)

            // Parse the DNS response
            val responseCode = if (responsePacket.length >= 4) {
                responseBuffer[3].toInt() and 0x0F
            } else 0

            // For A records, try to extract the IP
            if (recordType == DNS_TYPE_A) {
                val resolvedIp = parseDnsResponse(responseBuffer, responsePacket.length)

                if (resolvedIp != null) {
                    // Check for censorship (10.x.x.x hijacking)
                    val isCensored = resolvedIp.startsWith("10.") ||
                            resolvedIp == "0.0.0.0" ||
                            resolvedIp.startsWith("127.")

                    DnsQueryResult(
                        success = true,
                        resolvedIp = resolvedIp,
                        isCensored = isCensored,
                        responseCode = responseCode
                    )
                } else {
                    // NXDOMAIN (3) or NOERROR (0) without answer is still a valid response
                    DnsQueryResult(
                        success = responseCode == 0 || responseCode == 3,
                        error = if (responseCode != 0 && responseCode != 3) "Response code: $responseCode" else null,
                        responseCode = responseCode
                    )
                }
            } else {
                // For NS/TXT queries, we just care that we got a response
                // NXDOMAIN (3), NOERROR (0), or even NOTIMP (4) means the server processed the query
                DnsQueryResult(
                    success = responseCode == 0 || responseCode == 3,
                    responseCode = responseCode,
                    error = if (responseCode != 0 && responseCode != 3) "Response code: $responseCode" else null,
                    rawResponse = responseBuffer.copyOf(responsePacket.length),
                    rawLength = responsePacket.length
                )
            }
        } catch (e: Exception) {
            DnsQueryResult(success = false, error = e.message)
        } finally {
            socket?.close()
        }
    }

    /**
     * Build a DNS query packet for a specific record type
     */
    private fun buildDnsQuery(domain: String, recordType: Int = DNS_TYPE_A): ByteArray {
        val buffer = mutableListOf<Byte>()

        // Transaction ID (random)
        val transactionId = Random.nextInt(65536)
        buffer.add((transactionId shr 8).toByte())
        buffer.add((transactionId and 0xFF).toByte())

        // Flags: Standard query (0x0100)
        buffer.add(0x01.toByte())
        buffer.add(0x00.toByte())

        // Questions: 1
        buffer.add(0x00.toByte())
        buffer.add(0x01.toByte())

        // Answer RRs: 0
        buffer.add(0x00.toByte())
        buffer.add(0x00.toByte())

        // Authority RRs: 0
        buffer.add(0x00.toByte())
        buffer.add(0x00.toByte())

        // Additional RRs: 0
        buffer.add(0x00.toByte())
        buffer.add(0x00.toByte())

        // Query name (domain in DNS format)
        domain.split(".").forEach { label ->
            buffer.add(label.length.toByte())
            label.forEach { buffer.add(it.code.toByte()) }
        }
        buffer.add(0x00.toByte()) // Null terminator

        // Query type (A=1, NS=2, TXT=16, etc.)
        buffer.add((recordType shr 8).toByte())
        buffer.add((recordType and 0xFF).toByte())

        // Query class: IN (0x0001)
        buffer.add(0x00.toByte())
        buffer.add(0x01.toByte())

        return buffer.toByteArray()
    }

    /**
     * Parse the DNS response to extract the first A record IP
     */
    private fun parseDnsResponse(response: ByteArray, length: Int): String? {
        if (length < 12) return null

        // Check response code (last 4 bits of byte 3)
        val responseCode = response[3].toInt() and 0x0F
        if (responseCode != 0) return null // Error response

        // Get answer count
        val answerCount = ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)
        if (answerCount == 0) return null

        // Skip the header (12 bytes) and question section
        var offset = 12

        // Skip the question section
        while (offset < length && response[offset].toInt() != 0) {
            val labelLength = response[offset].toInt() and 0xFF
            if (labelLength >= 0xC0) {
                // Pointer, skip 2 bytes
                offset += 2
                break
            }
            offset += labelLength + 1
        }
        if (response[offset].toInt() == 0) offset++ // Skip null terminator
        offset += 4 // Skip QTYPE and QCLASS

        // Parse answer records
        for (i in 0 until answerCount) {
            if (offset >= length) break

            // Skip name (might be a pointer)
            if ((response[offset].toInt() and 0xC0) == 0xC0) {
                offset += 2 // Pointer
            } else {
                while (offset < length && response[offset].toInt() != 0) {
                    val labelLength = response[offset].toInt() and 0xFF
                    if (labelLength >= 0xC0) {
                        offset += 2
                        break
                    }
                    offset += labelLength + 1
                }
                if (offset < length && response[offset].toInt() == 0) offset++
            }

            if (offset + 10 > length) break

            // Read type
            val recordType = ((response[offset].toInt() and 0xFF) shl 8) or
                    (response[offset + 1].toInt() and 0xFF)
            offset += 2

            // Skip class
            offset += 2

            // Skip TTL
            offset += 4

            // Read data length
            val dataLength = ((response[offset].toInt() and 0xFF) shl 8) or
                    (response[offset + 1].toInt() and 0xFF)
            offset += 2

            // If it's an A record (type 1) with 4 bytes of data
            if (recordType == 1 && dataLength == 4 && offset + 4 <= length) {
                return "${response[offset].toInt() and 0xFF}." +
                        "${response[offset + 1].toInt() and 0xFF}." +
                        "${response[offset + 2].toInt() and 0xFF}." +
                        "${response[offset + 3].toInt() and 0xFF}"
            }

            offset += dataLength
        }

        return null
    }

    /**
     * Read a DNS wire-format domain name starting at [startOffset], handling compression pointers.
     * Returns (domainName, offsetAfterName).
     */
    private fun readDnsName(response: ByteArray, length: Int, startOffset: Int): Pair<String, Int> {
        val parts = mutableListOf<String>()
        var offset = startOffset
        var jumped = false
        var returnOffset = -1
        var safety = 0

        while (offset < length && safety++ < 128) {
            val labelLen = response[offset].toInt() and 0xFF
            if (labelLen == 0) {
                offset++
                break
            }
            if ((labelLen and 0xC0) == 0xC0) {
                // Compression pointer
                if (offset + 1 >= length) break
                if (!jumped) returnOffset = offset + 2
                offset = ((labelLen and 0x3F) shl 8) or (response[offset + 1].toInt() and 0xFF)
                jumped = true
                continue
            }
            offset++
            if (offset + labelLen > length) break
            parts.add(String(response, offset, labelLen))
            offset += labelLen
        }

        val afterName = if (jumped) returnOffset else offset
        return Pair(parts.joinToString("."), afterName)
    }

    /**
     * Skip the DNS header (12 bytes) and question section, returning offset to the answer section.
     */
    private fun skipQuestionSection(response: ByteArray, length: Int): Int {
        if (length < 12) return length

        val qdCount = ((response[4].toInt() and 0xFF) shl 8) or (response[5].toInt() and 0xFF)
        var offset = 12

        for (i in 0 until qdCount) {
            if (offset >= length) break
            // Skip QNAME
            while (offset < length) {
                val labelLen = response[offset].toInt() and 0xFF
                if (labelLen == 0) { offset++; break }
                if ((labelLen and 0xC0) == 0xC0) { offset += 2; break }
                offset += labelLen + 1
            }
            offset += 4 // Skip QTYPE + QCLASS
        }
        return offset
    }

    /**
     * Parse resource records in a section, extracting NS hostnames.
     */
    private fun parseNsFromSection(
        response: ByteArray,
        length: Int,
        startOffset: Int,
        count: Int,
        results: MutableList<String>
    ): Int {
        var offset = startOffset
        for (i in 0 until count) {
            if (offset >= length) break

            // Skip RR name
            val (_, afterName) = readDnsName(response, length, offset)
            offset = afterName

            if (offset + 10 > length) break

            val rrType = ((response[offset].toInt() and 0xFF) shl 8) or
                    (response[offset + 1].toInt() and 0xFF)
            offset += 2 // type
            offset += 2 // class
            offset += 4 // TTL

            val rdLength = ((response[offset].toInt() and 0xFF) shl 8) or
                    (response[offset + 1].toInt() and 0xFF)
            offset += 2

            if (rrType == DNS_TYPE_NS && offset + rdLength <= length) {
                val (nsName, _) = readDnsName(response, length, offset)
                if (nsName.isNotEmpty()) {
                    results.add(nsName)
                }
            }

            offset += rdLength
        }
        return offset
    }

    /**
     * Parse a raw DNS response to extract NS hostnames.
     * Checks answer section first, falls back to authority section.
     */
    private fun parseDnsNsResponse(response: ByteArray, length: Int): List<String> {
        if (length < 12) return emptyList()

        val anCount = ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)
        val nsCount = ((response[8].toInt() and 0xFF) shl 8) or (response[9].toInt() and 0xFF)

        val offset = skipQuestionSection(response, length)

        val results = mutableListOf<String>()

        // Parse answer section for NS records
        val afterAnswers = parseNsFromSection(response, length, offset, anCount, results)

        // If no NS in answers, check authority section
        if (results.isEmpty() && nsCount > 0) {
            parseNsFromSection(response, length, afterAnswers, nsCount, results)
        }

        return results
    }

    /**
     * Derive the parent domain for NS queries. For tunnel subdomains like
     * "t.example.com", the NS delegation records live in the parent zone
     * "example.com" — querying the tunnel subdomain itself would hit the
     * DNSTT server which can't answer NS queries. For 2-label domains like
     * "google.com", return as-is.
     */
    private fun getParentDomain(domain: String): String {
        val labels = domain.split(".")
        return if (labels.size > 2) labels.drop(1).joinToString(".") else domain
    }

    /**
     * Two-step NS delegation + glue record check:
     * 1. Query NS for the parent zone (where delegation records live)
     * 2. Resolve first NS hostname via A record → validates delegation chain
     */
    private suspend fun testNsDelegation(
        host: String,
        port: Int,
        testDomain: String,
        timeoutMs: Long
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            // Query NS for the parent zone — that's where the NS delegation for
            // the tunnel subdomain is defined (e.g. NS for "example.com" holds
            // the delegation "t.example.com NS ns.example.com").
            val nsDomain = getParentDomain(testDomain)
            val nsResult = withTimeoutOrNull(timeoutMs) {
                performDnsQuery(host, port, nsDomain, DNS_TYPE_NS, timeoutMs)
            } ?: return@withContext false

            if (!nsResult.success || nsResult.rawResponse == null) return@withContext false

            // Parse NS hostnames from the response
            val nsHosts = parseDnsNsResponse(nsResult.rawResponse, nsResult.rawLength)
            if (nsHosts.isEmpty()) return@withContext false

            // Resolve the first NS hostname (glue record) via A query
            val nsHostname = nsHosts[0].trimEnd('.')
            val glueResult = withTimeoutOrNull(timeoutMs) {
                performDnsQuery(host, port, nsHostname, DNS_TYPE_A, timeoutMs)
            } ?: return@withContext false

            // Pass only if the A query succeeded and returned an IP
            glueResult.success && glueResult.resolvedIp != null
        } catch (e: Exception) {
            false
        }
    }
}
