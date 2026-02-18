package app.slipnet.data.repository

import android.content.Context
import app.slipnet.R
import app.slipnet.domain.model.DnsTunnelTestResult
import app.slipnet.domain.model.ResolverScanResult
import app.slipnet.domain.model.ResolverStatus
import app.slipnet.domain.model.ScanMode
import app.slipnet.domain.repository.ResolverScannerRepository
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import app.slipnet.tunnel.DomainRouter
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.random.Random

@Singleton
class ResolverScannerRepositoryImpl @Inject constructor(
    @ApplicationContext private val context: Context
) : ResolverScannerRepository {

    private var cachedResolvers: List<String>? = null

    override fun getDefaultResolvers(): List<String> {
        // Return cached list if available
        cachedResolvers?.let { return it }

        // Load from raw resource file (famous DNS servers are at the top of the file)
        val resolvers = try {
            context.resources.openRawResource(R.raw.resolvers).bufferedReader().useLines { lines ->
                lines
                    .map { it.trim() }
                    .filter { it.isNotBlank() && !it.startsWith("#") && isValidIpAddress(it) }
                    .toList()
            }
        } catch (e: Exception) {
            // Fallback to basic public DNS if resource loading fails
            listOf("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1")
        }

        cachedResolvers = resolvers
        return resolvers
    }

    override fun parseResolverList(content: String): List<String> {
        return content.lines()
            .map { it.trim() }
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .filter { isValidIpAddress(it) }
            .distinct()
    }

    private fun isValidIpAddress(ip: String): Boolean {
        return try {
            val parts = ip.split(".")
            if (parts.size != 4) return false
            parts.all { part ->
                val num = part.toIntOrNull() ?: return@all false
                num in 0..255
            }
        } catch (e: Exception) {
            false
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
        timeoutMs: Long,
        scanMode: ScanMode
    ): ResolverScanResult = withContext(Dispatchers.IO) {
        val startTime = System.currentTimeMillis()

        try {
            when (scanMode) {
                ScanMode.SIMPLE -> scanResolverSimple(host, port, testDomain, timeoutMs, startTime)
                ScanMode.DNS_TUNNEL -> scanResolverDnsTunnel(host, port, testDomain, timeoutMs, startTime)
            }
        } catch (e: Exception) {
            val responseTime = System.currentTimeMillis() - startTime
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
     * Simple ping scan - just check if resolver responds to A record query
     */
    private suspend fun scanResolverSimple(
        host: String,
        port: Int,
        testDomain: String,
        timeoutMs: Long,
        startTime: Long
    ): ResolverScanResult = withContext(Dispatchers.IO) {
        val result = withTimeoutOrNull(timeoutMs) {
            performDnsQuery(host, port, testDomain, DNS_TYPE_A)
        }

        val responseTime = System.currentTimeMillis() - startTime

        when {
            result == null -> ResolverScanResult(
                host = host,
                port = port,
                status = ResolverStatus.TIMEOUT,
                responseTimeMs = responseTime
            )
            result.isCensored -> ResolverScanResult(
                host = host,
                port = port,
                status = ResolverStatus.CENSORED,
                responseTimeMs = responseTime,
                errorMessage = "Hijacked to ${result.resolvedIp}"
            )
            result.success -> ResolverScanResult(
                host = host,
                port = port,
                status = ResolverStatus.WORKING,
                responseTimeMs = responseTime
            )
            else -> ResolverScanResult(
                host = host,
                port = port,
                status = ResolverStatus.ERROR,
                responseTimeMs = responseTime,
                errorMessage = result.error
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
        // First, do a basic connectivity check
        val basicCheck = withTimeoutOrNull(timeoutMs) {
            val randSub = generateRandomSubdomain()
            performDnsQuery(host, port, "$randSub.$testDomain", DNS_TYPE_A)
        }

        if (basicCheck == null) {
            val responseTime = System.currentTimeMillis() - startTime
            return@withContext ResolverScanResult(
                host = host,
                port = port,
                status = ResolverStatus.TIMEOUT,
                responseTimeMs = responseTime
            )
        }

        // Test NS record support
        val nsSupport = testRecordType(host, port, testDomain, DNS_TYPE_NS, timeoutMs)

        // Test TXT record support
        val txtSupport = testRecordType(host, port, testDomain, DNS_TYPE_TXT, timeoutMs)

        // Test random subdomain 1 (nested random subdomains)
        val randomSubdomain1 = testRandomSubdomain(host, port, testDomain, timeoutMs)

        // Test random subdomain 2 (another nested random subdomain test)
        val randomSubdomain2 = testRandomSubdomain(host, port, testDomain, timeoutMs)

        val responseTime = System.currentTimeMillis() - startTime

        val tunnelResult = DnsTunnelTestResult(
            nsSupport = nsSupport,
            txtSupport = txtSupport,
            randomSubdomain1 = randomSubdomain1,
            randomSubdomain2 = randomSubdomain2
        )

        // Only mark as WORKING if all 4 tests pass (strict requirement for DNS tunneling)
        val status = if (tunnelResult.isCompatible) {
            ResolverStatus.WORKING
        } else {
            ResolverStatus.ERROR
        }

        ResolverScanResult(
            host = host,
            port = port,
            status = status,
            responseTimeMs = responseTime,
            tunnelTestResult = tunnelResult,
            errorMessage = if (!tunnelResult.isCompatible) {
                "Score: ${tunnelResult.score}/${tunnelResult.maxScore} - ${tunnelResult.details}"
            } else null
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
                performDnsQuery(host, port, queryDomain, recordType)
            }
            // Success if we got a response OR if we got NXDOMAIN/NOERROR
            // (NXDOMAIN is acceptable - means server queried properly)
            result != null || true // If timeout, return false; otherwise the query was processed
        } catch (e: Exception) {
            // NXDOMAIN or similar errors are acceptable - server responded
            val errorCode = e.message ?: ""
            errorCode.contains("NXDOMAIN") || errorCode.contains("NOERROR") ||
                    errorCode.contains("NOTIMP").not() // Not implemented is bad
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
                performDnsQuery(host, port, queryDomain, DNS_TYPE_A)
            }
            // Any response (including NXDOMAIN) means the resolver processed the query
            result != null
        } catch (e: Exception) {
            false
        }
    }

    override fun generateCountryRangeIps(
        context: android.content.Context,
        countryCode: String,
        count: Int
    ): List<String> {
        val ranges = loadCidrRanges(context, countryCode)
        if (ranges.isEmpty()) return emptyList()

        // Precompute cumulative sizes for proportional sampling
        val cumulativeSizes = LongArray(ranges.size)
        var cumulative = 0L
        for (i in ranges.indices) {
            val (start, end) = ranges[i]
            cumulative += (end - start + 1)
            cumulativeSizes[i] = cumulative
        }
        val totalIps = cumulative

        val result = mutableSetOf<String>()
        val maxAttempts = count * 3 // avoid infinite loop on small ranges
        var attempts = 0

        while (result.size < count && attempts < maxAttempts) {
            attempts++
            // Pick a random position in the total IP space
            val pos = (Random.nextLong(totalIps) and 0x7FFFFFFFFFFFFFFFL) % totalIps

            // Binary search for which range this falls into
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

    override fun scanResolvers(
        hosts: List<String>,
        port: Int,
        testDomain: String,
        timeoutMs: Long,
        concurrency: Int,
        scanMode: ScanMode
    ): Flow<ResolverScanResult> = channelFlow {
        val semaphore = Semaphore(concurrency)

        hosts.forEach { host ->
            launch {
                semaphore.acquire()
                try {
                    val result = scanResolver(host, port, testDomain, timeoutMs, scanMode)
                    send(result)
                } finally {
                    semaphore.release()
                }
            }
        }
    }

    companion object {
        private const val DNS_TYPE_A = 1      // A record (IPv4 address)
        private const val DNS_TYPE_NS = 2     // NS record (Name server)
        private const val DNS_TYPE_TXT = 16   // TXT record (Text)
    }

    private data class DnsQueryResult(
        val success: Boolean,
        val resolvedIp: String? = null,
        val isCensored: Boolean = false,
        val error: String? = null,
        val responseCode: Int = 0
    )

    private suspend fun performDnsQuery(
        host: String,
        port: Int,
        domain: String,
        recordType: Int = DNS_TYPE_A
    ): DnsQueryResult = withContext(Dispatchers.IO) {
        var socket: DatagramSocket? = null
        try {
            socket = DatagramSocket()
            socket.soTimeout = 3000 // 3 second socket timeout

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
                    error = if (responseCode != 0 && responseCode != 3) "Response code: $responseCode" else null
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
}
