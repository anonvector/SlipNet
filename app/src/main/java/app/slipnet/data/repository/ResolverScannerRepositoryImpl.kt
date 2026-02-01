package app.slipnet.data.repository

import app.slipnet.data.scanner.DefaultResolvers
import app.slipnet.domain.model.ResolverScanResult
import app.slipnet.domain.model.ResolverStatus
import app.slipnet.domain.repository.ResolverScannerRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ResolverScannerRepositoryImpl @Inject constructor() : ResolverScannerRepository {

    override fun getDefaultResolvers(): List<String> {
        return DefaultResolvers.list
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

    override suspend fun scanResolver(
        host: String,
        port: Int,
        testDomain: String,
        timeoutMs: Long
    ): ResolverScanResult = withContext(Dispatchers.IO) {
        val startTime = System.currentTimeMillis()

        try {
            val result = withTimeoutOrNull(timeoutMs) {
                performDnsQuery(host, port, testDomain)
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

    private data class DnsQueryResult(
        val success: Boolean,
        val resolvedIp: String? = null,
        val isCensored: Boolean = false,
        val error: String? = null
    )

    private suspend fun performDnsQuery(
        host: String,
        port: Int,
        domain: String
    ): DnsQueryResult = withContext(Dispatchers.IO) {
        var socket: DatagramSocket? = null
        try {
            socket = DatagramSocket()
            socket.soTimeout = 3000 // 3 second socket timeout

            val dnsQuery = buildDnsQuery(domain)
            val serverAddress = InetAddress.getByName(host)
            val requestPacket = DatagramPacket(dnsQuery, dnsQuery.size, serverAddress, port)

            socket.send(requestPacket)

            val responseBuffer = ByteArray(512)
            val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
            socket.receive(responsePacket)

            // Parse the DNS response
            val resolvedIp = parseDnsResponse(responseBuffer, responsePacket.length)

            if (resolvedIp != null) {
                // Check for censorship (10.x.x.x hijacking)
                val isCensored = resolvedIp.startsWith("10.") ||
                        resolvedIp == "0.0.0.0" ||
                        resolvedIp.startsWith("127.")

                DnsQueryResult(
                    success = true,
                    resolvedIp = resolvedIp,
                    isCensored = isCensored
                )
            } else {
                DnsQueryResult(success = false, error = "No IP in response")
            }
        } catch (e: Exception) {
            DnsQueryResult(success = false, error = e.message)
        } finally {
            socket?.close()
        }
    }

    /**
     * Build a simple DNS query packet for an A record
     */
    private fun buildDnsQuery(domain: String): ByteArray {
        val buffer = mutableListOf<Byte>()

        // Transaction ID (random)
        val transactionId = (Math.random() * 65535).toInt()
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

        // Query type: A (0x0001)
        buffer.add(0x00.toByte())
        buffer.add(0x01.toByte())

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
