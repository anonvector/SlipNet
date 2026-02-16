package app.slipnet.tunnel

import app.slipnet.util.AppLog as Log
import java.io.InputStream

/**
 * Sniffs TLS SNI and HTTP Host headers from the first bytes of a connection.
 * Used for domain-based routing when hev-socks5-tunnel sends SOCKS5 CONNECT
 * with IP addresses (TUN only sees IPs, not domain names).
 */
object ProtocolSniffer {
    private const val TAG = "ProtocolSniffer"
    private const val MAX_SNIFF_SIZE = 4096

    data class SniffResult(
        val domain: String?,
        val bufferedData: ByteArray,
        val bufferedLength: Int
    )

    /**
     * Read up to [MAX_SNIFF_SIZE] bytes from [clientInput] and attempt to extract
     * a domain name from TLS ClientHello SNI or HTTP Host header.
     *
     * Returns the sniffed domain (if any) along with the buffered bytes that must
     * be prepended to the stream before forwarding.
     */
    fun sniff(clientInput: InputStream, timeoutMs: Int = 3000): SniffResult {
        val buffer = ByteArray(MAX_SNIFF_SIZE)
        var totalRead = 0

        try {
            // Read available bytes (up to buffer size)
            val bytesRead = clientInput.read(buffer, 0, buffer.size)
            if (bytesRead > 0) {
                totalRead = bytesRead
            }
        } catch (e: Exception) {
            Log.w(TAG, "Sniff read error: ${e.message}")
        }

        if (totalRead == 0) {
            return SniffResult(null, buffer, 0)
        }

        // Try TLS SNI first, then HTTP Host
        val domain = extractTlsSni(buffer, totalRead) ?: extractHttpHost(buffer, totalRead)

        return SniffResult(domain, buffer, totalRead)
    }

    /**
     * Extract SNI hostname from a TLS ClientHello message.
     *
     * TLS record format:
     *   [0]    ContentType = 0x16 (Handshake)
     *   [1-2]  ProtocolVersion
     *   [3-4]  Length
     *   [5]    HandshakeType = 0x01 (ClientHello)
     *   [6-8]  Length (3 bytes)
     *   [9-10] ClientVersion
     *   [11-42] Random (32 bytes)
     *   [43]   SessionID length
     *   ...    SessionID
     *   ...    CipherSuites (2-byte length prefix)
     *   ...    CompressionMethods (1-byte length prefix)
     *   ...    Extensions (2-byte length prefix)
     *     Each extension:
     *       [0-1] Type
     *       [2-3] Length
     *       SNI extension (type 0x0000):
     *         [0-1] ServerNameList length
     *         [2]   NameType (0x00 = host_name)
     *         [3-4] HostName length
     *         [5..] HostName (ASCII)
     */
    private fun extractTlsSni(buf: ByteArray, len: Int): String? {
        if (len < 44) return null

        // Check TLS record header
        if (buf[0].toInt() and 0xFF != 0x16) return null // Not a Handshake record

        val recordLength = ((buf[3].toInt() and 0xFF) shl 8) or (buf[4].toInt() and 0xFF)
        if (5 + recordLength > len) return null // Incomplete record

        // Check Handshake type = ClientHello
        if (buf[5].toInt() and 0xFF != 0x01) return null

        var pos = 43 // After fixed ClientHello fields (5 record + 4 handshake + 2 version + 32 random)

        // Skip Session ID
        if (pos >= len) return null
        val sessionIdLen = buf[pos].toInt() and 0xFF
        pos += 1 + sessionIdLen

        // Skip Cipher Suites
        if (pos + 2 > len) return null
        val cipherSuitesLen = ((buf[pos].toInt() and 0xFF) shl 8) or (buf[pos + 1].toInt() and 0xFF)
        pos += 2 + cipherSuitesLen

        // Skip Compression Methods
        if (pos >= len) return null
        val compMethodsLen = buf[pos].toInt() and 0xFF
        pos += 1 + compMethodsLen

        // Extensions
        if (pos + 2 > len) return null
        val extensionsLen = ((buf[pos].toInt() and 0xFF) shl 8) or (buf[pos + 1].toInt() and 0xFF)
        pos += 2

        val extensionsEnd = pos + extensionsLen
        if (extensionsEnd > len) return null

        while (pos + 4 <= extensionsEnd) {
            val extType = ((buf[pos].toInt() and 0xFF) shl 8) or (buf[pos + 1].toInt() and 0xFF)
            val extLen = ((buf[pos + 2].toInt() and 0xFF) shl 8) or (buf[pos + 3].toInt() and 0xFF)
            pos += 4

            if (extType == 0x0000 && extLen > 0) { // SNI extension
                // ServerNameList
                if (pos + 2 > len) return null
                // val sniListLen = ((buf[pos].toInt() and 0xFF) shl 8) or (buf[pos + 1].toInt() and 0xFF)
                var sniPos = pos + 2

                if (sniPos + 3 > len) return null
                val nameType = buf[sniPos].toInt() and 0xFF
                val nameLen = ((buf[sniPos + 1].toInt() and 0xFF) shl 8) or (buf[sniPos + 2].toInt() and 0xFF)
                sniPos += 3

                if (nameType == 0x00 && nameLen > 0 && sniPos + nameLen <= len) {
                    return String(buf, sniPos, nameLen, Charsets.US_ASCII).lowercase()
                }
            }

            pos += extLen
        }

        return null
    }

    /**
     * Extract Host header from an HTTP request.
     * Checks for common HTTP method prefixes, then scans for "Host:" header.
     */
    private fun extractHttpHost(buf: ByteArray, len: Int): String? {
        if (len < 16) return null

        // Check for HTTP method at start
        val start = String(buf, 0, minOf(len, 10), Charsets.US_ASCII)
        val httpMethods = listOf("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ")
        if (httpMethods.none { start.startsWith(it) }) return null

        // Find "Host:" header (case-insensitive)
        val text = String(buf, 0, len, Charsets.US_ASCII)
        val hostIdx = text.indexOf("\r\nHost:", ignoreCase = true)
        if (hostIdx < 0) return null

        val valueStart = hostIdx + 7 // length of "\r\nHost:"
        val lineEnd = text.indexOf("\r\n", valueStart)
        if (lineEnd < 0) return null

        var host = text.substring(valueStart, lineEnd).trim()

        // Strip port if present (e.g., "example.com:8080" -> "example.com")
        val colonIdx = host.lastIndexOf(':')
        if (colonIdx > 0) {
            // Make sure it's not an IPv6 address
            val afterColon = host.substring(colonIdx + 1)
            if (afterColon.all { it.isDigit() }) {
                host = host.substring(0, colonIdx)
            }
        }

        return host.lowercase().ifEmpty { null }
    }
}
