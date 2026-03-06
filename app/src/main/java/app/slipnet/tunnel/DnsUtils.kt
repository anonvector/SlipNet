package app.slipnet.tunnel

/**
 * DNS utility functions shared across SOCKS bridges.
 */
object DnsUtils {
    private const val QTYPE_AAAA: Int = 28

    /**
     * Check if a raw DNS query payload is an AAAA (IPv6) query.
     * DNS header is 12 bytes, followed by QNAME, QTYPE (2 bytes), QCLASS (2 bytes).
     */
    fun isAAAAQuery(payload: ByteArray): Boolean {
        if (payload.size < 14) return false // too short for a valid DNS query
        // Skip 12-byte header, then skip QNAME labels
        var offset = 12
        while (offset < payload.size) {
            val labelLen = payload[offset].toInt() and 0xFF
            if (labelLen == 0) {
                offset++ // null terminator
                break
            }
            offset += labelLen + 1
        }
        // QTYPE is the next 2 bytes
        if (offset + 2 > payload.size) return false
        val qtype = ((payload[offset].toInt() and 0xFF) shl 8) or (payload[offset + 1].toInt() and 0xFF)
        return qtype == QTYPE_AAAA
    }

    /**
     * Build a synthetic NODATA response for an AAAA query.
     * Copies the query header, flips QR bit, sets RCODE=0 (no error),
     * ANCOUNT=0 (no answers). Apps see "no AAAA records" and fall back to A.
     */
    fun buildAAAANoDataResponse(query: ByteArray): ByteArray? {
        if (query.size < 12) return null
        val response = query.copyOf()
        // Byte 2: set QR=1 (response), keep opcode, clear AA/TC/RD bits then set RD
        response[2] = ((query[2].toInt() and 0xFF) or 0x80).toByte() // QR=1
        // Byte 3: RA=1, RCODE=0 (no error)
        response[3] = ((query[3].toInt() and 0xF0) or 0x80).toByte()
        // ANCOUNT = 0
        response[6] = 0
        response[7] = 0
        // NSCOUNT = 0
        response[8] = 0
        response[9] = 0
        // ARCOUNT = 0
        response[10] = 0
        response[11] = 0
        return response
    }
}
