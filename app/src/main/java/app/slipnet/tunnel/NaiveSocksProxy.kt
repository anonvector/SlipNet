package app.slipnet.tunnel

import app.slipnet.util.AppLog as Log
import com.jcraft.jsch.Proxy
import com.jcraft.jsch.SocketFactory
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Custom SOCKS5 proxy for NaiveProxy's Chromium-based SOCKS5 server.
 *
 * Differences from JSch's ProxySOCKS5:
 *  - Only offers NO_AUTH (0x00) method. JSch offers both NO_AUTH + USERNAME/PASSWORD;
 *    NaiveProxy's Chromium SOCKS5 server may select USERNAME/PASSWORD and reject
 *    empty credentials, causing silent connection failure.
 *  - Uses ATYP 0x01 (IPv4) for IP addresses. JSch always uses ATYP 0x03 (domain)
 *    even for "127.0.0.1", which Chromium may handle differently.
 *  - Detailed logging at every step of the SOCKS5 handshake for debugging.
 */
class NaiveSocksProxy(
    private val proxyHost: String,
    private val proxyPort: Int
) : Proxy {

    companion object {
        private const val TAG = "NaiveSocksProxy"
        private const val SOCKS5_VERSION: Byte = 0x05
        private const val CMD_CONNECT: Byte = 0x01
        private const val ATYP_IPV4: Byte = 0x01
        private const val ATYP_DOMAIN: Byte = 0x03
        private const val METHOD_NO_AUTH: Byte = 0x00
    }

    private var socket: Socket? = null
    private var inputStream: InputStream? = null
    private var outputStream: OutputStream? = null

    override fun connect(
        socketFactory: SocketFactory?,
        host: String,
        port: Int,
        timeout: Int
    ) {
        Log.i(TAG, "Connecting to NaiveProxy SOCKS5 at $proxyHost:$proxyPort -> $host:$port")

        // Step 1: Open TCP connection to NaiveProxy
        val sock = if (socketFactory != null) {
            socketFactory.createSocket(proxyHost, proxyPort) as Socket
        } else {
            Socket().apply {
                val addr = InetSocketAddress(proxyHost, proxyPort)
                connect(addr, if (timeout > 0) timeout else 15000)
            }
        }
        socket = sock
        sock.tcpNoDelay = true

        val out = sock.getOutputStream()
        val inp = sock.getInputStream()
        outputStream = out
        inputStream = inp

        // Step 2: SOCKS5 greeting — only offer NO_AUTH (not USERNAME/PASSWORD)
        val greeting = byteArrayOf(
            SOCKS5_VERSION, // VER
            0x01,           // NMETHODS = 1
            METHOD_NO_AUTH  // NO AUTHENTICATION REQUIRED
        )
        Log.d(TAG, "TX greeting: ${greeting.toHex()}")
        out.write(greeting)
        out.flush()

        // Step 3: Read server's method selection
        val methodReply = ByteArray(2)
        readFully(inp, methodReply, 2)
        Log.d(TAG, "RX method: ${methodReply.toHex()}")

        if (methodReply[0] != SOCKS5_VERSION) {
            throw RuntimeException("SOCKS5 version mismatch: got ${methodReply[0].toInt() and 0xFF}, expected 5")
        }
        if (methodReply[1] != METHOD_NO_AUTH) {
            throw RuntimeException("SOCKS5 method rejected: server selected ${methodReply[1].toInt() and 0xFF}, expected NO_AUTH (0)")
        }

        // Step 4: Send CONNECT request
        val ipv4 = parseIPv4(host)
        if (ipv4 != null) {
            // ATYP 0x01 (IPv4) for IP addresses
            val req = ByteArray(10)
            req[0] = SOCKS5_VERSION
            req[1] = CMD_CONNECT
            req[2] = 0x00 // RSV
            req[3] = ATYP_IPV4
            System.arraycopy(ipv4, 0, req, 4, 4)
            req[8] = (port shr 8).toByte()
            req[9] = (port and 0xFF).toByte()
            Log.d(TAG, "TX CONNECT (IPv4 $host:$port): ${req.toHex()}")
            out.write(req)
        } else {
            // ATYP 0x03 (domain) for hostnames
            val hostBytes = host.toByteArray(Charsets.US_ASCII)
            val req = ByteArray(7 + hostBytes.size)
            req[0] = SOCKS5_VERSION
            req[1] = CMD_CONNECT
            req[2] = 0x00 // RSV
            req[3] = ATYP_DOMAIN
            req[4] = hostBytes.size.toByte()
            System.arraycopy(hostBytes, 0, req, 5, hostBytes.size)
            req[5 + hostBytes.size] = (port shr 8).toByte()
            req[6 + hostBytes.size] = (port and 0xFF).toByte()
            Log.d(TAG, "TX CONNECT (domain $host:$port): ${req.toHex()}")
            out.write(req)
        }
        out.flush()

        // Step 5: Read CONNECT reply header (VER + REP + RSV + ATYP)
        val hdr = ByteArray(4)
        readFully(inp, hdr, 4)
        Log.d(TAG, "RX reply header: ${hdr.toHex()}")

        if (hdr[0] != SOCKS5_VERSION) {
            throw RuntimeException("SOCKS5 reply version mismatch: got ${hdr[0].toInt() and 0xFF}")
        }
        val rep = hdr[1].toInt() and 0xFF
        if (rep != 0x00) {
            val msg = when (rep) {
                0x01 -> "general SOCKS server failure"
                0x02 -> "connection not allowed by ruleset"
                0x03 -> "network unreachable"
                0x04 -> "host unreachable"
                0x05 -> "connection refused"
                0x06 -> "TTL expired"
                0x07 -> "command not supported"
                0x08 -> "address type not supported"
                else -> "unknown error 0x${rep.toString(16)}"
            }
            throw RuntimeException("SOCKS5 CONNECT failed: $msg (REP=0x${rep.toString(16)})")
        }

        // Read BND.ADDR + BND.PORT based on ATYP
        when (hdr[3].toInt() and 0xFF) {
            0x01 -> readFully(inp, ByteArray(6), 6)   // IPv4 (4) + port (2)
            0x03 -> {                                   // Domain
                val lenBuf = ByteArray(1)
                readFully(inp, lenBuf, 1)
                readFully(inp, ByteArray((lenBuf[0].toInt() and 0xFF) + 2), (lenBuf[0].toInt() and 0xFF) + 2)
            }
            0x04 -> readFully(inp, ByteArray(18), 18)  // IPv6 (16) + port (2)
            else -> throw RuntimeException("SOCKS5 unknown ATYP: 0x${(hdr[3].toInt() and 0xFF).toString(16)}")
        }

        Log.i(TAG, "SOCKS5 tunnel established to $host:$port")
    }

    override fun getInputStream(): InputStream = inputStream!!
    override fun getOutputStream(): OutputStream = outputStream!!
    override fun getSocket(): Socket = socket!!

    override fun close() {
        try { socket?.close() } catch (_: Exception) {}
        socket = null
        inputStream = null
        outputStream = null
    }

    private fun readFully(input: InputStream, buf: ByteArray, len: Int) {
        var off = 0
        while (off < len) {
            val n = input.read(buf, off, len - off)
            if (n <= 0) {
                throw RuntimeException("SOCKS5 stream closed after $off/$len bytes")
            }
            off += n
        }
    }

    private fun parseIPv4(host: String): ByteArray? {
        val parts = host.split('.')
        if (parts.size != 4) return null
        return try {
            ByteArray(4) { i ->
                val v = parts[i].toInt()
                if (v !in 0..255) return null
                v.toByte()
            }
        } catch (_: NumberFormatException) {
            null
        }
    }

    private fun ByteArray.toHex(): String =
        joinToString(" ") { "%02X".format(it) }
}
