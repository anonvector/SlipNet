package app.slipnet.tunnel

import app.slipnet.util.AppLog as Log
import com.jcraft.jsch.Proxy
import com.jcraft.jsch.SocketFactory
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * JSch [Proxy] that tunnels SSH through a WebSocket connection.
 *
 * Flow:
 *   1. TCP connect to [wsHost]:[wsPort]
 *   2. (Optional) TLS handshake with custom SNI
 *   3. HTTP Upgrade to WebSocket at [path] with custom Host header
 *   4. Read 101 Switching Protocols
 *   5. Wrap I/O in WebSocket binary frames (RFC 6455)
 *   6. JSch runs SSH over the framed streams
 *
 * Compatible with CDN WebSocket proxies (Cloudflare, etc.) and standard
 * WebSocket-to-TCP bridges (websockify, wstunnel, xray, etc.).
 *
 * @param wsHost       WebSocket server address.
 * @param wsPort       WebSocket server port.
 * @param path         WebSocket endpoint path (default "/").
 * @param useTls       Use TLS (wss://) instead of plain (ws://).
 * @param tlsSni       TLS SNI override (empty → use wsHost).
 * @param customHost   Custom Host header for the upgrade request (empty → use wsHost).
 */
class ProxyWebSocket(
    private val wsHost: String,
    private val wsPort: Int,
    private val path: String = "/",
    private val useTls: Boolean = true,
    private val tlsSni: String = "",
    private val customHost: String = ""
) : Proxy {

    companion object {
        private const val TAG = "ProxyWebSocket"
        private const val CONNECT_TIMEOUT_MS = 30_000
        private const val WS_VERSION = "13"
        // WebSocket opcodes
        private const val OP_CONTINUATION = 0x0
        private const val OP_TEXT = 0x1
        private const val OP_BINARY = 0x2
        private const val OP_CLOSE = 0x8
        private const val OP_PING = 0x9
        private const val OP_PONG = 0xA
    }

    private var socket: Socket? = null
    private var wsInput: WebSocketInputStream? = null
    private var wsOutput: WebSocketOutputStream? = null

    override fun connect(
        socketFactory: SocketFactory?,
        host: String,
        port: Int,
        timeout: Int
    ) {
        Log.i(TAG, "Connecting WebSocket to $wsHost:$wsPort$path")
        if (useTls) Log.i(TAG, "  TLS: enabled (SNI: ${tlsSni.ifBlank { wsHost }})")
        if (customHost.isNotBlank()) Log.i(TAG, "  Custom Host: $customHost")

        val timeoutMs = if (timeout > 0) timeout else CONNECT_TIMEOUT_MS

        // Step 1: TCP connect
        val rawSocket = Socket().apply {
            connect(InetSocketAddress(wsHost, wsPort), timeoutMs)
            tcpNoDelay = true
        }

        // Step 2: Optional TLS (trust all certs for self-signed StunTLS servers)
        val activeSocket: Socket = if (useTls) {
            val sniHost = tlsSni.ifBlank { wsHost }
            val sslFactory = trustAllSslFactory()
            val sslSocket = sslFactory.createSocket(rawSocket, sniHost, wsPort, true) as SSLSocket
            val params = sslSocket.sslParameters
            params.serverNames = listOf(SNIHostName(sniHost))
            sslSocket.sslParameters = params
            sslSocket.startHandshake()
            Log.i(TAG, "TLS handshake complete (${sslSocket.session.protocol})")
            sslSocket
        } else {
            rawSocket
        }
        socket = activeSocket

        val rawOut = activeSocket.getOutputStream()
        val rawIn = activeSocket.getInputStream()

        // Step 3: WebSocket upgrade
        val wsKey = generateWebSocketKey()
        val hostHeader = customHost.ifBlank { if (wsPort == 443 || wsPort == 80) wsHost else "$wsHost:$wsPort" }
        val upgradeReq = "GET $path HTTP/1.1\r\n" +
                "Host: $hostHeader\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Key: $wsKey\r\n" +
                "Sec-WebSocket-Version: $WS_VERSION\r\n" +
                "\r\n"
        Log.d(TAG, "TX: WebSocket upgrade (Host: $hostHeader, Path: $path)")
        rawOut.write(upgradeReq.toByteArray(Charsets.US_ASCII))
        rawOut.flush()

        // Step 4: Read upgrade response
        val statusLine = readLine(rawIn)
            ?: throw RuntimeException("WebSocket server closed connection without response")
        Log.d(TAG, "RX: $statusLine")

        if (!statusLine.contains("101")) {
            throw RuntimeException("WebSocket upgrade failed: $statusLine")
        }
        // Consume response headers
        while (true) {
            val line = readLine(rawIn) ?: break
            if (line.isEmpty()) break
            Log.d(TAG, "RX header: $line")
        }

        Log.i(TAG, "WebSocket connection established")

        // Step 5: Wrap streams in WebSocket framing
        wsInput = WebSocketInputStream(rawIn, rawOut)
        wsOutput = WebSocketOutputStream(rawOut)
    }

    override fun getInputStream(): InputStream = wsInput!!
    override fun getOutputStream(): OutputStream = wsOutput!!
    override fun getSocket(): Socket = socket!!

    override fun close() {
        try { socket?.close() } catch (_: Exception) {}
        socket = null
        wsInput = null
        wsOutput = null
    }

    private fun generateWebSocketKey(): String {
        val bytes = ByteArray(16)
        SecureRandom().nextBytes(bytes)
        return android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
    }

    private fun readLine(input: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = input.read()
            if (b == -1) return if (sb.isEmpty()) null else sb.toString()
            if (b == '\r'.code) {
                val next = input.read()
                if (next == '\n'.code) return sb.toString()
                sb.append('\r')
                if (next != -1) sb.append(next.toChar())
            } else {
                sb.append(b.toChar())
            }
        }
    }

    // ── WebSocket binary frame I/O (RFC 6455) ────────────────────────

    /**
     * Reads WebSocket frames, returns payload of binary/text data frames.
     * Automatically handles ping (responds with pong) and close frames.
     */
    private inner class WebSocketInputStream(
        private val rawIn: InputStream,
        private val rawOut: OutputStream
    ) : InputStream() {

        private var frameBuffer: ByteArray? = null
        private var frameOffset = 0
        private var framLen = 0

        override fun read(): Int {
            val buf = ByteArray(1)
            val n = read(buf, 0, 1)
            return if (n == -1) -1 else (buf[0].toInt() and 0xFF)
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            while (true) {
                // Return buffered data first
                val fb = frameBuffer
                if (fb != null && frameOffset < framLen) {
                    val available = framLen - frameOffset
                    val toRead = minOf(available, len)
                    System.arraycopy(fb, frameOffset, b, off, toRead)
                    frameOffset += toRead
                    if (frameOffset >= framLen) {
                        frameBuffer = null
                    }
                    return toRead
                }

                // Read next frame
                val frame = readFrame() ?: return -1
                val opcode = frame.first
                val payload = frame.second

                when (opcode) {
                    OP_BINARY, OP_TEXT, OP_CONTINUATION -> {
                        if (payload.isEmpty()) continue
                        frameBuffer = payload
                        frameOffset = 0
                        framLen = payload.size
                        // Loop back to return data from buffer
                    }
                    OP_PING -> {
                        // Auto-respond with pong
                        writeFrame(rawOut, OP_PONG, payload)
                    }
                    OP_PONG -> { /* ignore */ }
                    OP_CLOSE -> {
                        return -1
                    }
                    else -> { /* ignore unknown opcodes */ }
                }
            }
        }

        private fun readFrame(): Pair<Int, ByteArray>? {
            val b0 = rawIn.read()
            if (b0 == -1) return null
            val b1 = rawIn.read()
            if (b1 == -1) return null

            val opcode = b0 and 0x0F
            val masked = (b1 and 0x80) != 0
            var payloadLen = (b1 and 0x7F).toLong()

            if (payloadLen == 126L) {
                val h = readExact(rawIn, 2) ?: return null
                payloadLen = ((h[0].toInt() and 0xFF).toLong() shl 8) or
                        (h[1].toInt() and 0xFF).toLong()
            } else if (payloadLen == 127L) {
                val h = readExact(rawIn, 8) ?: return null
                payloadLen = 0L
                for (i in 0..7) {
                    payloadLen = (payloadLen shl 8) or (h[i].toInt() and 0xFF).toLong()
                }
            }

            val maskKey = if (masked) readExact(rawIn, 4) else null

            val payload = if (payloadLen > 0) {
                val data = readExact(rawIn, payloadLen.toInt()) ?: return null
                if (maskKey != null) {
                    for (i in data.indices) {
                        data[i] = (data[i].toInt() xor maskKey[i % 4].toInt()).toByte()
                    }
                }
                data
            } else {
                ByteArray(0)
            }

            return opcode to payload
        }
    }

    /**
     * Wraps writes in masked WebSocket binary frames.
     */
    private inner class WebSocketOutputStream(
        private val rawOut: OutputStream
    ) : OutputStream() {

        override fun write(b: Int) {
            write(byteArrayOf(b.toByte()), 0, 1)
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            if (len == 0) return
            val payload = if (off == 0 && len == b.size) b else b.copyOfRange(off, off + len)
            writeFrame(rawOut, OP_BINARY, payload)
        }

        override fun flush() {
            rawOut.flush()
        }
    }

    private val frameRandom = SecureRandom()

    private fun writeFrame(out: OutputStream, opcode: Int, payload: ByteArray) {
        val len = payload.size

        // FIN + opcode
        out.write(0x80 or opcode)

        // Mask bit (always set for client) + payload length
        when {
            len <= 125 -> out.write(0x80 or len)
            len <= 65535 -> {
                out.write(0x80 or 126)
                out.write(len shr 8)
                out.write(len and 0xFF)
            }
            else -> {
                out.write(0x80 or 127)
                val longLen = len.toLong()
                for (i in 7 downTo 0) {
                    out.write(((longLen shr (i * 8)) and 0xFF).toInt())
                }
            }
        }

        // Masking key
        val mask = ByteArray(4)
        frameRandom.nextBytes(mask)
        out.write(mask)

        // Masked payload
        val masked = ByteArray(len)
        for (i in 0 until len) {
            masked[i] = (payload[i].toInt() xor mask[i % 4].toInt()).toByte()
        }
        out.write(masked)
        out.flush()
    }

    private fun readExact(input: InputStream, len: Int): ByteArray? {
        val buf = ByteArray(len)
        var off = 0
        while (off < len) {
            val n = input.read(buf, off, len - off)
            if (n <= 0) return null
            off += n
        }
        return buf
    }

    private fun trustAllSslFactory(): SSLSocketFactory {
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        })
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, trustAll, SecureRandom())
        return ctx.socketFactory
    }
}
