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
 * JSch [Proxy] that tunnels SSH through an HTTP CONNECT proxy.
 *
 * Supports:
 *  - Custom Host header for CDN facades / header-based routing.
 *  - Optional TLS wrapping after CONNECT succeeds (SSH-over-TLS-over-HTTP-proxy).
 *
 * Flow:
 *   1. TCP connect to [proxyHost]:[proxyPort]
 *   2. Send  CONNECT sshHost:sshPort HTTP/1.1\r\nHost: customHost\r\n\r\n
 *   3. Read  HTTP/1.x 200 ...
 *   4. (Optional) TLS handshake with custom SNI
 *   5. JSch runs SSH protocol over the resulting streams
 *
 * @param proxyHost  HTTP proxy address.
 * @param proxyPort  HTTP proxy port.
 * @param customHost Custom Host header value (empty → use target host:port).
 * @param tlsEnabled Wrap the tunneled connection in TLS after CONNECT succeeds.
 * @param tlsSni     SNI hostname for the TLS ClientHello (empty → use target host).
 */
class ProxyHttpConnect(
    private val proxyHost: String,
    private val proxyPort: Int,
    private val customHost: String = "",
    private val tlsEnabled: Boolean = false,
    private val tlsSni: String = ""
) : Proxy {

    companion object {
        private const val TAG = "ProxyHttpConnect"
        private const val CONNECT_TIMEOUT_MS = 30_000
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
        Log.i(TAG, "Connecting to HTTP proxy $proxyHost:$proxyPort -> $host:$port")
        if (customHost.isNotBlank()) Log.i(TAG, "  Custom Host header: $customHost")
        if (tlsEnabled) Log.i(TAG, "  TLS enabled (SNI: ${tlsSni.ifBlank { host }})")

        // Step 1: TCP connect to the proxy
        val timeoutMs = if (timeout > 0) timeout else CONNECT_TIMEOUT_MS
        val sock = Socket().apply {
            connect(InetSocketAddress(proxyHost, proxyPort), timeoutMs)
            tcpNoDelay = true
        }
        socket = sock

        val out = sock.getOutputStream()
        val inp = sock.getInputStream()

        // Step 2: Send HTTP CONNECT request
        val hostHeader = customHost.ifBlank { "$host:$port" }
        val connectReq = "CONNECT $host:$port HTTP/1.1\r\n" +
                "Host: $hostHeader\r\n" +
                "Proxy-Connection: keep-alive\r\n" +
                "\r\n"
        Log.d(TAG, "TX: CONNECT $host:$port (Host: $hostHeader)")
        out.write(connectReq.toByteArray(Charsets.US_ASCII))
        out.flush()

        // Step 3: Read HTTP response status line (byte-by-byte to avoid over-reading
        // into a BufferedReader buffer, which would consume SSH protocol data)
        val statusLine = readLine(inp)
            ?: throw RuntimeException("HTTP proxy closed connection without response")
        Log.d(TAG, "RX: $statusLine")

        // Expect "HTTP/1.x 200 ..."
        if (!statusLine.startsWith("HTTP/")) {
            throw RuntimeException("HTTP proxy returned invalid response: $statusLine")
        }
        val statusCode = statusLine.split(" ").getOrNull(1)?.toIntOrNull()
            ?: throw RuntimeException("HTTP proxy returned unparseable status: $statusLine")
        if (statusCode !in 200..299) {
            throw RuntimeException("HTTP proxy CONNECT failed: $statusLine")
        }

        // Consume remaining response headers until empty line
        while (true) {
            val line = readLine(inp) ?: break
            if (line.isEmpty()) break
            Log.d(TAG, "RX header: $line")
        }

        Log.i(TAG, "HTTP CONNECT tunnel established to $host:$port")

        // Step 4: Optional TLS wrapping
        var activeSocket: Socket = sock
        if (tlsEnabled) {
            val sniHost = tlsSni.ifBlank { host }
            Log.i(TAG, "Upgrading to TLS (SNI: $sniHost)")

            val sslFactory = trustAllSslFactory()
            val sslSocket = sslFactory.createSocket(sock, sniHost, port, true) as SSLSocket

            val params = sslSocket.sslParameters
            params.serverNames = listOf(SNIHostName(sniHost))
            sslSocket.sslParameters = params

            sslSocket.startHandshake()
            Log.i(TAG, "TLS handshake complete (${sslSocket.session.protocol}, ${sslSocket.session.cipherSuite})")
            activeSocket = sslSocket
        }

        inputStream = activeSocket.getInputStream()
        outputStream = activeSocket.getOutputStream()
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
}
