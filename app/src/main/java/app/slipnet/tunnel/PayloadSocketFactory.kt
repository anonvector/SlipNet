package app.slipnet.tunnel

import app.slipnet.util.AppLog as Log
import com.jcraft.jsch.SocketFactory
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * JSch [SocketFactory] that sends a raw payload on the TCP socket before
 * the SSH handshake begins. Optionally wraps the connection in TLS afterwards.
 *
 * This is used for DPI bypass: the raw prefix disguises the initial bytes
 * of the connection so that deep packet inspection does not immediately
 * identify the SSH protocol banner.
 *
 * Payload placeholders:
 *  - `[host]`  → replaced with the target hostname
 *  - `[port]`  → replaced with the target port
 *  - `[crlf]`  → \r\n
 *  - `[cr]`    → \r
 *  - `[lf]`    → \n
 *
 * @param payload      Raw payload template string.
 * @param tlsEnabled   Wrap in TLS after sending the payload.
 * @param tlsSni       SNI hostname for TLS (empty → use target host).
 * @param connectTimeoutMs TCP connect timeout in milliseconds.
 */
class PayloadSocketFactory(
    private val payload: String,
    private val tlsEnabled: Boolean = false,
    private val tlsSni: String = "",
    private val connectTimeoutMs: Int = 30_000
) : SocketFactory {

    private val TAG = "PayloadSocketFactory"

    override fun createSocket(host: String, port: Int): Socket {
        Log.i(TAG, "Creating socket to $host:$port (payload: ${payload.length} chars, TLS: $tlsEnabled)")

        // 1. Open a plain TCP socket
        val rawSocket = Socket()
        rawSocket.connect(InetSocketAddress(host, port), connectTimeoutMs)

        // 2. Send raw payload before anything else
        val resolvedPayload = resolvePayload(payload, host, port)
        val payloadBytes = resolvedPayload.toByteArray(Charsets.UTF_8)
        Log.d(TAG, "Sending ${payloadBytes.size} byte payload")
        rawSocket.getOutputStream().apply {
            write(payloadBytes)
            flush()
        }

        // 3. Optionally wrap in TLS
        if (tlsEnabled) {
            val sniHost = tlsSni.ifBlank { host }
            Log.i(TAG, "Upgrading to TLS (SNI: $sniHost)")

            val sslFactory = trustAllSslFactory()
            val sslSocket = sslFactory.createSocket(
                rawSocket, sniHost, port, true
            ) as SSLSocket

            val params = sslSocket.sslParameters
            params.serverNames = listOf(SNIHostName(sniHost))
            sslSocket.sslParameters = params

            sslSocket.startHandshake()
            Log.i(TAG, "TLS handshake complete (${sslSocket.session.protocol}, ${sslSocket.session.cipherSuite})")

            return sslSocket
        }

        return rawSocket
    }

    override fun getInputStream(socket: Socket): InputStream = socket.getInputStream()

    override fun getOutputStream(socket: Socket): OutputStream = socket.getOutputStream()

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

    companion object {
        /**
         * Resolve placeholder tokens in a payload template.
         */
        fun resolvePayload(template: String, host: String, port: Int): String {
            return template
                .replace("[host]", host)
                .replace("[port]", port.toString())
                .replace("[crlf]", "\r\n")
                .replace("[cr]", "\r")
                .replace("[lf]", "\n")
        }
    }
}
