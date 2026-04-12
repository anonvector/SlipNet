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
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * JSch [SocketFactory] that wraps TCP connections in TLS with a configurable SNI hostname.
 *
 * Used for SSH-over-TLS (stunnel-style): the client opens a TLS tunnel to the server,
 * then runs the SSH protocol inside the encrypted TLS channel. This disguises SSH traffic
 * as ordinary HTTPS and allows custom SNI for domain fronting or firewall bypass.
 *
 * @param sniHost The hostname to send in the TLS ClientHello SNI extension.
 * @param connectTimeoutMs TCP connect timeout in milliseconds.
 */
class TlsSocketFactory(
    private val sniHost: String,
    private val connectTimeoutMs: Int = 30_000
) : SocketFactory {

    private val TAG = "TlsSocketFactory"

    override fun createSocket(host: String, port: Int): Socket {
        Log.i(TAG, "Creating TLS socket to $host:$port (SNI: $sniHost)")

        // 1. Open a plain TCP socket
        val rawSocket = Socket()
        rawSocket.connect(InetSocketAddress(host, port), connectTimeoutMs)

        // 2. Wrap in TLS with custom SNI (trust all certs for self-signed StunTLS servers)
        val sslFactory = trustAllSslFactory()
        val sslSocket = sslFactory.createSocket(
            rawSocket, sniHost, port, true  // autoClose = true
        ) as SSLSocket

        val params = sslSocket.sslParameters
        params.serverNames = listOf(SNIHostName(sniHost))
        sslSocket.sslParameters = params

        // 3. Perform TLS handshake
        sslSocket.startHandshake()
        Log.i(TAG, "TLS handshake complete (protocol: ${sslSocket.session.protocol}, cipher: ${sslSocket.session.cipherSuite})")

        return sslSocket
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

    override fun getInputStream(socket: Socket): InputStream = socket.getInputStream()

    override fun getOutputStream(socket: Socket): OutputStream = socket.getOutputStream()
}
