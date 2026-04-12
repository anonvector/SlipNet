package app.slipnet.tunnel

import app.slipnet.util.AppLog as Log
import java.io.InputStream
import java.io.OutputStream

/**
 * Shared SOCKS5 local proxy authentication handler.
 *
 * Implements RFC 1929 Username/Password Authentication for the local SOCKS5
 * listener side. When auth is enabled, clients must provide valid credentials
 * before the proxy will accept CONNECT or FWD_UDP requests.
 *
 * This prevents other apps on the device from abusing the local proxy to
 * bypass VPNService routing, split tunneling, and per-app rules.
 */
object LocalProxyAuth {
    private const val TAG = "LocalProxyAuth"

    /**
     * Handle SOCKS5 greeting authentication after VER, NMETHODS, and METHODS
     * have been read from the client.
     *
     * @param methods The authentication methods offered by the client
     * @param input Client input stream
     * @param output Client output stream
     * @param username Required username (null/empty = no auth required)
     * @param password Required password (null/empty = no auth required)
     * @return true if authentication succeeded (or was not required), false if rejected
     */
    fun handleGreeting(
        methods: ByteArray,
        input: InputStream,
        output: OutputStream,
        username: String?,
        password: String?
    ): Boolean {
        val authRequired = !username.isNullOrEmpty() && !password.isNullOrEmpty()

        if (!authRequired) {
            // No authentication required
            output.write(byteArrayOf(0x05, 0x00))
            output.flush()
            return true
        }

        // Check if client supports USERNAME/PASSWORD (0x02)
        if (!methods.contains(0x02.toByte())) {
            // Client doesn't support USERNAME/PASSWORD — reject with 0xFF (no acceptable methods).
            // Expected for readiness probes and apps that only offer NO_AUTH.
            Log.d(TAG, "Client does not support USERNAME/PASSWORD auth, rejecting")
            output.write(byteArrayOf(0x05, 0xFF.toByte()))
            output.flush()
            return false
        }

        // Select USERNAME/PASSWORD auth method
        output.write(byteArrayOf(0x05, 0x02))
        output.flush()

        // RFC 1929 subnegotiation
        val authVer = input.read()
        if (authVer != 0x01) {
            Log.w(TAG, "Invalid auth subnegotiation version: $authVer")
            output.write(byteArrayOf(0x01, 0x01)) // failure
            output.flush()
            return false
        }

        val uLen = input.read()
        if (uLen < 0) return false
        val uBytes = ByteArray(uLen)
        readExactly(input, uBytes)
        val clientUser = String(uBytes, Charsets.UTF_8)

        val pLen = input.read()
        if (pLen < 0) return false
        val pBytes = ByteArray(pLen)
        readExactly(input, pBytes)
        val clientPass = String(pBytes, Charsets.UTF_8)

        return if (clientUser == username && clientPass == password) {
            // Auth success
            output.write(byteArrayOf(0x01, 0x00))
            output.flush()
            true
        } else {
            // Auth failure
            Log.w(TAG, "Authentication failed for user: $clientUser")
            output.write(byteArrayOf(0x01, 0x01))
            output.flush()
            false
        }
    }

    private fun readExactly(input: InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n < 0) throw java.io.IOException("Unexpected end of stream during auth")
            off += n
        }
    }
}
