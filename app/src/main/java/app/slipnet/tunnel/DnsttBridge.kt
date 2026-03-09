package app.slipnet.tunnel

import android.net.VpnService
import app.slipnet.util.AppLog as Log
import mobile.Mobile
import mobile.DnsttClient
import java.lang.ref.WeakReference
import java.net.ServerSocket

/**
 * Bridge to the Go-based DNSTT library.
 * Provides a SOCKS5 proxy that tunnels traffic through DNS.
 */
object DnsttBridge {
    private const val TAG = "DnsttBridge"

    private var client: DnsttClient? = null
    private var currentPort: Int = 0
    // Port that may still be held by a dying Go process even after client is nulled.
    // stopClient() clears client immediately, but the Go listener may linger.
    @Volatile private var pendingReleasePort: Int = 0
    private var vpnServiceRef: WeakReference<VpnService>? = null

    /**
     * Set the VPN service reference for socket protection.
     */
    fun setVpnService(service: VpnService?) {
        vpnServiceRef = service?.let { WeakReference(it) }
        Log.d(TAG, if (service != null) "VpnService set" else "VpnService cleared")
    }

    /**
     * Get the port the DNSTT client is listening on.
     * May differ from the requested port if a fallback was used.
     */
    fun getClientPort(): Int = currentPort

    /**
     * Start the DNSTT client.
     *
     * @param dnsServer DNS resolver address (e.g., "8.8.8.8" or "1.1.1.1:53")
     * @param tunnelDomain The domain configured on the DNSTT server
     * @param publicKey The server's Noise protocol public key (hex encoded)
     * @param listenPort Local port for the SOCKS5 proxy
     * @param listenHost Local host for the SOCKS5 proxy (default: 127.0.0.1)
     * @return Result indicating success or failure
     */
    fun startClient(
        dnsServer: String,
        tunnelDomain: String,
        publicKey: String,
        listenPort: Int,
        listenHost: String = "127.0.0.1",
        authoritativeMode: Boolean = false,
        noizMode: Boolean = false,
        stealthMode: Boolean = false,
        maxPayload: Int = 0
    ): Result<Unit> {
        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting DNSTT client")
        Log.i(TAG, "  DNS Server: $dnsServer")
        Log.i(TAG, "  Tunnel Domain: $tunnelDomain")
        Log.i(TAG, "  Public Key: ${publicKey.take(16)}...")
        Log.i(TAG, "  Listen: $listenHost:$listenPort")
        Log.i(TAG, "  Authoritative Mode: $authoritativeMode")
        Log.i(TAG, "  NoizMode: $noizMode")
        Log.i(TAG, "  StealthMode: $stealthMode")
        Log.i(TAG, "========================================")

        // Validate inputs
        if (tunnelDomain.isBlank()) {
            return Result.failure(IllegalArgumentException("Tunnel domain is required"))
        }
        if (publicKey.isBlank()) {
            return Result.failure(IllegalArgumentException("Public key is required"))
        }

        // Stop any existing client and wait for full cleanup
        stopClient()

        // Wait for the port to become free.  We give the Go runtime up to 10s to
        // fully drain goroutines.  Do NOT silently fall back to alternative ports —
        // a stuck port means the old instance is still alive and would leak traffic.
        if (!waitForPortAvailable(listenPort, 10_000)) {
            Log.e(TAG, "Port $listenPort still in use after 10s — old DNSTT instance may be leaking")
            return Result.failure(RuntimeException("Port $listenPort is still in use by a previous DNSTT instance"))
        }
        val actualPort = listenPort

        return try {
            val listenAddr = "$listenHost:$actualPort"

            // Format address(es): may be comma-separated for multi-resolver (UDP/DoT/TCP).
            // DoH/DoT/TCP URLs pass through, UDP gets default port if missing.
            val dnsAddr = dnsServer.split(",").joinToString(",") { addr ->
                val trimmed = addr.trim()
                when {
                    trimmed.startsWith("https://") -> trimmed  // DoH URL (native Go HTTP/2 + uTLS)
                    trimmed.startsWith("tls://") -> trimmed    // DoT URL (native Go TLS + uTLS)
                    trimmed.startsWith("tcp://") -> trimmed    // TCP DNS (plain TCP, 2-byte framing)
                    trimmed.contains(":") -> trimmed           // Already has port
                    else -> "$trimmed:53"                      // Default UDP port
                }
            }

            // Create the DNSTT client via Go mobile bindings
            val newClient = Mobile.newClient(dnsAddr, tunnelDomain, publicKey, listenAddr)
            newClient.setAuthoritativeMode(authoritativeMode)
            if (maxPayload > 0) {
                newClient.setMaxPayload(maxPayload.toLong())
            }
            if (noizMode) {
                newClient.setNoizMode(true)
                if (stealthMode) {
                    newClient.setStealthMode(true)
                }
            }
            client = newClient
            currentPort = actualPort

            // Start the client
            newClient.start()

            // Wait a bit and verify it's running
            Thread.sleep(100)

            if (newClient.isRunning) {
                Log.i(TAG, "DNSTT client started successfully on port $actualPort")

                // Verify SOCKS5 proxy is listening
                if (verifySocks5Listening(listenHost, actualPort)) {
                    Log.d(TAG, "SOCKS5 proxy verified listening on $listenHost:$actualPort")
                } else {
                    Log.w(TAG, "SOCKS5 proxy verification failed, but client reports running")
                }

                Result.success(Unit)
            } else {
                Log.e(TAG, "DNSTT client failed to start - not running")
                client = null
                Result.failure(RuntimeException("DNSTT client failed to start"))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start DNSTT client", e)
            client = null
            Result.failure(e)
        }
    }

    /**
     * Stop the DNSTT client and wait for port to be released.
     *
     * NOTE: This blocks the calling thread for up to ~5s while waiting for the Go
     * runtime to fully clean up (listener close + goroutine drain).  Prefer calling
     * [stopClientBlocking] from a coroutine on [Dispatchers.IO].
     */
    fun stopClient() {
        val c = client
        val port = if (c != null) currentPort else pendingReleasePort

        if (c != null) {
            client = null  // Clear reference immediately to prevent new operations
            pendingReleasePort = port
            try {
                Log.d(TAG, "Stopping DNSTT client...")
                c.stop()
                // Give Go runtime time to close listener AND drain active goroutines.
                // The listener.Close() is synchronous, but tunnel-session goroutines may
                // still be sending DNS queries for a short while after the listener is gone.
                Thread.sleep(500)
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping DNSTT client", e)
            }
            currentPort = 0
        }

        // Wait for port release even when client is already null — a previous
        // stopClient() may have cleared the reference while Go is still dying.
        if (port > 0) {
            val portFree = if (isPortInUse(port)) {
                Log.w(TAG, "Port $port still in use after DNSTT stop, waiting...")
                waitForPortAvailable(port, 5000)
            } else {
                true
            }
            // Only clear pendingReleasePort if the port is actually free.
            // If still held, keep it so the next stopClient() or startClient() retries.
            if (portFree) {
                pendingReleasePort = 0
                Log.d(TAG, "DNSTT client stopped (port $port released)")
            } else {
                Log.w(TAG, "DNSTT client stopped but port $port still held by Go runtime")
            }
        }
    }

    /**
     * Stop the DNSTT client on the IO dispatcher and block the coroutine (not the
     * thread) until the port is verified released.  This is the preferred way to
     * stop during reconnection.
     */
    suspend fun stopClientBlocking() = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        stopClient()
    }

    /**
     * Check if the DNSTT client is running.
     */
    fun isRunning(): Boolean {
        return client?.isRunning == true
    }

    /**
     * Check if the client is healthy (running and responsive).
     */
    fun isClientHealthy(): Boolean {
        val c = client ?: return false
        return try {
            c.isRunning
        } catch (e: Exception) {
            Log.w(TAG, "Health check failed", e)
            false
        }
    }

    private fun waitForPortAvailable(port: Int, maxWaitMs: Long = 5000): Boolean {
        val startTime = System.currentTimeMillis()
        while (System.currentTimeMillis() - startTime < maxWaitMs) {
            if (!isPortInUse(port)) {
                return true
            }
            Log.d(TAG, "Waiting for port $port to be released...")
            Thread.sleep(200)
        }
        return !isPortInUse(port)
    }

    private fun isPortInUse(port: Int): Boolean {
        return try {
            ServerSocket().use { serverSocket ->
                serverSocket.reuseAddress = true
                serverSocket.bind(java.net.InetSocketAddress("127.0.0.1", port))
                false
            }
        } catch (e: java.net.BindException) {
            true
        } catch (e: Exception) {
            Log.w(TAG, "Error checking port $port: ${e.message}")
            true
        }
    }

    private fun verifySocks5Listening(host: String, port: Int): Boolean {
        return try {
            java.net.Socket().use { socket ->
                socket.connect(java.net.InetSocketAddress(host, port), 2000)
                true
            }
        } catch (e: Exception) {
            Log.w(TAG, "SOCKS5 verify failed: ${e.message}")
            false
        }
    }
}
