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
    private var vpnServiceRef: WeakReference<VpnService>? = null

    /**
     * Set the VPN service reference for socket protection.
     */
    fun setVpnService(service: VpnService?) {
        vpnServiceRef = service?.let { WeakReference(it) }
        Log.d(TAG, if (service != null) "VpnService set" else "VpnService cleared")
    }

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
        listenHost: String = "127.0.0.1"
    ): Result<Unit> {
        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting DNSTT client")
        Log.i(TAG, "  DNS Server: $dnsServer")
        Log.i(TAG, "  Tunnel Domain: $tunnelDomain")
        Log.i(TAG, "  Public Key: ${publicKey.take(16)}...")
        Log.i(TAG, "  Listen: $listenHost:$listenPort")
        Log.i(TAG, "========================================")

        // Validate inputs
        if (tunnelDomain.isBlank()) {
            return Result.failure(IllegalArgumentException("Tunnel domain is required"))
        }
        if (publicKey.isBlank()) {
            return Result.failure(IllegalArgumentException("Public key is required"))
        }

        // Stop any existing client
        stopClient()

        // Wait for port to be available
        if (!waitForPortAvailable(listenPort)) {
            Log.e(TAG, "Port $listenPort is still in use after waiting")
            return Result.failure(RuntimeException("Port $listenPort is in use"))
        }

        return try {
            val listenAddr = "$listenHost:$listenPort"

            // Format address(es): may be comma-separated for multi-resolver (UDP/DoT).
            // DoH/DoT URLs pass through, UDP gets default port if missing.
            val dnsAddr = dnsServer.split(",").joinToString(",") { addr ->
                val trimmed = addr.trim()
                when {
                    trimmed.startsWith("https://") -> trimmed  // DoH URL (native Go HTTP/2 + uTLS)
                    trimmed.startsWith("tls://") -> trimmed    // DoT URL (native Go TLS + uTLS)
                    trimmed.contains(":") -> trimmed           // Already has port
                    else -> "$trimmed:53"                      // Default UDP port
                }
            }

            // Create the DNSTT client via Go mobile bindings
            val newClient = Mobile.newClient(dnsAddr, tunnelDomain, publicKey, listenAddr)
            client = newClient
            currentPort = listenPort

            // Start the client
            newClient.start()

            // Wait a bit and verify it's running
            Thread.sleep(100)

            if (newClient.isRunning) {
                Log.i(TAG, "DNSTT client started successfully")

                // Verify SOCKS5 proxy is listening
                if (verifySocks5Listening(listenHost, listenPort)) {
                    Log.d(TAG, "SOCKS5 proxy verified listening on $listenHost:$listenPort")
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
     */
    fun stopClient() {
        client?.let { c ->
            try {
                Log.d(TAG, "Stopping DNSTT client...")
                c.stop()
                // Verify port is actually released instead of blind sleep.
                // Go's listener.Close() is synchronous, but give the OS a moment.
                Thread.sleep(200)
                val port = currentPort
                if (port > 0 && isPortInUse(port)) {
                    Log.w(TAG, "Port $port still in use after DNSTT stop, waiting...")
                    waitForPortAvailable(port, 3000)
                }
                Log.d(TAG, "DNSTT client stopped")
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping DNSTT client", e)
            }
        }
        client = null
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
            ServerSocket(port).use { false }
        } catch (e: Exception) {
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
