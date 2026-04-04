package app.slipnet.tunnel

import app.slipnet.util.AppLog as Log
import vaydns.Vaydns
import vaydns.VaydnsClient
import java.lang.ref.WeakReference
import java.net.ServerSocket

/**
 * Bridge to the Go-based VayDNS library.
 * Provides a TCP tunnel through DNS queries with leaner wire protocol than DNSTT.
 */
object VaydnsBridge {
    private const val TAG = "VaydnsBridge"

    private var client: VaydnsClient? = null
    private var currentPort: Int = 0
    @Volatile private var pendingReleasePort: Int = 0

    fun getClientPort(): Int = currentPort

    /**
     * Start the VayDNS client.
     *
     * @param dnsServer DNS resolver address (e.g., "8.8.8.8:53")
     * @param tunnelDomain The domain configured on the VayDNS/DNSTT server
     * @param publicKey The server's Noise protocol public key (hex encoded)
     * @param listenPort Local port for the tunnel listener
     * @param listenHost Local host (default: 127.0.0.1)
     * @param dnsttCompat Enable dnstt wire-format compatibility
     * @param maxPayload Cap per-query payload size (0 = full capacity)
     * @return Result indicating success or failure
     */
    fun startClient(
        dnsServer: String,
        tunnelDomain: String,
        publicKey: String,
        listenPort: Int,
        listenHost: String = "127.0.0.1",
        dnsttCompat: Boolean = false,
        maxPayload: Int = 0,
        recordType: String = "txt",
        maxQnameLen: Int = 101,
        rps: Double = 0.0,
        idleTimeout: Int = 0,
        keepalive: Int = 0,
        udpTimeout: Int = 0,
        maxNumLabels: Int = 0,
        clientIdSize: Int = 0
    ): Result<Unit> {
        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting VayDNS client")
        Log.i(TAG, "  DNS Server: $dnsServer")
        Log.i(TAG, "  Tunnel Domain: $tunnelDomain")
        Log.i(TAG, "  Public Key: ${publicKey.take(16)}...")
        Log.i(TAG, "  Listen: $listenHost:$listenPort")
        Log.i(TAG, "  DNSTT Compat: $dnsttCompat")
        Log.i(TAG, "  Record Type: $recordType")
        Log.i(TAG, "  Max QNAME Len: $maxQnameLen")
        Log.i(TAG, "  RPS Limit: ${if (rps > 0) rps.toString() else "unlimited"}")
        Log.i(TAG, "  Idle Timeout: ${if (idleTimeout > 0) "${idleTimeout}s" else "default"}")
        Log.i(TAG, "  Keepalive: ${if (keepalive > 0) "${keepalive}s" else "default"}")
        Log.i(TAG, "  UDP Timeout: ${if (udpTimeout > 0) "${udpTimeout}ms" else "default"}")
        Log.i(TAG, "  Max Labels: ${if (maxNumLabels > 0) maxNumLabels.toString() else "unlimited"}")
        Log.i(TAG, "  Client ID Size: ${if (clientIdSize > 0) "${clientIdSize}B" else "default"}")
        Log.i(TAG, "========================================")

        if (tunnelDomain.isBlank()) {
            return Result.failure(IllegalArgumentException("Tunnel domain is required"))
        }
        if (publicKey.isBlank()) {
            return Result.failure(IllegalArgumentException("Public key is required"))
        }

        stopClient()

        var actualPort = listenPort
        if (isPortInUse(listenPort)) {
            Log.w(TAG, "Port $listenPort still in use, scanning for alternative port")
            var found = false
            for (alt in (listenPort + 1)..(listenPort + 10)) {
                if (!isPortInUse(alt)) {
                    Log.i(TAG, "Using alternative port $alt (preferred $listenPort was still draining)")
                    actualPort = alt
                    found = true
                    break
                }
            }
            if (!found) {
                Log.w(TAG, "All alternative ports busy, waiting up to 3s for port $listenPort")
                if (!waitForPortAvailable(listenPort, 3_000)) {
                    return Result.failure(RuntimeException("Port $listenPort is still in use by a previous VayDNS instance"))
                }
            }
        }

        return try {
            val listenAddr = "$listenHost:$actualPort"

            val dnsAddr = dnsServer.split(",").joinToString(",") { addr ->
                val trimmed = addr.trim()
                when {
                    trimmed.startsWith("https://") -> trimmed
                    trimmed.startsWith("tls://") -> trimmed
                    trimmed.contains(":") -> trimmed
                    else -> "$trimmed:53"
                }
            }

            val newClient = Vaydns.newClient(dnsAddr, tunnelDomain, publicKey, listenAddr)
            newClient.setDnsttCompat(dnsttCompat)
            if (maxPayload > 0) {
                newClient.setMaxPayload(maxPayload.toLong())
            }
            if (recordType != "txt") {
                newClient.setRecordType(recordType)
            }
            if (maxQnameLen != 101) {
                newClient.setMaxQnameLen(maxQnameLen.toLong())
            }
            if (rps > 0) {
                newClient.setRPS(rps)
            }
            if (idleTimeout > 0) {
                newClient.setIdleTimeout(idleTimeout.toLong())
            }
            if (keepalive > 0) {
                newClient.setKeepAlive(keepalive.toLong())
            }
            if (udpTimeout > 0) {
                newClient.setUDPTimeout(udpTimeout.toLong())
            }
            if (maxNumLabels > 0) {
                newClient.setMaxNumLabels(maxNumLabels.toLong())
            }
            if (clientIdSize > 0) {
                newClient.setClientIDSize(clientIdSize.toLong())
            }
            client = newClient
            currentPort = actualPort

            newClient.start()

            Thread.sleep(100)

            if (newClient.isRunning) {
                Log.i(TAG, "VayDNS client started successfully on port $actualPort")

                if (verifySocks5Listening(listenHost, actualPort)) {
                    Log.d(TAG, "Tunnel verified listening on $listenHost:$actualPort")
                } else {
                    Log.w(TAG, "Tunnel verification failed, but client reports running")
                }

                Result.success(Unit)
            } else {
                Log.e(TAG, "VayDNS client failed to start - not running")
                client = null
                Result.failure(RuntimeException("VayDNS client failed to start"))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VayDNS client", e)
            client = null
            Result.failure(e)
        }
    }

    fun stopClient() {
        val c = client
        val port = if (c != null) currentPort else pendingReleasePort

        if (c != null) {
            client = null
            pendingReleasePort = port
            try {
                Log.d(TAG, "Stopping VayDNS client...")
                c.stop()
                if (port > 0) {
                    try {
                        java.net.Socket().use { s ->
                            s.connect(java.net.InetSocketAddress("127.0.0.1", port), 500)
                        }
                    } catch (_: Exception) {}
                }
                Thread.sleep(100)
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping VayDNS client", e)
            }
            currentPort = 0
        }

        if (port > 0) {
            val portFree = if (isPortInUse(port)) {
                Log.w(TAG, "Port $port still in use after VayDNS stop, waiting briefly...")
                waitForPortAvailable(port, 1000)
            } else {
                true
            }
            if (portFree) {
                pendingReleasePort = 0
                Log.d(TAG, "VayDNS client stopped (port $port released)")
            } else {
                Log.w(TAG, "VayDNS client stopped but port $port still held by Go runtime")
            }
        }
    }

    suspend fun stopClientBlocking() = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        stopClient()
    }

    fun isRunning(): Boolean {
        return client?.isRunning == true
    }

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
            Thread.sleep(50)
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
            Log.w(TAG, "Tunnel verify failed: ${e.message}")
            false
        }
    }
}
