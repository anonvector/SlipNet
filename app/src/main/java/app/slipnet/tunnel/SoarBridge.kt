package app.slipnet.tunnel

import app.slipnet.util.AppLog as Log
import soar.Soar
import soar.SoarClient
import java.net.ServerSocket

/**
 * Bridge to the Go-based Soar client (github.com/getlantern/soar).
 *
 * Soar tunnels TCP streams through every configured recursive resolver at once
 * to a server that dials each stream's destination itself. The Go side exposes
 * a local SOCKS5 server (CONNECT only, no auth) on the listen port; a CONNECT to
 * port 53 is resolved with DNS over HTTPS through the tunnel, because a stock
 * soar-server only lets streams reach ports 80 and 443.
 */
object SoarBridge {
    private const val TAG = "SoarBridge"

    private var client: SoarClient? = null
    private var currentPort: Int = 0
    @Volatile private var pendingReleasePort: Int = 0

    fun getClientPort(): Int = currentPort

    /**
     * Start the Soar client.
     *
     * @param resolvers Comma-separated resolvers ("ip:port"; "tcp://ip:port" for TCP-only)
     * @param zone The tunnel zone delegated to the Soar server
     * @param publicKey The server's Ed25519 public key (base64 or hex)
     * @param listenPort Local port for the SOCKS5 listener
     * @param listenHost Local host (default: 127.0.0.1)
     * @param discovery Discover more resolvers that carry the tunnel
     * @param country ISO country code selecting bundled resolver lists ("" = global)
     * @param tcpMode TCP/53 paths: "auto", "on", "only" or "off"
     * @param upstreamSocks SOCKS5 proxy (host:port) to send resolver traffic through, as DNS
     *        over TCP — the previous layer of a proxy chain. Null = resolvers are reached directly.
     * @return Result indicating success or failure
     */
    fun startClient(
        resolvers: String,
        zone: String,
        publicKey: String,
        listenPort: Int,
        listenHost: String = "127.0.0.1",
        discovery: Boolean = false,
        country: String = "",
        tcpMode: String = "auto",
        verbose: Boolean = false,
        upstreamSocks: String? = null,
        upstreamSocksUser: String? = null,
        upstreamSocksPass: String? = null
    ): Result<Unit> {
        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting Soar client")
        Log.i(TAG, "  Resolvers: ${resolvers.ifBlank { "(none)" }}")
        Log.i(TAG, "  Zone: $zone")
        Log.i(TAG, "  Public Key: ${publicKey.take(12)}...")
        Log.i(TAG, "  Listen: $listenHost:$listenPort")
        Log.i(TAG, "  Discovery: ${if (discovery) "on (${country.ifBlank { "global" }})" else "off"}")
        Log.i(TAG, "  TCP/53: ${if (upstreamSocks != null) "only (through upstream SOCKS5)" else tcpMode}")
        if (upstreamSocks != null) {
            Log.i(TAG, "  Upstream SOCKS5: $upstreamSocks")
        }
        Log.i(TAG, "========================================")

        if (zone.isBlank()) {
            return Result.failure(IllegalArgumentException("Tunnel domain is required"))
        }
        if (publicKey.isBlank()) {
            return Result.failure(IllegalArgumentException("Public key is required"))
        }
        if (resolvers.isBlank() && !discovery) {
            return Result.failure(IllegalArgumentException("Add a resolver or enable resolver discovery"))
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
                    return Result.failure(RuntimeException("Port $listenPort is still in use by a previous Soar instance"))
                }
            }
        }

        return try {
            val newClient = Soar.newClient(resolvers, zone, publicKey, "$listenHost:$actualPort")
            newClient.setDiscovery(discovery, country)
            newClient.setTCPMode(tcpMode)
            newClient.setVerbose(verbose)
            if (upstreamSocks != null) {
                newClient.setUpstreamSocks5(upstreamSocks, upstreamSocksUser ?: "", upstreamSocksPass ?: "")
            }
            client = newClient
            currentPort = actualPort

            newClient.start()

            if (newClient.isRunning) {
                Log.i(TAG, "Soar client started on port $actualPort (session handshakes in the background)")
                Result.success(Unit)
            } else {
                Log.e(TAG, "Soar client failed to start - not running")
                client = null
                currentPort = 0
                Result.failure(RuntimeException("Soar client failed to start"))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start Soar client", e)
            client = null
            currentPort = 0
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
                Log.d(TAG, "Stopping Soar client...")
                c.stop()
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping Soar client", e)
            }
            currentPort = 0
        }

        if (port > 0) {
            val portFree = if (isPortInUse(port)) {
                Log.w(TAG, "Port $port still in use after Soar stop, waiting briefly...")
                waitForPortAvailable(port, 1000)
            } else {
                true
            }
            if (portFree) {
                pendingReleasePort = 0
                Log.d(TAG, "Soar client stopped (port $port released)")
            } else {
                Log.w(TAG, "Soar client stopped but port $port still held by Go runtime")
            }
        }
    }

    suspend fun stopClientBlocking() = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        stopClient()
    }

    fun isRunning(): Boolean {
        return try {
            client?.isRunning == true
        } catch (e: Exception) {
            false
        }
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
}
