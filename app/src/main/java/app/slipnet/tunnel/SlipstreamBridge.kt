package app.slipnet.tunnel

import android.net.VpnService
import app.slipnet.util.AppLog as Log
import java.lang.ref.WeakReference

/**
 * Bridge to the Rust slipstream client library.
 * Provides all CLI parameters for the slipstream-client.
 * TUN packet processing is done in Kotlin.
 */
@Suppress("KotlinJniMissingFunction")
object SlipstreamBridge {
    private const val TAG = "SlipstreamBridge"
    const val DEFAULT_SLIPSTREAM_PORT = 1080
    const val DEFAULT_LISTEN_HOST = "127.0.0.1"

    private var isLibraryLoaded = false
    private var currentPort = DEFAULT_SLIPSTREAM_PORT

    // Use WeakReference to avoid memory leak - VpnService can be garbage collected
    @Volatile
    private var vpnServiceRef: WeakReference<VpnService>? = null

    // In proxy-only mode there is no VPN interface, so protect() always returns
    // false.  That is harmless — no TUN exists to create a routing loop — so we
    // skip the protect call entirely and tell the Rust client "success".
    @Volatile
    var proxyOnlyMode = false

    init {
        try {
            System.loadLibrary("slipstream")
            isLibraryLoaded = true
            Log.d(TAG, "Native library loaded successfully")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load native library", e)
            isLibraryLoaded = false
        }
    }

    fun isLoaded(): Boolean = isLibraryLoaded

    /**
     * Set the VpnService reference for socket protection.
     * Uses WeakReference to prevent memory leaks.
     */
    fun setVpnService(service: VpnService?) {
        vpnServiceRef = service?.let { WeakReference(it) }
        Log.d(TAG, "VpnService ${if (service != null) "set" else "cleared"}")
    }

    /**
     * Called from JNI to protect a socket fd.
     */
    @JvmStatic
    fun protectSocket(fd: Int): Boolean {
        if (proxyOnlyMode) return true // No VPN interface — protection not needed
        val service = vpnServiceRef?.get()
        if (service == null) {
            Log.e(TAG, "Cannot protect socket: VpnService not available")
            return false
        }
        val result = service.protect(fd)
        Log.d(TAG, "Protected socket fd=$fd, result=$result")
        return result
    }

    /**
     * Start the slipstream client (DNS tunnel).
     * The client will listen on the specified host:port for SOCKS5 connections.
     *
     * @param domain The domain for DNS tunneling
     * @param resolvers List of DNS resolvers
     * @param congestionControl Congestion control algorithm: "bbr" or "dcubic"
     * @param keepAliveInterval Keep-alive interval in ms
     * @param tcpListenPort TCP port to listen on
     * @param tcpListenHost TCP host to bind to
     * @param gsoEnabled Enable Generic Segmentation Offload
     * @param debugPoll Enable debug logging for DNS polling
     * @param debugStreams Enable debug logging for streams
     */
    fun startClient(
        domain: String,
        resolvers: List<ResolverConfig>,
        congestionControl: String = "bbr",
        keepAliveInterval: Int = 200,
        tcpListenPort: Int = DEFAULT_SLIPSTREAM_PORT,
        tcpListenHost: String = DEFAULT_LISTEN_HOST,
        gsoEnabled: Boolean = false,
        debugPoll: Boolean = false,
        debugStreams: Boolean = false,
        idlePollIntervalMs: Int = 2000
    ): Result<Unit> {
        if (!isLibraryLoaded) {
            return Result.failure(IllegalStateException("Native library not loaded"))
        }

        // Stop any previous instance
        if (isNativeRunning()) {
            Log.w(TAG, "Slipstream client already running, stopping first...")
            stopClient()
        }

        // Wait for port to become free (up to 10 seconds).
        // Native stop waits up to 3s internally + OS socket teardown can take a few more.
        if (!waitForPortFree(tcpListenPort, 10000)) {
            return Result.failure(RuntimeException("Port $tcpListenPort is already in use"))
        }

        return try {
            Log.i(TAG, "Starting slipstream client on $tcpListenHost:$tcpListenPort, domain=$domain")
            currentPort = tcpListenPort

            val result = nativeStartSlipstreamClient(
                domain = domain,
                resolverHosts = resolvers.map { it.host }.toTypedArray(),
                resolverPorts = resolvers.map { it.port }.toIntArray(),
                resolverAuthoritative = resolvers.map { it.authoritative }.toBooleanArray(),
                listenPort = tcpListenPort,
                listenHost = tcpListenHost,
                congestionControl = congestionControl,
                keepAliveInterval = keepAliveInterval,
                gsoEnabled = gsoEnabled,
                debugPoll = debugPoll,
                debugStreams = debugStreams,
                idlePollInterval = idlePollIntervalMs
            )

            when (result) {
                0 -> {
                    Log.i(TAG, "Slipstream client started successfully")
                    Result.success(Unit)
                }
                -1 -> Result.failure(RuntimeException("Invalid domain"))
                -2 -> Result.failure(RuntimeException("Invalid resolver configuration"))
                -10 -> Result.failure(RuntimeException("Failed to spawn client thread"))
                -11 -> Result.failure(RuntimeException("Failed to listen on port"))
                else -> Result.failure(RuntimeException("Failed to start client: error $result"))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception starting slipstream client", e)
            Result.failure(e)
        }
    }

    private fun waitForPortFree(port: Int, maxWaitMs: Int): Boolean {
        if (!isPortInUse(port)) return true

        Log.w(TAG, "Port $port in use, waiting...")
        var waited = 0
        while (waited < maxWaitMs) {
            Thread.sleep(100)
            waited += 100
            if (!isPortInUse(port)) {
                Log.i(TAG, "Port $port became free after ${waited}ms")
                return true
            }
        }
        Log.e(TAG, "Port $port still in use after ${waited}ms")
        return false
    }

    /**
     * Stop the slipstream client.
     * Sends stop signal and waits for the port to be released.
     */
    fun stopClient() {
        if (!isLibraryLoaded) return

        val port = currentPort
        Log.i(TAG, "Stopping slipstream client on port $port")
        try {
            nativeStopSlipstreamClient()
            // Native stop waits up to 3s internally. Verify port is actually released
            // to avoid "port already in use" on the next connect.
            if (port > 0 && isPortInUse(port)) {
                Log.w(TAG, "Port $port still in use after native stop, waiting...")
                waitForPortFree(port, 5000)
            }
            Log.i(TAG, "Slipstream client stopped (port $port free: ${port <= 0 || !isPortInUse(port)})")
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping slipstream client", e)
        }
    }

    /**
     * Check if the slipstream client is running (native flag).
     */
    fun isClientRunning(): Boolean {
        if (!isLibraryLoaded) return false
        return try {
            nativeIsClientRunning()
        } catch (e: Exception) {
            Log.e(TAG, "Error checking native running state", e)
            false
        }
    }

    /**
     * Check if the client is running AND the port is actually listening.
     * Use this for health checks after connection is established.
     */
    fun isClientHealthy(): Boolean {
        if (!isClientRunning()) return false

        // Verify the port is actually listening
        return try {
            java.net.Socket().use { socket ->
                socket.connect(java.net.InetSocketAddress("127.0.0.1", currentPort), 200)
                true
            }
        } catch (e: Exception) {
            Log.w(TAG, "Client reports running but port $currentPort is not listening")
            false
        }
    }

    /**
     * Get the port the slipstream client is listening on.
     */
    fun getClientPort(): Int = currentPort

    /**
     * Check if a port is currently in use (bound by another socket).
     * This tries to bind a server socket to the port - if it fails, the port is in use.
     * This is more reliable than trying to connect, because a stuck/abandoned listener
     * may not be accepting connections but still has the port bound.
     */
    private fun isPortInUse(port: Int): Boolean {
        return try {
            java.net.ServerSocket().use { serverSocket ->
                serverSocket.reuseAddress = true
                serverSocket.bind(java.net.InetSocketAddress("127.0.0.1", port))
                // Successfully bound - port is free
                false
            }
        } catch (e: java.net.BindException) {
            // Port is in use
            true
        } catch (e: Exception) {
            // Other error - assume port might be in use to be safe
            Log.w(TAG, "Error checking port $port: ${e.message}")
            true
        }
    }

    // Native methods - matches slipstream-client CLI parameters
    private external fun nativeStartSlipstreamClient(
        domain: String,
        resolverHosts: Array<String>,
        resolverPorts: IntArray,
        resolverAuthoritative: BooleanArray,
        listenPort: Int,
        listenHost: String,
        congestionControl: String,
        keepAliveInterval: Int,
        gsoEnabled: Boolean,
        debugPoll: Boolean,
        debugStreams: Boolean,
        idlePollInterval: Int
    ): Int

    private external fun nativeStopSlipstreamClient()
    private external fun nativeIsClientRunning(): Boolean
    private external fun nativeIsQuicReady(): Boolean

    /**
     * Check if the native client reports it's running (alias for isClientRunning).
     */
    fun isNativeRunning(): Boolean = isClientRunning()

    /**
     * Check if the QUIC connection is established and ready for streams.
     * This is true once the QUIC handshake completes after client startup.
     * Use this to ensure the tunnel is fully operational before routing traffic.
     */
    fun isQuicReady(): Boolean {
        if (!isLibraryLoaded) return false
        return try {
            nativeIsQuicReady()
        } catch (e: Exception) {
            Log.e(TAG, "Error checking QUIC ready state", e)
            false
        }
    }
}
