package app.slipnet.tunnel

import android.net.VpnService
import android.util.Log

/**
 * Bridge to the Rust slipstream client library.
 * Provides all CLI parameters for the slipstream-client.
 * TUN packet processing is done in Kotlin.
 */
object SlipstreamBridge {
    private const val TAG = "SlipstreamBridge"
    const val DEFAULT_SLIPSTREAM_PORT = 10800
    const val DEFAULT_LISTEN_HOST = "127.0.0.1"

    private var isLibraryLoaded = false
    private var currentPort = DEFAULT_SLIPSTREAM_PORT

    @Volatile
    private var vpnService: VpnService? = null

    @Volatile
    private var isClientRunning = false

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
     */
    fun setVpnService(service: VpnService?) {
        vpnService = service
        Log.d(TAG, "VpnService ${if (service != null) "set" else "cleared"}")
    }

    /**
     * Called from JNI to protect a socket fd.
     */
    @JvmStatic
    fun protectSocket(fd: Int): Boolean {
        val service = vpnService
        if (service == null) {
            Log.e(TAG, "Cannot protect socket: VpnService not set")
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
     * Parameters match the slipstream-client CLI:
     * @param domain The domain for DNS tunneling (--domain)
     * @param resolvers List of DNS resolvers (--resolver, --authoritative)
     * @param congestionControl Congestion control algorithm: "bbr" or "dcubic" (--congestion-control)
     * @param keepAliveInterval Keep-alive interval in ms (--keep-alive-interval)
     * @param tcpListenPort TCP port to listen on (--tcp-listen-port)
     * @param tcpListenHost TCP host to bind to (--tcp-listen-host)
     * @param gsoEnabled Enable Generic Segmentation Offload (--gso)
     * @param debugPoll Enable debug logging for DNS polling (--debug-poll)
     * @param debugStreams Enable debug logging for streams (--debug-streams)
     */
    fun startClient(
        domain: String,
        resolvers: List<ResolverConfig>,
        congestionControl: String = "bbr",
        keepAliveInterval: Int = 400,
        tcpListenPort: Int = DEFAULT_SLIPSTREAM_PORT,
        tcpListenHost: String = DEFAULT_LISTEN_HOST,
        gsoEnabled: Boolean = false,
        debugPoll: Boolean = false,
        debugStreams: Boolean = false
    ): Result<Unit> {
        if (!isLibraryLoaded) {
            Log.e(TAG, "Cannot start client: native library not loaded")
            return Result.failure(IllegalStateException("Native library not loaded"))
        }

        if (isClientRunning) {
            Log.w(TAG, "Slipstream client already running, stopping first...")
            stopClient()
            // Give it a moment to clean up
            Thread.sleep(500)
        }

        return try {
            val hosts = resolvers.map { it.host }.toTypedArray()
            val ports = resolvers.map { it.port }.toIntArray()
            val authoritative = resolvers.map { it.authoritative }.toBooleanArray()

            Log.i(TAG, "========================================")
            Log.i(TAG, "Starting slipstream client")
            Log.i(TAG, "  Listen host: $tcpListenHost")
            Log.i(TAG, "  Listen port: $tcpListenPort")
            Log.i(TAG, "  Domain: $domain")
            Log.i(TAG, "  Resolvers: ${resolvers.joinToString { "${it.host}:${it.port}${if (it.authoritative) " (auth)" else ""}" }}")
            Log.i(TAG, "  Congestion control: $congestionControl")
            Log.i(TAG, "  Keep-alive: ${keepAliveInterval}ms")
            Log.i(TAG, "  GSO: $gsoEnabled")
            Log.i(TAG, "  Debug poll: $debugPoll")
            Log.i(TAG, "  Debug streams: $debugStreams")
            Log.i(TAG, "========================================")

            currentPort = tcpListenPort

            val result = nativeStartSlipstreamClient(
                domain = domain,
                resolverHosts = hosts,
                resolverPorts = ports,
                resolverAuthoritative = authoritative,
                listenPort = tcpListenPort,
                listenHost = tcpListenHost,
                congestionControl = congestionControl,
                keepAliveInterval = keepAliveInterval,
                gsoEnabled = gsoEnabled,
                debugPoll = debugPoll,
                debugStreams = debugStreams
            )

            when (result) {
                0 -> {
                    isClientRunning = true
                    Log.i(TAG, "Slipstream client started successfully on $tcpListenHost:$tcpListenPort")
                    Result.success(Unit)
                }
                -1 -> {
                    Log.e(TAG, "Invalid domain: $domain")
                    Result.failure(RuntimeException("Invalid domain"))
                }
                -2 -> {
                    Log.e(TAG, "Invalid resolver configuration")
                    Result.failure(RuntimeException("Invalid resolver configuration"))
                }
                -10 -> {
                    Log.e(TAG, "Failed to spawn slipstream client thread")
                    Result.failure(RuntimeException("Failed to spawn client thread"))
                }
                -11 -> {
                    Log.e(TAG, "Slipstream client failed to listen on $tcpListenHost:$tcpListenPort (port may be in use)")
                    Result.failure(RuntimeException("Failed to listen on port - port may be in use"))
                }
                else -> {
                    Log.e(TAG, "Failed to start slipstream client: error $result")
                    Result.failure(RuntimeException("Failed to start client: error code $result"))
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception starting slipstream client", e)
            Result.failure(e)
        }
    }

    /**
     * Stop the slipstream client.
     */
    fun stopClient() {
        if (!isLibraryLoaded) {
            Log.w(TAG, "Cannot stop client: native library not loaded")
            return
        }

        Log.i(TAG, "Stopping slipstream client (wasRunning=$isClientRunning, port=$currentPort)")

        try {
            nativeStopSlipstreamClient()
            isClientRunning = false
            Log.i(TAG, "Slipstream client stop requested")

            // Give the client a moment to actually stop
            Thread.sleep(200)

            // Check if it actually stopped
            val stillListening = try {
                java.net.Socket("127.0.0.1", currentPort).use { true }
            } catch (e: Exception) {
                false
            }

            if (stillListening) {
                Log.w(TAG, "Slipstream client may still be running on port $currentPort")
            } else {
                Log.i(TAG, "Slipstream client stopped (port $currentPort is free)")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping slipstream client", e)
        }
    }

    /**
     * Check if the slipstream client is running.
     */
    fun isClientRunning(): Boolean {
        if (!isLibraryLoaded) return false
        return try {
            nativeIsClientRunning()
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Get the port the slipstream client is listening on.
     */
    fun getClientPort(): Int = currentPort

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
        debugStreams: Boolean
    ): Int

    private external fun nativeStopSlipstreamClient()
    private external fun nativeIsClientRunning(): Boolean
}
