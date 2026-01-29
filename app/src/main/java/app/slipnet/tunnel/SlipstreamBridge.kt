package app.slipnet.tunnel

import android.net.VpnService
import android.util.Log

/**
 * Simplified bridge to the Rust slipstream client.
 * Only handles starting/stopping the DNS tunnel client.
 * TUN packet processing is done in Kotlin.
 */
object SlipstreamBridge {
    private const val TAG = "SlipstreamBridge"
    private const val SLIPSTREAM_PORT = 15201

    private var isLibraryLoaded = false

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
     * The client will listen on localhost:SLIPSTREAM_PORT.
     */
    fun startClient(
        domain: String,
        resolvers: List<ResolverConfig>,
        certificatePath: String? = null,
        congestionControl: String = "bbr",
        keepAliveInterval: Int = 200
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
            Log.i(TAG, "  Port: $SLIPSTREAM_PORT")
            Log.i(TAG, "  Domain: $domain")
            Log.i(TAG, "  Resolvers: ${resolvers.joinToString { "${it.host}:${it.port}" }}")
            Log.i(TAG, "  Congestion control: $congestionControl")
            Log.i(TAG, "  Keep-alive: ${keepAliveInterval}ms")
            Log.i(TAG, "========================================")

            val result = nativeStartSlipstreamClient(
                domain = domain,
                resolverHosts = hosts,
                resolverPorts = ports,
                resolverAuthoritative = authoritative,
                listenPort = SLIPSTREAM_PORT,
                certificatePath = certificatePath ?: "",
                congestionControl = congestionControl,
                keepAliveInterval = keepAliveInterval
            )

            when (result) {
                0 -> {
                    isClientRunning = true
                    Log.i(TAG, "Slipstream client started successfully on port $SLIPSTREAM_PORT")
                    Result.success(Unit)
                }
                -10 -> {
                    Log.e(TAG, "Failed to spawn slipstream client thread")
                    Result.failure(RuntimeException("Failed to spawn client thread"))
                }
                -11 -> {
                    Log.e(TAG, "Slipstream client failed to listen on port $SLIPSTREAM_PORT (port may be in use)")
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

        Log.i(TAG, "Stopping slipstream client (wasRunning=$isClientRunning)")

        try {
            nativeStopSlipstreamClient()
            isClientRunning = false
            Log.i(TAG, "Slipstream client stop requested")

            // Give the client a moment to actually stop
            Thread.sleep(200)

            // Check if it actually stopped
            val stillListening = try {
                java.net.Socket("127.0.0.1", SLIPSTREAM_PORT).use { true }
            } catch (e: Exception) {
                false
            }

            if (stillListening) {
                Log.w(TAG, "Slipstream client may still be running on port $SLIPSTREAM_PORT")
            } else {
                Log.i(TAG, "Slipstream client stopped (port $SLIPSTREAM_PORT is free)")
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
    fun getClientPort(): Int = SLIPSTREAM_PORT

    // Native methods
    private external fun nativeStartSlipstreamClient(
        domain: String,
        resolverHosts: Array<String>,
        resolverPorts: IntArray,
        resolverAuthoritative: BooleanArray,
        listenPort: Int,
        certificatePath: String,
        congestionControl: String,
        keepAliveInterval: Int
    ): Int

    private external fun nativeStopSlipstreamClient()
    private external fun nativeIsClientRunning(): Boolean
}
