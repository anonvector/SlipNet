package app.slipnet.data.native

import android.util.Log
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.TrafficStats
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Bridge between Kotlin and native Rust code for VPN tunnel management.
 *
 * Uses direct connection mode where the slipstream server handles target routing.
 */
object NativeBridge : NativeCallback {
    private const val TAG = "NativeBridge"

    private val _connectionState = MutableStateFlow<ConnectionState>(ConnectionState.Disconnected)
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    private val _trafficStats = MutableStateFlow(TrafficStats.EMPTY)
    val trafficStats: StateFlow<TrafficStats> = _trafficStats.asStateFlow()

    private var isLibraryLoaded = false

    // VpnService reference for socket protection
    @Volatile
    private var vpnService: android.net.VpnService? = null

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
     * Must be called before starting the tunnel.
     */
    fun setVpnService(service: android.net.VpnService?) {
        vpnService = service
        Log.d(TAG, "VpnService ${if (service != null) "set" else "cleared"}")
    }

    /**
     * Called from JNI to protect a socket fd so it bypasses the VPN.
     * Returns true if protection was successful.
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
     * Start the VPN tunnel with direct connection mode.
     */
    fun startTunnel(config: NativeConfig): Result<Unit> {
        if (!isLibraryLoaded) {
            return Result.failure(IllegalStateException("Native library not loaded"))
        }

        _connectionState.value = ConnectionState.Connecting

        return try {
            val result = nativeStartTunnel(
                domain = config.domain,
                resolverHosts = config.resolvers.map { it.host }.toTypedArray(),
                resolverPorts = config.resolvers.map { it.port }.toIntArray(),
                resolverAuthoritative = config.resolvers.map { it.authoritative }.toBooleanArray(),
                keepAliveInterval = config.keepAliveInterval,
                congestionControl = config.congestionControl,
                tunFd = config.tunFd,
                dnsServer = config.dnsServer ?: ""
            )

            if (result == 0) {
                Result.success(Unit)
            } else {
                val errorMsg = getErrorMessage(result)
                _connectionState.value = ConnectionState.Error(errorMsg)
                Result.failure(RuntimeException(errorMsg))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error starting tunnel", e)
            _connectionState.value = ConnectionState.Error(e.message ?: "Unknown error")
            Result.failure(e)
        }
    }

    /**
     * Start tunnel with simplified configuration (backward compatible).
     */
    fun startTunnelSimple(config: NativeConfig): Result<Unit> {
        if (!isLibraryLoaded) {
            return Result.failure(IllegalStateException("Native library not loaded"))
        }

        _connectionState.value = ConnectionState.Connecting

        return try {
            val result = nativeStartTunnelSimple(
                domain = config.domain,
                resolverHosts = config.resolvers.map { "${it.host}:${it.port}" }.toTypedArray(),
                resolverAuthoritative = config.resolvers.map { it.authoritative }.toBooleanArray(),
                authoritativeMode = config.authoritativeMode,
                keepAliveInterval = config.keepAliveInterval,
                congestionControl = config.congestionControl,
                tunFd = config.tunFd
            )

            if (result == 0) {
                Result.success(Unit)
            } else {
                val errorMsg = getErrorMessage(result)
                _connectionState.value = ConnectionState.Error(errorMsg)
                Result.failure(RuntimeException(errorMsg))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error starting tunnel", e)
            _connectionState.value = ConnectionState.Error(e.message ?: "Unknown error")
            Result.failure(e)
        }
    }

    private fun getErrorMessage(code: Int): String = when (code) {
        -1 -> "Failed to parse domain"
        -2 -> "Failed to get resolver hosts"
        -3 -> "Failed to get resolver ports"
        -4 -> "Failed to get resolver at index"
        -5 -> "Failed to convert resolver host"
        -6 -> "Failed to get certificate path"
        -7 -> "Failed to get congestion control"
        -100 -> "Failed to start tunnel"
        else -> "Unknown error: $code"
    }

    fun stopTunnel(): Result<Unit> {
        if (!isLibraryLoaded) {
            return Result.failure(IllegalStateException("Native library not loaded"))
        }

        _connectionState.value = ConnectionState.Disconnecting

        return try {
            nativeStopTunnel()
            _connectionState.value = ConnectionState.Disconnected
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping tunnel", e)
            _connectionState.value = ConnectionState.Error(e.message ?: "Unknown error")
            Result.failure(e)
        }
    }

    fun getTrafficStats(): NativeStats {
        if (!isLibraryLoaded) {
            return NativeStats.EMPTY
        }

        return try {
            val stats = nativeGetTrafficStats()
            if (stats.size >= 6) {
                NativeStats(
                    bytesSent = stats[0],
                    bytesReceived = stats[1],
                    packetsSent = stats[2],
                    packetsReceived = stats[3],
                    activeConnections = stats[4],
                    rttMs = stats[5]
                )
            } else if (stats.size >= 5) {
                NativeStats(
                    bytesSent = stats[0],
                    bytesReceived = stats[1],
                    packetsSent = stats[2],
                    packetsReceived = stats[3],
                    activeConnections = 0,
                    rttMs = stats[4]
                )
            } else {
                NativeStats.EMPTY
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error getting traffic stats", e)
            NativeStats.EMPTY
        }
    }

    fun isConnected(): Boolean {
        if (!isLibraryLoaded) {
            return false
        }

        return try {
            nativeIsConnected()
        } catch (e: Exception) {
            Log.e(TAG, "Error checking connection status", e)
            false
        }
    }

    fun getVersion(): String {
        if (!isLibraryLoaded) {
            return "unknown"
        }

        return try {
            nativeGetVersion() ?: "unknown"
        } catch (e: Exception) {
            Log.e(TAG, "Error getting version", e)
            "unknown"
        }
    }

    // NativeCallback implementation - called from JNI
    override fun onStateChanged(state: Int) {
        _connectionState.value = when (state) {
            NativeCallback.STATE_DISCONNECTED -> ConnectionState.Disconnected
            NativeCallback.STATE_CONNECTING -> ConnectionState.Connecting
            NativeCallback.STATE_CONNECTED -> ConnectionState.Disconnected // Will be updated with profile
            NativeCallback.STATE_DISCONNECTING -> ConnectionState.Disconnecting
            NativeCallback.STATE_ERROR -> ConnectionState.Error("Native error")
            else -> ConnectionState.Disconnected
        }
    }

    override fun onStatsUpdated(stats: NativeStats) {
        _trafficStats.value = stats.toTrafficStats()
    }

    override fun onError(errorCode: Int, message: String) {
        Log.e(TAG, "Native error: $errorCode - $message")
        _connectionState.value = ConnectionState.Error(message)
    }

    // Called from JNI to update stats
    @JvmStatic
    fun updateStats(bytesSent: Long, bytesReceived: Long, packetsSent: Long, packetsReceived: Long, activeConnections: Long, rttMs: Long) {
        onStatsUpdated(NativeStats(bytesSent, bytesReceived, packetsSent, packetsReceived, activeConnections, rttMs))
    }

    // Called from JNI to update state
    @JvmStatic
    fun updateState(state: Int) {
        onStateChanged(state)
    }

    // Called from JNI to report error
    @JvmStatic
    fun reportError(errorCode: Int, message: String) {
        onError(errorCode, message)
    }

    // Native method declarations - Direct tunnel start
    private external fun nativeStartTunnel(
        domain: String,
        resolverHosts: Array<String>,
        resolverPorts: IntArray,
        resolverAuthoritative: BooleanArray,
        keepAliveInterval: Int,
        congestionControl: String,
        tunFd: Int,
        dnsServer: String
    ): Int

    // Simplified tunnel start (backward compatible)
    private external fun nativeStartTunnelSimple(
        domain: String,
        resolverHosts: Array<String>,
        resolverAuthoritative: BooleanArray,
        authoritativeMode: Boolean,
        keepAliveInterval: Int,
        congestionControl: String,
        tunFd: Int
    ): Int

    private external fun nativeStopTunnel()
    private external fun nativeGetTrafficStats(): LongArray
    private external fun nativeIsConnected(): Boolean
    private external fun nativeGetVersion(): String?
}
