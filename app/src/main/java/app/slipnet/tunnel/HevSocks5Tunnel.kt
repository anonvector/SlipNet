package app.slipnet.tunnel

import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * Bridge to hev-socks5-tunnel native library.
 * Provides tun2socks functionality - routes TUN traffic through SOCKS5 proxy.
 */
object HevSocks5Tunnel {
    private const val TAG = "HevSocks5Tunnel"

    private var isLibraryLoaded = false

    init {
        try {
            System.loadLibrary("hev-socks5-tunnel")
            System.loadLibrary("hev-tunnel-jni")
            isLibraryLoaded = true
            Log.d(TAG, "Native libraries loaded successfully")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load native libraries", e)
            isLibraryLoaded = false
        }
    }

    /**
     * Start the tunnel with the given configuration.
     *
     * @param tunFd TUN file descriptor
     * @param socksAddress SOCKS5 server address
     * @param socksPort SOCKS5 server port
     * @param socksUsername SOCKS5 username (optional)
     * @param socksPassword SOCKS5 password (optional)
     * @param dnsAddress DNS server address (optional, for UDP DNS)
     * @param mtu MTU size
     * @param ipv4Address IPv4 address for TUN interface
     * @return Result indicating success or failure
     */
    fun start(
        tunFd: ParcelFileDescriptor,
        socksAddress: String,
        socksPort: Int,
        socksUsername: String? = null,
        socksPassword: String? = null,
        dnsAddress: String? = null,
        mtu: Int = 1500,
        ipv4Address: String = "10.255.255.1"
    ): Result<Unit> {
        if (!isLibraryLoaded) {
            return Result.failure(IllegalStateException("Native library not loaded"))
        }

        if (isRunning()) {
            Log.w(TAG, "Tunnel already running, stopping first...")
            stop()
            Thread.sleep(500)
        }

        val config = buildConfig(
            socksAddress = socksAddress,
            socksPort = socksPort,
            socksUsername = socksUsername,
            socksPassword = socksPassword,
            dnsAddress = dnsAddress,
            mtu = mtu,
            ipv4Address = ipv4Address
        )

        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting hev-socks5-tunnel")
        Log.i(TAG, "  SOCKS5: $socksAddress:$socksPort")
        Log.i(TAG, "  MTU: $mtu")
        Log.i(TAG, "  IPv4: $ipv4Address")
        if (dnsAddress != null) {
            Log.i(TAG, "  DNS: $dnsAddress")
        }
        Log.i(TAG, "========================================")

        return try {
            val fd = tunFd.fd
            val result = nativeStart(config, fd)
            if (result == 0) {
                Log.i(TAG, "Tunnel started successfully")
                Result.success(Unit)
            } else {
                Log.e(TAG, "Failed to start tunnel: error code $result")
                Result.failure(RuntimeException("Failed to start tunnel: error $result"))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception starting tunnel", e)
            Result.failure(e)
        }
    }

    /**
     * Stop the tunnel.
     */
    fun stop() {
        if (!isLibraryLoaded) {
            return
        }

        Log.i(TAG, "Stopping tunnel...")
        try {
            nativeStop()
            Log.i(TAG, "Tunnel stopped")
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping tunnel", e)
        }
    }

    /**
     * Check if the tunnel is running.
     */
    fun isRunning(): Boolean {
        if (!isLibraryLoaded) return false
        return try {
            nativeIsRunning()
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Get traffic statistics.
     * @return TrafficStats or null if tunnel not running
     */
    fun getStats(): TrafficStats? {
        if (!isLibraryLoaded || !isRunning()) return null

        return try {
            val stats = nativeGetStats()
            if (stats != null && stats.size == 4) {
                TrafficStats(
                    txPackets = stats[0],
                    txBytes = stats[1],
                    rxPackets = stats[2],
                    rxBytes = stats[3]
                )
            } else null
        } catch (e: Exception) {
            null
        }
    }

    private fun buildConfig(
        socksAddress: String,
        socksPort: Int,
        socksUsername: String?,
        socksPassword: String?,
        dnsAddress: String?,
        mtu: Int,
        ipv4Address: String
    ): String {
        val sb = StringBuilder()

        sb.appendLine("tunnel:")
        sb.appendLine("  mtu: $mtu")
        sb.appendLine("  ipv4: $ipv4Address")
        sb.appendLine()

        sb.appendLine("socks5:")
        sb.appendLine("  address: $socksAddress")
        sb.appendLine("  port: $socksPort")
        // Use 'tcp' mode to tunnel UDP over TCP through SOCKS5
        // This is required because Slipstream is a TCP-only SOCKS5 proxy
        // and doesn't support SOCKS5 UDP association (RFC 1928)
        sb.appendLine("  udp: 'tcp'")

        if (!socksUsername.isNullOrBlank() && !socksPassword.isNullOrBlank()) {
            sb.appendLine("  username: '$socksUsername'")
            sb.appendLine("  password: '$socksPassword'")
        }

        sb.appendLine()
        sb.appendLine("misc:")
        sb.appendLine("  task-stack-size: 32768")  // 32KB - sufficient for tun2socks, reduces memory
        sb.appendLine("  connect-timeout: 5000")   // 5s - faster failure detection
        sb.appendLine("  tcp-read-write-timeout: 120000")  // 2min - detect dead connections faster
        sb.appendLine("  udp-read-write-timeout: 30000")   // 30s - faster UDP timeout
        sb.appendLine("  log-level: info")

        return sb.toString()
    }

    data class TrafficStats(
        val txPackets: Long,
        val txBytes: Long,
        val rxPackets: Long,
        val rxBytes: Long
    )

    // Native methods
    private external fun nativeStart(config: String, tunFd: Int): Int
    private external fun nativeStop()
    private external fun nativeIsRunning(): Boolean
    private external fun nativeGetStats(): LongArray?
}
