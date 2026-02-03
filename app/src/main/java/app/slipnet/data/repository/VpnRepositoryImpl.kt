package app.slipnet.data.repository

import android.os.ParcelFileDescriptor
import android.util.Log
import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TrafficStats
import app.slipnet.domain.repository.VpnRepository
import app.slipnet.tunnel.HevSocks5Tunnel
import app.slipnet.tunnel.ResolverConfig
import app.slipnet.tunnel.SlipstreamBridge
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class VpnRepositoryImpl @Inject constructor(
    private val preferencesDataStore: PreferencesDataStore
) : VpnRepository {
    companion object {
        private const val TAG = "VpnRepositoryImpl"
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    private val _connectionState = MutableStateFlow<ConnectionState>(ConnectionState.Disconnected)
    override val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    private val _trafficStats = MutableStateFlow(TrafficStats.EMPTY)
    override val trafficStats: StateFlow<TrafficStats> = _trafficStats.asStateFlow()

    private var connectedProfile: ServerProfile? = null
    private var currentTunFd: ParcelFileDescriptor? = null
    private var tunnelStartException: Exception? = null

    override suspend fun connect(profile: ServerProfile): Result<Unit> {
        if (_connectionState.value is ConnectionState.Connected ||
            _connectionState.value is ConnectionState.Connecting) {
            return Result.failure(IllegalStateException("Already connected or connecting"))
        }

        _connectionState.value = ConnectionState.Connecting
        connectedProfile = profile

        return Result.success(Unit)
    }

    fun startWithFd(
        profile: ServerProfile,
        pfd: ParcelFileDescriptor,
        vpnProtect: ((java.net.DatagramSocket) -> Boolean)? = null
    ): Result<Unit> {
        connectedProfile = profile
        currentTunFd = pfd

        val debugLogging = runBlocking { preferencesDataStore.debugLogging.first() }

        // Convert profile to resolver config
        val resolvers = profile.resolvers.map { resolver ->
            ResolverConfig(
                host = resolver.host,
                port = resolver.port,
                authoritative = resolver.authoritative
            )
        }

        // Use first resolver from profile as DNS server, fallback to 8.8.8.8
        val dnsServer = profile.resolvers.firstOrNull()?.host ?: "8.8.8.8"

        // Start the tunnel in a background coroutine
        scope.launch(Dispatchers.IO) {
            try {
                // Step 1: Start the Slipstream DNS tunnel (SOCKS5 proxy)
                val socksPort = profile.tcpListenPort
                val success = startSlipstreamClient(profile.domain, resolvers, profile, debugLogging)

                if (!success) {
                    val error = tunnelStartException?.message ?: "Failed to start tunnel"
                    _connectionState.value = ConnectionState.Error(error)
                    connectedProfile = null
                    Log.e(TAG, "Failed to start tunnel: $error")
                    return@launch
                }

                // Give the SOCKS5 proxy time to start
                Thread.sleep(500)

                // Step 2: Start hev-socks5-tunnel (tun2socks)
                // This routes TUN traffic through the SOCKS5 proxy
                Log.i(TAG, "========================================")
                Log.i(TAG, "Starting hev-socks5-tunnel")
                Log.i(TAG, "  SOCKS5 proxy: 127.0.0.1:$socksPort")
                Log.i(TAG, "  DNS server: $dnsServer")
                Log.i(TAG, "========================================")

                val hevResult = HevSocks5Tunnel.start(
                    tunFd = pfd,
                    socksAddress = "127.0.0.1",
                    socksPort = socksPort,
                    dnsAddress = dnsServer,
                    mtu = 1500,
                    ipv4Address = "10.255.255.1"
                )

                if (hevResult.isSuccess) {
                    _connectionState.value = ConnectionState.Connected(profile)
                    Log.i(TAG, "Tunnel started successfully")
                } else {
                    val error = hevResult.exceptionOrNull()?.message ?: "Failed to start tun2socks"
                    _connectionState.value = ConnectionState.Error(error)
                    connectedProfile = null
                    // Stop the SOCKS5 proxy since tun2socks failed
                    SlipstreamBridge.stopClient()
                    Log.e(TAG, "Failed to start tunnel: $error")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Exception starting tunnel", e)
                _connectionState.value = ConnectionState.Error(e.message ?: "Unknown error")
                connectedProfile = null
            }
        }

        return Result.success(Unit)
    }

    private fun startSlipstreamClient(
        domain: String,
        resolvers: List<ResolverConfig>,
        profile: ServerProfile,
        debugLogging: Boolean
    ): Boolean {
        tunnelStartException = null
        val result = SlipstreamBridge.startClient(
            domain = domain,
            resolvers = resolvers,
            congestionControl = profile.congestionControl.value,
            keepAliveInterval = profile.keepAliveInterval,
            tcpListenPort = profile.tcpListenPort,
            tcpListenHost = profile.tcpListenHost,
            gsoEnabled = profile.gsoEnabled,
            debugPoll = debugLogging,
            debugStreams = debugLogging
        )
        if (result.isFailure) {
            val exception = result.exceptionOrNull()
            tunnelStartException = Exception("DNS tunnel failed: ${exception?.message ?: "Unknown error"}", exception)
            Log.e(TAG, "Failed to start Slipstream client", exception)
        }
        return result.isSuccess
    }

    override suspend fun disconnect(): Result<Unit> {
        if (_connectionState.value is ConnectionState.Disconnected) {
            return Result.success(Unit)
        }

        _connectionState.value = ConnectionState.Disconnecting

        try {
            // Stop hev-socks5-tunnel first
            HevSocks5Tunnel.stop()

            // Then stop the Slipstream client
            SlipstreamBridge.stopClient()

            currentTunFd = null
            _connectionState.value = ConnectionState.Disconnected
            connectedProfile = null
            Log.i(TAG, "Tunnel stopped successfully")
            return Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping tunnel", e)
            _connectionState.value = ConnectionState.Error(e.message ?: "Unknown error")
            return Result.failure(e)
        }
    }

    override fun isConnected(): Boolean {
        return _connectionState.value is ConnectionState.Connected
    }

    override fun getConnectedProfile(): ServerProfile? {
        return connectedProfile
    }

    fun updateConnectionState(state: ConnectionState) {
        _connectionState.value = state
    }

    fun updateTrafficStats(stats: TrafficStats) {
        _trafficStats.value = stats
    }

    fun refreshTrafficStats() {
        val stats = HevSocks5Tunnel.getStats()
        if (stats != null) {
            _trafficStats.value = TrafficStats(
                bytesSent = stats.txBytes,
                bytesReceived = stats.rxBytes,
                packetsSent = stats.txPackets,
                packetsReceived = stats.rxPackets
            )
        }
    }
}
