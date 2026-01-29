package app.slipnet.data.repository

import android.os.ParcelFileDescriptor
import android.util.Log
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TrafficStats
import app.slipnet.domain.repository.VpnRepository
import app.slipnet.tunnel.KotlinTunnelConfig
import app.slipnet.tunnel.KotlinTunnelManager
import app.slipnet.tunnel.ResolverConfig
import app.slipnet.tunnel.SlipstreamBridge
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class VpnRepositoryImpl @Inject constructor() : VpnRepository {
    companion object {
        private const val TAG = "VpnRepositoryImpl"
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    private val _connectionState = MutableStateFlow<ConnectionState>(ConnectionState.Disconnected)
    override val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    private val _trafficStats = MutableStateFlow(TrafficStats.EMPTY)
    override val trafficStats: StateFlow<TrafficStats> = _trafficStats.asStateFlow()

    private var connectedProfile: ServerProfile? = null
    private var tunnelManager: KotlinTunnelManager? = null

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

        // Convert profile to tunnel config
        val resolvers = profile.resolvers.map { resolver ->
            ResolverConfig(
                host = resolver.host,
                port = resolver.port,
                authoritative = resolver.authoritative
            )
        }

        // Use first resolver from profile as DNS server, fallback to 8.8.8.8
        val dnsServer = profile.resolvers.firstOrNull()?.host ?: "8.8.8.8"

        val config = KotlinTunnelConfig(
            domain = profile.domain,
            resolvers = resolvers,
            slipstreamPort = 15201,
            dnsServer = dnsServer
        )

        // Create and start the Kotlin tunnel manager
        tunnelManager = KotlinTunnelManager(
            config = config,
            tunFd = pfd,
            onSlipstreamStart = { domain, resolverList ->
                startSlipstreamClient(domain, resolverList, profile)
            },
            onSlipstreamStop = {
                SlipstreamBridge.stopClient()
            },
            vpnProtect = vpnProtect
        )

        // Start the tunnel
        scope.launch {
            val result = tunnelManager?.start()
            if (result?.isSuccess == true) {
                _connectionState.value = ConnectionState.Connected(profile)
                Log.i(TAG, "Tunnel started successfully")
            } else {
                val error = result?.exceptionOrNull()?.message ?: "Unknown error"
                _connectionState.value = ConnectionState.Error(error)
                connectedProfile = null
                Log.e(TAG, "Failed to start tunnel: $error")
            }
        }

        return Result.success(Unit)
    }

    private fun startSlipstreamClient(
        domain: String,
        resolvers: List<ResolverConfig>,
        profile: ServerProfile
    ): Boolean {
        val result = SlipstreamBridge.startClient(
            domain = domain,
            resolvers = resolvers,
            certificatePath = profile.certificatePath,
            congestionControl = profile.congestionControl.value,
            keepAliveInterval = profile.keepAliveInterval
        )
        return result.isSuccess
    }

    override suspend fun disconnect(): Result<Unit> {
        if (_connectionState.value is ConnectionState.Disconnected) {
            return Result.success(Unit)
        }

        _connectionState.value = ConnectionState.Disconnecting

        try {
            tunnelManager?.stop()
            tunnelManager = null
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
        val manager = tunnelManager
        if (manager != null) {
            val stats = manager.getStats()
            _trafficStats.value = TrafficStats(
                bytesSent = stats.bytesSent,
                bytesReceived = stats.bytesReceived,
                packetsSent = stats.packetsSent,
                packetsReceived = stats.packetsReceived
            )
        }
    }
}
