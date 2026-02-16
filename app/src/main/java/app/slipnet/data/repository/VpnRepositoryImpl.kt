package app.slipnet.data.repository

import android.os.ParcelFileDescriptor
import android.util.Log
import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TrafficStats
import app.slipnet.domain.model.DnsTransport
import app.slipnet.domain.model.TunnelType
import app.slipnet.domain.repository.VpnRepository
import app.slipnet.tunnel.DnsDoHProxy
import app.slipnet.tunnel.DnsttBridge
import app.slipnet.tunnel.DohBridge
import app.slipnet.tunnel.HevSocks5Tunnel
import app.slipnet.tunnel.ResolverConfig
import app.slipnet.tunnel.SlipstreamBridge
import app.slipnet.tunnel.SlipstreamSocksBridge
import app.slipnet.tunnel.SnowflakeBridge
import app.slipnet.tunnel.SshTunnelBridge
import app.slipnet.tunnel.TorSocksBridge
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class VpnRepositoryImpl @Inject constructor(
    @dagger.hilt.android.qualifiers.ApplicationContext private val context: android.content.Context,
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
    private var currentTunnelType: TunnelType? = null

    /**
     * Override the current tunnel type. Used by VPN service for chained startup
     * (e.g., DNSTT+SSH starts as DNSTT first, then switches to DNSTT_SSH).
     */
    fun setCurrentTunnelType(type: TunnelType) {
        currentTunnelType = type
    }

    override suspend fun connect(profile: ServerProfile): Result<Unit> {
        if (_connectionState.value is ConnectionState.Connected ||
            _connectionState.value is ConnectionState.Connecting) {
            return Result.failure(IllegalStateException("Already connected or connecting"))
        }

        _connectionState.value = ConnectionState.Connecting
        connectedProfile = profile

        return Result.success(Unit)
    }

    /**
     * Start the Slipstream SOCKS5 proxy. Call this BEFORE establishing the VPN interface.
     * This ensures the proxy is ready to handle traffic when the VPN starts routing.
     */
    suspend fun startSlipstreamProxy(
        profile: ServerProfile,
        portOverride: Int? = null,
        hostOverride: String? = null
    ): Result<Unit> {
        connectedProfile = profile
        val debugLogging = preferencesDataStore.debugLogging.first()

        // Convert profile to resolver config
        val resolvers = profile.resolvers.map { resolver ->
            ResolverConfig(
                host = resolver.host,
                port = resolver.port,
                authoritative = resolver.authoritative
            )
        }

        val listenPort = portOverride ?: preferencesDataStore.proxyListenPort.first()
        val listenHost = hostOverride ?: preferencesDataStore.proxyListenAddress.first()
        val success = startSlipstreamClient(profile.domain, resolvers, profile, debugLogging, listenPort, listenHost)

        return if (success) {
            Log.i(TAG, "Slipstream SOCKS5 proxy started successfully")
            currentTunnelType = TunnelType.SLIPSTREAM
            // Note: Caller should verify proxy is ready by checking the port
            Result.success(Unit)
        } else {
            val error = tunnelStartException?.message ?: "Failed to start Slipstream proxy"
            connectedProfile = null
            Log.e(TAG, "Failed to start Slipstream proxy: $error")
            Result.failure(Exception(error))
        }
    }

    /**
     * Start the DNSTT SOCKS5 proxy. Call this AFTER establishing the VPN interface.
     * The VPN must be established first with addDisallowedApplication so DNSTT's
     * DNS queries bypass the VPN.
     */
    suspend fun startDnsttProxy(
        profile: ServerProfile,
        portOverride: Int? = null,
        hostOverride: String? = null
    ): Result<Unit> = withContext(Dispatchers.IO) {
        connectedProfile = profile

        // Format DNS server address based on transport type.
        // The Go library supports DoH (https://...) and DoT (tls://...) natively.
        val dnsServer = when (profile.dnsTransport) {
            DnsTransport.UDP -> {
                // Pass all resolvers comma-separated for multi-resolver load balancing
                profile.resolvers.joinToString(",") { "${it.host}:${it.port}" }
                    .ifBlank { "8.8.8.8:53" }
            }
            DnsTransport.DOH -> {
                // Go library handles DoH natively via https:// prefix (HTTP/2 + uTLS)
                // DoH stays single URL — no multi-resolver
                profile.dohUrl.ifBlank { "https://dns.google/dns-query" }
            }
            DnsTransport.DOT -> {
                // Pass all resolvers comma-separated with tls:// prefix for multi-resolver
                profile.resolvers.joinToString(",") { "tls://${it.host}:${it.port}" }
                    .ifBlank { "tls://8.8.8.8:853" }
            }
        }

        val proxyPort = portOverride ?: preferencesDataStore.proxyListenPort.first()
        val proxyHost = hostOverride ?: preferencesDataStore.proxyListenAddress.first()

        val result = DnsttBridge.startClient(
            dnsServer = dnsServer,
            tunnelDomain = profile.domain,
            publicKey = profile.dnsttPublicKey,
            listenPort = proxyPort,
            listenHost = proxyHost
        )

        if (result.isSuccess) {
            Log.i(TAG, "DNSTT SOCKS5 proxy started successfully")
            currentTunnelType = TunnelType.DNSTT
            Result.success(Unit)
        } else {
            val error = result.exceptionOrNull()?.message ?: "Failed to start DNSTT proxy"
            connectedProfile = null
            Log.e(TAG, "Failed to start DNSTT proxy: $error")
            Result.failure(Exception(error))
        }
    }

    /**
     * Start the DoH SOCKS5 proxy. Call this AFTER establishing the VPN interface.
     * DNS queries are encrypted via HTTPS; all other traffic flows directly.
     */
    suspend fun startDohProxy(profile: ServerProfile): Result<Unit> = withContext(Dispatchers.IO) {
        connectedProfile = profile

        val proxyPort = preferencesDataStore.proxyListenPort.first()
        val proxyHost = preferencesDataStore.proxyListenAddress.first()

        val result = DohBridge.start(
            dohUrl = profile.dohUrl,
            listenPort = proxyPort,
            listenHost = proxyHost
        )

        if (result.isSuccess) {
            Log.i(TAG, "DoH SOCKS5 proxy started successfully")
            currentTunnelType = TunnelType.DOH
            Result.success(Unit)
        } else {
            val error = result.exceptionOrNull()?.message ?: "Failed to start DoH proxy"
            connectedProfile = null
            Log.e(TAG, "Failed to start DoH proxy: $error")
            Result.failure(Exception(error))
        }
    }

    /**
     * Start SlipstreamSocksBridge — a middleman SOCKS5 proxy for Slipstream non-SSH.
     * Chains CONNECT to Slipstream's SOCKS5 and handles FWD_UDP (DNS/UDP) directly.
     */
    suspend fun startSlipstreamSocksBridge(
        slipstreamPort: Int,
        slipstreamHost: String,
        bridgePort: Int,
        bridgeHost: String,
        socksUsername: String? = null,
        socksPassword: String? = null
    ): Result<Unit> = withContext(Dispatchers.IO) {
        val result = SlipstreamSocksBridge.start(
            slipstreamPort = slipstreamPort,
            slipstreamHost = slipstreamHost,
            listenPort = bridgePort,
            listenHost = bridgeHost,
            socksUsername = socksUsername,
            socksPassword = socksPassword
        )
        if (result.isSuccess) {
            Log.i(TAG, "SlipstreamSocksBridge started on $bridgeHost:$bridgePort -> $slipstreamHost:$slipstreamPort")
        } else {
            Log.e(TAG, "Failed to start SlipstreamSocksBridge: ${result.exceptionOrNull()?.message}")
        }
        result
    }

    /**
     * Start the Snowflake proxy stack: Snowflake PT + Tor + TorSocksBridge.
     * Call this AFTER establishing the VPN interface.
     *
     * Port allocation:
     * - bridgePort (proxyPort): TorSocksBridge (what hev-socks5-tunnel connects to)
     * - torSocksPort (proxyPort+1): Tor SOCKS5 (what bridge chains CONNECT to)
     * - snowflakePtPort (proxyPort+2): Snowflake PT SOCKS5 (what Tor connects through)
     */
    suspend fun startSnowflakeProxy(
        profile: ServerProfile,
        snowflakePtPort: Int,
        torSocksPort: Int,
        bridgePort: Int
    ): Result<Unit> = withContext(Dispatchers.IO) {
        connectedProfile = profile
        val proxyHost = preferencesDataStore.proxyListenAddress.first()

        // Step 1: Start Snowflake PT + Tor (or other PT based on bridge lines)
        val sfResult = SnowflakeBridge.startClient(
            context = context,
            snowflakePort = snowflakePtPort,
            torSocksPort = torSocksPort,
            listenHost = proxyHost,
            bridgeLines = profile.torBridgeLines
        )

        if (sfResult.isFailure) {
            connectedProfile = null
            Log.e(TAG, "Failed to start Snowflake + Tor: ${sfResult.exceptionOrNull()?.message}")
            return@withContext Result.failure(sfResult.exceptionOrNull() ?: Exception("Failed to start Snowflake"))
        }

        // Step 2: Start TorSocksBridge
        val bridgeResult = TorSocksBridge.start(
            torSocksPort = torSocksPort,
            torHost = proxyHost,
            listenPort = bridgePort,
            listenHost = proxyHost
        )

        if (bridgeResult.isFailure) {
            SnowflakeBridge.stopClient()
            connectedProfile = null
            Log.e(TAG, "Failed to start TorSocksBridge: ${bridgeResult.exceptionOrNull()?.message}")
            return@withContext Result.failure(bridgeResult.exceptionOrNull() ?: Exception("Failed to start TorSocksBridge"))
        }

        currentTunnelType = TunnelType.SNOWFLAKE
        Log.i(TAG, "Snowflake proxy stack started successfully")
        Result.success(Unit)
    }

    /**
     * Start hev-socks5-tunnel after the VPN interface is established.
     * Call this AFTER startSlipstreamProxy() succeeds and VPN interface is established.
     *
     * DNS resolution works through the VPN's configured DNS servers (via VpnService.addDnsServer())
     * combined with hev-socks5-tunnel's UDP-over-TCP mode that tunnels DNS queries through SOCKS5.
     */
    suspend fun startTun2Socks(
        profile: ServerProfile,
        pfd: ParcelFileDescriptor,
        socksPortOverride: Int? = null
    ): Result<Unit> {
        currentTunFd = pfd

        val socksPort = socksPortOverride ?: preferencesDataStore.proxyListenPort.first()
        val disableQuic = preferencesDataStore.disableQuic.first()
        // Only DNSTT sends SOCKS5 auth (remote Dante server supports it).
        // All other tunnel types use local bridges/proxies that don't support auth:
        // SSH/DNSTT_SSH/SLIPSTREAM_SSH: SSH handles auth, local SOCKS5 is no-auth
        // SLIPSTREAM: SlipstreamSocksBridge is no-auth
        // DOH: DohBridge is no-auth
        val useAuth = profile.tunnelType == TunnelType.DNSTT
        val enableUdpTunneling = true
        val socksUsername = if (useAuth) profile.socksUsername else null
        val socksPassword = if (useAuth) profile.socksPassword else null

        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting hev-socks5-tunnel")
        Log.i(TAG, "  SOCKS5 proxy: 127.0.0.1:$socksPort")
        Log.i(TAG, "  SOCKS auth: ${if (!socksUsername.isNullOrBlank()) "enabled" else "disabled"}")
        Log.i(TAG, "  Tunnel type: ${profile.tunnelType}")
        Log.i(TAG, "  UDP tunneling: $enableUdpTunneling")
        Log.i(TAG, "========================================")

        val hevResult = HevSocks5Tunnel.start(
            tunFd = pfd,
            socksAddress = "127.0.0.1",
            socksPort = socksPort,
            socksUsername = socksUsername,
            socksPassword = socksPassword,
            enableUdpTunneling = enableUdpTunneling,
            mtu = 1500,
            ipv4Address = "10.255.255.1",
            disableQuic = disableQuic
        )

        return if (hevResult.isSuccess) {
            _connectionState.value = ConnectionState.Connected(profile)
            Log.i(TAG, "Tunnel started successfully")
            Result.success(Unit)
        } else {
            val error = hevResult.exceptionOrNull()?.message ?: "Failed to start tun2socks"
            _connectionState.value = ConnectionState.Error(error)
            connectedProfile = null
            // Stop the SOCKS5 proxy since tun2socks failed
            stopCurrentProxy()
            Log.e(TAG, "Failed to start tun2socks: $error")
            Result.failure(Exception(error))
        }
    }

    /**
     * Stop the currently running proxy (Slipstream, DNSTT, or SSH).
     */
    private fun stopCurrentProxy() {
        when (currentTunnelType) {
            TunnelType.SLIPSTREAM -> {
                Log.d(TAG, "Stopping Slipstream proxy and bridge")
                SlipstreamSocksBridge.stop()
                SlipstreamBridge.stopClient()
            }
            TunnelType.DNSTT -> {
                Log.d(TAG, "Stopping DNSTT proxy")
                DnsttBridge.stopClient()
                DnsDoHProxy.stop()
            }
            TunnelType.SSH -> {
                Log.d(TAG, "Stopping SSH proxy")
                SshTunnelBridge.stop()
            }
            TunnelType.DNSTT_SSH -> {
                Log.d(TAG, "Stopping DNSTT+SSH: SSH first, then DNSTT")
                SshTunnelBridge.stop()
                DnsttBridge.stopClient()
                DnsDoHProxy.stop()
            }
            TunnelType.SLIPSTREAM_SSH -> {
                Log.d(TAG, "Stopping Slipstream+SSH: SSH first, then Slipstream")
                SshTunnelBridge.stop()
                SlipstreamBridge.stopClient()
            }
            TunnelType.DOH -> {
                Log.d(TAG, "Stopping DoH proxy")
                DohBridge.stop()
            }
            TunnelType.SNOWFLAKE -> {
                Log.d(TAG, "Stopping Snowflake: TorSocksBridge first, then Snowflake+Tor")
                TorSocksBridge.stop()
                SnowflakeBridge.stopClient()
            }
            null -> {
                // Try to stop all just in case
                Log.d(TAG, "No tunnel type set, stopping all proxies")
                SlipstreamSocksBridge.stop()
                SlipstreamBridge.stopClient()
                DnsttBridge.stopClient()
                SshTunnelBridge.stop()
                DnsDoHProxy.stop()
                TorSocksBridge.stop()
                SnowflakeBridge.stopClient()
            }
        }
        currentTunnelType = null
    }

    @Deprecated("Use startSlipstreamProxy() and startTun2Socks() instead for proper startup ordering")
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

        // Start the tunnel in a background coroutine
        scope.launch(Dispatchers.IO) {
            try {
                // Step 1: Start the Slipstream DNS tunnel (SOCKS5 proxy)
                val proxyPort = runBlocking { preferencesDataStore.proxyListenPort.first() }
                val proxyHost = runBlocking { preferencesDataStore.proxyListenAddress.first() }
                val success = startSlipstreamClient(profile.domain, resolvers, profile, debugLogging, proxyPort, proxyHost)

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
                Log.i(TAG, "  SOCKS5 proxy: 127.0.0.1:$proxyPort")
                Log.i(TAG, "  SOCKS auth: ${if (!profile.socksUsername.isNullOrBlank()) "enabled" else "disabled"}")
                Log.i(TAG, "========================================")

                val hevResult = HevSocks5Tunnel.start(
                    tunFd = pfd,
                    socksAddress = "127.0.0.1",
                    socksPort = proxyPort,
                    socksUsername = profile.socksUsername,
                    socksPassword = profile.socksPassword,
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
        debugLogging: Boolean,
        listenPort: Int,
        listenHost: String
    ): Boolean {
        tunnelStartException = null
        val result = SlipstreamBridge.startClient(
            domain = domain,
            resolvers = resolvers,
            congestionControl = profile.congestionControl.value,
            keepAliveInterval = profile.keepAliveInterval,
            tcpListenPort = listenPort,
            tcpListenHost = listenHost,
            gsoEnabled = profile.gsoEnabled,
            debugPoll = debugLogging,
            debugStreams = debugLogging,
            idlePollIntervalMs = 2000
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

            // Then stop the current proxy (Slipstream or DNSTT)
            stopCurrentProxy()

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

    fun setProxyConnected(profile: ServerProfile) {
        _connectionState.value = ConnectionState.Connected(profile)
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
