package app.slipnet.service

import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.ProxyInfo
import android.net.VpnService
import android.net.wifi.WifiManager
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import app.slipnet.util.AppLog as Log
import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.data.local.datastore.SplitTunnelingMode
import app.slipnet.data.local.datastore.SshCipher
import app.slipnet.tunnel.DomainRouter
import app.slipnet.tunnel.GeoBypassCountry
import app.slipnet.tunnel.GeoBypassData
import app.slipnet.data.repository.VpnRepositoryImpl
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.TunnelType
import app.slipnet.domain.model.isAvailable
import app.slipnet.tunnel.DnsttBridge
import app.slipnet.tunnel.DnsttSocksBridge
import app.slipnet.tunnel.DohBridge
import app.slipnet.tunnel.HevSocks5Tunnel
import app.slipnet.tunnel.HttpProxyServer
import app.slipnet.tunnel.NaiveBridge
import app.slipnet.tunnel.NaiveSocksBridge
import app.slipnet.tunnel.SlipstreamBridge
import app.slipnet.tunnel.SlipstreamSocksBridge
import app.slipnet.tunnel.Socks5ProxyBridge
import app.slipnet.tunnel.SnowflakeBridge
import app.slipnet.tunnel.SshTunnelBridge
import app.slipnet.tunnel.TorSocksBridge
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

@AndroidEntryPoint
class SlipNetVpnService : VpnService() {

    companion object {
        private const val TAG = "SlipNetVpnService"
        const val ACTION_CONNECT = "app.slipnet.CONNECT"
        const val ACTION_DISCONNECT = "app.slipnet.DISCONNECT"
        const val EXTRA_PROFILE_ID = "profile_id"
        const val EXTRA_CHAIN_ID = "chain_id"

        private const val VPN_MTU = 1280
        private const val VPN_ADDRESS = "10.255.255.1"
        private const val VPN_ROUTE = "0.0.0.0"
        private const val DEFAULT_DNS = "8.8.8.8"
        private const val WAKELOCK_TIMEOUT_MS = 10 * 60 * 1000L  // 10 minutes (Chinese OEM ROMs kill indefinite WakeLocks)
        private const val WAKELOCK_RENEW_INTERVAL_MS = 9 * 60 * 1000L  // renew 1 min before expiry
        private const val HEALTH_CHECK_INTERVAL_MS = 15000L
        private const val QUIC_DOWN_THRESHOLD = 2 // Reconnect after 2 checks (~30s) with QUIC down
        private const val SSH_PROBE_INTERVAL = 2 // Probe SSH session every 2 health checks (~30s)
        private const val DNS_POOL_DEAD_THRESHOLD = 3 // Warn after 3 consecutive checks (~45s) with all workers dead
        private const val DNS_POOL_DEAD_THRESHOLD_SOCKS = 2 // Faster warning for SOCKS profiles (~30s)
        private const val TUNNEL_STALL_CHECK_INTERVAL = 4 // Check traffic flow every 4 health checks (~60s)
        private const val TUNNEL_STALL_CHECK_INTERVAL_SOCKS = 2 // Faster stall check for SOCKS profiles (~30s)
        private const val TUNNEL_STALL_THRESHOLD = 2 // Reconnect after 2 consecutive stalls
        private const val TUNNEL_STALL_THRESHOLD_SOCKS = 1 // Faster reconnect for SOCKS profiles (~30s)

        // Persistence keys for auto-restart
        private const val PREFS_NAME = "vpn_service_state"
        private const val PREF_LAST_PROFILE_ID = "last_profile_id"
        private const val PREF_WAS_CONNECTED = "was_connected"

        // Auto-reconnect settings
        private const val AUTO_RECONNECT_MAX_RETRIES = 5
        private val AUTO_RECONNECT_DELAYS_MS = longArrayOf(3000, 3000, 3000, 3000, 3000)

        // Seamless reconnect: try restarting just the proxy (keeping TUN + tun2socks alive)
        // before escalating to kill-switch / auto-reconnect / stop.
        private const val MAX_SEAMLESS_RECONNECTS = 2
    }

    @Inject
    lateinit var connectionManager: VpnConnectionManager

    @Inject
    lateinit var vpnRepository: VpnRepositoryImpl

    @Inject
    lateinit var notificationHelper: NotificationHelper

    @Inject
    lateinit var preferencesDataStore: PreferencesDataStore

    @Inject
    lateinit var chainRepository: app.slipnet.domain.repository.ChainRepository

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var healthCheckJob: Job? = null
    private var currentProfileId: Long = -1
    private var currentTunnelType: TunnelType = TunnelType.SLIPSTREAM
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastNetworkAddresses: Set<String> = emptySet()
    private var reconnectDebounceJob: Job? = null
    private var networkLostJob: Job? = null
    private var connectJob: Job? = null
    private var disconnectJob: Job? = null
    private var stateObserverJob: Job? = null
    @Volatile
    private var isReconnecting = false
    @Volatile
    private var isKillSwitchActive = false
    private var isProxyOnly = false
    private var isUserInitiatedDisconnect = false
    private var currentProfileName = ""
    private var currentChainId: Long = -1
    /** Tunnel types active in the current chain (outermost first), for cleanup ordering. */
    private var activeChainLayers: List<TunnelType> = emptyList()

    // Auto-reconnect state
    @Volatile
    private var isAutoReconnecting = false
    private var autoReconnectJob: Job? = null
    private var autoReconnectAttempt = 0
    private var connectionWasSuccessful = false

    // Health check state
    private var quicDownChecks = 0
    private var healthCheckCount = 0
    private var dnsPoolDeadChecks = 0
    private var dnsPoolDeadNotified = false
    private var tunnelStallChecks = 0
    private var lastTxBytes = 0L
    private var lastRxBytes = 0L

    // Seamless reconnect state: tracks how many times we've tried a lightweight
    // proxy-only restart before escalating to full teardown.
    private var seamlessReconnectAttempts = 0

    // Timestamp when the connection was fully established. Network change events
    // arriving within a few seconds of this are spurious (common on Chinese OEM
    // ROMs like MIUI/HyperOS that fire network callbacks when the VPN interface
    // is first created) and should be ignored.
    private var connectionEstablishedAt = 0L
    private val NETWORK_CHANGE_GRACE_MS = 5_000L

    // Persistence for service resilience
    private lateinit var prefs: SharedPreferences

    // WakeLock to prevent CPU sleep during VPN session
    private var wakeLock: PowerManager.WakeLock? = null

    // WifiLock to prevent Wi-Fi radio from entering low-power mode when screen is off
    private var wifiLock: WifiManager.WifiLock? = null
    private var wakeLockRenewJob: Job? = null

    // Doze mode receiver to detect idle state exits
    private var dozeReceiver: BroadcastReceiver? = null

    // DNS servers tracked for the current network (detects DNS changes during handoff)
    private var lastNetworkDnsServers: Set<String> = emptySet()

    override fun onCreate() {
        super.onCreate()
        connectivityManager = getSystemService(ConnectivityManager::class.java)
        prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val chainId = intent.getLongExtra(EXTRA_CHAIN_ID, -1)
                val profileId = intent.getLongExtra(EXTRA_PROFILE_ID, -1)
                if (chainId != -1L) {
                    connectChain(chainId)
                } else if (profileId != -1L) {
                    connect(profileId)
                }
            }
            ACTION_DISCONNECT -> {
                disconnect()
            }
            null -> {
                // Service was restarted by the system after being killed
                // Try to reconnect using the last profile
                handleServiceRestart(flags)
            }
        }

        return START_STICKY
    }

    /**
     * Handle service restart after being killed by Android.
     * Attempts to reconnect using the last connected profile.
     */
    private fun handleServiceRestart(flags: Int) {
        val wasConnected = prefs.getBoolean(PREF_WAS_CONNECTED, false)
        val lastProfileId = prefs.getLong(PREF_LAST_PROFILE_ID, -1)

        Log.i(TAG, "Service restarted by system (flags=$flags, wasConnected=$wasConnected, lastProfileId=$lastProfileId)")

        if (wasConnected && lastProfileId != -1L) {
            Log.i(TAG, "Attempting to auto-reconnect with profile $lastProfileId")
            connect(lastProfileId)
        } else {
            Log.d(TAG, "No previous connection to restore, stopping service")
            stopSelf()
        }
    }

    /**
     * Save connection state for auto-restart.
     */
    private fun saveConnectionState(profileId: Long, connected: Boolean) {
        prefs.edit()
            .putLong(PREF_LAST_PROFILE_ID, profileId)
            .putBoolean(PREF_WAS_CONNECTED, connected)
            .apply()
        Log.d(TAG, "Saved connection state: profileId=$profileId, connected=$connected")
    }

    /**
     * Clear saved connection state.
     */
    private fun clearConnectionState() {
        prefs.edit()
            .putBoolean(PREF_WAS_CONNECTED, false)
            .apply()
        connectionEstablishedAt = 0
        Log.d(TAG, "Cleared connection state")
    }

    private fun connect(profileId: Long) {
        // Cancel stale state observer from a previous connection to prevent it
        // from calling stopSelf() while the new connection is starting.
        stateObserverJob?.cancel()
        stateObserverJob = null

        connectJob?.cancel()
        connectJob = serviceScope.launch {
            // Wait for any in-progress disconnect to finish releasing ports
            disconnectJob?.join()

            // Always stop previous proxies to ensure ports are freed.
            // This handles the case where onDestroy() sent stop signals but
            // didn't wait for native code to release ports (e.g. abandoned Rust threads).
            withContext(Dispatchers.IO) {
                try { stopCurrentProxy() } catch (_: Exception) {}
                // DnsttBridge is a process-level singleton — a previous service
                // instance may have left the Go DNSTT listener alive even though
                // currentTunnelType has been reset.  Always stop it explicitly.
                try { DnsttBridge.stopClient() } catch (_: Exception) {}
                // Give native threads extra time to fully release ports after stop.
                // Both Go (DNSTT) and Rust (Slipstream) may take a moment to close listeners.
                delay(300)
            }

            // Clean up previous connection resources if switching profiles
            if (currentProfileId != -1L && currentProfileId != profileId) {
                Log.i(TAG, "Switching profile: cleaning up previous connection")
                cleanupConnection()
            }

            val profile = connectionManager.getProfileById(profileId)
            if (profile == null) {
                connectionManager.onVpnError("Profile not found")
                stopSelf()
                return@launch
            }

            if (profile.isExpired) {
                connectionManager.onVpnError("This profile has expired")
                stopSelf()
                return@launch
            }
            if (profile.boundDeviceId.isNotEmpty() && profile.boundDeviceId != connectionManager.getDeviceId()) {
                connectionManager.onVpnError("This profile is bound to a different device")
                stopSelf()
                return@launch
            }

            currentProfileId = profileId
            currentProfileName = profile.name
            isUserInitiatedDisconnect = false

            // Redact sensitive config from in-app debug log for locked profiles
            app.slipnet.util.AppLog.redactSensitive = profile.isLocked

            // Dismiss any previous reconnect/disconnect notifications
            getSystemService(NotificationManager::class.java).apply {
                cancel(NotificationHelper.RECONNECT_NOTIFICATION_ID)
                cancel(NotificationHelper.DISCONNECT_NOTIFICATION_ID)
            }

            // Show connecting notification
            val notification = notificationHelper.createVpnNotification(ConnectionState.Connecting)
            startForeground(NotificationHelper.VPN_NOTIFICATION_ID, notification)

            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager

            // Acquire WakeLock with timeout (Chinese OEM ROMs kill indefinite WakeLocks)
            if (wakeLock == null) {
                wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "SlipNet:VpnWakeLock").apply {
                    setReferenceCounted(false)
                    acquire(WAKELOCK_TIMEOUT_MS)
                }
                Log.d(TAG, "WakeLock acquired (${WAKELOCK_TIMEOUT_MS / 60000}min timeout)")
            }
            startWakeLockRenewal()

            // Acquire WifiLock to keep Wi-Fi radio active when screen is off.
            // Chinese OEMs (Xiaomi, Huawei, etc.) kill apps using WIFI_MODE_FULL_LOW_LATENCY,
            // so fall back to WIFI_MODE_FULL on those devices.
            if (wifiLock == null) {
                val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
                @Suppress("DEPRECATION")
                val wifiMode = when {
                    isChineseOem() -> WifiManager.WIFI_MODE_FULL
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q -> WifiManager.WIFI_MODE_FULL_LOW_LATENCY
                    else -> WifiManager.WIFI_MODE_FULL_HIGH_PERF
                }
                wifiLock = wifiManager?.createWifiLock(wifiMode, "SlipNet:VpnWifiLock")?.apply {
                    setReferenceCounted(false)
                    acquire()
                }
                if (wifiLock != null) Log.d(TAG, "WifiLock acquired")
            }

            // Warn if battery optimization is not disabled
            if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                Log.w(TAG, "Battery optimization is enabled - VPN may be interrupted by Doze mode")
            }

            // Warn if Private DNS is enabled (bypasses VPN DNS, can break DNS-based tunnels)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    val privateDnsMode = android.provider.Settings.Global.getString(
                        contentResolver, "private_dns_mode"
                    )
                    if (privateDnsMode != null && privateDnsMode != "off") {
                        Log.w(TAG, "Private DNS is enabled (mode=$privateDnsMode) - DNS queries may bypass the VPN tunnel")
                    }
                } catch (_: Exception) {}
            }

            try {
                // Read proxy-only mode setting
                isProxyOnly = preferencesDataStore.proxyOnlyMode.first()

                // Set debug logging on tunnel bridges
                val debug = preferencesDataStore.debugLogging.first()
                SshTunnelBridge.debugLogging = debug
                DohBridge.debugLogging = debug
                SlipstreamSocksBridge.debugLogging = debug
                DnsttSocksBridge.debugLogging = debug
                NaiveSocksBridge.debugLogging = debug
                TorSocksBridge.debugLogging = debug
                HttpProxyServer.debugLogging = debug

                // Configure domain routing on bridges
                val domainRouter = buildDomainRouter()
                SshTunnelBridge.domainRouter = domainRouter
                DohBridge.domainRouter = domainRouter
                SlipstreamSocksBridge.domainRouter = domainRouter
                NaiveSocksBridge.domainRouter = domainRouter
                TorSocksBridge.domainRouter = domainRouter

                // Track the tunnel type for this connection
                currentTunnelType = profile.tunnelType
                Log.i(TAG, "Starting VPN with tunnel type: $currentTunnelType")

                val dnsServer = resolveToIp(profile.resolvers.firstOrNull()?.host)
                // Remote DNS: the DNS servers used on the remote side of the tunnel
                var remoteDns = preferencesDataStore.getEffectiveRemoteDns().first()
                var remoteDnsFallback = preferencesDataStore.getEffectiveRemoteDnsFallback().first()

                // DNSTT+SSH / NoizDNS+SSH: default to server's local resolver (127.0.0.53) instead of
                // external DNS (8.8.8.8). External DNS servers often close long-lived TCP
                // connections opened via SSH direct-tcpip, causing DNS workers to die.
                // Only override when user hasn't set a custom remote DNS.
                if (currentTunnelType == TunnelType.DNSTT_SSH || currentTunnelType == TunnelType.NOIZDNS_SSH) {
                    val dnsMode = preferencesDataStore.remoteDnsMode.first()
                    if (dnsMode == "default") {
                        remoteDns = "127.0.0.53"
                        remoteDnsFallback = "8.8.8.8"
                    }
                }

                Log.i(TAG, "Remote DNS: $remoteDns (fallback: $remoteDnsFallback)")

                // Check if tunnel type is available in this build flavor
                if (!currentTunnelType.isAvailable()) {
                    handleTunnelFailure("${currentTunnelType.displayName} is not available in this edition")
                    return@launch
                }

                // The startup order differs between tunnel types:
                // - Slipstream: Start proxy first (Rust uses protect_socket JNI callback)
                // - DNSTT: Establish VPN first (uses addDisallowedApplication for socket protection)
                when (currentTunnelType) {
                    TunnelType.SLIPSTREAM -> connectSlipstream(profile, dnsServer, remoteDns, remoteDnsFallback)
                    TunnelType.SLIPSTREAM_SSH -> connectSlipstreamSsh(profile, dnsServer, remoteDns, remoteDnsFallback)
                    TunnelType.DNSTT -> connectDnstt(profile, dnsServer, remoteDns, remoteDnsFallback)
                    TunnelType.NOIZDNS -> connectDnstt(profile, dnsServer, remoteDns, remoteDnsFallback)
                    TunnelType.SSH -> connectSsh(profile, dnsServer, remoteDns, remoteDnsFallback)
                    TunnelType.DNSTT_SSH -> connectDnsttSsh(profile, dnsServer, remoteDns, remoteDnsFallback)
                    TunnelType.NOIZDNS_SSH -> connectDnsttSsh(profile, dnsServer, remoteDns, remoteDnsFallback)
                    TunnelType.DOH -> connectDoh(profile, dnsServer)
                    TunnelType.SNOWFLAKE -> connectSnowflake(profile, dnsServer)
                    TunnelType.NAIVE_SSH -> connectNaiveSsh(profile, dnsServer, remoteDns, remoteDnsFallback)
                    TunnelType.NAIVE -> connectNaive(profile, dnsServer, remoteDns, remoteDnsFallback)
                    TunnelType.SOCKS5 -> connectSocks5(profile, dnsServer, remoteDns)
                }

            } catch (e: kotlinx.coroutines.CancellationException) {
                // Coroutine was cancelled (user disconnected, service stopped, or new connect).
                // Do NOT treat as an error — let the cancelling code handle cleanup.
                Log.d(TAG, "Connection coroutine cancelled")
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Exception during connection", e)
                // If this was an auto-reconnect attempt and we can still retry, re-enter the retry loop
                val autoReconnectEnabled = try { preferencesDataStore.autoReconnect.first() } catch (_: Exception) { false }
                if (autoReconnectEnabled && connectionWasSuccessful && !isUserInitiatedDisconnect
                    && autoReconnectAttempt < AUTO_RECONNECT_MAX_RETRIES) {
                    handleTunnelFailure("reconnect failed: ${e.message}")
                } else {
                    connectionManager.onVpnError(e.message ?: "Unknown error")
                    cleanupConnection()
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        }
    }

    // ── Chain Connection ──────────────────────────────────────────────

    private fun connectChain(chainId: Long) {
        stateObserverJob?.cancel()
        stateObserverJob = null

        connectJob?.cancel()
        connectJob = serviceScope.launch {
            disconnectJob?.join()
            withContext(Dispatchers.IO) {
                try { stopCurrentProxy() } catch (_: Exception) {}
                delay(300)
            }

            val chain = chainRepository.getChainById(chainId)
            if (chain == null) {
                connectionManager.onVpnError("Chain not found")
                stopSelf()
                return@launch
            }

            // Resolve all profiles in the chain
            val profiles = chain.profileIds.mapNotNull { connectionManager.getProfileById(it) }
            if (profiles.size != chain.profileIds.size) {
                connectionManager.onVpnError("Some profiles in chain were deleted")
                stopSelf()
                return@launch
            }

            // Validate the chain
            val validationError = app.slipnet.domain.model.ChainValidation.validate(profiles)
            if (validationError != null) {
                connectionManager.onVpnError(validationError)
                stopSelf()
                return@launch
            }

            currentChainId = chainId
            // Use first profile for connection state tracking
            val primaryProfile = profiles.first()
            currentProfileId = primaryProfile.id
            currentProfileName = chain.name
            isUserInitiatedDisconnect = false
            app.slipnet.util.AppLog.redactSensitive = profiles.any { it.isLocked }

            getSystemService(android.app.NotificationManager::class.java).apply {
                cancel(NotificationHelper.RECONNECT_NOTIFICATION_ID)
                cancel(NotificationHelper.DISCONNECT_NOTIFICATION_ID)
            }

            val notification = notificationHelper.createVpnNotification(ConnectionState.Connecting)
            startForeground(NotificationHelper.VPN_NOTIFICATION_ID, notification)

            val pm = getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
            if (wakeLock == null) {
                wakeLock = pm.newWakeLock(android.os.PowerManager.PARTIAL_WAKE_LOCK, "SlipNet:VpnWakeLock").apply {
                    setReferenceCounted(false)
                    acquire(WAKELOCK_TIMEOUT_MS)
                }
            }
            startWakeLockRenewal()
            if (wifiLock == null) {
                val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as? android.net.wifi.WifiManager
                @Suppress("DEPRECATION")
                val wifiMode = when {
                    isChineseOem() -> android.net.wifi.WifiManager.WIFI_MODE_FULL
                    android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q -> android.net.wifi.WifiManager.WIFI_MODE_FULL_LOW_LATENCY
                    else -> android.net.wifi.WifiManager.WIFI_MODE_FULL_HIGH_PERF
                }
                wifiLock = wifiManager?.createWifiLock(wifiMode, "SlipNet:VpnWifiLock")?.apply {
                    setReferenceCounted(false)
                    acquire()
                }
            }

            try {
                isProxyOnly = preferencesDataStore.proxyOnlyMode.first()
                val debug = preferencesDataStore.debugLogging.first()
                SshTunnelBridge.debugLogging = debug
                DohBridge.debugLogging = debug
                SlipstreamSocksBridge.debugLogging = debug
                DnsttSocksBridge.debugLogging = debug
                NaiveSocksBridge.debugLogging = debug
                TorSocksBridge.debugLogging = debug
                HttpProxyServer.debugLogging = debug

                val domainRouter = buildDomainRouter()
                SshTunnelBridge.domainRouter = domainRouter
                DohBridge.domainRouter = domainRouter
                SlipstreamSocksBridge.domainRouter = domainRouter
                NaiveSocksBridge.domainRouter = domainRouter
                TorSocksBridge.domainRouter = domainRouter

                executeChain(profiles)
            } catch (e: kotlinx.coroutines.CancellationException) {
                Log.d(TAG, "Chain connection coroutine cancelled")
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Exception during chain connection", e)
                connectionManager.onVpnError(e.message ?: "Chain connection failed")
                cleanupConnection()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    /**
     * Execute a chain of profiles, starting each layer and wiring them together.
     *
     * Port allocation: final layer on proxyPort, each preceding layer on proxyPort + offset.
     * Example for 3-layer chain: layer[0] on proxyPort+2, layer[1] on proxyPort+1, layer[2] on proxyPort.
     */
    private suspend fun executeChain(profiles: List<app.slipnet.domain.model.ServerProfile>) {
        val proxyPort = preferencesDataStore.proxyListenPort.first()
        val proxyHost = preferencesDataStore.proxyListenAddress.first()
        val chainSize = profiles.size
        val dnsServer = resolveToIp(profiles.first().resolvers.firstOrNull()?.host)
        var remoteDns = preferencesDataStore.getEffectiveRemoteDns().first()
        var remoteDnsFallback = preferencesDataStore.getEffectiveRemoteDnsFallback().first()

        // Track started layers for cleanup on failure
        val startedLayers = mutableListOf<TunnelType>()

        // Determine if VPN is needed before outermost layer
        val outermost = profiles.first()
        val needsVpnFirst = app.slipnet.domain.model.ChainValidation.needsVpnFirst(outermost.tunnelType)

        if (!isProxyOnly && needsVpnFirst) {
            vpnInterface = establishVpnInterface(dnsServer)
            if (vpnInterface == null) {
                connectionManager.onVpnError("Failed to establish VPN interface")
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }
            delay(200)
        }

        // Start each layer from outermost to innermost
        for (i in profiles.indices) {
            val profile = profiles[i]
            val layerPort = proxyPort + (chainSize - 1 - i)
            val layerHost = if (i < chainSize - 1) "127.0.0.1" else proxyHost
            val isLast = i == chainSize - 1

            // Previous layer's output (null for outermost)
            val prevPort = if (i > 0) proxyPort + (chainSize - i) else -1

            Log.i(TAG, "Chain layer $i/${chainSize - 1}: ${profile.tunnelType.displayName} on port $layerPort" +
                    if (prevPort > 0) " (through port $prevPort)" else " (outermost)")

            val prevLayerType = if (i > 0) profiles[i - 1].tunnelType else null
            val prevProfile = if (i > 0) profiles[i - 1] else null

            // Internal ports (for bridges that need a separate Go/Rust process port)
            // must be above the chain port range [proxyPort, proxyPort+chainSize-1]
            // to avoid collisions between chain layers.
            val internalPortBase = proxyPort + chainSize

            val result = startChainLayer(
                profile = profile,
                layerIndex = i,
                layerPort = layerPort,
                layerHost = layerHost,
                prevPort = prevPort,
                prevHost = "127.0.0.1",
                prevLayerType = prevLayerType,
                prevProfile = prevProfile,
                isLast = isLast,
                remoteDns = remoteDns,
                remoteDnsFallback = remoteDnsFallback,
                internalPortBase = internalPortBase
            )
            if (result.isFailure) {
                val error = result.exceptionOrNull()?.message ?: "Failed to start ${profile.tunnelType.displayName}"
                connectionManager.onVpnError(error)
                // Clean up started layers in reverse
                for (layer in startedLayers.reversed()) {
                    stopLayer(layer)
                }
                activeChainLayers = emptyList()
                currentChainId = -1
                vpnInterface?.close()
                vpnInterface = null
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }
            startedLayers.add(profile.tunnelType)
            // Keep activeChainLayers in sync so stopCurrentProxy() can clean up on retry
            activeChainLayers = startedLayers.toList()

            // Wait for this layer's port to be ready
            val actualPort = if (profile.tunnelType == TunnelType.DNSTT || profile.tunnelType == TunnelType.NOIZDNS) {
                DnsttBridge.getClientPort().also {
                    if (it != layerPort) Log.i(TAG, "DNSTT bound to alternative port $it (preferred $layerPort)")
                }
            } else layerPort

            // NaiveProxy needs its own readiness check (log-based, not TCP probe)
            // Also temporarily set currentTunnelType so waitForProxyReady checks the right bridge
            val savedTunnelType = currentTunnelType
            currentTunnelType = profile.tunnelType
            val layerReady = if (profile.tunnelType == TunnelType.NAIVE || profile.tunnelType == TunnelType.NAIVE_SSH) {
                waitForNaiveReady(maxAttempts = 30, delayMs = 100)
            } else {
                waitForProxyReady(actualPort, maxAttempts = 30, delayMs = 100)
            }
            currentTunnelType = savedTunnelType

            if (!layerReady) {
                Log.e(TAG, "Chain layer $i failed to become ready on port $actualPort")
                connectionManager.onVpnError("${profile.tunnelType.displayName} failed to start")
                for (layer in startedLayers.reversed()) stopLayer(layer)
                activeChainLayers = emptyList()
                currentChainId = -1
                vpnInterface?.close()
                vpnInterface = null
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            // For Slipstream, wait for QUIC handshake
            if (profile.tunnelType == TunnelType.SLIPSTREAM) {
                if (!waitForQuicReady(maxAttempts = 50, delayMs = 200)) {
                    connectionManager.onVpnError("Slipstream QUIC handshake failed")
                    for (layer in startedLayers.reversed()) stopLayer(layer)
                    activeChainLayers = emptyList()
                    currentChainId = -1
                    vpnInterface?.close()
                    vpnInterface = null
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                    return
                }

                // VPN interface after Slipstream is ready (if not already established)
                if (!isProxyOnly && vpnInterface == null) {
                    vpnInterface = establishVpnInterface(dnsServer)
                    if (vpnInterface == null) {
                        connectionManager.onVpnError("Failed to establish VPN interface")
                        for (layer in startedLayers.reversed()) stopLayer(layer)
                        activeChainLayers = emptyList()
                        currentChainId = -1
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                        return
                    }
                    delay(200)
                }
            }
        }

        // Store chain layers for cleanup
        activeChainLayers = startedLayers.toList()
        // Track the final layer's tunnel type for stats
        currentTunnelType = profiles.last().tunnelType
        vpnRepository.setCurrentTunnelType(currentTunnelType)

        // Proxy-only mode: skip tun2socks
        if (isProxyOnly) {
            vpnRepository.setProxyConnected(profiles.first())
            Log.i(TAG, "Proxy-only mode: chain ready on $proxyHost:$proxyPort")
            finishConnection()
            return
        }

        // Start tun2socks on the final proxy port
        val tun2socksResult = vpnRepository.startTun2Socks(profiles.first(), vpnInterface!!)
        if (tun2socksResult.isFailure) {
            connectionManager.onVpnError(tun2socksResult.exceptionOrNull()?.message ?: "Failed to start tunnel")
            for (layer in activeChainLayers.reversed()) stopLayer(layer)
            activeChainLayers = emptyList()
            currentChainId = -1
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        Log.i(TAG, "Chain started: ${profiles.joinToString(" → ") { it.tunnelType.displayName }}")
        finishConnection()
    }

    /**
     * Start a single layer in the chain.
     */
    private suspend fun startChainLayer(
        profile: app.slipnet.domain.model.ServerProfile,
        layerIndex: Int = 0,
        layerPort: Int,
        layerHost: String,
        prevPort: Int,
        prevHost: String,
        prevLayerType: TunnelType?,
        prevProfile: app.slipnet.domain.model.ServerProfile? = null,
        isLast: Boolean,
        remoteDns: String,
        remoteDnsFallback: String,
        internalPortBase: Int = layerPort + 1
    ): Result<Unit> {
        return when (profile.tunnelType) {
            TunnelType.DNSTT, TunnelType.NOIZDNS -> {
                DnsttBridge.setVpnService(this@SlipNetVpnService)
                val isNoizdns = profile.tunnelType == TunnelType.NOIZDNS

                // Build upstream SOCKS5 proxy params if previous layer provides SOCKS5.
                // Skip for SSH: SOCKS5 forces TCP promotion but most DNS resolvers
                // only accept UDP. DNSTT's protected sockets bypass the VPN,
                // so direct DNS queries work without routing through SSH.
                var socksAddr: String? = null
                var socksUser: String? = null
                var socksPass: String? = null
                if (prevPort > 0 && prevLayerType != null && prevLayerType != TunnelType.SSH) {
                    val prevOutput = app.slipnet.domain.model.ChainValidation.outputType(prevLayerType)
                    if (prevOutput == app.slipnet.domain.model.LayerOutput.SOCKS5) {
                        socksAddr = "$prevHost:$prevPort"
                        socksUser = prevProfile?.socksUsername
                        socksPass = prevProfile?.socksPassword
                        Log.i(TAG, "DNSTT[$layerIndex]: routing DNS through SOCKS5 proxy $socksAddr")
                    }
                }

                if (isLast) {
                    val bridgePort = layerPort
                    val internalPort = internalPortBase
                    val proxyResult = if (isNoizdns)
                        vpnRepository.startNoizdnsProxy(profile, portOverride = internalPort, hostOverride = "127.0.0.1",
                            socksProxyAddr = socksAddr, socksProxyUser = socksUser, socksProxyPass = socksPass)
                    else
                        vpnRepository.startDnsttProxy(profile, portOverride = internalPort, hostOverride = "127.0.0.1",
                            socksProxyAddr = socksAddr, socksProxyUser = socksUser, socksProxyPass = socksPass)
                    if (proxyResult.isFailure) return proxyResult
                    val actualPort = DnsttBridge.getClientPort()
                    DnsttSocksBridge.authoritativeMode = profile.dnsttAuthoritative
                    DnsttSocksBridge.proxyOnlyMode = isProxyOnly
                    vpnRepository.startDnsttSocksBridge(
                        dnsttPort = actualPort, dnsttHost = "127.0.0.1",
                        bridgePort = bridgePort, bridgeHost = layerHost,
                        socksUsername = profile.socksUsername, socksPassword = profile.socksPassword,
                        dnsServer = remoteDns, dnsFallback = remoteDnsFallback
                    )
                } else {
                    if (isNoizdns)
                        vpnRepository.startNoizdnsProxy(profile, portOverride = layerPort, hostOverride = "127.0.0.1",
                            socksProxyAddr = socksAddr, socksProxyUser = socksUser, socksProxyPass = socksPass)
                    else
                        vpnRepository.startDnsttProxy(profile, portOverride = layerPort, hostOverride = "127.0.0.1",
                            socksProxyAddr = socksAddr, socksProxyUser = socksUser, socksProxyPass = socksPass)
                }
            }
            TunnelType.SLIPSTREAM -> {
                SlipstreamBridge.setVpnService(this@SlipNetVpnService)
                if (isLast) {
                    val internalPort = internalPortBase
                    val proxyResult = vpnRepository.startSlipstreamProxy(profile, portOverride = internalPort, hostOverride = "127.0.0.1")
                    if (proxyResult.isFailure) return proxyResult
                    vpnRepository.startSlipstreamSocksBridge(
                        slipstreamPort = internalPort, slipstreamHost = "127.0.0.1",
                        bridgePort = layerPort, bridgeHost = layerHost,
                        socksUsername = profile.socksUsername, socksPassword = profile.socksPassword,
                        dnsServer = remoteDns, dnsFallback = remoteDnsFallback
                    )
                } else {
                    vpnRepository.startSlipstreamProxy(profile, portOverride = layerPort, hostOverride = "127.0.0.1")
                }
            }
            TunnelType.SSH -> {
                // Create a named SSH instance for this chain layer
                val sshInstance = SshTunnelBridge.createInstance("chain-ssh-$layerIndex")
                configureSshInstance(sshInstance)

                if (prevPort > 0) {
                    val resolvedPrevType = prevLayerType
                        ?: return Result.failure(Exception("No previous layer for SSH"))
                    val output = app.slipnet.domain.model.ChainValidation.outputType(resolvedPrevType)

                    // In a chain, SSH connects to the remote server through the previous
                    // layer's proxy, so use `domain` (the actual server address).
                    // sshHost defaults to 127.0.0.1 for DNSTT+SSH co-located scenarios
                    // which is wrong when chaining through an external proxy.
                    val chainSshHost = profile.domain.ifEmpty { profile.sshHost }

                    withContext(Dispatchers.IO) {
                        when (output) {
                            app.slipnet.domain.model.LayerOutput.RAW_TCP -> {
                                Log.i(TAG, "Starting SSH[$layerIndex] over raw TCP ($chainSshHost:${profile.sshPort} via $prevHost:$prevPort)")
                                sshInstance.startOverProxy(
                                    sshHost = chainSshHost,
                                    sshPort = profile.sshPort,
                                    sshUsername = profile.sshUsername,
                                    sshPassword = profile.sshPassword,
                                    proxyHost = prevHost,
                                    proxyPort = prevPort,
                                    listenPort = layerPort,
                                    listenHost = layerHost,
                                    blockDirectDns = true,
                                    sshAuthType = profile.sshAuthType,
                                    sshPrivateKey = profile.sshPrivateKey,
                                    sshKeyPassphrase = profile.sshKeyPassphrase,
                                    remoteDnsHost = remoteDns,
                                    remoteDnsFallback = remoteDnsFallback
                                )
                            }
                            app.slipnet.domain.model.LayerOutput.SOCKS5 -> {
                                Log.i(TAG, "Starting SSH[$layerIndex] over SOCKS5 ($chainSshHost:${profile.sshPort} via $prevHost:$prevPort)")
                                sshInstance.startOverSocks5Proxy(
                                    sshHost = chainSshHost,
                                    sshPort = profile.sshPort,
                                    sshUsername = profile.sshUsername,
                                    sshPassword = profile.sshPassword,
                                    proxyHost = prevHost,
                                    proxyPort = prevPort,
                                    socksUsername = prevProfile?.socksUsername,
                                    socksPassword = prevProfile?.socksPassword,
                                    listenPort = layerPort,
                                    listenHost = layerHost,
                                    sshAuthType = profile.sshAuthType,
                                    sshPrivateKey = profile.sshPrivateKey,
                                    sshKeyPassphrase = profile.sshKeyPassphrase,
                                    remoteDnsHost = remoteDns,
                                    remoteDnsFallback = remoteDnsFallback
                                )
                            }
                            null -> Result.failure(Exception("Previous layer cannot provide output for SSH"))
                        }
                    }
                } else {
                    withContext(Dispatchers.IO) {
                        sshInstance.startDirect(
                            tunnelHost = profile.domain,
                            tunnelPort = profile.sshPort,
                            sshUsername = profile.sshUsername,
                            sshPassword = profile.sshPassword,
                            listenPort = layerPort,
                            listenHost = layerHost,
                            forwardDnsThroughSsh = true,
                            sshAuthType = profile.sshAuthType,
                            sshPrivateKey = profile.sshPrivateKey,
                            sshKeyPassphrase = profile.sshKeyPassphrase,
                            remoteDnsHost = remoteDns,
                            remoteDnsFallback = remoteDnsFallback
                        )
                    }
                }
            }
            TunnelType.NAIVE -> {
                if (isLast && prevPort <= 0) {
                    val internalPort = internalPortBase
                    val naiveResult = withContext(Dispatchers.IO) {
                        NaiveBridge.start(
                            context = this@SlipNetVpnService,
                            listenPort = internalPort,
                            serverHost = profile.domain,
                            serverPort = profile.naivePort,
                            username = profile.naiveUsername,
                            password = profile.naivePassword
                        )
                    }
                    if (naiveResult.isFailure) return naiveResult
                    vpnRepository.startNaiveSocksBridge(
                        naivePort = internalPort, naiveHost = "127.0.0.1",
                        bridgePort = layerPort, bridgeHost = layerHost,
                        dnsServer = remoteDns, dnsFallback = remoteDnsFallback
                    )
                } else {
                    withContext(Dispatchers.IO) {
                        NaiveBridge.start(
                            context = this@SlipNetVpnService,
                            listenPort = layerPort,
                            serverHost = profile.domain,
                            serverPort = profile.naivePort,
                            username = profile.naiveUsername,
                            password = profile.naivePassword
                        )
                    }
                }
            }
            TunnelType.SNOWFLAKE -> {
                val ptPort = internalPortBase + 1
                val torPort = internalPortBase
                vpnRepository.startSnowflakeProxy(profile, ptPort, torPort, layerPort)
            }
            TunnelType.DOH -> {
                vpnRepository.startDohProxy(profile)
            }
            TunnelType.SOCKS5 -> {
                val socksInstance = Socks5ProxyBridge.createInstance("chain-socks5-$layerIndex")
                socksInstance.debugLogging = Socks5ProxyBridge.debugLogging
                socksInstance.domainRouter = Socks5ProxyBridge.domainRouter
                withContext(Dispatchers.IO) {
                    socksInstance.start(
                        remoteHost = profile.domain,
                        remotePort = profile.socks5ServerPort,
                        remoteUsername = profile.socksUsername,
                        remotePassword = profile.socksPassword,
                        listenPort = layerPort,
                        listenHost = layerHost,
                        dnsHost = remoteDns
                    )
                }
            }
            else -> Result.failure(Exception("${profile.tunnelType.displayName} cannot be used in a chain"))
        }
    }

    /** Stop a single tunnel layer by type. */
    private fun stopLayer(type: TunnelType) {
        when (type) {
            TunnelType.DNSTT, TunnelType.NOIZDNS -> {
                DnsttSocksBridge.stop()
                DnsttBridge.stopClient()
            }
            TunnelType.SLIPSTREAM -> {
                SlipstreamSocksBridge.stop()
                SlipstreamBridge.stopClient()
            }
            TunnelType.SSH -> SshTunnelBridge.stopAll()
            TunnelType.NAIVE -> {
                NaiveSocksBridge.stop()
                NaiveBridge.stop()
            }
            TunnelType.SNOWFLAKE -> {
                TorSocksBridge.stop()
                SnowflakeBridge.stopClient()
            }
            TunnelType.DOH -> DohBridge.stop()
            TunnelType.SOCKS5 -> Socks5ProxyBridge.stopAll()
            else -> {}
        }
    }

    /**
     * Connect using Slipstream tunnel type.
     * Order: Set VpnService ref -> Start proxy -> Wait for ready -> Wait for QUIC
     *        -> VPN interface (with addDisallowedApplication) -> Start bridge -> tun2socks on bridge port
     *
     * Slipstream's SOCKS5 proxy only supports CONNECT (no auth, no FWD_UDP).
     * SlipstreamSocksBridge sits between hev-socks5-tunnel and Slipstream:
     * - CONNECT: chains to Slipstream's SOCKS5 proxy
     * - FWD_UDP: forwards DNS/UDP directly via DatagramSocket
     *
     * addDisallowedApplication ensures the bridge's DatagramSockets bypass VPN.
     */
    private suspend fun connectSlipstream(profile: app.slipnet.domain.model.ServerProfile, dnsServer: String, remoteDns: String, remoteDnsFallback: String) {
        val proxyPort = preferencesDataStore.proxyListenPort.first()
        val proxyHost = preferencesDataStore.proxyListenAddress.first()
        val slipstreamPort = proxyPort + 1

        // Step 1: Set VpnService reference for socket protection via JNI
        SlipstreamBridge.proxyOnlyMode = isProxyOnly
        SlipstreamBridge.setVpnService(this@SlipNetVpnService)

        // Step 2: Start Slipstream proxy on internal port (127.0.0.1 only)
        val proxyResult = vpnRepository.startSlipstreamProxy(profile, portOverride = slipstreamPort, hostOverride = "127.0.0.1")
        if (proxyResult.isFailure) {
            connectionManager.onVpnError(proxyResult.exceptionOrNull()?.message ?: "Failed to start proxy")
            SlipstreamBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Read actual port — may differ from requested if preferred port was stuck
        val actualSlipstreamPort = SlipstreamBridge.getClientPort()
        if (actualSlipstreamPort != slipstreamPort) {
            Log.i(TAG, "Slipstream bound to alternative port $actualSlipstreamPort (preferred $slipstreamPort was stuck)")
        }

        // Step 2.5: Verify proxy is listening
        if (!waitForProxyReady(actualSlipstreamPort, maxAttempts = 20, delayMs = 100)) {
            handleProxyStartupFailure(actualSlipstreamPort)
            return
        }

        // Step 2.6: Wait for QUIC handshake before VPN setup
        val quicReady = waitForQuicReady(maxAttempts = 50, delayMs = 100)
        if (!quicReady) {
            Log.w(TAG, "QUIC connection not ready within timeout, continuing anyway")
        }

        // Step 3: Start SlipstreamSocksBridge on proxyPort (user-facing, with auth for Dante)
        // DNS target resolved at the REMOTE server (through Dante),
        // not locally. Using local/ISP DNS would give poisoned results in censored networks.
        val bridgeResult = vpnRepository.startSlipstreamSocksBridge(
            slipstreamPort = actualSlipstreamPort,
            slipstreamHost = "127.0.0.1",
            bridgePort = proxyPort,
            bridgeHost = proxyHost,
            socksUsername = profile.socksUsername,
            socksPassword = profile.socksPassword,
            dnsServer = remoteDns,
            dnsFallback = remoteDnsFallback
        )
        if (bridgeResult.isFailure) {
            connectionManager.onVpnError(bridgeResult.exceptionOrNull()?.message ?: "Failed to start SOCKS5 bridge")
            stopCurrentProxy()
            SlipstreamBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 3.5: Verify bridge is listening
        if (!waitForProxyReady(proxyPort, maxAttempts = 20, delayMs = 100)) {
            Log.e(TAG, "SlipstreamSocksBridge failed to become ready on port $proxyPort")
            connectionManager.onVpnError("SOCKS5 bridge failed to start")
            stopCurrentProxy()
            SlipstreamBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Proxy-only mode: skip VPN interface and tun2socks
        if (isProxyOnly) {
            vpnRepository.setProxyConnected(profile)
            Log.i(TAG, "Proxy-only mode: Slipstream SOCKS5 bridge ready on $proxyHost:$proxyPort")
            finishConnection()
            return
        }

        // Step 4: Establish VPN interface (with addDisallowedApplication)
        // App exclusion ensures SlipstreamSocksBridge's DNS DatagramSockets bypass VPN
        vpnInterface = establishVpnInterface(dnsServer)
        if (vpnInterface == null) {
            connectionManager.onVpnError("Failed to establish VPN interface")
            stopCurrentProxy()
            SlipstreamBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 5: Start tun2socks pointing at bridge on proxyPort
        val tun2socksResult = vpnRepository.startTun2Socks(profile, vpnInterface!!)
        if (tun2socksResult.isFailure) {
            connectionManager.onVpnError(tun2socksResult.exceptionOrNull()?.message ?: "Failed to start tunnel")
            vpnInterface?.close()
            vpnInterface = null
            SlipstreamBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        finishConnection()
    }

    /**
     * Connect using Slipstream+SSH tunnel type.
     * Order: Set VpnService ref -> Start Slipstream -> Wait for ready -> Wait for QUIC (hard req)
     *        -> Start SSH directly through Slipstream tunnel (loopback, no VPN needed)
     *        -> Wait for SSH ready -> VPN interface -> tun2socks on SSH port
     *
     * Slipstream in SSH mode is a raw TCP tunnel to the SSH server (like DNSTT).
     * The server's --target-address points to SSH port 22, so all tunnel traffic
     * goes directly to SSH. JSch connects directly to Slipstream's local port —
     * no ProxySOCKS5 or Dante needed.
     *
     * VPN interface is established AFTER SSH connects. The SSH connection goes
     * through loopback (JSch -> 127.0.0.1:proxyPort+1 -> Slipstream), so VPN routing
     * isn't needed. Establishing VPN too early can disrupt QUIC establishment.
     *
     * Traffic flow:
     * App -> TUN -> hev-socks5-tunnel -> SSH SOCKS5 (proxyPort)
     *   -> SSH direct-tcpip -> Slipstream (proxyPort+1, 127.0.0.1, raw TCP tunnel)
     *   -> DNS tunnel (UDP 53) -> Slipstream Server -> SSH Server -> Internet
     */
    /**
     * Build a DomainRouter from DataStore preferences.
     */
    private suspend fun buildDomainRouter(): DomainRouter {
        val domainRoutingEnabled = preferencesDataStore.domainRoutingEnabled.first()
        val geoBypassEnabled = preferencesDataStore.geoBypassEnabled.first()

        if (!domainRoutingEnabled && !geoBypassEnabled) return DomainRouter.DISABLED

        val mode = preferencesDataStore.domainRoutingMode.first()
        val domains = if (domainRoutingEnabled) preferencesDataStore.domainRoutingDomains.first() else emptySet()

        val geoData = if (geoBypassEnabled) {
            val countryCode = preferencesDataStore.geoBypassCountry.first()
            val country = GeoBypassCountry.fromCode(countryCode)
            Log.i(TAG, "Geo-bypass enabled: country=${country.displayName}")
            DomainRouter.loadGeoData(this, country)
        } else {
            GeoBypassData.EMPTY
        }

        if (domainRoutingEnabled) {
            Log.i(TAG, "Domain routing enabled: mode=$mode, ${domains.size} domains")
        }

        return DomainRouter(
            enabled = domainRoutingEnabled || geoBypassEnabled,
            mode = mode,
            domains = domains,
            geoBypassEnabled = geoBypassEnabled,
            geoBypass = geoData
        )
    }

    /**
     * Read SSH tunnel settings from DataStore and apply to SshTunnelBridge.
     * Must be called before any SshTunnelBridge.start* method.
     *
     * If the user hasn't manually set Max Channels, uses a tunnel-type-aware default:
     * - SSH-only: 32 (direct TCP, good bandwidth)
     * - Slipstream+SSH: 24 (moderate throughput)
     * - DNSTT+SSH: 12 (limited DNS throughput, too many channels choke the tunnel)
     */
    private suspend fun configureSshBridge() {
        val cipher = preferencesDataStore.sshCipher.first()
        val compression = preferencesDataStore.sshCompression.first()
        val isCustom = preferencesDataStore.sshMaxChannelsIsCustom.first()
        val maxChannels = if (isCustom) {
            preferencesDataStore.sshMaxChannels.first()
        } else {
            when (currentTunnelType) {
                TunnelType.SSH -> 32
                TunnelType.NAIVE_SSH -> 32
                TunnelType.SLIPSTREAM_SSH -> 24
                TunnelType.DNSTT_SSH -> 12
                TunnelType.NOIZDNS_SSH -> 12
                else -> 16
            }
        }
        SshTunnelBridge.configure(
            cipher = cipher.jschConfig,
            compression = compression,
            maxChannels = maxChannels
        )
    }

    private suspend fun configureSshInstance(instance: app.slipnet.tunnel.SshTunnelInstance) {
        val cipher = preferencesDataStore.sshCipher.first()
        val compression = preferencesDataStore.sshCompression.first()
        val isCustom = preferencesDataStore.sshMaxChannelsIsCustom.first()
        val maxChannels = if (isCustom) preferencesDataStore.sshMaxChannels.first() else 32
        instance.configure(
            cipher = cipher.jschConfig,
            compression = compression,
            maxChannels = maxChannels
        )
    }

    private suspend fun connectSlipstreamSsh(profile: app.slipnet.domain.model.ServerProfile, dnsServer: String, remoteDns: String, remoteDnsFallback: String) {
        val proxyPort = preferencesDataStore.proxyListenPort.first()
        val proxyHost = preferencesDataStore.proxyListenAddress.first()
        val slipstreamPort = proxyPort + 1

        // Step 1: Set VpnService reference for socket protection via JNI
        SlipstreamBridge.proxyOnlyMode = isProxyOnly
        SlipstreamBridge.setVpnService(this@SlipNetVpnService)

        // Step 2: Start Slipstream tunnel on internal port (127.0.0.1 only)
        val proxyResult = vpnRepository.startSlipstreamProxy(profile, portOverride = slipstreamPort, hostOverride = "127.0.0.1")
        if (proxyResult.isFailure) {
            connectionManager.onVpnError(proxyResult.exceptionOrNull()?.message ?: "Failed to start Slipstream proxy")
            SlipstreamBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Read actual port — may differ from requested if preferred port was stuck
        val actualSlipstreamPort = SlipstreamBridge.getClientPort()
        if (actualSlipstreamPort != slipstreamPort) {
            Log.i(TAG, "Slipstream bound to alternative port $actualSlipstreamPort (preferred $slipstreamPort was stuck)")
        }

        // Step 2.5: Verify Slipstream is listening
        if (!waitForProxyReady(actualSlipstreamPort, maxAttempts = 20, delayMs = 100)) {
            handleProxyStartupFailure(actualSlipstreamPort)
            return
        }

        // Step 2.6: Wait for QUIC handshake — REQUIRED for Slipstream+SSH.
        // SSH needs a working QUIC tunnel before JSch can connect through it.
        // Wait longer than plain Slipstream (30s vs 5s) since this is a hard requirement.
        val quicReady = waitForQuicReady(maxAttempts = 150, delayMs = 200)
        if (!quicReady) {
            Log.e(TAG, "QUIC connection not ready — cannot establish SSH through Slipstream")
            connectionManager.onVpnError("Slipstream tunnel failed to connect (QUIC timeout)")
            SlipstreamBridge.stopClient()
            SlipstreamBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 3: Switch tunnel type to SLIPSTREAM_SSH before starting SSH
        vpnRepository.setCurrentTunnelType(TunnelType.SLIPSTREAM_SSH)
        currentTunnelType = TunnelType.SLIPSTREAM_SSH

        // Step 4: Start SSH tunnel directly through Slipstream
        // Slipstream in SSH mode is a raw TCP tunnel (like DNSTT) — the server's
        // --target-address forwards all traffic to SSH. JSch connects directly to
        // Slipstream's local port, no SOCKS5 proxy wrapper needed.
        configureSshBridge()
        val sshResult = withContext(Dispatchers.IO) {
            Log.i(TAG, "Starting SSH tunnel through Slipstream (${profile.sshHost}:${profile.sshPort} via 127.0.0.1:$actualSlipstreamPort)")
            SshTunnelBridge.startOverProxy(
                sshHost = profile.sshHost,
                sshPort = profile.sshPort,
                sshUsername = profile.sshUsername,
                sshPassword = profile.sshPassword,
                proxyHost = "127.0.0.1",
                proxyPort = actualSlipstreamPort,
                listenPort = proxyPort,
                listenHost = proxyHost,
                blockDirectDns = true,  // No addDisallowedApplication — direct UDP would loop through VPN
                sshAuthType = profile.sshAuthType,
                sshPrivateKey = profile.sshPrivateKey,
                sshKeyPassphrase = profile.sshKeyPassphrase,
                remoteDnsHost = remoteDns,
                remoteDnsFallback = remoteDnsFallback
            )
        }
        if (sshResult.isFailure) {
            connectionManager.onVpnError(sshResult.exceptionOrNull()?.message ?: "Failed to start SSH tunnel over Slipstream")
            SlipstreamBridge.stopClient()
            SlipstreamBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 4.5: Wait for SSH SOCKS5 proxy to be ready
        if (!waitForProxyReady(proxyPort, maxAttempts = 30, delayMs = 100)) {
            Log.e(TAG, "SSH SOCKS5 proxy failed to become ready on port $proxyPort")
            connectionManager.onVpnError("SSH tunnel failed to start over Slipstream")
            SshTunnelBridge.stop()
            SlipstreamBridge.stopClient()
            SlipstreamBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Proxy-only mode: skip VPN interface and tun2socks
        if (isProxyOnly) {
            vpnRepository.setProxyConnected(profile)
            Log.i(TAG, "Proxy-only mode: Slipstream+SSH SOCKS5 proxy ready on $proxyHost:$proxyPort")
            finishConnection()
            return
        }

        // Step 5: Establish VPN interface (with addDisallowedApplication — needed for geo-bypass
        // direct sockets; Slipstream QUIC sockets are also protected via JNI)
        // Done after SSH is connected to avoid disrupting QUIC during startup
        vpnInterface = establishVpnInterface(dnsServer)
        if (vpnInterface == null) {
            connectionManager.onVpnError("Failed to establish VPN interface")
            SshTunnelBridge.stop()
            SlipstreamBridge.stopClient()
            SlipstreamBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 6: Start tun2socks pointing at SSH SOCKS5 on proxyPort
        val tun2socksResult = vpnRepository.startTun2Socks(profile, vpnInterface!!)
        if (tun2socksResult.isFailure) {
            connectionManager.onVpnError(tun2socksResult.exceptionOrNull()?.message ?: "Failed to start tunnel")
            SshTunnelBridge.stop()
            SlipstreamBridge.stopClient()
            vpnInterface?.close()
            vpnInterface = null
            SlipstreamBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        delay(500)
        Log.d(TAG, "Slipstream+SSH tunnel started")
        finishConnection()
    }

    /**
     * Connect using DNSTT tunnel type.
     * Order: Establish VPN interface (with app exclusion) -> Start proxy -> Wait for ready -> tun2socks
     *
     * IMPORTANT: VPN must be established BEFORE starting DNSTT so that addDisallowedApplication
     * is in effect when DNSTT creates its UDP sockets. This prevents a routing loop where
     * DNSTT's DNS queries would be captured by the VPN.
     */
    private suspend fun connectDnstt(profile: app.slipnet.domain.model.ServerProfile, dnsServer: String, remoteDns: String, remoteDnsFallback: String) {
        val proxyPort = preferencesDataStore.proxyListenPort.first()
        val proxyHost = preferencesDataStore.proxyListenAddress.first()
        val dnsttPort = proxyPort + 1

        // Step 1: Set VpnService reference (for potential future use)
        DnsttBridge.setVpnService(this@SlipNetVpnService)

        // Step 2: Establish VPN interface FIRST (with addDisallowedApplication for this app)
        // This ensures DNSTT's sockets bypass the VPN when created
        if (!isProxyOnly) {
            vpnInterface = establishVpnInterface(dnsServer)
            if (vpnInterface == null) {
                connectionManager.onVpnError("Failed to establish VPN interface")
                DnsttBridge.setVpnService(null)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            // Brief delay to let VPN routing settle (as reference app does)
            delay(200)
        }

        // Step 3: Start DNSTT/NoizDNS on internal port (its sockets bypass VPN due to app exclusion)
        val isNoizdns = profile.tunnelType == TunnelType.NOIZDNS || profile.tunnelType == TunnelType.NOIZDNS_SSH
        val proxyResult = if (isNoizdns) {
            vpnRepository.startNoizdnsProxy(profile, portOverride = dnsttPort, hostOverride = "127.0.0.1")
        } else {
            vpnRepository.startDnsttProxy(profile, portOverride = dnsttPort, hostOverride = "127.0.0.1")
        }
        if (proxyResult.isFailure) {
            connectionManager.onVpnError(proxyResult.exceptionOrNull()?.message ?: "Failed to start ${if (isNoizdns) "NoizDNS" else "DNSTT"} proxy")
            vpnInterface?.close()
            vpnInterface = null
            DnsttBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Read actual port — may differ from requested if preferred port was stuck
        val actualDnsttPort = DnsttBridge.getClientPort()
        if (actualDnsttPort != dnsttPort) {
            Log.i(TAG, "DNSTT bound to alternative port $actualDnsttPort (preferred $dnsttPort was stuck)")
        }

        // Step 3.5: Verify DNSTT is listening on internal port
        if (!waitForProxyReady(actualDnsttPort, maxAttempts = 20, delayMs = 100)) {
            handleProxyStartupFailure(actualDnsttPort)
            vpnInterface?.close()
            vpnInterface = null
            return
        }

        // Step 4: Start DnsttSocksBridge on proxyPort (user-facing, with auth for Dante)
        // DNS target resolved at the REMOTE server (through Dante),
        // not locally. Using local/ISP DNS would give poisoned results in censored networks.
        DnsttSocksBridge.authoritativeMode = profile.dnsttAuthoritative
        DnsttSocksBridge.proxyOnlyMode = isProxyOnly
        val bridgeResult = vpnRepository.startDnsttSocksBridge(
            dnsttPort = actualDnsttPort,
            dnsttHost = "127.0.0.1",
            bridgePort = proxyPort,
            bridgeHost = proxyHost,
            socksUsername = profile.socksUsername,
            socksPassword = profile.socksPassword,
            dnsServer = remoteDns,
            dnsFallback = remoteDnsFallback
        )
        if (bridgeResult.isFailure) {
            connectionManager.onVpnError(bridgeResult.exceptionOrNull()?.message ?: "Failed to start DNSTT SOCKS5 bridge")
            stopCurrentProxy()
            DnsttBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 4.5: Verify bridge is listening
        if (!waitForProxyReady(proxyPort, maxAttempts = 20, delayMs = 100)) {
            Log.e(TAG, "DnsttSocksBridge failed to become ready on port $proxyPort")
            connectionManager.onVpnError("DNSTT SOCKS5 bridge failed to start")
            stopCurrentProxy()
            DnsttBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Proxy-only mode: skip tun2socks
        if (isProxyOnly) {
            vpnRepository.setProxyConnected(profile)
            Log.i(TAG, "Proxy-only mode: DNSTT SOCKS5 bridge ready on $proxyHost:$proxyPort")
            finishConnection()
            return
        }

        // Step 5: Start tun2socks pointing at bridge on proxyPort
        val tun2socksResult = vpnRepository.startTun2Socks(profile, vpnInterface!!)
        if (tun2socksResult.isFailure) {
            connectionManager.onVpnError(tun2socksResult.exceptionOrNull()?.message ?: "Failed to start tunnel")
            vpnInterface?.close()
            vpnInterface = null
            DnsttBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Give DNSTT a moment to establish the connection
        delay(500)
        Log.d(TAG, "DNSTT tunnel started with bridge")

        finishConnection()
    }

    /**
     * Connect using SSH-only tunnel type.
     * Order: Establish VPN interface (with app exclusion) -> Start SSH tunnel -> Wait for ready -> tun2socks
     *
     * SSH connects directly to the remote server (no DNS tunneling).
     * DNS queries go direct via DatagramSocket (bypasses VPN via addDisallowedApplication).
     */
    private suspend fun connectSsh(profile: app.slipnet.domain.model.ServerProfile, dnsServer: String, remoteDns: String, remoteDnsFallback: String) {
        val proxyPort = preferencesDataStore.proxyListenPort.first()
        val proxyHost = preferencesDataStore.proxyListenAddress.first()
        vpnRepository.setCurrentTunnelType(TunnelType.SSH)

        if (isProxyOnly) {
            // Proxy-only: no VPN needed, start SSH directly (sockets go direct anyway)
            configureSshBridge()
            val sshResult = withContext(Dispatchers.IO) {
                Log.i(TAG, "Starting SSH tunnel (direct to ${profile.domain}:${profile.sshPort})")
                SshTunnelBridge.startDirect(
                    tunnelHost = profile.domain,
                    tunnelPort = profile.sshPort,
                    sshUsername = profile.sshUsername,
                    sshPassword = profile.sshPassword,
                    listenPort = proxyPort,
                    listenHost = proxyHost,
                    forwardDnsThroughSsh = true,
                    sshAuthType = profile.sshAuthType,
                    sshPrivateKey = profile.sshPrivateKey,
                    sshKeyPassphrase = profile.sshKeyPassphrase,
                    remoteDnsHost = remoteDns,
                    remoteDnsFallback = remoteDnsFallback
                )
            }
            if (sshResult.isFailure) {
                connectionManager.onVpnError(sshResult.exceptionOrNull()?.message ?: "Failed to start SSH tunnel")
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            if (!waitForProxyReady(proxyPort, maxAttempts = 30, delayMs = 100)) {
                Log.e(TAG, "SSH SOCKS5 proxy failed to become ready")
                connectionManager.onVpnError("SSH tunnel failed to start")
                SshTunnelBridge.stop()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            vpnRepository.setProxyConnected(profile)
            Log.i(TAG, "Proxy-only mode: SSH SOCKS5 proxy ready on $proxyHost:$proxyPort")
            finishConnection()
            return
        }

        // Step 1: Establish VPN interface with addDisallowedApplication
        // This ensures SSH's socket and DNS queries bypass the VPN
        vpnInterface = establishVpnInterface(dnsServer)
        if (vpnInterface == null) {
            connectionManager.onVpnError("Failed to establish VPN interface")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Brief delay to let VPN routing settle
        delay(200)

        // Step 2: Start SSH tunnel directly to the SSH server
        configureSshBridge()
        val sshResult = withContext(Dispatchers.IO) {
            Log.i(TAG, "Starting SSH tunnel (direct to ${profile.domain}:${profile.sshPort})")
            SshTunnelBridge.startDirect(
                tunnelHost = profile.domain,
                tunnelPort = profile.sshPort,
                sshUsername = profile.sshUsername,
                sshPassword = profile.sshPassword,
                listenPort = proxyPort,
                listenHost = proxyHost,
                forwardDnsThroughSsh = true,
                sshAuthType = profile.sshAuthType,
                sshPrivateKey = profile.sshPrivateKey,
                sshKeyPassphrase = profile.sshKeyPassphrase,
                remoteDnsHost = remoteDns,
                remoteDnsFallback = remoteDnsFallback
            )
        }
        if (sshResult.isFailure) {
            connectionManager.onVpnError(sshResult.exceptionOrNull()?.message ?: "Failed to start SSH tunnel")
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 2.5: Wait for SSH SOCKS5 proxy to be ready
        if (!waitForProxyReady(proxyPort, maxAttempts = 30, delayMs = 100)) {
            Log.e(TAG, "SSH SOCKS5 proxy failed to become ready")
            connectionManager.onVpnError("SSH tunnel failed to start")
            SshTunnelBridge.stop()
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 3: Start tun2socks
        val tun2socksResult = vpnRepository.startTun2Socks(profile, vpnInterface!!)
        if (tun2socksResult.isFailure) {
            connectionManager.onVpnError(tun2socksResult.exceptionOrNull()?.message ?: "Failed to start tunnel")
            SshTunnelBridge.stop()
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        Log.d(TAG, "SSH tunnel started")
        finishConnection()
    }

    /**
     * Connect using NaiveProxy + SSH tunnel type.
     * NaiveProxy provides a local SOCKS5 proxy that tunnels through Caddy's
     * forwardproxy with authentic Chrome TLS fingerprinting. JSch connects
     * through NaiveProxy's SOCKS5 to reach the SSH server.
     *
     * Traffic flow:
     * App -> TUN -> hev-socks5-tunnel -> SshTunnelBridge SOCKS5 (proxyPort)
     *   -> SSH direct-tcpip -> [JSch via ProxySOCKS5] -> NaiveProxy SOCKS5 (proxyPort+1)
     *   -> Chrome TLS/HTTP2 CONNECT -> Caddy Server (forwardproxy) -> SSH:22
     */
    private suspend fun connectNaiveSsh(profile: app.slipnet.domain.model.ServerProfile, dnsServer: String, remoteDns: String, remoteDnsFallback: String) {
        val proxyPort = preferencesDataStore.proxyListenPort.first()
        val proxyHost = preferencesDataStore.proxyListenAddress.first()
        val naivePort = proxyPort + 1

        if (isProxyOnly) {
            // Proxy-only: no VPN needed, start NaiveProxy + SSH directly
            val naiveResult = withContext(Dispatchers.IO) {
                NaiveBridge.start(
                    context = this@SlipNetVpnService,
                    listenPort = naivePort,
                    listenHost = "127.0.0.1",
                    serverHost = profile.domain,
                    serverPort = profile.naivePort,
                    username = profile.naiveUsername,
                    password = profile.naivePassword,
                )
            }
            if (naiveResult.isFailure) {
                connectionManager.onVpnError(naiveResult.exceptionOrNull()?.message ?: "Failed to start NaiveProxy")
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            if (!waitForNaiveReady(maxAttempts = 30, delayMs = 200)) {
                Log.e(TAG, "NaiveProxy failed to become ready on port $naivePort")
                connectionManager.onVpnError("NaiveProxy failed to start")
                NaiveBridge.stop()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            // For NaiveProxy: use server domain instead of 127.0.0.1 as SSH target.
            // NaiveProxy (Chromium) may bypass the HTTPS proxy for loopback addresses,
            // causing SOCKS5 CONNECT to 127.0.0.1 to connect locally instead of remotely.
            val naiveSshHost = if (profile.sshHost == "127.0.0.1" || profile.sshHost.isBlank()) {
                profile.domain
            } else {
                profile.sshHost
            }

            configureSshBridge()
            val sshResult = withContext(Dispatchers.IO) {
                Log.i(TAG, "Starting SSH tunnel through NaiveProxy ($naiveSshHost:${profile.sshPort} via 127.0.0.1:$naivePort)")
                SshTunnelBridge.startOverSocks5Proxy(
                    sshHost = naiveSshHost,
                    sshPort = profile.sshPort,
                    sshUsername = profile.sshUsername,
                    sshPassword = profile.sshPassword,
                    proxyHost = "127.0.0.1",
                    proxyPort = naivePort,
                    socksUsername = null,
                    socksPassword = null,
                    listenPort = proxyPort,
                    listenHost = proxyHost,
                    sshAuthType = profile.sshAuthType,
                    sshPrivateKey = profile.sshPrivateKey,
                    sshKeyPassphrase = profile.sshKeyPassphrase,
                    remoteDnsHost = remoteDns,
                    remoteDnsFallback = remoteDnsFallback,
                    naiveMode = true
                )
            }
            if (sshResult.isFailure) {
                connectionManager.onVpnError(sshResult.exceptionOrNull()?.message ?: "Failed to start SSH tunnel over NaiveProxy")
                NaiveBridge.stop()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            if (!waitForProxyReady(proxyPort, maxAttempts = 30, delayMs = 100)) {
                Log.e(TAG, "SSH SOCKS5 proxy failed to become ready")
                connectionManager.onVpnError("SSH tunnel failed to start over NaiveProxy")
                SshTunnelBridge.stop()
                NaiveBridge.stop()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            vpnRepository.setProxyConnected(profile)
            Log.i(TAG, "Proxy-only mode: NaiveProxy+SSH SOCKS5 proxy ready on $proxyHost:$proxyPort")
            finishConnection()
            return
        }

        // Step 1: Establish VPN interface with addDisallowedApplication
        vpnInterface = establishVpnInterface(dnsServer)
        if (vpnInterface == null) {
            connectionManager.onVpnError("Failed to establish VPN interface")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        delay(200)

        // Step 2: Start NaiveProxy
        val naiveResult = withContext(Dispatchers.IO) {
            NaiveBridge.start(
                context = this@SlipNetVpnService,
                listenPort = naivePort,
                listenHost = "127.0.0.1",
                serverHost = profile.domain,
                serverPort = profile.naivePort,
                username = profile.naiveUsername,
                password = profile.naivePassword
            )
        }
        if (naiveResult.isFailure) {
            connectionManager.onVpnError(naiveResult.exceptionOrNull()?.message ?: "Failed to start NaiveProxy")
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Wait for NaiveProxy ready (use isReady flag, not TCP connect, to avoid
        // ERR_SOCKS_CONNECTION_FAILED noise from non-SOCKS5 probe)
        if (!waitForNaiveReady(maxAttempts = 30, delayMs = 200)) {
            Log.e(TAG, "NaiveProxy failed to become ready on port $naivePort")
            connectionManager.onVpnError("NaiveProxy failed to start")
            NaiveBridge.stop()
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 3: SSH over NaiveProxy's SOCKS5
        // Use server domain instead of 127.0.0.1 to avoid Chromium loopback bypass
        val naiveSshHost = if (profile.sshHost == "127.0.0.1" || profile.sshHost.isBlank()) {
            profile.domain
        } else {
            profile.sshHost
        }

        configureSshBridge()
        val sshResult = withContext(Dispatchers.IO) {
            Log.i(TAG, "Starting SSH tunnel through NaiveProxy ($naiveSshHost:${profile.sshPort} via 127.0.0.1:$naivePort)")
            SshTunnelBridge.startOverSocks5Proxy(
                sshHost = naiveSshHost,
                sshPort = profile.sshPort,
                sshUsername = profile.sshUsername,
                sshPassword = profile.sshPassword,
                proxyHost = "127.0.0.1",
                proxyPort = naivePort,
                socksUsername = null,
                socksPassword = null,
                listenPort = proxyPort,
                listenHost = proxyHost,
                sshAuthType = profile.sshAuthType,
                sshPrivateKey = profile.sshPrivateKey,
                sshKeyPassphrase = profile.sshKeyPassphrase,
                remoteDnsHost = remoteDns,
                remoteDnsFallback = remoteDnsFallback,
                naiveMode = true
            )
        }
        if (sshResult.isFailure) {
            connectionManager.onVpnError(sshResult.exceptionOrNull()?.message ?: "Failed to start SSH tunnel over NaiveProxy")
            NaiveBridge.stop()
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 3.5: Wait for SSH SOCKS5 proxy to be ready
        if (!waitForProxyReady(proxyPort, maxAttempts = 30, delayMs = 100)) {
            Log.e(TAG, "SSH SOCKS5 proxy failed to become ready on port $proxyPort")
            connectionManager.onVpnError("SSH tunnel failed to start over NaiveProxy")
            SshTunnelBridge.stop()
            NaiveBridge.stop()
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 4: Start tun2socks
        val tun2socksResult = vpnRepository.startTun2Socks(profile, vpnInterface!!)
        if (tun2socksResult.isFailure) {
            connectionManager.onVpnError(tun2socksResult.exceptionOrNull()?.message ?: "Failed to start tunnel")
            SshTunnelBridge.stop()
            NaiveBridge.stop()
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        Log.d(TAG, "NaiveProxy+SSH tunnel started")
        finishConnection()
    }

    /**
     * Connect using standalone NaiveProxy tunnel type.
     * Order: VPN interface (with addDisallowedApplication) -> NaiveProxy on proxyPort+1
     *        -> Wait for ready -> NaiveSocksBridge on proxyPort -> tun2socks on proxyPort
     *
     * Traffic flow:
     * App -> TUN -> hev-socks5-tunnel -> NaiveSocksBridge (proxyPort, NO_AUTH)
     *   TCP CONNECT: -> NaiveProxy SOCKS5 (proxyPort+1, NO_AUTH) -> Caddy HTTPS -> Internet
     *   DNS FWD_UDP: -> worker pool (SOCKS5 CONNECT through NaiveProxy to DNS) -> DNS-over-TCP
     */
    private suspend fun connectNaive(profile: app.slipnet.domain.model.ServerProfile, dnsServer: String, remoteDns: String, remoteDnsFallback: String) {
        val proxyPort = preferencesDataStore.proxyListenPort.first()
        val proxyHost = preferencesDataStore.proxyListenAddress.first()
        val naivePort = proxyPort + 1

        if (isProxyOnly) {
            // Proxy-only: no VPN needed, start NaiveProxy + bridge directly
            val naiveResult = withContext(Dispatchers.IO) {
                NaiveBridge.start(
                    context = this@SlipNetVpnService,
                    listenPort = naivePort,
                    listenHost = "127.0.0.1",
                    serverHost = profile.domain,
                    serverPort = profile.naivePort,
                    username = profile.naiveUsername,
                    password = profile.naivePassword,
                )
            }
            if (naiveResult.isFailure) {
                connectionManager.onVpnError(naiveResult.exceptionOrNull()?.message ?: "Failed to start NaiveProxy")
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            if (!waitForNaiveReady(maxAttempts = 30, delayMs = 200)) {
                Log.e(TAG, "NaiveProxy failed to become ready on port $naivePort")
                connectionManager.onVpnError("NaiveProxy failed to start")
                NaiveBridge.stop()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            // Start NaiveSocksBridge on proxyPort
            val bridgeResult = vpnRepository.startNaiveSocksBridge(
                naivePort = naivePort,
                naiveHost = "127.0.0.1",
                bridgePort = proxyPort,
                bridgeHost = proxyHost,
                dnsServer = remoteDns,
                dnsFallback = remoteDnsFallback
            )
            if (bridgeResult.isFailure) {
                connectionManager.onVpnError(bridgeResult.exceptionOrNull()?.message ?: "Failed to start NaiveProxy bridge")
                NaiveBridge.stop()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            if (!waitForProxyReady(proxyPort, maxAttempts = 30, delayMs = 100)) {
                Log.e(TAG, "NaiveSocksBridge failed to become ready on port $proxyPort")
                connectionManager.onVpnError("NaiveProxy bridge failed to start")
                NaiveSocksBridge.stop()
                NaiveBridge.stop()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            vpnRepository.setProxyConnected(profile)
            Log.i(TAG, "Proxy-only mode: NaiveProxy SOCKS5 proxy ready on $proxyHost:$proxyPort")
            finishConnection()
            return
        }

        // Step 1: Establish VPN interface with addDisallowedApplication
        vpnInterface = establishVpnInterface(dnsServer)
        if (vpnInterface == null) {
            connectionManager.onVpnError("Failed to establish VPN interface")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        delay(200)

        // Step 2: Start NaiveProxy on internal port
        val naiveResult = withContext(Dispatchers.IO) {
            NaiveBridge.start(
                context = this@SlipNetVpnService,
                listenPort = naivePort,
                listenHost = "127.0.0.1",
                serverHost = profile.domain,
                serverPort = profile.naivePort,
                username = profile.naiveUsername,
                password = profile.naivePassword
            )
        }
        if (naiveResult.isFailure) {
            connectionManager.onVpnError(naiveResult.exceptionOrNull()?.message ?: "Failed to start NaiveProxy")
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        if (!waitForNaiveReady(maxAttempts = 30, delayMs = 200)) {
            Log.e(TAG, "NaiveProxy failed to become ready on port $naivePort")
            connectionManager.onVpnError("NaiveProxy failed to start")
            NaiveBridge.stop()
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 3: Start NaiveSocksBridge on proxyPort
        val bridgeResult = vpnRepository.startNaiveSocksBridge(
            naivePort = naivePort,
            naiveHost = "127.0.0.1",
            bridgePort = proxyPort,
            bridgeHost = proxyHost,
            dnsServer = remoteDns,
            dnsFallback = remoteDnsFallback
        )
        if (bridgeResult.isFailure) {
            connectionManager.onVpnError(bridgeResult.exceptionOrNull()?.message ?: "Failed to start NaiveProxy bridge")
            NaiveBridge.stop()
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        if (!waitForProxyReady(proxyPort, maxAttempts = 30, delayMs = 100)) {
            Log.e(TAG, "NaiveSocksBridge failed to become ready on port $proxyPort")
            connectionManager.onVpnError("NaiveProxy bridge failed to start")
            NaiveSocksBridge.stop()
            NaiveBridge.stop()
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 4: Start tun2socks
        val tun2socksResult = vpnRepository.startTun2Socks(profile, vpnInterface!!)
        if (tun2socksResult.isFailure) {
            connectionManager.onVpnError(tun2socksResult.exceptionOrNull()?.message ?: "Failed to start tunnel")
            NaiveSocksBridge.stop()
            NaiveBridge.stop()
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        Log.d(TAG, "Standalone NaiveProxy tunnel started")
        finishConnection()
    }

    /**
     * Connect using DNSTT+SSH tunnel type.
     * Order: Set DNSTT ref -> VPN interface (with app exclusion) -> Start DNSTT -> Wait for DNSTT ready
     *        -> Start SSH over DNSTT proxy -> Wait for SSH ready -> Start tun2socks on proxyPort
     *
     * Traffic flow:
     * App -> TUN -> hev-socks5-tunnel -> SSH SOCKS5 (proxyPort)
     *   -> SSH direct-tcpip -> DNSTT (proxyPort+1, 127.0.0.1, raw TCP tunnel)
     *   -> DNS tunnel (UDP 53) -> DNSTT Server -> SSH Server -> Internet
     */
    private suspend fun connectDnsttSsh(profile: app.slipnet.domain.model.ServerProfile, dnsServer: String, remoteDns: String, remoteDnsFallback: String) {
        val proxyPort = preferencesDataStore.proxyListenPort.first()
        val proxyHost = preferencesDataStore.proxyListenAddress.first()
        val dnsttPort = proxyPort + 1

        // Step 1: Set VpnService reference for DNSTT
        DnsttBridge.setVpnService(this@SlipNetVpnService)

        if (!isProxyOnly) {
            // Step 2: Establish VPN interface with addDisallowedApplication
            vpnInterface = establishVpnInterface(dnsServer)
            if (vpnInterface == null) {
                connectionManager.onVpnError("Failed to establish VPN interface")
                DnsttBridge.setVpnService(null)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            // Brief delay to let VPN routing settle
            delay(200)
        }

        // Step 3: Start DNSTT/NoizDNS proxy on internal port (127.0.0.1 only)
        val isNoizdns = profile.tunnelType == TunnelType.NOIZDNS || profile.tunnelType == TunnelType.NOIZDNS_SSH
        val proxyResult = if (isNoizdns) {
            vpnRepository.startNoizdnsProxy(profile, portOverride = dnsttPort, hostOverride = "127.0.0.1")
        } else {
            vpnRepository.startDnsttProxy(profile, portOverride = dnsttPort, hostOverride = "127.0.0.1")
        }
        if (proxyResult.isFailure) {
            connectionManager.onVpnError(proxyResult.exceptionOrNull()?.message ?: "Failed to start ${if (isNoizdns) "NoizDNS" else "DNSTT"} proxy")
            vpnInterface?.close()
            vpnInterface = null
            DnsttBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Read actual port — may differ from requested if preferred port was stuck
        val actualDnsttPort = DnsttBridge.getClientPort()
        if (actualDnsttPort != dnsttPort) {
            Log.i(TAG, "DNSTT bound to alternative port $actualDnsttPort (preferred $dnsttPort was stuck)")
        }

        // Step 3.5: Verify proxy is listening
        if (!waitForProxyReady(actualDnsttPort, maxAttempts = 20, delayMs = 100)) {
            handleProxyStartupFailure(actualDnsttPort)
            vpnInterface?.close()
            vpnInterface = null
            return
        }

        // Step 4: Switch tunnel type to DNSTT_SSH/NOIZDNS_SSH before starting SSH
        val sshTunnelType = if (isNoizdns) TunnelType.NOIZDNS_SSH else TunnelType.DNSTT_SSH
        vpnRepository.setCurrentTunnelType(sshTunnelType)
        currentTunnelType = sshTunnelType

        // Step 4.5: Probe DNS transport before committing to the full SSH connect.
        // Verifies that DNS responses are reaching this device by waiting for the SSH
        // banner through DNSTT. If nothing arrives within the probe window, DNS
        // responses are filtered — fail fast instead of wasting 30 s and ~75 MB of
        // upload from QUIC retransmissions. The timeout is intentionally generous
        // (20 s) to accommodate the multiple DNS round-trips dnstt needs to complete
        // its own handshake on heavily restricted or high-latency networks.
        Log.i(TAG, "Probing DNSTT transport (up to 20 s)…")
        val probeOk = withContext(Dispatchers.IO) {
            probeDnsttTransport("127.0.0.1", actualDnsttPort, timeoutMs = 20_000)
        }
        if (!probeOk) {
            val tunnelName = if (isNoizdns) "NoizDNS" else "DNSTT"
            Log.e(TAG, "$tunnelName transport probe failed — DNS responses may be filtered by the network")
            connectionManager.onVpnError("DNS tunnel not responding. DNS responses may be filtered. Try a different resolver or profile.")
            DnsttBridge.stopClient()
            vpnInterface?.close()
            vpnInterface = null
            DnsttBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }
        Log.i(TAG, "DNSTT transport probe passed — proceeding with SSH")

        // Step 5: Start SSH tunnel through DNSTT
        // DNSTT is a raw TCP tunnel — JSch connects directly to its local port
        configureSshBridge()
        val sshResult = withContext(Dispatchers.IO) {
            Log.i(TAG, "Starting SSH tunnel through DNSTT (${profile.sshHost}:${profile.sshPort} via 127.0.0.1:$actualDnsttPort)")
            SshTunnelBridge.startOverProxy(
                sshHost = profile.sshHost,
                sshPort = profile.sshPort,
                sshUsername = profile.sshUsername,
                sshPassword = profile.sshPassword,
                proxyHost = "127.0.0.1",
                proxyPort = actualDnsttPort,
                listenPort = proxyPort,
                listenHost = proxyHost,
                blockDirectDns = true,
                sshAuthType = profile.sshAuthType,
                sshPrivateKey = profile.sshPrivateKey,
                sshKeyPassphrase = profile.sshKeyPassphrase,
                remoteDnsHost = remoteDns,
                remoteDnsFallback = remoteDnsFallback
            )
        }
        if (sshResult.isFailure) {
            connectionManager.onVpnError(sshResult.exceptionOrNull()?.message ?: "Failed to start SSH tunnel over DNSTT")
            DnsttBridge.stopClient()
            vpnInterface?.close()
            vpnInterface = null
            DnsttBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 5.5: Wait for SSH SOCKS5 proxy to be ready
        if (!waitForProxyReady(proxyPort, maxAttempts = 30, delayMs = 100)) {
            Log.e(TAG, "SSH SOCKS5 proxy failed to become ready on port $proxyPort")
            connectionManager.onVpnError("SSH tunnel failed to start over DNSTT")
            SshTunnelBridge.stop()
            DnsttBridge.stopClient()
            vpnInterface?.close()
            vpnInterface = null
            DnsttBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Proxy-only mode: skip tun2socks
        if (isProxyOnly) {
            vpnRepository.setProxyConnected(profile)
            Log.i(TAG, "Proxy-only mode: DNSTT+SSH SOCKS5 proxy ready on $proxyHost:$proxyPort")
            finishConnection()
            return
        }

        // Step 6: Start tun2socks pointing at SSH SOCKS5 on proxyPort
        val tun2socksResult = vpnRepository.startTun2Socks(profile, vpnInterface!!)
        if (tun2socksResult.isFailure) {
            connectionManager.onVpnError(tun2socksResult.exceptionOrNull()?.message ?: "Failed to start tunnel")
            SshTunnelBridge.stop()
            DnsttBridge.stopClient()
            vpnInterface?.close()
            vpnInterface = null
            DnsttBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        delay(500)
        Log.d(TAG, "DNSTT+SSH tunnel started")
        finishConnection()
    }

    /**
     * Connect using DoH (DNS-over-HTTPS) tunnel type.
     * Order: Establish VPN interface (with app exclusion) -> Start DoH proxy -> Wait for ready -> tun2socks
     *
     * Only DNS queries are encrypted via HTTPS. All other traffic flows directly.
     * Uses addDisallowedApplication so DoH HTTPS requests and direct TCP/UDP bypass VPN.
     */
    private suspend fun connectDoh(profile: app.slipnet.domain.model.ServerProfile, dnsServer: String) {
        val proxyPort = preferencesDataStore.proxyListenPort.first()
        val proxyHost = preferencesDataStore.proxyListenAddress.first()

        if (isProxyOnly) {
            // Proxy-only: no VPN needed, start DoH proxy directly
            val proxyResult = vpnRepository.startDohProxy(profile)
            if (proxyResult.isFailure) {
                connectionManager.onVpnError(proxyResult.exceptionOrNull()?.message ?: "Failed to start DoH proxy")
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            if (!waitForProxyReady(proxyPort, maxAttempts = 20, delayMs = 100)) {
                handleProxyStartupFailure(proxyPort)
                return
            }

            vpnRepository.setProxyConnected(profile)
            Log.i(TAG, "Proxy-only mode: DoH SOCKS5 proxy ready on $proxyHost:$proxyPort")
            finishConnection()
            return
        }

        // Step 1: Establish VPN interface with addDisallowedApplication
        // Use a virtual DNS address so Android can't DoT to a real server.
        // All DNS goes through FWD_UDP → DohBridge → DoH HTTPS instead.
        vpnInterface = establishVpnInterface("10.255.255.2")
        if (vpnInterface == null) {
            connectionManager.onVpnError("Failed to establish VPN interface")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Brief delay to let VPN routing settle
        delay(200)

        // Step 2: Start DoH proxy
        val proxyResult = vpnRepository.startDohProxy(profile)
        if (proxyResult.isFailure) {
            connectionManager.onVpnError(proxyResult.exceptionOrNull()?.message ?: "Failed to start DoH proxy")
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 2.5: Verify proxy is listening
        if (!waitForProxyReady(proxyPort, maxAttempts = 20, delayMs = 100)) {
            handleProxyStartupFailure(proxyPort)
            vpnInterface?.close()
            vpnInterface = null
            return
        }

        // Step 3: Start tun2socks
        val tun2socksResult = vpnRepository.startTun2Socks(profile, vpnInterface!!)
        if (tun2socksResult.isFailure) {
            connectionManager.onVpnError(tun2socksResult.exceptionOrNull()?.message ?: "Failed to start tunnel")
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        Log.d(TAG, "DoH tunnel started")
        finishConnection()
    }

    /**
     * Connect using Snowflake (Tor) tunnel type.
     * Order: VPN interface (virtual DNS, addDisallowedApplication)
     *        -> Start Snowflake PT + Tor + TorSocksBridge
     *        -> Wait for Tor bootstrap (60s)
     *        -> Wait for bridge ready -> tun2socks on bridge port
     *
     * Snowflake routes traffic through Tor's network using WebRTC volunteer proxies.
     * TorSocksBridge handles CONNECT (chain to Tor SOCKS5) and FWD_UDP DNS
     * (DNS-over-TCP through Tor).
     */
    private suspend fun connectSnowflake(profile: app.slipnet.domain.model.ServerProfile, dnsServer: String) {
        // Route SMART profiles to the Smart Connect orchestrator
        if (profile.torBridgeLines.trim() == "SMART") {
            connectSnowflakeSmart(profile, dnsServer)
            return
        }

        val proxyPort = preferencesDataStore.proxyListenPort.first()
        val proxyHost = preferencesDataStore.proxyListenAddress.first()
        val torSocksPort = proxyPort + 1
        val snowflakePtPort = proxyPort + 2

        if (isProxyOnly) {
            // Start proxy stack directly
            val proxyResult = vpnRepository.startSnowflakeProxy(profile, snowflakePtPort, torSocksPort, proxyPort)
            if (proxyResult.isFailure) {
                connectionManager.onVpnError(proxyResult.exceptionOrNull()?.message ?: "Failed to start Snowflake proxy")
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            // Wait for Tor to bootstrap (webtunnel/obfs4 can be slow)
            if (!waitForTorReady(maxWaitMs = 300000)) {
                connectionManager.onVpnError("Tor failed to bootstrap within timeout (${SnowflakeBridge.torBootstrapProgress}%)")
                stopCurrentProxy()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            if (!waitForProxyReady(proxyPort, maxAttempts = 20, delayMs = 100)) {
                handleProxyStartupFailure(proxyPort)
                return
            }

            vpnRepository.setProxyConnected(profile)
            Log.i(TAG, "Proxy-only mode: Snowflake proxy stack ready on $proxyHost:$proxyPort")
            finishConnection()
            return
        }

        // Step 1: Start Snowflake proxy stack (Snowflake PT + Tor + TorSocksBridge)
        // VPN interface is NOT established yet — no VPN key icon during bootstrap
        val proxyResult = vpnRepository.startSnowflakeProxy(profile, snowflakePtPort, torSocksPort, proxyPort)
        if (proxyResult.isFailure) {
            connectionManager.onVpnError(proxyResult.exceptionOrNull()?.message ?: "Failed to start Snowflake proxy")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 2: Wait for Tor to bootstrap (webtunnel/obfs4 can be slow)
        Log.i(TAG, "Waiting for Tor to bootstrap...")
        if (!waitForTorReady(maxWaitMs = 300000)) {
            connectionManager.onVpnError("Tor failed to bootstrap within timeout (${SnowflakeBridge.torBootstrapProgress}%)")
            stopCurrentProxy()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }
        Log.i(TAG, "Tor bootstrapped successfully")

        // Step 3: Verify bridge is listening
        if (!waitForProxyReady(proxyPort, maxAttempts = 20, delayMs = 100)) {
            handleProxyStartupFailure(proxyPort)
            return
        }

        // Step 4: Establish VPN interface now that Tor is ready (VPN key icon appears here)
        vpnInterface = establishVpnInterface("10.255.255.2")
        if (vpnInterface == null) {
            connectionManager.onVpnError("Failed to establish VPN interface")
            stopCurrentProxy()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Brief delay to let VPN routing settle
        delay(200)

        // Step 5: Start tun2socks pointing at TorSocksBridge port
        val tun2socksResult = vpnRepository.startTun2Socks(profile, vpnInterface!!)
        if (tun2socksResult.isFailure) {
            connectionManager.onVpnError(tun2socksResult.exceptionOrNull()?.message ?: "Failed to start tunnel")
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        Log.d(TAG, "Snowflake tunnel started")
        finishConnection()
    }

    /**
     * Smart Connect: tries multiple Tor transports sequentially until one works.
     * Transport sequence: Direct → Snowflake → obfs4 → Meek Azure.
     * On reconnect, SMART profiles fall back to built-in Snowflake (SnowflakeBridge
     * treats "SMART" sentinel as built-in Snowflake).
     */

    /**
     * Connect using a remote SOCKS5 proxy.
     * Traffic flow:
     * App -> TUN -> hev-socks5-tunnel -> Socks5ProxyBridge (proxyPort)
     *   -> Remote SOCKS5 Proxy (domain:socks5ServerPort) -> Internet
     */
    private suspend fun connectSocks5(profile: app.slipnet.domain.model.ServerProfile, dnsServer: String, remoteDns: String) {
        val proxyPort = preferencesDataStore.proxyListenPort.first()
        val proxyHost = preferencesDataStore.proxyListenAddress.first()
        vpnRepository.setCurrentTunnelType(TunnelType.SOCKS5)

        if (isProxyOnly) {
            Socks5ProxyBridge.debugLogging = preferencesDataStore.debugLogging.first()
            val bridgeResult = withContext(Dispatchers.IO) {
                Socks5ProxyBridge.start(
                    remoteHost = profile.domain,
                    remotePort = profile.socks5ServerPort,
                    remoteUsername = profile.socksUsername,
                    remotePassword = profile.socksPassword,
                    listenPort = proxyPort,
                    listenHost = proxyHost,
                    dnsHost = remoteDns
                )
            }
            if (bridgeResult.isFailure) {
                connectionManager.onVpnError(bridgeResult.exceptionOrNull()?.message ?: "Failed to start SOCKS5 proxy bridge")
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            if (!waitForProxyReady(proxyPort, maxAttempts = 30, delayMs = 100)) {
                connectionManager.onVpnError("SOCKS5 proxy bridge failed to start")
                Socks5ProxyBridge.stop()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            vpnRepository.setProxyConnected(profile)
            Log.i(TAG, "Proxy-only mode: SOCKS5 proxy bridge ready on $proxyHost:$proxyPort")
            finishConnection()
            return
        }

        // Step 1: Establish VPN interface
        vpnInterface = establishVpnInterface(dnsServer)
        if (vpnInterface == null) {
            connectionManager.onVpnError("Failed to establish VPN interface")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }
        delay(200)

        // Step 2: Start SOCKS5 proxy bridge
        Socks5ProxyBridge.debugLogging = preferencesDataStore.debugLogging.first()
        val bridgeResult = withContext(Dispatchers.IO) {
            Socks5ProxyBridge.start(
                remoteHost = profile.domain,
                remotePort = profile.socks5ServerPort,
                remoteUsername = profile.socksUsername,
                remotePassword = profile.socksPassword,
                listenPort = proxyPort,
                listenHost = proxyHost,
                dnsHost = remoteDns
            )
        }
        if (bridgeResult.isFailure) {
            connectionManager.onVpnError(bridgeResult.exceptionOrNull()?.message ?: "Failed to start SOCKS5 proxy bridge")
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        if (!waitForProxyReady(proxyPort, maxAttempts = 30, delayMs = 100)) {
            connectionManager.onVpnError("SOCKS5 proxy bridge failed to start")
            Socks5ProxyBridge.stop()
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 3: Start tun2socks
        val tun2socksResult = vpnRepository.startTun2Socks(profile, vpnInterface!!)
        if (tun2socksResult.isFailure) {
            connectionManager.onVpnError(tun2socksResult.exceptionOrNull()?.message ?: "Failed to start tunnel")
            Socks5ProxyBridge.stop()
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        Log.d(TAG, "SOCKS5 proxy tunnel started")
        finishConnection()
    }

    private suspend fun connectSnowflakeSmart(profile: app.slipnet.domain.model.ServerProfile, dnsServer: String) {
        val proxyPort = preferencesDataStore.proxyListenPort.first()
        val proxyHost = preferencesDataStore.proxyListenAddress.first()
        val torSocksPort = proxyPort + 1
        val snowflakePtPort = proxyPort + 2

        data class SmartTransport(val label: String, val bridgeLines: String, val timeoutMs: Long)
        val transports = listOf(
            SmartTransport("Direct", "DIRECT", 30000),
            SmartTransport("Snowflake", "", 60000),
            SmartTransport("obfs4", app.slipnet.presentation.profiles.EditProfileViewModel.DEFAULT_OBFS4_BRIDGES, 60000),
            SmartTransport("Meek Azure", app.slipnet.presentation.profiles.EditProfileViewModel.DEFAULT_MEEK_BRIDGE, 60000)
        )

        val notificationManager = getSystemService(NotificationManager::class.java)
        var success = false

        for ((index, transport) in transports.withIndex()) {
            Log.i(TAG, "Smart Connect: Trying ${transport.label} (${index + 1}/${transports.size})")

            // Update notification with current transport attempt
            val notification = notificationHelper.createSmartConnectNotification(
                transport.label, index + 1, transports.size
            )
            notificationManager.notify(NotificationHelper.VPN_NOTIFICATION_ID, notification)

            // Create modified profile with this transport's bridge lines
            val modifiedProfile = profile.copy(torBridgeLines = transport.bridgeLines)

            // Try starting proxy stack
            val proxyResult = vpnRepository.startSnowflakeProxy(modifiedProfile, snowflakePtPort, torSocksPort, proxyPort)
            if (proxyResult.isFailure) {
                Log.w(TAG, "Smart Connect: ${transport.label} proxy start failed: ${proxyResult.exceptionOrNull()?.message}")
                continue
            }

            // Wait for Tor to bootstrap with transport-specific timeout
            if (waitForTorReady(maxWaitMs = transport.timeoutMs)) {
                if (waitForProxyReady(proxyPort, maxAttempts = 20, delayMs = 100)) {
                    Log.i(TAG, "Smart Connect: ${transport.label} succeeded!")
                    success = true
                    break
                }
            }

            // This transport failed — stop proxy stack and try the next one
            Log.w(TAG, "Smart Connect: ${transport.label} failed (bootstrap: ${SnowflakeBridge.torBootstrapProgress}%)")
            TorSocksBridge.stop()
            SnowflakeBridge.stopClient()
        }

        if (!success) {
            connectionManager.onVpnError("Smart Connect: All transports failed")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        if (isProxyOnly) {
            vpnRepository.setProxyConnected(profile)
            Log.i(TAG, "Proxy-only mode: Smart Connect proxy stack ready on $proxyHost:$proxyPort")
            finishConnection()
            return
        }

        // Establish VPN interface now that a transport succeeded (VPN key icon appears here)
        vpnInterface = establishVpnInterface("10.255.255.2")
        if (vpnInterface == null) {
            connectionManager.onVpnError("Failed to establish VPN interface")
            stopCurrentProxy()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Brief delay to let VPN routing settle
        delay(200)

        // Start tun2socks pointing at TorSocksBridge port
        val tun2socksResult = vpnRepository.startTun2Socks(profile, vpnInterface!!)
        if (tun2socksResult.isFailure) {
            connectionManager.onVpnError(tun2socksResult.exceptionOrNull()?.message ?: "Failed to start tunnel")
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        Log.d(TAG, "Smart Connect tunnel started")
        finishConnection()
    }

    /**
     * Wait for Tor to finish bootstrapping (isTorReady == true).
     */
    private suspend fun waitForTorReady(maxWaitMs: Long = 90000): Boolean {
        val startTime = System.currentTimeMillis()
        while (System.currentTimeMillis() - startTime < maxWaitMs) {
            if (SnowflakeBridge.isTorReady) return true
            if (!SnowflakeBridge.isRunning()) {
                Log.e(TAG, "Snowflake/Tor died during bootstrap")
                return false
            }
            delay(1000)
        }
        return SnowflakeBridge.isTorReady
    }

    /**
     * Handle proxy startup failure - common to both tunnel types.
     */
    private suspend fun handleProxyStartupFailure(port: Int) {
        val nativeRunning = when (currentTunnelType) {
            TunnelType.SLIPSTREAM -> try { SlipstreamBridge.isNativeRunning() } catch (e: Exception) { false }
            TunnelType.SLIPSTREAM_SSH -> try { SlipstreamBridge.isNativeRunning() } catch (e: Exception) { false }
            TunnelType.DNSTT -> try { DnsttBridge.isRunning() } catch (e: Exception) { false }
            TunnelType.NOIZDNS -> try { DnsttBridge.isRunning() } catch (e: Exception) { false }
            TunnelType.SSH -> SshTunnelBridge.isRunning()
            TunnelType.DNSTT_SSH -> try { DnsttBridge.isRunning() } catch (e: Exception) { false }
            TunnelType.NOIZDNS_SSH -> try { DnsttBridge.isRunning() } catch (e: Exception) { false }
            TunnelType.DOH -> DohBridge.isRunning()
            TunnelType.NAIVE_SSH -> NaiveBridge.isRunning()
            TunnelType.NAIVE -> NaiveBridge.isRunning()
            TunnelType.SNOWFLAKE -> SnowflakeBridge.isRunning()
            TunnelType.SOCKS5 -> Socks5ProxyBridge.isRunning()
        }
        Log.e(TAG, "Proxy failed to become ready on port $port, nativeRunning=$nativeRunning")

        val errorMsg = if (!nativeRunning) {
            "Proxy failed to start - client crashed"
        } else {
            "Proxy failed to start - port not listening"
        }
        connectionManager.onVpnError(errorMsg)
        stopCurrentProxy()
        clearVpnServiceRef()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    /**
     * Finish connection setup - common to all tunnel types.
     */
    private fun finishConnection() {
        // Mark connection as successful for auto-reconnect eligibility
        connectionWasSuccessful = true
        autoReconnectAttempt = 0
        connectionEstablishedAt = System.currentTimeMillis()

        // Notify connection manager for bookkeeping (profile preferences, etc.)
        connectionManager.onVpnEstablished()

        // Tag the Connected state with chain info so the UI can highlight the chain
        if (currentChainId > 0) {
            val current = vpnRepository.connectionState.value
            if (current is ConnectionState.Connected) {
                vpnRepository.updateConnectionState(
                    current.copy(chainId = currentChainId, chainName = currentProfileName)
                )
            }
        }

        // Save connection state for auto-restart if killed by system
        saveConnectionState(currentProfileId, connected = true)

        // Start HTTP proxy if enabled (chains through existing SOCKS5 proxy).
        // Skip if already running (started earlier by establishVpnInterface for VPN append).
        serviceScope.launch {
            try {
                if (!HttpProxyServer.isRunning()) {
                    val httpEnabled = preferencesDataStore.httpProxyEnabled.first()
                    if (httpEnabled) {
                        val httpPort = preferencesDataStore.httpProxyPort.first()
                        val listenHost = preferencesDataStore.proxyListenAddress.first()
                        val socksPort = preferencesDataStore.proxyListenPort.first()
                        val result = HttpProxyServer.start(
                            socksHost = "127.0.0.1",
                            socksPort = socksPort,
                            listenHost = listenHost,
                            listenPort = httpPort
                        )
                        if (result.isFailure) {
                            Log.w(TAG, "HTTP proxy failed to start: ${result.exceptionOrNull()?.message}")
                        }
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Error starting HTTP proxy: ${e.message}")
            }
        }

        // Start health monitoring and network change detection
        startHealthCheck()
        registerNetworkCallback()
        registerDozeReceiver()

        // Tell Android which physical networks the VPN uses for seamless failover
        updateUnderlyingNetworks()

        // Update notification to connected state
        observeConnectionState()
    }

    /**
     * Wait for the QUIC connection to be established (handshake complete).
     * This ensures the tunnel is fully ready before routing traffic through it.
     */
    private suspend fun waitForQuicReady(maxAttempts: Int, delayMs: Long): Boolean {
        Log.d(TAG, "Waiting for QUIC connection to be ready (max ${maxAttempts * delayMs}ms)")

        return kotlinx.coroutines.withContext(Dispatchers.IO) {
            repeat(maxAttempts) { attempt ->
                // Check if native client is still running
                val nativeRunning = try {
                    SlipstreamBridge.isNativeRunning()
                } catch (e: Exception) {
                    Log.e(TAG, "Error checking native state: ${e.message}")
                    true // Assume it's running if we can't check
                }

                if (!nativeRunning) {
                    Log.e(TAG, "Native client stopped while waiting for QUIC (attempt ${attempt + 1})")
                    return@withContext false
                }

                // Check if QUIC is ready
                val quicReady = try {
                    SlipstreamBridge.isQuicReady()
                } catch (e: Exception) {
                    Log.e(TAG, "Error checking QUIC ready state: ${e.message}")
                    false
                }

                if (quicReady) {
                    Log.i(TAG, "QUIC connection ready after ${attempt + 1} attempts (${(attempt + 1) * delayMs}ms)")
                    return@withContext true
                }

                if (attempt % 10 == 0) {
                    Log.d(TAG, "QUIC not ready yet (attempt ${attempt + 1})")
                }

                if (attempt < maxAttempts - 1) {
                    Thread.sleep(delayMs)
                }
            }

            Log.w(TAG, "QUIC connection not ready after $maxAttempts attempts (${maxAttempts * delayMs}ms)")
            false
        }
    }

    /**
     * Probes the DNSTT/NoizDNS transport by opening a raw TCP connection and waiting for
     * the first byte from the remote end (SSH server banner).
     *
     * DNSTT is a raw TCP forwarder: it carries data through DNS queries (upload) and
     * DNS responses (download). Receiving any byte from the SSH server proves that
     * DNS responses are actually reaching this device — i.e., the transport is
     * bidirectional. A timeout here means DNS responses are being filtered or dropped
     * by the network, and the subsequent SSH connect would also fail after 30 s while
     * generating ~75 MB of upload from QUIC retransmissions.
     *
     * Exception handling:
     *  - SocketTimeoutException → probe window elapsed, DNS responses blocked → false
     *  - SocketException (reset, broken pipe) → DNSTT dropped the connection, DNS likely broken → false
     *  - ConnectException → DNSTT port unreachable (should not happen after waitForProxyReady) → fail open (true)
     *  - Any other exception → unexpected, fail open so SSH can surface a more specific error
     */
    private fun probeDnsttTransport(host: String, port: Int, timeoutMs: Int): Boolean {
        Log.i(TAG, "DNSTT transport probe: $host:$port timeout=${timeoutMs}ms")
        val socket = java.net.Socket()
        return try {
            socket.connect(java.net.InetSocketAddress(host, port), timeoutMs)
            socket.soTimeout = timeoutMs
            val b = socket.getInputStream().read()
            val ok = b != -1
            Log.i(TAG, "DNSTT transport probe: ${if (ok) "data received — transport OK" else "EOF from server"}")
            ok
        } catch (e: java.net.SocketTimeoutException) {
            Log.w(TAG, "DNSTT transport probe: timed out after ${timeoutMs}ms — DNS responses likely filtered")
            false
        } catch (e: java.net.ConnectException) {
            // Port not reachable — DNSTT may not be bound yet despite waitForProxyReady;
            // fail open so SSH surfaces a more specific error.
            Log.w(TAG, "DNSTT transport probe: connect exception (failing open): ${e.message}")
            true
        } catch (e: java.net.SocketException) {
            // Connection reset or broken pipe: DNSTT accepted the connection but dropped
            // it, most likely because the DNS tunnel is not responding.
            Log.w(TAG, "DNSTT transport probe: socket exception — ${e.message}")
            false
        } catch (e: Exception) {
            // Unexpected error (security policy, OOM, etc.) — fail open.
            Log.w(TAG, "DNSTT transport probe: unexpected error (failing open): ${e.message}")
            true
        } finally {
            try { socket.close() } catch (_: Exception) {}
        }
    }

    /**
     * Wait for the SOCKS5 proxy to be ready by checking if the port is listening.
     */
    private suspend fun waitForProxyReady(port: Int, maxAttempts: Int, delayMs: Long): Boolean {
        Log.d(TAG, "Waiting for proxy to be ready on port $port (max ${maxAttempts * delayMs}ms, type=$currentTunnelType)")

        return kotlinx.coroutines.withContext(Dispatchers.IO) {
            repeat(maxAttempts) { attempt ->
                // Check if native client is still running based on tunnel type
                val nativeRunning = when (currentTunnelType) {
                    TunnelType.SLIPSTREAM -> try {
                        SlipstreamBridge.isNativeRunning()
                    } catch (e: Exception) {
                        Log.e(TAG, "Error checking Slipstream native state: ${e.message}")
                        true // Assume it's running if we can't check
                    }
                    TunnelType.SLIPSTREAM_SSH -> try {
                        SlipstreamBridge.isNativeRunning()
                    } catch (e: Exception) {
                        Log.e(TAG, "Error checking Slipstream native state: ${e.message}")
                        true
                    }
                    TunnelType.DNSTT -> try {
                        DnsttBridge.isRunning()
                    } catch (e: Exception) {
                        Log.e(TAG, "Error checking DNSTT state: ${e.message}")
                        true // Assume it's running if we can't check
                    }
                    TunnelType.NOIZDNS -> try {
                        DnsttBridge.isRunning()
                    } catch (e: Exception) {
                        Log.e(TAG, "Error checking NoizDNS state: ${e.message}")
                        true
                    }
                    TunnelType.SSH -> {
                        // Check default instance or any chain instance
                        SshTunnelBridge.isRunning() || (0..3).any {
                            SshTunnelBridge.getInstance("chain-ssh-$it")?.isRunning() == true
                        }
                    }
                    TunnelType.DNSTT_SSH -> try {
                        DnsttBridge.isRunning()
                    } catch (e: Exception) {
                        Log.e(TAG, "Error checking DNSTT state: ${e.message}")
                        true
                    }
                    TunnelType.NOIZDNS_SSH -> try {
                        DnsttBridge.isRunning()
                    } catch (e: Exception) {
                        Log.e(TAG, "Error checking NoizDNS state: ${e.message}")
                        true
                    }
                    TunnelType.DOH -> DohBridge.isRunning()
                    TunnelType.NAIVE_SSH -> NaiveBridge.isRunning()
                    TunnelType.NAIVE -> NaiveBridge.isRunning()
                    TunnelType.SNOWFLAKE -> SnowflakeBridge.isRunning()
                    TunnelType.SOCKS5 -> {
                        Socks5ProxyBridge.isRunning() || (0..3).any {
                            Socks5ProxyBridge.getInstance("chain-socks5-$it")?.isRunning() == true
                        }
                    }
                }

                if (!nativeRunning) {
                    Log.e(TAG, "Native client stopped during startup (attempt ${attempt + 1}, type=$currentTunnelType)")
                    return@withContext false
                }

                try {
                    java.net.Socket().use { socket ->
                        socket.connect(java.net.InetSocketAddress("127.0.0.1", port), 200)
                        Log.i(TAG, "Proxy ready on port $port after ${attempt + 1} attempts (${(attempt + 1) * delayMs}ms)")
                        return@withContext true
                    }
                } catch (e: java.net.ConnectException) {
                    // Connection refused - port not listening yet
                    if (attempt % 10 == 0) {
                        Log.d(TAG, "Proxy not ready yet (attempt ${attempt + 1}): connection refused")
                    }
                } catch (e: java.net.SocketTimeoutException) {
                    // Timeout - port might be in weird state
                    Log.d(TAG, "Proxy not ready yet (attempt ${attempt + 1}): timeout")
                } catch (e: Exception) {
                    Log.d(TAG, "Proxy not ready yet (attempt ${attempt + 1}): ${e.javaClass.simpleName} - ${e.message}")
                }

                if (attempt < maxAttempts - 1) {
                    Thread.sleep(delayMs)
                }
            }

            Log.e(TAG, "Proxy failed to become ready after $maxAttempts attempts (${maxAttempts * delayMs}ms)")
            false
        }
    }

    /**
     * Wait for NaiveProxy to report readiness via its "Listening on" log line.
     * Unlike waitForProxyReady (which opens a TCP connection), this checks the
     * NaiveBridge.isReady flag set by the output reader thread. This avoids
     * sending a non-SOCKS5 probe that causes ERR_SOCKS_CONNECTION_FAILED noise.
     */
    private suspend fun waitForNaiveReady(maxAttempts: Int = 30, delayMs: Long = 200): Boolean {
        Log.d(TAG, "Waiting for NaiveProxy to become ready (max ${maxAttempts * delayMs}ms)")
        return kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            repeat(maxAttempts) { attempt ->
                if (!NaiveBridge.isRunning()) {
                    Log.e(TAG, "NaiveProxy process died during startup (attempt ${attempt + 1})")
                    return@withContext false
                }
                if (NaiveBridge.isReady) {
                    Log.i(TAG, "NaiveProxy ready after ${attempt + 1} attempts (${(attempt + 1) * delayMs}ms)")
                    return@withContext true
                }
                if (attempt < maxAttempts - 1) {
                    Thread.sleep(delayMs)
                }
            }
            Log.e(TAG, "NaiveProxy failed to become ready after $maxAttempts attempts")
            false
        }
    }

    /**
     * Start periodic health check to detect if the Rust client has crashed
     * or if the connection has become stale.
     */
    private fun startHealthCheck() {
        healthCheckJob?.cancel()
        quicDownChecks = 0
        healthCheckCount = 0
        dnsPoolDeadChecks = 0
        dnsPoolDeadNotified = false
        tunnelStallChecks = 0
        lastTxBytes = 0L
        lastRxBytes = 0L
        seamlessReconnectAttempts = 0  // Reset on successful reconnection
        healthCheckJob = serviceScope.launch(Dispatchers.IO) {
            // Give the connection time to establish before monitoring
            delay(10_000L)

            while (isActive) {
                delay(HEALTH_CHECK_INTERVAL_MS)
                healthCheckCount++

                // Check if both native clients are still running and healthy
                val proxyHealthy = isCurrentProxyHealthy()
                val tunnelRunning = if (isProxyOnly) true else HevSocks5Tunnel.isRunning()

                if (!proxyHealthy || !tunnelRunning) {
                    Log.e(TAG, "Health check failed: proxy=$proxyHealthy (type=$currentTunnelType), tunnel=$tunnelRunning")
                    launch(Dispatchers.Main) {
                        handleTunnelFailure("health check failed")
                    }
                    break
                }

                // For Slipstream types: check if QUIC connection is alive.
                if (currentTunnelType == TunnelType.SLIPSTREAM || currentTunnelType == TunnelType.SLIPSTREAM_SSH) {
                    if (SlipstreamBridge.isQuicReady()) {
                        if (quicDownChecks > 0) {
                            Log.i(TAG, "QUIC connection recovered after $quicDownChecks checks")
                        }
                        quicDownChecks = 0
                    } else {
                        quicDownChecks++
                        Log.w(TAG, "QUIC not ready ($quicDownChecks/${QUIC_DOWN_THRESHOLD})")
                        if (quicDownChecks >= QUIC_DOWN_THRESHOLD) {
                            Log.e(TAG, "QUIC connection dead for ${quicDownChecks * HEALTH_CHECK_INTERVAL_MS}ms, triggering reconnect")
                            quicDownChecks = 0
                            launch(Dispatchers.Main) {
                                handleTunnelFailure("QUIC connection lost")
                            }
                            break
                        }
                    }
                }

                // For SSH-based tunnels: actively probe the SSH session every ~30s.
                val usesSsh = currentTunnelType == TunnelType.SSH ||
                        currentTunnelType == TunnelType.DNSTT_SSH ||
                        currentTunnelType == TunnelType.NOIZDNS_SSH ||
                        currentTunnelType == TunnelType.SLIPSTREAM_SSH ||
                        currentTunnelType == TunnelType.NAIVE_SSH
                if (usesSsh && healthCheckCount % SSH_PROBE_INTERVAL == 0) {
                    val alive = SshTunnelBridge.probeSessionAlive()
                    if (!alive) {
                        Log.e(TAG, "SSH session probe failed — session is dead")
                        launch(Dispatchers.Main) {
                            handleTunnelFailure("SSH session unresponsive")
                        }
                        break
                    }
                }

                // For tunnels with DNS worker pools: warn when all workers are dead.
                // In proxy-only mode, DNS workers are unused (apps resolve DNS via CONNECT),
                // so skip this check to avoid false warnings.
                val dnsPoolDead = if (isProxyOnly) false else when (currentTunnelType) {
                    TunnelType.DNSTT, TunnelType.NOIZDNS -> DnsttSocksBridge.isDnsPoolDead()
                    TunnelType.SLIPSTREAM -> SlipstreamSocksBridge.isDnsPoolDead()
                    TunnelType.NAIVE -> NaiveSocksBridge.isDnsPoolDead()
                    TunnelType.SSH, TunnelType.DNSTT_SSH, TunnelType.NOIZDNS_SSH,
                    TunnelType.SLIPSTREAM_SSH, TunnelType.NAIVE_SSH -> SshTunnelBridge.isDnsPoolDead()
                    else -> false
                }
                if (dnsPoolDead) {
                    dnsPoolDeadChecks++
                    val isDnsTunneled = currentTunnelType in listOf(
                        TunnelType.DNSTT, TunnelType.DNSTT_SSH,
                        TunnelType.NOIZDNS, TunnelType.NOIZDNS_SSH,
                        TunnelType.SLIPSTREAM, TunnelType.SLIPSTREAM_SSH
                    )
                    val threshold = if (isDnsTunneled) DNS_POOL_DEAD_THRESHOLD else DNS_POOL_DEAD_THRESHOLD_SOCKS
                    if (dnsPoolDeadChecks >= threshold && !dnsPoolDeadNotified) {
                        Log.w(TAG, "All DNS workers dead for ${dnsPoolDeadChecks * HEALTH_CHECK_INTERVAL_MS / 1000}s")
                        dnsPoolDeadNotified = true
                        connectionManager.setDnsWarning("Connection is not working. Try different dns resolver or switching profiles.")
                    }
                } else {
                    if (dnsPoolDeadNotified) {
                        Log.i(TAG, "DNS workers recovered")
                        connectionManager.setDnsWarning(null)
                    }
                    dnsPoolDeadChecks = 0
                    dnsPoolDeadNotified = false
                }

                // Traffic stall detection: if VPN is forwarding outgoing packets but
                // getting nothing back, the tunnel is dead (connected but can't transfer data).
                val isDnsTunneledStall = currentTunnelType in listOf(
                    TunnelType.DNSTT, TunnelType.DNSTT_SSH,
                    TunnelType.NOIZDNS, TunnelType.NOIZDNS_SSH,
                    TunnelType.SLIPSTREAM, TunnelType.SLIPSTREAM_SSH
                )
                val stallCheckInterval = if (isDnsTunneledStall) TUNNEL_STALL_CHECK_INTERVAL else TUNNEL_STALL_CHECK_INTERVAL_SOCKS
                val stallThreshold = if (isDnsTunneledStall) TUNNEL_STALL_THRESHOLD else TUNNEL_STALL_THRESHOLD_SOCKS
                if (!isProxyOnly && healthCheckCount % stallCheckInterval == 0) {
                    val stats = HevSocks5Tunnel.getStats()
                    if (stats != null) {
                        val txIncreased = stats.txBytes > lastTxBytes
                        val rxIncreased = stats.rxBytes > lastRxBytes

                        if (txIncreased && !rxIncreased) {
                            tunnelStallChecks++
                            Log.w(TAG, "Tunnel stall detected ($tunnelStallChecks/$stallThreshold): tx flowing but no rx")
                            if (tunnelStallChecks >= stallThreshold) {
                                Log.e(TAG, "Tunnel stalled — data sent but no response for ~${tunnelStallChecks * stallCheckInterval * HEALTH_CHECK_INTERVAL_MS / 1000}s")
                                tunnelStallChecks = 0
                                launch(Dispatchers.Main) {
                                    handleTunnelFailure("tunnel not responding")
                                }
                                break
                            }
                        } else {
                            if (tunnelStallChecks > 0) {
                                Log.i(TAG, "Tunnel stall recovered after $tunnelStallChecks checks")
                            }
                            tunnelStallChecks = 0
                        }

                        lastTxBytes = stats.txBytes
                        lastRxBytes = stats.rxBytes
                    }
                }

            }
        }
    }

    /**
     * Update the VPN's underlying networks for seamless handover.
     * Tells Android which physical networks the VPN uses, enabling
     * automatic failover during WiFi↔cellular switches without full reconnection.
     */
    @Suppress("DEPRECATION")
    private fun updateUnderlyingNetworks() {
        try {
            val cm = connectivityManager ?: return
            val networks = cm.allNetworks
                .mapNotNull { network ->
                    val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
                    if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
                        network
                    } else null
                }
                .sortedByDescending { network ->
                    val caps = cm.getNetworkCapabilities(network)
                    when {
                        caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> 3
                        caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> 2
                        caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> 1
                        else -> 0
                    }
                }
                .toTypedArray()

            setUnderlyingNetworks(if (networks.isNotEmpty()) networks else null)
            Log.d(TAG, "Updated underlying networks: ${networks.size} available")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to update underlying networks", e)
        }
    }

    /**
     * Register a BroadcastReceiver to detect when the device exits Doze mode.
     * Doze suspends network access — when it lifts, connections may be stale
     * and need immediate refresh.
     */
    private fun registerDozeReceiver() {
        if (dozeReceiver != null) return
        dozeReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
                if (pm.isDeviceIdleMode) {
                    Log.d(TAG, "Device entered Doze mode")
                } else {
                    Log.i(TAG, "Device exited Doze mode — checking connection health")
                    // Update underlying networks immediately (network state may have changed in Doze)
                    updateUnderlyingNetworks()
                    // Debounced reconnect to refresh stale connections
                    debouncedReconnect("doze mode exit")
                }
            }
        }
        @Suppress("UnspecifiedRegisterReceiverFlag")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(dozeReceiver, IntentFilter(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED), Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(dozeReceiver, IntentFilter(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED))
        }
        Log.d(TAG, "Doze mode receiver registered")
    }

    private fun unregisterDozeReceiver() {
        dozeReceiver?.let {
            try {
                unregisterReceiver(it)
                Log.d(TAG, "Doze mode receiver unregistered")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to unregister Doze receiver", e)
            }
        }
        dozeReceiver = null
    }

    /**
     * Register for network connectivity changes to detect when we need to reconnect.
     */
    private fun registerNetworkCallback() {
        unregisterNetworkCallback() // Clean up any existing callback

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            private var currentNetwork: Network? = null
            // Ignore onAvailable calls for 2s after registration to let all
            // initial callbacks settle (WiFi + cellular fire back-to-back)
            private val registeredAt = System.currentTimeMillis()
            private val quietPeriodMs = 2000L

            override fun onAvailable(network: Network) {
                Log.d(TAG, "Network available: $network")
                // A network arrived — cancel any pending "no network" disconnect
                networkLostJob?.cancel()
                networkLostJob = null

                // Always update underlying networks so the VPN can use the new network
                updateUnderlyingNetworks()

                if (System.currentTimeMillis() - registeredAt < quietPeriodMs) {
                    Log.d(TAG, "Initial network detected: $network (quiet period, no reconnection)")
                    currentNetwork = network
                    updateTrackedAddresses(network)
                    return
                }
                if (currentNetwork == null) {
                    Log.i(TAG, "Network restored: $network, triggering reconnection")
                    debouncedReconnect("network restored")
                } else if (currentNetwork != network) {
                    Log.i(TAG, "Network changed from $currentNetwork to $network, triggering reconnection")
                    debouncedReconnect("network change")
                }
                currentNetwork = network
                // Update tracked addresses for new network
                updateTrackedAddresses(network)
            }

            override fun onLost(network: Network) {
                Log.d(TAG, "Network lost: $network")
                // Update underlying networks to remove the lost network
                updateUnderlyingNetworks()

                if (network == currentNetwork) {
                    currentNetwork = null
                    lastNetworkAddresses = emptySet()
                    lastNetworkDnsServers = emptySet()

                    // Wait briefly for a replacement network (e.g. WiFi → cellular handoff).
                    // If no network arrives within the window, treat as full connectivity loss.
                    networkLostJob?.cancel()
                    networkLostJob = serviceScope.launch {
                        delay(3000)
                        Log.w(TAG, "No network available after loss of $network — reporting tunnel failure")
                        handleTunnelFailure("network lost")
                    }
                }
            }

            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                // Network capabilities changed - check if we still have internet
                val hasInternet = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                Log.d(TAG, "Network capabilities changed: $network, hasInternet=$hasInternet")
                // Refresh underlying networks (capabilities like VALIDATED may have changed)
                updateUnderlyingNetworks()
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                // Link properties changed - check for IP address and DNS server changes
                val newAddresses = linkProperties.linkAddresses
                    .mapNotNull { it.address?.hostAddress }
                    .toSet()

                val newDnsServers = linkProperties.dnsServers
                    .mapNotNull { it.hostAddress }
                    .toSet()

                Log.d(TAG, "Link properties changed: $network, addresses=$newAddresses, dns=$newDnsServers")

                // Skip change detection during quiet period
                if (System.currentTimeMillis() - registeredAt < quietPeriodMs) {
                    lastNetworkAddresses = newAddresses
                    lastNetworkDnsServers = newDnsServers
                    return
                }

                // If IP addresses changed, we need to reconnect
                if (lastNetworkAddresses.isNotEmpty() && newAddresses != lastNetworkAddresses) {
                    val added = newAddresses - lastNetworkAddresses
                    val removed = lastNetworkAddresses - newAddresses
                    Log.i(TAG, "IP addresses changed: added=$added, removed=$removed")
                    debouncedReconnect("IP address change")
                }
                // If DNS servers changed (common during WiFi↔cellular handoff), reconnect
                else if (lastNetworkDnsServers.isNotEmpty() && newDnsServers != lastNetworkDnsServers) {
                    Log.i(TAG, "DNS servers changed: ${lastNetworkDnsServers} → $newDnsServers")
                    debouncedReconnect("DNS server change")
                }
                lastNetworkAddresses = newAddresses
                lastNetworkDnsServers = newDnsServers
            }

            private fun updateTrackedAddresses(network: Network) {
                try {
                    val linkProps = connectivityManager?.getLinkProperties(network)
                    lastNetworkAddresses = linkProps?.linkAddresses
                        ?.mapNotNull { it.address?.hostAddress }
                        ?.toSet() ?: emptySet()
                    lastNetworkDnsServers = linkProps?.dnsServers
                        ?.mapNotNull { it.hostAddress }
                        ?.toSet() ?: emptySet()
                    Log.d(TAG, "Updated tracked addresses: $lastNetworkAddresses, dns: $lastNetworkDnsServers")
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to get link properties", e)
                }
            }
        }

        try {
            connectivityManager?.registerNetworkCallback(request, networkCallback!!)
            Log.d(TAG, "Network callback registered")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to register network callback", e)
        }
    }

    private fun unregisterNetworkCallback() {
        networkCallback?.let { callback ->
            try {
                connectivityManager?.unregisterNetworkCallback(callback)
                Log.d(TAG, "Network callback unregistered")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to unregister network callback", e)
            }
        }
        networkCallback = null
    }

    /**
     * Debounced reconnection to avoid thrashing on rapid network changes.
     * Waits 2s before triggering reconnection in case more changes come in.
     */
    private fun debouncedReconnect(reason: String) {
        // A reconnect supersedes any pending "network lost" disconnect
        networkLostJob?.cancel()
        networkLostJob = null
        reconnectDebounceJob?.cancel()
        reconnectDebounceJob = serviceScope.launch {
            Log.d(TAG, "Debouncing reconnect for: $reason")
            delay(2000) // Wait 2s for network to stabilize
            handleNetworkChange(reason)
        }
    }

    /**
     * Handle network change by restarting the tunnel connection.
     * Keeps HevSocks5Tunnel (tun2socks) running during the proxy restart to minimize
     * the traffic gap. The TUN interface stays alive and tun2socks buffers/retries
     * connections until the new proxy is ready.
     */
    private fun handleNetworkChange(reason: String = "unknown") {
        serviceScope.launch {
            // Ignore spurious network changes fired shortly after connection.
            // Chinese OEM ROMs (MIUI/HyperOS, EMUI) trigger network callbacks
            // when the VPN interface is first created, causing the proxy to be
            // torn down before any data flows. Skip unless this is a tunnel
            // recovery (seamless reconnect), which must always proceed.
            if (!reason.startsWith("tunnel recovery") && connectionEstablishedAt > 0) {
                val elapsed = System.currentTimeMillis() - connectionEstablishedAt
                if (elapsed < NETWORK_CHANGE_GRACE_MS) {
                    Log.d(TAG, "Ignoring network change '$reason' — ${elapsed}ms after connection (grace period ${NETWORK_CHANGE_GRACE_MS}ms)")
                    return@launch
                }
            }

            // Prevent concurrent reconnection attempts
            if (isReconnecting) {
                Log.d(TAG, "Skipping reconnection for '$reason' - already reconnecting")
                return@launch
            }
            isReconnecting = true

            try {
                Log.i(TAG, "Handling network change ($reason) - restarting connection")

                // Update underlying networks immediately for the new network
                updateUnderlyingNetworks()

                // Stop health check during reconnection
                healthCheckJob?.cancel()

                // Get the current profile
                val profile = connectionManager.getProfileById(currentProfileId)
                if (profile == null) {
                    Log.e(TAG, "Cannot reconnect: profile not found")
                    return@launch
                }

                // Save chain state before stopCurrentProxy clears it
                val savedChainId = currentChainId
                val wasChain = activeChainLayers.isNotEmpty()

                // Stop proxy on IO but keep HevSocks5Tunnel (tun2socks) running.
                // The TUN interface stays alive and tun2socks will retry connections
                // once the new proxy is ready, minimizing the traffic interruption gap.
                withContext(Dispatchers.IO) {
                    stopCurrentProxy()
                }

                // Chain reconnection: re-execute the full chain.
                // Chains rebuild the VPN interface, so stop tun2socks first.
                if (wasChain && savedChainId > 0) {
                    if (!isProxyOnly) {
                        withContext(Dispatchers.IO) {
                            try { HevSocks5Tunnel.stop() } catch (_: Exception) {}
                        }
                    }
                    Log.i(TAG, "Reconnecting chain $savedChainId after network change")
                    val chain = chainRepository.getChainById(savedChainId)
                    if (chain == null) {
                        Log.e(TAG, "Cannot reconnect chain: chain not found")
                        handleTunnelFailure("chain not found during reconnect")
                        return@launch
                    }
                    val chainProfiles = chain.profileIds.mapNotNull { connectionManager.getProfileById(it) }
                    if (chainProfiles.size != chain.profileIds.size) {
                        Log.e(TAG, "Cannot reconnect chain: some profiles were deleted")
                        handleTunnelFailure("chain profiles missing during reconnect")
                        return@launch
                    }
                    currentChainId = savedChainId
                    executeChain(chainProfiles)
                    Log.i(TAG, "Chain reconnected successfully after network change")
                    return@launch
                }

                // For DNSTT-based tunnels, explicitly wait for the Go runtime to
                // fully release the port.  stopCurrentProxy() already waits inside
                // DnsttBridge.stopClient(), but we add an extra coroutine-friendly
                // check here to be safe — this avoids spawning a second DNSTT
                // instance on a fallback port (which caused massive upload leaks).
                val isDnstt = currentTunnelType in listOf(
                    TunnelType.DNSTT, TunnelType.DNSTT_SSH,
                    TunnelType.NOIZDNS, TunnelType.NOIZDNS_SSH
                )
                if (isDnstt) {
                    DnsttBridge.stopClientBlocking()  // no-op if already stopped, but ensures port is released
                }

                val proxyPort = preferencesDataStore.proxyListenPort.first()
                val proxyHost = preferencesDataStore.proxyListenAddress.first()
                var remoteDns = preferencesDataStore.getEffectiveRemoteDns().first()
                var remoteDnsFallback = preferencesDataStore.getEffectiveRemoteDnsFallback().first()

                // DNSTT+SSH / NoizDNS+SSH: default to server's local resolver (same override as initial connect)
                if (currentTunnelType == TunnelType.DNSTT_SSH || currentTunnelType == TunnelType.NOIZDNS_SSH) {
                    val dnsMode = preferencesDataStore.remoteDnsMode.first()
                    if (dnsMode == "default") {
                        remoteDns = "127.0.0.53"
                        remoteDnsFallback = "8.8.8.8"
                    }
                }

                // Restart the appropriate proxy
                if (currentTunnelType == TunnelType.SSH) {
                    // SSH-only: restart SSH tunnel directly
                    configureSshBridge()
                    val sshResult = withContext(Dispatchers.IO) {
                        SshTunnelBridge.startDirect(
                            tunnelHost = profile.domain,
                            tunnelPort = profile.sshPort,
                            sshUsername = profile.sshUsername,
                            sshPassword = profile.sshPassword,
                            listenPort = proxyPort,
                            listenHost = proxyHost,
                            forwardDnsThroughSsh = true,
                            sshAuthType = profile.sshAuthType,
                            sshPrivateKey = profile.sshPrivateKey,
                            sshKeyPassphrase = profile.sshKeyPassphrase,
                            remoteDnsHost = remoteDns,
                            remoteDnsFallback = remoteDnsFallback
                        )
                    }
                    if (sshResult.isFailure) {
                        Log.e(TAG, "Failed to restart SSH tunnel after network change", sshResult.exceptionOrNull())
                        handleTunnelFailure("failed to reconnect SSH after network change")
                        return@launch
                    }

                    // Wait for SSH SOCKS5 proxy to be ready
                    if (!waitForProxyReady(proxyPort, maxAttempts = 30, delayMs = 50)) {
                        Log.e(TAG, "SSH SOCKS5 proxy failed to restart")
                        handleTunnelFailure("failed to reconnect SSH after network change")
                        return@launch
                    }
                } else if (currentTunnelType == TunnelType.DNSTT_SSH || currentTunnelType == TunnelType.NOIZDNS_SSH) {
                    // DNSTT+SSH / NoizDNS+SSH: restart tunnel on internal port, then SSH on proxyPort
                    val dnsttPort = proxyPort + 1
                    val isNoizdns = currentTunnelType == TunnelType.NOIZDNS_SSH

                    val dnsttResult = if (isNoizdns) {
                        vpnRepository.startNoizdnsProxy(profile, portOverride = dnsttPort, hostOverride = "127.0.0.1")
                    } else {
                        vpnRepository.startDnsttProxy(profile, portOverride = dnsttPort, hostOverride = "127.0.0.1")
                    }
                    if (dnsttResult.isFailure) {
                        Log.e(TAG, "Failed to restart ${if (isNoizdns) "NoizDNS" else "DNSTT"} after network change", dnsttResult.exceptionOrNull())
                        handleTunnelFailure("failed to reconnect ${if (isNoizdns) "NoizDNS" else "DNSTT"}+SSH after network change")
                        return@launch
                    }

                    val actualDnsttPort = DnsttBridge.getClientPort()

                    if (!waitForProxyReady(actualDnsttPort, maxAttempts = 20, delayMs = 50)) {
                        Log.e(TAG, "${if (isNoizdns) "NoizDNS" else "DNSTT"} proxy failed to restart")
                        handleTunnelFailure("failed to reconnect ${if (isNoizdns) "NoizDNS" else "DNSTT"}+SSH after network change")
                        return@launch
                    }

                    vpnRepository.setCurrentTunnelType(currentTunnelType!!)

                    // Connect SSH directly through the tunnel's local port
                    configureSshBridge()
                    val sshResult = withContext(Dispatchers.IO) {
                        SshTunnelBridge.startOverProxy(
                            sshHost = profile.sshHost,
                            sshPort = profile.sshPort,
                            sshUsername = profile.sshUsername,
                            sshPassword = profile.sshPassword,
                            proxyHost = "127.0.0.1",
                            proxyPort = actualDnsttPort,
                            listenPort = proxyPort,
                            listenHost = proxyHost,
                            blockDirectDns = true,
                            sshAuthType = profile.sshAuthType,
                            sshPrivateKey = profile.sshPrivateKey,
                            sshKeyPassphrase = profile.sshKeyPassphrase,
                            remoteDnsHost = remoteDns,
                            remoteDnsFallback = remoteDnsFallback
                        )
                    }
                    if (sshResult.isFailure) {
                        Log.e(TAG, "Failed to restart SSH over ${if (isNoizdns) "NoizDNS" else "DNSTT"} after network change", sshResult.exceptionOrNull())
                        handleTunnelFailure("failed to reconnect ${if (isNoizdns) "NoizDNS" else "DNSTT"}+SSH after network change")
                        return@launch
                    }

                    if (!waitForProxyReady(proxyPort, maxAttempts = 30, delayMs = 50)) {
                        Log.e(TAG, "SSH SOCKS5 proxy failed to restart on port $proxyPort")
                        handleTunnelFailure("failed to reconnect ${if (isNoizdns) "NoizDNS" else "DNSTT"}+SSH after network change")
                        return@launch
                    }
                } else if (currentTunnelType == TunnelType.SLIPSTREAM_SSH) {
                    // Slipstream+SSH: restart Slipstream on internal port, wait QUIC, then SSH on proxyPort
                    val slipstreamPort = proxyPort + 1

                    val slipResult = vpnRepository.startSlipstreamProxy(profile, portOverride = slipstreamPort, hostOverride = "127.0.0.1")
                    if (slipResult.isFailure) {
                        Log.e(TAG, "Failed to restart Slipstream after network change", slipResult.exceptionOrNull())
                        handleTunnelFailure("failed to reconnect Slipstream+SSH after network change")
                        return@launch
                    }

                    val actualSlipstreamPort = SlipstreamBridge.getClientPort()

                    if (!waitForProxyReady(actualSlipstreamPort, maxAttempts = 20, delayMs = 50)) {
                        Log.e(TAG, "Slipstream proxy failed to restart")
                        handleTunnelFailure("failed to reconnect Slipstream+SSH after network change")
                        return@launch
                    }

                    val quicReady = waitForQuicReady(maxAttempts = 50, delayMs = 100)
                    if (!quicReady) {
                        Log.w(TAG, "QUIC connection not ready after reconnect, continuing anyway")
                    }

                    vpnRepository.setCurrentTunnelType(TunnelType.SLIPSTREAM_SSH)

                    configureSshBridge()
                    val sshResult = withContext(Dispatchers.IO) {
                        SshTunnelBridge.startOverProxy(
                            sshHost = profile.sshHost,
                            sshPort = profile.sshPort,
                            sshUsername = profile.sshUsername,
                            sshPassword = profile.sshPassword,
                            proxyHost = "127.0.0.1",
                            proxyPort = actualSlipstreamPort,
                            listenPort = proxyPort,
                            listenHost = proxyHost,
                            blockDirectDns = true,
                            sshAuthType = profile.sshAuthType,
                            sshPrivateKey = profile.sshPrivateKey,
                            sshKeyPassphrase = profile.sshKeyPassphrase,
                            remoteDnsHost = remoteDns,
                            remoteDnsFallback = remoteDnsFallback
                        )
                    }
                    if (sshResult.isFailure) {
                        Log.e(TAG, "Failed to restart SSH over Slipstream after network change", sshResult.exceptionOrNull())
                        handleTunnelFailure("failed to reconnect Slipstream+SSH after network change")
                        return@launch
                    }

                    if (!waitForProxyReady(proxyPort, maxAttempts = 30, delayMs = 50)) {
                        Log.e(TAG, "SSH SOCKS5 proxy failed to restart on port $proxyPort")
                        handleTunnelFailure("failed to reconnect Slipstream+SSH after network change")
                        return@launch
                    }
                } else if (currentTunnelType == TunnelType.SLIPSTREAM) {
                    // Slipstream: restart proxy on internal port + bridge on proxyPort
                    val slipstreamPort = proxyPort + 1

                    val slipResult = vpnRepository.startSlipstreamProxy(profile, portOverride = slipstreamPort, hostOverride = "127.0.0.1")
                    if (slipResult.isFailure) {
                        Log.e(TAG, "Failed to restart Slipstream after network change", slipResult.exceptionOrNull())
                        handleTunnelFailure("failed to reconnect Slipstream after network change")
                        return@launch
                    }

                    val actualSlipstreamPort = SlipstreamBridge.getClientPort()

                    if (!waitForProxyReady(actualSlipstreamPort, maxAttempts = 20, delayMs = 50)) {
                        Log.e(TAG, "Slipstream proxy failed to restart")
                        handleTunnelFailure("failed to reconnect Slipstream after network change")
                        return@launch
                    }

                    val quicReady = waitForQuicReady(maxAttempts = 50, delayMs = 100)
                    if (!quicReady) {
                        Log.w(TAG, "QUIC not ready after reconnect, continuing anyway")
                    }

                    // Restart bridge on proxyPort (with auth for Dante)
                    val bridgeResult = vpnRepository.startSlipstreamSocksBridge(
                        slipstreamPort = actualSlipstreamPort,
                        slipstreamHost = "127.0.0.1",
                        bridgePort = proxyPort,
                        bridgeHost = proxyHost,
                        socksUsername = profile.socksUsername,
                        socksPassword = profile.socksPassword
                    )
                    if (bridgeResult.isFailure) {
                        Log.e(TAG, "Failed to restart bridge after network change")
                        handleTunnelFailure("failed to reconnect after network change")
                        return@launch
                    }

                    if (!waitForProxyReady(proxyPort, maxAttempts = 20, delayMs = 50)) {
                        Log.e(TAG, "Bridge failed to restart on port $proxyPort")
                        handleTunnelFailure("failed to reconnect after network change")
                        return@launch
                    }
                } else if (currentTunnelType == TunnelType.DNSTT || currentTunnelType == TunnelType.NOIZDNS) {
                    // DNSTT / NoizDNS: restart tunnel on internal port + bridge on proxyPort
                    val dnsttPort = proxyPort + 1
                    val isNoizdns = currentTunnelType == TunnelType.NOIZDNS

                    val dnsttResult = if (isNoizdns) {
                        vpnRepository.startNoizdnsProxy(profile, portOverride = dnsttPort, hostOverride = "127.0.0.1")
                    } else {
                        vpnRepository.startDnsttProxy(profile, portOverride = dnsttPort, hostOverride = "127.0.0.1")
                    }
                    if (dnsttResult.isFailure) {
                        Log.e(TAG, "Failed to restart ${if (isNoizdns) "NoizDNS" else "DNSTT"} after network change", dnsttResult.exceptionOrNull())
                        handleTunnelFailure("failed to reconnect ${if (isNoizdns) "NoizDNS" else "DNSTT"} after network change")
                        return@launch
                    }

                    val actualDnsttPort = DnsttBridge.getClientPort()

                    if (!waitForProxyReady(actualDnsttPort, maxAttempts = 20, delayMs = 50)) {
                        Log.e(TAG, "${if (isNoizdns) "NoizDNS" else "DNSTT"} proxy failed to restart on port $actualDnsttPort")
                        handleTunnelFailure("failed to reconnect ${if (isNoizdns) "NoizDNS" else "DNSTT"} after network change")
                        return@launch
                    }

                    // Restart bridge on proxyPort (with auth for Dante)
                    DnsttSocksBridge.authoritativeMode = profile.dnsttAuthoritative
                    DnsttSocksBridge.proxyOnlyMode = isProxyOnly
                    val bridgeResult = vpnRepository.startDnsttSocksBridge(
                        dnsttPort = actualDnsttPort,
                        dnsttHost = "127.0.0.1",
                        bridgePort = proxyPort,
                        bridgeHost = proxyHost,
                        socksUsername = profile.socksUsername,
                        socksPassword = profile.socksPassword,
                        dnsServer = remoteDns,
                        dnsFallback = remoteDnsFallback
                    )
                    if (bridgeResult.isFailure) {
                        Log.e(TAG, "Failed to restart ${if (isNoizdns) "NoizDNS" else "DNSTT"} bridge after network change")
                        handleTunnelFailure("failed to reconnect ${if (isNoizdns) "NoizDNS" else "DNSTT"} after network change")
                        return@launch
                    }

                    if (!waitForProxyReady(proxyPort, maxAttempts = 20, delayMs = 50)) {
                        Log.e(TAG, "${if (isNoizdns) "NoizDNS" else "DNSTT"} bridge failed to restart on port $proxyPort")
                        handleTunnelFailure("failed to reconnect ${if (isNoizdns) "NoizDNS" else "DNSTT"} after network change")
                        return@launch
                    }
                } else if (currentTunnelType == TunnelType.NAIVE_SSH) {
                    // NaiveProxy+SSH: restart NaiveProxy on internal port, then SSH on proxyPort
                    val naivePort = proxyPort + 1

                    val naiveResult = withContext(Dispatchers.IO) {
                        NaiveBridge.start(
                            context = this@SlipNetVpnService,
                            listenPort = naivePort,
                            listenHost = "127.0.0.1",
                            serverHost = profile.domain,
                            serverPort = profile.naivePort,
                            username = profile.naiveUsername,
                            password = profile.naivePassword,
                                )
                    }
                    if (naiveResult.isFailure) {
                        Log.e(TAG, "Failed to restart NaiveProxy after network change", naiveResult.exceptionOrNull())
                        handleTunnelFailure("failed to reconnect NaiveProxy+SSH after network change")
                        return@launch
                    }

                    if (!waitForNaiveReady(maxAttempts = 30, delayMs = 200)) {
                        Log.e(TAG, "NaiveProxy failed to become ready after network change")
                        handleTunnelFailure("failed to reconnect NaiveProxy+SSH after network change")
                        return@launch
                    }

                    val naiveSshHost = if (profile.sshHost == "127.0.0.1" || profile.sshHost.isBlank()) {
                        profile.domain
                    } else {
                        profile.sshHost
                    }

                    configureSshBridge()
                    val sshResult = withContext(Dispatchers.IO) {
                        SshTunnelBridge.startOverSocks5Proxy(
                            sshHost = naiveSshHost,
                            sshPort = profile.sshPort,
                            sshUsername = profile.sshUsername,
                            sshPassword = profile.sshPassword,
                            proxyHost = "127.0.0.1",
                            proxyPort = naivePort,
                            socksUsername = null,
                            socksPassword = null,
                            listenPort = proxyPort,
                            listenHost = proxyHost,
                            sshAuthType = profile.sshAuthType,
                            sshPrivateKey = profile.sshPrivateKey,
                            sshKeyPassphrase = profile.sshKeyPassphrase,
                            remoteDnsHost = remoteDns,
                            remoteDnsFallback = remoteDnsFallback,
                            naiveMode = true
                        )
                    }
                    if (sshResult.isFailure) {
                        Log.e(TAG, "Failed to restart SSH over NaiveProxy after network change", sshResult.exceptionOrNull())
                        handleTunnelFailure("failed to reconnect NaiveProxy+SSH after network change")
                        return@launch
                    }

                    if (!waitForProxyReady(proxyPort, maxAttempts = 30, delayMs = 50)) {
                        Log.e(TAG, "SSH SOCKS5 proxy failed to restart on port $proxyPort")
                        handleTunnelFailure("failed to reconnect NaiveProxy+SSH after network change")
                        return@launch
                    }
                } else if (currentTunnelType == TunnelType.NAIVE) {
                    // Standalone NaiveProxy: restart NaiveProxy on internal port, then bridge on proxyPort
                    val naivePort = proxyPort + 1

                    val naiveResult = withContext(Dispatchers.IO) {
                        NaiveBridge.start(
                            context = this@SlipNetVpnService,
                            listenPort = naivePort,
                            listenHost = "127.0.0.1",
                            serverHost = profile.domain,
                            serverPort = profile.naivePort,
                            username = profile.naiveUsername,
                            password = profile.naivePassword,
                        )
                    }
                    if (naiveResult.isFailure) {
                        Log.e(TAG, "Failed to restart NaiveProxy after network change", naiveResult.exceptionOrNull())
                        handleTunnelFailure("failed to reconnect NaiveProxy after network change")
                        return@launch
                    }

                    if (!waitForNaiveReady(maxAttempts = 30, delayMs = 200)) {
                        Log.e(TAG, "NaiveProxy failed to become ready after network change")
                        handleTunnelFailure("failed to reconnect NaiveProxy after network change")
                        return@launch
                    }

                    val bridgeResult = vpnRepository.startNaiveSocksBridge(
                        naivePort = naivePort,
                        naiveHost = "127.0.0.1",
                        bridgePort = proxyPort,
                        bridgeHost = proxyHost,
                        dnsServer = remoteDns,
                        dnsFallback = remoteDnsFallback
                    )
                    if (bridgeResult.isFailure) {
                        Log.e(TAG, "Failed to restart NaiveSocksBridge after network change")
                        handleTunnelFailure("failed to reconnect NaiveProxy after network change")
                        return@launch
                    }

                    if (!waitForProxyReady(proxyPort, maxAttempts = 30, delayMs = 50)) {
                        Log.e(TAG, "NaiveSocksBridge failed to restart on port $proxyPort")
                        handleTunnelFailure("failed to reconnect NaiveProxy after network change")
                        return@launch
                    }
                } else {
                    val proxyResult = when (currentTunnelType) {
                        TunnelType.DOH -> vpnRepository.startDohProxy(profile)
                        TunnelType.SNOWFLAKE -> {
                            val torSocksPort = proxyPort + 1
                            val snowflakePtPort = proxyPort + 2
                            vpnRepository.startSnowflakeProxy(profile, snowflakePtPort, torSocksPort, proxyPort)
                        }
                        else -> Result.success(Unit) // handled above
                    }
                    if (proxyResult.isFailure) {
                        Log.e(TAG, "Failed to restart proxy after network change", proxyResult.exceptionOrNull())
                        handleTunnelFailure("failed to reconnect after network change")
                        return@launch
                    }

                    // Wait for proxy to be ready
                    if (!waitForProxyReady(proxyPort, maxAttempts = 20, delayMs = 50)) {
                        Log.e(TAG, "Proxy failed to restart")
                        handleTunnelFailure("failed to reconnect after network change")
                        return@launch
                    }
                }

                // HevSocks5Tunnel (tun2socks) was kept running — it will automatically
                // reconnect to the new proxy on the same port. No restart needed.
                // In proxy-only mode, just mark as connected again.
                if (isProxyOnly) {
                    vpnRepository.setProxyConnected(profile)
                }

                // Wait for tunnel to be re-established
                if (currentTunnelType == TunnelType.SLIPSTREAM) {
                    // QUIC wait already done during Slipstream reconnection above
                    delay(500)
                } else if (currentTunnelType == TunnelType.SLIPSTREAM_SSH) {
                    // QUIC wait already done during Slipstream+SSH reconnection above
                    delay(500)
                } else if (currentTunnelType == TunnelType.SNOWFLAKE) {
                    // Wait for Tor to re-bootstrap after network change
                    if (!waitForTorReady(maxWaitMs = 90000)) {
                        Log.e(TAG, "Tor failed to re-bootstrap after network change")
                        handleTunnelFailure("Tor failed to reconnect after network change")
                        return@launch
                    }
                } else if (currentTunnelType == TunnelType.NAIVE_SSH || currentTunnelType == TunnelType.NAIVE) {
                    delay(500)
                } else {
                    // For DNSTT/DNSTT+SSH, give it a moment to re-establish
                    delay(500)
                }

                // Restart HTTP proxy if it was running before (stopped by stopCurrentProxy)
                if (!HttpProxyServer.isRunning()) {
                    val appendProxy = preferencesDataStore.appendHttpProxyToVpn.first()
                    val httpEnabled = preferencesDataStore.httpProxyEnabled.first()
                    if (appendProxy || httpEnabled) {
                        val httpPort = preferencesDataStore.httpProxyPort.first()
                        val socksPort = preferencesDataStore.proxyListenPort.first()
                        // Use proxyListenAddress when HTTP proxy (LAN sharing) is enabled so other
                        // devices can reach it. Use 127.0.0.1 only when appendProxy is the sole
                        // reason (local VPN use only, no LAN sharing needed).
                        val listenHost = if (httpEnabled) preferencesDataStore.proxyListenAddress.first() else "127.0.0.1"
                        val result = HttpProxyServer.start(
                            socksHost = "127.0.0.1",
                            socksPort = socksPort,
                            listenHost = listenHost,
                            listenPort = httpPort
                        )
                        if (result.isFailure) {
                            Log.w(TAG, "HTTP proxy failed to restart after reconnect: ${result.exceptionOrNull()?.message}")
                        } else {
                            Log.i(TAG, "HTTP proxy restarted on $listenHost:$httpPort after reconnect")
                        }
                    }
                }

                // Restart health check
                startHealthCheck()

                // Refresh underlying networks after successful reconnection
                updateUnderlyingNetworks()

                // Clear kill switch state and restore connected notification
                if (isKillSwitchActive) {
                    isKillSwitchActive = false
                    val state = vpnRepository.connectionState.first()
                    val notification = notificationHelper.createVpnNotification(state, isProxyOnly)
                    val notificationManager = getSystemService(NotificationManager::class.java)
                    notificationManager.notify(NotificationHelper.VPN_NOTIFICATION_ID, notification)
                }

                Log.i(TAG, "Successfully reconnected after network change (tunnel type: $currentTunnelType)")
            } finally {
                isReconnecting = false
            }
        }
    }

    /**
     * Stop the currently running proxy based on tunnel type.
     * Stops SSH first if enabled, then the DNS tunnel.
     * Synchronized to prevent double-stop from onDestroy + coroutine cleanup.
     */
    @Synchronized
    private fun stopCurrentProxy() {
        // Always stop HTTP proxy (it chains through whatever SOCKS5 proxy is running)
        HttpProxyServer.stop()

        // If this was a chain connection, stop all layers in reverse order
        if (activeChainLayers.isNotEmpty()) {
            Log.d(TAG, "Stopping chain layers: ${activeChainLayers.reversed().joinToString(" → ") { it.displayName }}")
            for (layer in activeChainLayers.reversed()) {
                stopLayer(layer)
            }
            activeChainLayers = emptyList()
            currentChainId = -1
            return
        }

        when (currentTunnelType) {
            TunnelType.SLIPSTREAM -> {
                Log.d(TAG, "Stopping Slipstream proxy and bridge")
                SlipstreamSocksBridge.stop()
                SlipstreamBridge.stopClient()
            }
            TunnelType.SLIPSTREAM_SSH -> {
                Log.d(TAG, "Stopping Slipstream+SSH: SSH first, then Slipstream")
                SshTunnelBridge.stop()
                SlipstreamBridge.stopClient()
            }
            TunnelType.DNSTT -> {
                Log.d(TAG, "Stopping DNSTT proxy and bridge")
                DnsttSocksBridge.stop()
                DnsttBridge.stopClient()
            }
            TunnelType.NOIZDNS -> {
                Log.d(TAG, "Stopping NoizDNS proxy and bridge")
                DnsttSocksBridge.stop()
                DnsttBridge.stopClient()
            }
            TunnelType.SSH -> {
                Log.d(TAG, "Stopping SSH tunnel")
                SshTunnelBridge.stop()
            }
            TunnelType.DNSTT_SSH -> {
                Log.d(TAG, "Stopping DNSTT+SSH: SSH first, then DNSTT")
                SshTunnelBridge.stop()
                DnsttBridge.stopClient()
            }
            TunnelType.NOIZDNS_SSH -> {
                Log.d(TAG, "Stopping NoizDNS+SSH: SSH first, then NoizDNS")
                SshTunnelBridge.stop()
                DnsttBridge.stopClient()
            }
            TunnelType.DOH -> {
                Log.d(TAG, "Stopping DoH proxy")
                DohBridge.stop()
            }
            TunnelType.NAIVE_SSH -> {
                Log.d(TAG, "Stopping NaiveProxy+SSH: SSH first, then NaiveProxy")
                SshTunnelBridge.stop()
                NaiveBridge.stop()
            }
            TunnelType.NAIVE -> {
                Log.d(TAG, "Stopping standalone NaiveProxy: bridge first, then NaiveProxy")
                NaiveSocksBridge.stop()
                NaiveBridge.stop()
            }
            TunnelType.SNOWFLAKE -> {
                Log.d(TAG, "Stopping Snowflake: TorSocksBridge first, then Snowflake+Tor")
                TorSocksBridge.stop()
                SnowflakeBridge.stopClient()
            }
            TunnelType.SOCKS5 -> {
                Log.d(TAG, "Stopping SOCKS5 proxy bridge")
                Socks5ProxyBridge.stop()
            }
        }
    }

    /**
     * Clear VPN service reference from the current bridge.
     */
    private fun clearVpnServiceRef() {
        when (currentTunnelType) {
            TunnelType.SLIPSTREAM -> { SlipstreamBridge.proxyOnlyMode = false; SlipstreamBridge.setVpnService(null) }
            TunnelType.SLIPSTREAM_SSH -> { SlipstreamBridge.proxyOnlyMode = false; SlipstreamBridge.setVpnService(null) }
            TunnelType.DNSTT -> DnsttBridge.setVpnService(null)
            TunnelType.NOIZDNS -> DnsttBridge.setVpnService(null)
            TunnelType.SSH -> { /* SSH-only: no bridge reference to clear */ }
            TunnelType.DNSTT_SSH -> DnsttBridge.setVpnService(null)
            TunnelType.NOIZDNS_SSH -> DnsttBridge.setVpnService(null)
            TunnelType.DOH -> { /* DOH: no bridge reference to clear */ }
            TunnelType.NAIVE_SSH -> { /* NaiveProxy+SSH: no bridge reference to clear */ }
            TunnelType.NAIVE -> { /* NaiveProxy standalone: no bridge reference to clear */ }
            TunnelType.SNOWFLAKE -> { /* Snowflake: no bridge reference to clear */ }
            TunnelType.SOCKS5 -> { /* SOCKS5: no bridge reference to clear */ }
        }
    }

    /**
     * Check if the current proxy is healthy.
     * When SSH is enabled, also checks SSH tunnel health.
     */
    private fun isCurrentProxyHealthy(): Boolean {
        // If HTTP proxy is running, it must also be healthy
        if (HttpProxyServer.isRunning() && !HttpProxyServer.isHealthy()) {
            return false
        }

        return when (currentTunnelType) {
            TunnelType.SLIPSTREAM -> SlipstreamBridge.isClientHealthy() && SlipstreamSocksBridge.isClientHealthy()
            TunnelType.SLIPSTREAM_SSH -> SlipstreamBridge.isClientHealthy() && SshTunnelBridge.isClientHealthy()
            TunnelType.DNSTT -> DnsttBridge.isClientHealthy() && DnsttSocksBridge.isClientHealthy()
            TunnelType.NOIZDNS -> DnsttBridge.isClientHealthy() && DnsttSocksBridge.isClientHealthy()
            TunnelType.SSH -> SshTunnelBridge.isClientHealthy()
            TunnelType.DNSTT_SSH -> DnsttBridge.isClientHealthy() && SshTunnelBridge.isClientHealthy()
            TunnelType.NOIZDNS_SSH -> DnsttBridge.isClientHealthy() && SshTunnelBridge.isClientHealthy()
            TunnelType.DOH -> DohBridge.isClientHealthy()
            TunnelType.NAIVE_SSH -> NaiveBridge.isClientHealthy() && SshTunnelBridge.isClientHealthy()
            TunnelType.NAIVE -> NaiveBridge.isClientHealthy() && NaiveSocksBridge.isClientHealthy()
            TunnelType.SNOWFLAKE -> SnowflakeBridge.isClientHealthy() && TorSocksBridge.isClientHealthy()
            TunnelType.SOCKS5 -> Socks5ProxyBridge.isRunning() && Socks5ProxyBridge.isClientHealthy()
        }
    }


    /**
     * Resolve a resolver host to a numeric IP for [Builder.addDnsServer].
     * Falls back to [DEFAULT_DNS] if resolution fails or host is null.
     */
    private fun resolveToIp(host: String?): String {
        if (host.isNullOrBlank()) return DEFAULT_DNS
        val resolved = VpnRepositoryImpl.resolveHost(host)
        return if (DomainRouter.isIpAddress(resolved)) resolved else DEFAULT_DNS
    }

    private suspend fun establishVpnInterface(dnsServer: String): ParcelFileDescriptor? {
        val mtu = try { preferencesDataStore.vpnMtu.first() } catch (_: Exception) { VPN_MTU }
        val builder = Builder()
            .setSession("SlipNet VPN")
            .setMtu(mtu)
            .addAddress(VPN_ADDRESS, 32)
            .addDnsServer(dnsServer)
            .setBlocking(false)

        // DoH mode: only route DNS traffic through the VPN so local network
        // (mDNS, Cast, SMB, LAN) and app traffic (VoIP, push) bypass it entirely.
        if (currentTunnelType == TunnelType.DOH) {
            builder.addRoute(dnsServer, 32)
        } else {
            builder.addRoute(VPN_ROUTE, 0)
        }

        val needsSelfExclusion = currentTunnelType == TunnelType.DNSTT ||
                currentTunnelType == TunnelType.NOIZDNS ||
                currentTunnelType == TunnelType.SSH ||
                currentTunnelType == TunnelType.DNSTT_SSH ||
                currentTunnelType == TunnelType.NOIZDNS_SSH ||
                currentTunnelType == TunnelType.DOH ||
                currentTunnelType == TunnelType.SLIPSTREAM ||
                currentTunnelType == TunnelType.SLIPSTREAM_SSH ||
                currentTunnelType == TunnelType.NAIVE_SSH ||
                currentTunnelType == TunnelType.NAIVE ||
                currentTunnelType == TunnelType.SNOWFLAKE ||
                currentTunnelType == TunnelType.SOCKS5

        val splitEnabled = preferencesDataStore.splitTunnelingEnabled.first()
        val splitMode = preferencesDataStore.splitTunnelingMode.first()
        val splitApps = preferencesDataStore.splitTunnelingApps.first()

        if (splitEnabled && splitApps.isNotEmpty()) {
            when (splitMode) {
                SplitTunnelingMode.DISALLOW -> {
                    // Selected apps bypass VPN. Always include self if tunnel type needs it.
                    if (needsSelfExclusion) {
                        try {
                            builder.addDisallowedApplication(packageName)
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to exclude self from VPN", e)
                        }
                    }
                    for (pkg in splitApps) {
                        if (pkg == packageName) continue // already handled above
                        try {
                            builder.addDisallowedApplication(pkg)
                        } catch (_: Exception) { }
                    }
                    Log.d(TAG, "Split tunneling: disallow mode, ${splitApps.size} apps bypass VPN")
                }
                SplitTunnelingMode.ALLOW -> {
                    // Only selected apps use VPN. Self is automatically excluded
                    // (not in the allowed list) — which is what tunnel types need.
                    for (pkg in splitApps) {
                        if (pkg == packageName) continue // don't route our own traffic through VPN
                        try {
                            builder.addAllowedApplication(pkg)
                        } catch (_: Exception) { }
                    }
                    Log.d(TAG, "Split tunneling: allow mode, ${splitApps.size} apps use VPN")
                }
            }
        } else {
            // Original behavior: exclude self for tunnel types that need it
            if (needsSelfExclusion) {
                try {
                    builder.addDisallowedApplication(packageName)
                    Log.d(TAG, "Excluded app from VPN: $packageName")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to exclude app from VPN", e)
                }
            }
        }

        // Append HTTP proxy to VPN so apps route HTTP/HTTPS through it directly,
        // bypassing TUN/tun2socks overhead. Requires API 29+.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val appendProxy = preferencesDataStore.appendHttpProxyToVpn.first()
            if (appendProxy) {
                val httpPort = preferencesDataStore.httpProxyPort.first()
                val socksPort = preferencesDataStore.proxyListenPort.first()

                // Start HTTP proxy now (before VPN) so it's ready when apps connect.
                // If "HTTP proxy" (LAN sharing) is also enabled, bind to proxyListenAddress
                // (e.g. 0.0.0.0) so other devices can reach it. setHttpProxy still uses
                // 127.0.0.1 which is reachable on a 0.0.0.0-bound socket.
                // If only appendProxy is active (no LAN sharing), 127.0.0.1 is sufficient.
                if (!HttpProxyServer.isRunning()) {
                    val httpEnabled = preferencesDataStore.httpProxyEnabled.first()
                    val httpListenHost = if (httpEnabled) preferencesDataStore.proxyListenAddress.first() else "127.0.0.1"
                    val result = HttpProxyServer.start(
                        socksHost = "127.0.0.1",
                        socksPort = socksPort,
                        listenHost = httpListenHost,
                        listenPort = httpPort
                    )
                    if (result.isFailure) {
                        Log.w(TAG, "HTTP proxy failed to start for VPN append: ${result.exceptionOrNull()?.message}")
                    }
                }

                if (HttpProxyServer.isRunning()) {
                    builder.setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", httpPort))
                    Log.i(TAG, "HTTP proxy appended to VPN on 127.0.0.1:$httpPort")
                }
            }
        }

        return builder.establish()
    }

    private fun observeConnectionState() {
        stateObserverJob?.cancel()
        stateObserverJob = serviceScope.launch {
            vpnRepository.connectionState.collect { state ->
                val notification = notificationHelper.createVpnNotification(state, isProxyOnly)
                val notificationManager = getSystemService(NotificationManager::class.java)
                notificationManager.notify(NotificationHelper.VPN_NOTIFICATION_ID, notification)

                when (state) {
                    is ConnectionState.Error -> {
                        // Don't stop service during kill switch — we're blocking traffic and reconnecting
                        if (isKillSwitchActive) return@collect

                        // Show reconnect notification before stopping
                        if (currentProfileId != -1L) {
                            val reconnectNotification = notificationHelper.createReconnectNotification(
                                message = state.message,
                                profileId = currentProfileId
                            )
                            notificationManager.notify(NotificationHelper.RECONNECT_NOTIFICATION_ID, reconnectNotification)
                        }
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                    }
                    // Disconnected is handled by the disconnect() coroutine which already
                    // calls stopForeground/stopSelf. Do NOT call stopSelf() here — if the
                    // user reconnects quickly on the same service instance, this observer
                    // may still be processing the old Disconnected state and would kill
                    // the new connection.
                    else -> { }
                }
            }
        }
    }

    private fun disconnect() {
        // Mark as user-initiated so onDestroy() doesn't show disconnect notification
        isUserInitiatedDisconnect = true

        // Clear kill switch so teardown proceeds normally
        isKillSwitchActive = false

        // Cancel auto-reconnect
        autoReconnectJob?.cancel()
        autoReconnectJob = null
        isAutoReconnecting = false
        autoReconnectAttempt = 0
        connectionWasSuccessful = false

        // Cancel any in-progress connection attempt
        connectJob?.cancel()
        connectJob = null

        // Cancel any in-progress reconnection immediately — before the coroutine.
        // This prevents a race where the reconnect coroutine is mid-flight in native
        // code (e.g., starting Slipstream on port 1081) while disconnect also tries
        // to stop/start, leading to "port already in use" on the next connect.
        reconnectDebounceJob?.cancel()
        reconnectDebounceJob = null
        networkLostJob?.cancel()
        networkLostJob = null
        isReconnecting = false

        // Cancel state observer to prevent stale stopSelf() calls
        stateObserverJob?.cancel()
        stateObserverJob = null

        disconnectJob = serviceScope.launch {
            Log.i(TAG, "Disconnecting VPN")
            // Clear saved state so we don't auto-reconnect on restart
            clearConnectionState()
            cleanupConnection()
            connectionManager.onVpnDisconnected()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    /**
     * Handle tunnel failure with seamless reconnect, kill switch, and auto-reconnect support.
     *
     * First tries a lightweight "seamless reconnect": restarts only the proxy while keeping
     * the TUN interface and tun2socks alive. This handles transient failures such as QUIC
     * idle timeouts on devices where the OS throttles background network (e.g. Chinese OEM
     * phones like Honor/Huawei), causing keepalive pings to fail and the transport connection
     * to drop. Seamless reconnect minimizes the traffic gap — tun2socks buffers/retries
     * connections until the new proxy is ready.
     *
     * If seamless reconnect is not possible (tun2socks crashed) or has been exhausted
     * (MAX_SEAMLESS_RECONNECTS attempts), escalates to kill switch or auto-reconnect.
     */
    private suspend fun handleTunnelFailure(reason: String) {
        // Try seamless proxy restart first if tun2socks is still alive.
        // Skip if: tun2socks is dead, already in kill-switch/auto-reconnect,
        // or we've exhausted seamless attempts (prevents infinite loop).
        val tunnelAlive = if (isProxyOnly) true else HevSocks5Tunnel.isRunning()
        if (tunnelAlive && seamlessReconnectAttempts < MAX_SEAMLESS_RECONNECTS
            && !isKillSwitchActive && !isAutoReconnecting) {
            seamlessReconnectAttempts++
            Log.i(TAG, "Attempting seamless reconnect ($seamlessReconnectAttempts/$MAX_SEAMLESS_RECONNECTS): $reason")
            handleNetworkChange("tunnel recovery: $reason")
            return
        }

        // Seamless reconnect exhausted or not possible — reset counter and escalate.
        Log.i(TAG, "Escalating tunnel failure (seamless attempts=$seamlessReconnectAttempts): $reason")
        seamlessReconnectAttempts = 0

        val killSwitchEnabled = preferencesDataStore.killSwitch.first()
        if (killSwitchEnabled && !isProxyOnly && vpnInterface != null) {
            enterKillSwitchMode(reason)
        } else {
            val autoReconnectEnabled = preferencesDataStore.autoReconnect.first()
            if (autoReconnectEnabled && connectionWasSuccessful && !isUserInitiatedDisconnect
                && autoReconnectAttempt < AUTO_RECONNECT_MAX_RETRIES) {
                enterAutoReconnectMode(reason)
            } else {
                connectionManager.onVpnError("VPN connection lost - $reason")
                cleanupConnection()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    /**
     * Enter kill switch mode: keep VPN interface alive (blocking all traffic),
     * stop proxy/tunnel, show kill switch notification, and attempt reconnection.
     */
    private suspend fun enterKillSwitchMode(reason: String) {
        Log.i(TAG, "Kill switch activated: $reason")
        isKillSwitchActive = true

        // Stop health check during kill switch
        healthCheckJob?.cancel()
        healthCheckJob = null

        // Stop proxy/tunnel but NOT vpnInterface — TUN stays alive to block traffic
        withContext(Dispatchers.IO) {
            if (!isProxyOnly) {
                try { HevSocks5Tunnel.stop() } catch (_: Exception) {}
            }
            try { stopCurrentProxy() } catch (_: Exception) {}
        }

        // Update foreground notification to kill switch notification
        val profile = connectionManager.getProfileById(currentProfileId)
        val profileName = profile?.name ?: "VPN"
        val notification = notificationHelper.createKillSwitchNotification(profileName)
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NotificationHelper.VPN_NOTIFICATION_ID, notification)

        // Attempt reconnection after a brief delay
        serviceScope.launch {
            delay(2000)
            if (isKillSwitchActive) {
                handleNetworkChange("kill switch reconnect")
            }
        }
    }

    /**
     * Enter auto-reconnect mode: tear down VPN (traffic flows directly during retry),
     * show reconnecting notification, and attempt reconnection with exponential backoff.
     */
    private suspend fun enterAutoReconnectMode(reason: String) {
        autoReconnectAttempt++
        isAutoReconnecting = true
        Log.i(TAG, "Auto-reconnect attempt $autoReconnectAttempt/$AUTO_RECONNECT_MAX_RETRIES: $reason")

        // Capture profile info BEFORE cleanup resets currentProfileId
        val profileId = currentProfileId
        val profileName = currentProfileName

        // Tear down the connection (VPN goes down, traffic flows directly)
        cleanupConnection()

        // Show auto-reconnect foreground notification to keep service alive
        val notification = notificationHelper.createAutoReconnectNotification(
            profileName, autoReconnectAttempt, AUTO_RECONNECT_MAX_RETRIES
        )
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NotificationHelper.VPN_NOTIFICATION_ID, notification)

        // Schedule reconnect with exponential backoff
        val delayMs = AUTO_RECONNECT_DELAYS_MS[
            (autoReconnectAttempt - 1).coerceAtMost(AUTO_RECONNECT_DELAYS_MS.size - 1)
        ]
        autoReconnectJob = serviceScope.launch {
            Log.d(TAG, "Auto-reconnect: waiting ${delayMs}ms before attempt $autoReconnectAttempt")
            delay(delayMs)
            if (isUserInitiatedDisconnect) {
                Log.i(TAG, "Auto-reconnect cancelled: user-initiated disconnect")
                return@launch
            }
            isAutoReconnecting = false
            connect(profileId)
        }
    }

    /** Release WakeLock and WifiLock if held. */
    private fun releaseLocks() {
        wakeLockRenewJob?.cancel()
        wakeLockRenewJob = null
        wakeLock?.let {
            if (it.isHeld) {
                it.release()
                Log.d(TAG, "WakeLock released")
            }
        }
        wakeLock = null
        wifiLock?.let {
            if (it.isHeld) {
                it.release()
                Log.d(TAG, "WifiLock released")
            }
        }
        wifiLock = null
    }

    /** Periodically re-acquires the WakeLock before it expires. */
    private fun startWakeLockRenewal() {
        wakeLockRenewJob?.cancel()
        wakeLockRenewJob = serviceScope.launch(Dispatchers.IO) {
            while (isActive) {
                kotlinx.coroutines.delay(WAKELOCK_RENEW_INTERVAL_MS)
                wakeLock?.let {
                    if (it.isHeld) {
                        it.acquire(WAKELOCK_TIMEOUT_MS)
                        Log.d(TAG, "WakeLock renewed")
                    }
                }
            }
        }
    }

    /** Chinese OEM ROMs aggressively kill apps using high-power WifiLock modes. */
    private fun isChineseOem(): Boolean {
        val manufacturer = Build.MANUFACTURER.lowercase()
        return manufacturer in listOf(
            "xiaomi", "redmi", "poco", "huawei", "honor",
            "oppo", "vivo", "realme", "oneplus", "meizu", "zte", "lenovo"
        )
    }

    /**
     * Clean up all resources - must be called before stopping service.
     * This is a suspend function to run blocking operations on IO dispatcher.
     */
    private suspend fun cleanupConnection() {
        app.slipnet.util.AppLog.redactSensitive = false
        Log.d(TAG, "Cleaning up connection resources")

        releaseLocks()

        // Stop health monitoring
        healthCheckJob?.cancel()
        healthCheckJob = null

        // Cancel any pending reconnect / network-loss timer
        reconnectDebounceJob?.cancel()
        reconnectDebounceJob = null
        networkLostJob?.cancel()
        networkLostJob = null
        isReconnecting = false

        // Unregister network callback and Doze receiver
        unregisterNetworkCallback()
        unregisterDozeReceiver()
        lastNetworkAddresses = emptySet()
        lastNetworkDnsServers = emptySet()

        // Stop native tunnels on IO thread to avoid ANR
        // These operations can block waiting for threads to stop
        withContext(Dispatchers.IO) {
            if (!isProxyOnly) {
                try {
                    HevSocks5Tunnel.stop()
                } catch (e: Exception) {
                    Log.e(TAG, "Error stopping HevSocks5Tunnel", e)
                }
            }

            try {
                stopCurrentProxy()
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping proxy", e)
            }
        }

        // Clear VPN service reference
        clearVpnServiceRef()

        // Close VPN interface
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface", e)
        }
        vpnInterface = null

        currentProfileId = -1
    }

    override fun onRevoke() {
        super.onRevoke()
        Log.i(TAG, "VPN permission revoked (another VPN took over)")
        // Do NOT mark as user-initiated — onRevoke means another VPN took over,
        // so onDestroy() should show the disconnect notification.
        // We still need to clean up, but skip setting isUserInitiatedDisconnect.
        isKillSwitchActive = false
        // Cancel auto-reconnect — another VPN took over, don't fight it
        autoReconnectJob?.cancel()
        autoReconnectJob = null
        isAutoReconnecting = false
        autoReconnectAttempt = 0
        connectionWasSuccessful = false
        connectJob?.cancel()
        connectJob = null
        reconnectDebounceJob?.cancel()
        reconnectDebounceJob = null
        networkLostJob?.cancel()
        networkLostJob = null
        isReconnecting = false
        stateObserverJob?.cancel()
        stateObserverJob = null
        disconnectJob = serviceScope.launch {
            Log.i(TAG, "Disconnecting VPN (revoked)")
            clearConnectionState()
            cleanupConnection()
            connectionManager.onVpnDisconnected()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        Log.i(TAG, "Task removed (app swiped from recents)")

        // If VPN is active, save state and re-deliver start intent to keep running
        if (currentProfileId != -1L) {
            saveConnectionState(currentProfileId, true)
            val restartIntent = Intent(this, SlipNetVpnService::class.java).apply {
                action = ACTION_CONNECT
                putExtra(EXTRA_PROFILE_ID, currentProfileId)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(restartIntent)
            } else {
                startService(restartIntent)
            }
            Log.i(TAG, "Re-delivered start intent for profile $currentProfileId")
        }
    }

    override fun onDestroy() {
        Log.i(TAG, "Service onDestroy")

        // Capture state before cleanup resets currentProfileId to -1
        val wasActive = currentProfileId != -1L
        val profileName = currentProfileName
        val profileId = currentProfileId

        // Quick non-blocking cleanup for onDestroy
        // Don't wait for native threads - they'll clean up themselves
        cleanupConnectionSync()

        // Ensure connection state is always reset when the service dies.
        // This is critical for onRevoke() (another VPN app takes over):
        // disconnect() runs cleanup in a coroutine on serviceScope, but onDestroy()
        // cancels serviceScope before the coroutine reaches onVpnDisconnected().
        // Without this, the UI would still show "Connected" after another VPN connects.
        clearConnectionState()
        connectionManager.onVpnDisconnected()

        // Show disconnect notification if the connection was active and not user-initiated.
        // Skip if kill switch is active (it has its own notification) or if reconnecting
        // (the reconnect/kill-switch flow handles notifications).
        if (wasActive && !isUserInitiatedDisconnect && !isKillSwitchActive && !isReconnecting && !isAutoReconnecting) {
            Log.i(TAG, "Unexpected disconnect detected, showing notification")
            val notification = notificationHelper.createDisconnectedNotification(profileName, profileId)
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.notify(NotificationHelper.DISCONNECT_NOTIFICATION_ID, notification)
        }

        serviceScope.cancel()
        super.onDestroy()
    }

    /**
     * Synchronous cleanup that doesn't wait for native threads.
     * Used in onDestroy where we can't suspend.
     */
    private fun cleanupConnectionSync() {
        app.slipnet.util.AppLog.redactSensitive = false
        Log.d(TAG, "Quick cleanup (sync)")

        releaseLocks()

        // Stop health monitoring
        healthCheckJob?.cancel()
        healthCheckJob = null

        // Cancel auto-reconnect
        autoReconnectJob?.cancel()
        autoReconnectJob = null
        isAutoReconnecting = false

        // Cancel any pending reconnect / network-loss timer
        reconnectDebounceJob?.cancel()
        reconnectDebounceJob = null
        networkLostJob?.cancel()
        networkLostJob = null
        isReconnecting = false

        // Unregister network callback and Doze receiver
        unregisterNetworkCallback()
        unregisterDozeReceiver()
        lastNetworkAddresses = emptySet()
        lastNetworkDnsServers = emptySet()

        // Stop HTTP proxy
        try {
            HttpProxyServer.stop()
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping HTTP proxy", e)
        }

        // Request native tunnels to stop (non-blocking)
        // The native code will handle the actual shutdown
        if (!isProxyOnly) {
            try {
                HevSocks5Tunnel.stop()
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping HevSocks5Tunnel", e)
            }
        }

        try {
            // Just send stop signal, don't wait
            stopCurrentProxy()
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping proxy", e)
        }

        // Clear VPN service reference
        clearVpnServiceRef()

        // Close VPN interface
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface", e)
        }
        vpnInterface = null

        currentProfileId = -1
    }
}
