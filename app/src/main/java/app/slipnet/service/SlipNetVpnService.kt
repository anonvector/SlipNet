package app.slipnet.service

import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.ProxyInfo
import android.net.VpnService
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
import app.slipnet.tunnel.DnsttBridge
import app.slipnet.tunnel.DohBridge
import app.slipnet.tunnel.HevSocks5Tunnel
import app.slipnet.tunnel.HttpProxyServer
import app.slipnet.tunnel.SlipstreamBridge
import app.slipnet.tunnel.SlipstreamSocksBridge
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

        private const val VPN_MTU = 1500
        private const val VPN_ADDRESS = "10.255.255.1"
        private const val VPN_ROUTE = "0.0.0.0"
        private const val DEFAULT_DNS = "8.8.8.8"
        private const val HEALTH_CHECK_INTERVAL_MS = 5000L
        private const val STALE_TRAFFIC_THRESHOLD = 3 // Reconnect after 3 checks with no traffic

        // Persistence keys for auto-restart
        private const val PREFS_NAME = "vpn_service_state"
        private const val PREF_LAST_PROFILE_ID = "last_profile_id"
        private const val PREF_WAS_CONNECTED = "was_connected"

        // WakeLock tag
        private const val WAKELOCK_TAG = "SlipNet:VpnWakeLock"
    }

    @Inject
    lateinit var connectionManager: VpnConnectionManager

    @Inject
    lateinit var vpnRepository: VpnRepositoryImpl

    @Inject
    lateinit var notificationHelper: NotificationHelper

    @Inject
    lateinit var preferencesDataStore: PreferencesDataStore

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var healthCheckJob: Job? = null
    private var currentProfileId: Long = -1
    private var currentTunnelType: TunnelType = TunnelType.SLIPSTREAM
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastNetworkAddresses: Set<String> = emptySet()
    private var reconnectDebounceJob: Job? = null
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

    // Traffic monitoring for stale connection detection
    private var lastTrafficRxBytes = 0L
    private var lastTrafficTxBytes = 0L
    private var staleTrafficChecks = 0

    // Persistence and WakeLock for service resilience
    private lateinit var prefs: SharedPreferences
    private var wakeLock: PowerManager.WakeLock? = null


    override fun onCreate() {
        super.onCreate()
        connectivityManager = getSystemService(ConnectivityManager::class.java)
        prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        // Acquire a partial WakeLock to keep the CPU running
        // This helps prevent Android from killing the service when screen is off
        val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            WAKELOCK_TAG
        ).apply {
            setReferenceCounted(false)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Acquire WakeLock when service starts
        acquireWakeLock()

        when (intent?.action) {
            ACTION_CONNECT -> {
                val profileId = intent.getLongExtra(EXTRA_PROFILE_ID, -1)
                if (profileId != -1L) {
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
            releaseWakeLock()
            stopSelf()
        }
    }

    /**
     * Acquire the WakeLock to keep the CPU running.
     */
    private fun acquireWakeLock() {
        try {
            wakeLock?.let { lock ->
                if (!lock.isHeld) {
                    // Acquire with a timeout to prevent battery drain if something goes wrong
                    // 10 minutes should be enough; we'll re-acquire in health check
                    lock.acquire(10 * 60 * 1000L)
                    Log.d(TAG, "WakeLock acquired")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to acquire WakeLock", e)
        }
    }

    /**
     * Release the WakeLock.
     */
    private fun releaseWakeLock() {
        try {
            wakeLock?.let { lock ->
                if (lock.isHeld) {
                    lock.release()
                    Log.d(TAG, "WakeLock released")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to release WakeLock", e)
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

            currentProfileId = profileId
            currentProfileName = profile.name
            isUserInitiatedDisconnect = false

            // Dismiss any previous reconnect/disconnect notifications
            getSystemService(NotificationManager::class.java).apply {
                cancel(NotificationHelper.RECONNECT_NOTIFICATION_ID)
                cancel(NotificationHelper.DISCONNECT_NOTIFICATION_ID)
            }

            // Show connecting notification
            val notification = notificationHelper.createVpnNotification(ConnectionState.Connecting)
            startForeground(NotificationHelper.VPN_NOTIFICATION_ID, notification)

            try {
                // Read proxy-only mode setting
                isProxyOnly = preferencesDataStore.proxyOnlyMode.first()

                // Set debug logging on tunnel bridges
                val debug = preferencesDataStore.debugLogging.first()
                SshTunnelBridge.debugLogging = debug
                DohBridge.debugLogging = debug
                SlipstreamSocksBridge.debugLogging = debug
                TorSocksBridge.debugLogging = debug
                HttpProxyServer.debugLogging = debug

                // Configure domain routing on bridges
                val domainRouter = buildDomainRouter()
                SshTunnelBridge.domainRouter = domainRouter
                DohBridge.domainRouter = domainRouter
                SlipstreamSocksBridge.domainRouter = domainRouter
                TorSocksBridge.domainRouter = domainRouter

                // Track the tunnel type for this connection
                currentTunnelType = profile.tunnelType
                Log.i(TAG, "Starting VPN with tunnel type: $currentTunnelType")

                val dnsServer = profile.resolvers.firstOrNull()?.host ?: DEFAULT_DNS

                // The startup order differs between tunnel types:
                // - Slipstream: Start proxy first (Rust uses protect_socket JNI callback)
                // - DNSTT: Establish VPN first (uses addDisallowedApplication for socket protection)
                when (currentTunnelType) {
                    TunnelType.SLIPSTREAM -> connectSlipstream(profile, dnsServer)
                    TunnelType.SLIPSTREAM_SSH -> connectSlipstreamSsh(profile, dnsServer)
                    TunnelType.DNSTT -> connectDnstt(profile, dnsServer)
                    TunnelType.SSH -> connectSsh(profile, dnsServer)
                    TunnelType.DNSTT_SSH -> connectDnsttSsh(profile, dnsServer)
                    TunnelType.DOH -> connectDoh(profile, dnsServer)
                    TunnelType.SNOWFLAKE -> connectSnowflake(profile, dnsServer)
                }

            } catch (e: kotlinx.coroutines.CancellationException) {
                // Coroutine was cancelled (user disconnected, service stopped, or new connect).
                // Do NOT treat as an error — let the cancelling code handle cleanup.
                Log.d(TAG, "Connection coroutine cancelled")
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Exception during connection", e)
                connectionManager.onVpnError(e.message ?: "Unknown error")
                cleanupConnection()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
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
    private suspend fun connectSlipstream(profile: app.slipnet.domain.model.ServerProfile, dnsServer: String) {
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

        // Step 2.5: Verify proxy is listening
        if (!waitForProxyReady(slipstreamPort, maxAttempts = 20, delayMs = 100)) {
            handleProxyStartupFailure(slipstreamPort)
            return
        }

        // Step 2.6: Wait for QUIC handshake before VPN setup
        val quicReady = waitForQuicReady(maxAttempts = 50, delayMs = 100)
        if (!quicReady) {
            Log.w(TAG, "QUIC connection not ready within timeout, continuing anyway")
        }

        // Step 3: Start SlipstreamSocksBridge on proxyPort (user-facing, with auth for Dante)
        val bridgeResult = vpnRepository.startSlipstreamSocksBridge(
            slipstreamPort = slipstreamPort,
            slipstreamHost = "127.0.0.1",
            bridgePort = proxyPort,
            bridgeHost = proxyHost,
            socksUsername = profile.socksUsername,
            socksPassword = profile.socksPassword
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
     */
    private suspend fun configureSshBridge() {
        val cipher = preferencesDataStore.sshCipher.first()
        val compression = preferencesDataStore.sshCompression.first()
        val maxChannels = preferencesDataStore.sshMaxChannels.first()
        SshTunnelBridge.configure(
            cipher = cipher.jschConfig,
            compression = compression,
            maxChannels = maxChannels
        )
    }

    private suspend fun connectSlipstreamSsh(profile: app.slipnet.domain.model.ServerProfile, dnsServer: String) {
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

        // Step 2.5: Verify Slipstream is listening
        if (!waitForProxyReady(slipstreamPort, maxAttempts = 20, delayMs = 100)) {
            handleProxyStartupFailure(slipstreamPort)
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
            Log.i(TAG, "Starting SSH tunnel through Slipstream (${profile.sshHost}:${profile.sshPort} via 127.0.0.1:$slipstreamPort)")
            SshTunnelBridge.startOverProxy(
                sshHost = profile.sshHost,
                sshPort = profile.sshPort,
                sshUsername = profile.sshUsername,
                sshPassword = profile.sshPassword,
                proxyHost = "127.0.0.1",
                proxyPort = slipstreamPort,
                listenPort = proxyPort,
                listenHost = proxyHost,
                blockDirectDns = true,  // No addDisallowedApplication — direct UDP would loop through VPN
                useServerDns = profile.useServerDns,
                sshAuthType = profile.sshAuthType,
                sshPrivateKey = profile.sshPrivateKey,
                sshKeyPassphrase = profile.sshKeyPassphrase
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

        // Step 5: Establish VPN interface (NO addDisallowedApplication — Slipstream uses JNI)
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
    private suspend fun connectDnstt(profile: app.slipnet.domain.model.ServerProfile, dnsServer: String) {
        val proxyPort = preferencesDataStore.proxyListenPort.first()
        val proxyHost = preferencesDataStore.proxyListenAddress.first()

        // Step 1: Set VpnService reference (for potential future use)
        DnsttBridge.setVpnService(this@SlipNetVpnService)

        if (isProxyOnly) {
            // Proxy-only: no VPN needed, start DNSTT directly (sockets go direct anyway)
            val proxyResult = vpnRepository.startDnsttProxy(profile)
            if (proxyResult.isFailure) {
                connectionManager.onVpnError(proxyResult.exceptionOrNull()?.message ?: "Failed to start DNSTT proxy")
                DnsttBridge.setVpnService(null)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            if (!waitForProxyReady(proxyPort, maxAttempts = 20, delayMs = 100)) {
                handleProxyStartupFailure(proxyPort)
                return
            }

            vpnRepository.setProxyConnected(profile)
            Log.i(TAG, "Proxy-only mode: DNSTT SOCKS5 proxy ready on $proxyHost:$proxyPort")
            finishConnection()
            return
        }

        // Step 2: Establish VPN interface FIRST (with addDisallowedApplication for this app)
        // This ensures DNSTT's sockets bypass the VPN when created
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

        // Step 3: Now start DNSTT proxy (its sockets will bypass VPN due to app exclusion)
        val proxyResult = vpnRepository.startDnsttProxy(profile)
        if (proxyResult.isFailure) {
            connectionManager.onVpnError(proxyResult.exceptionOrNull()?.message ?: "Failed to start DNSTT proxy")
            vpnInterface?.close()
            vpnInterface = null
            DnsttBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 3.5: Verify proxy is listening
        if (!waitForProxyReady(proxyPort, maxAttempts = 20, delayMs = 100)) {
            handleProxyStartupFailure(proxyPort)
            vpnInterface?.close()
            vpnInterface = null
            return
        }

        // Step 4: Start tun2socks
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
        Log.d(TAG, "DNSTT tunnel started")

        finishConnection()
    }

    /**
     * Connect using SSH-only tunnel type.
     * Order: Establish VPN interface (with app exclusion) -> Start SSH tunnel -> Wait for ready -> tun2socks
     *
     * SSH connects directly to the remote server (no DNS tunneling).
     * DNS queries go direct via DatagramSocket (bypasses VPN via addDisallowedApplication).
     */
    private suspend fun connectSsh(profile: app.slipnet.domain.model.ServerProfile, dnsServer: String) {
        val proxyPort = preferencesDataStore.proxyListenPort.first()
        val proxyHost = preferencesDataStore.proxyListenAddress.first()

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
                    useServerDns = profile.useServerDns,
                    sshAuthType = profile.sshAuthType,
                    sshPrivateKey = profile.sshPrivateKey,
                    sshKeyPassphrase = profile.sshKeyPassphrase
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
                useServerDns = profile.useServerDns,
                sshAuthType = profile.sshAuthType,
                sshPrivateKey = profile.sshPrivateKey,
                sshKeyPassphrase = profile.sshKeyPassphrase
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
     * Connect using DNSTT+SSH tunnel type.
     * Order: Set DNSTT ref -> VPN interface (with app exclusion) -> Start DNSTT -> Wait for DNSTT ready
     *        -> Start SSH over DNSTT proxy -> Wait for SSH ready -> Start tun2socks on proxyPort
     *
     * Traffic flow:
     * App -> TUN -> hev-socks5-tunnel -> SSH SOCKS5 (proxyPort)
     *   -> SSH direct-tcpip -> DNSTT (proxyPort+1, 127.0.0.1, raw TCP tunnel)
     *   -> DNS tunnel (UDP 53) -> DNSTT Server -> SSH Server -> Internet
     */
    private suspend fun connectDnsttSsh(profile: app.slipnet.domain.model.ServerProfile, dnsServer: String) {
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

        // Step 3: Start DNSTT proxy on internal port (127.0.0.1 only)
        val proxyResult = vpnRepository.startDnsttProxy(profile, portOverride = dnsttPort, hostOverride = "127.0.0.1")
        if (proxyResult.isFailure) {
            connectionManager.onVpnError(proxyResult.exceptionOrNull()?.message ?: "Failed to start DNSTT proxy")
            vpnInterface?.close()
            vpnInterface = null
            DnsttBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 3.5: Verify DNSTT proxy is listening
        if (!waitForProxyReady(dnsttPort, maxAttempts = 20, delayMs = 100)) {
            handleProxyStartupFailure(dnsttPort)
            vpnInterface?.close()
            vpnInterface = null
            return
        }

        // Step 4: Switch tunnel type to DNSTT_SSH before starting SSH
        vpnRepository.setCurrentTunnelType(TunnelType.DNSTT_SSH)
        currentTunnelType = TunnelType.DNSTT_SSH

        // Step 5: Start SSH tunnel through DNSTT
        // DNSTT is a raw TCP tunnel — JSch connects directly to its local port
        configureSshBridge()
        val sshResult = withContext(Dispatchers.IO) {
            Log.i(TAG, "Starting SSH tunnel through DNSTT (${profile.sshHost}:${profile.sshPort} via 127.0.0.1:$dnsttPort)")
            SshTunnelBridge.startOverProxy(
                sshHost = profile.sshHost,
                sshPort = profile.sshPort,
                sshUsername = profile.sshUsername,
                sshPassword = profile.sshPassword,
                proxyHost = "127.0.0.1",
                proxyPort = dnsttPort,
                listenPort = proxyPort,
                listenHost = proxyHost,
                blockDirectDns = true,
                useServerDns = profile.useServerDns,
                sshAuthType = profile.sshAuthType,
                sshPrivateKey = profile.sshPrivateKey,
                sshKeyPassphrase = profile.sshKeyPassphrase
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
            TunnelType.SSH -> SshTunnelBridge.isRunning()
            TunnelType.DNSTT_SSH -> try { DnsttBridge.isRunning() } catch (e: Exception) { false }
            TunnelType.DOH -> DohBridge.isRunning()
            TunnelType.SNOWFLAKE -> SnowflakeBridge.isRunning()
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
        // Notify connection manager for bookkeeping (profile preferences, etc.)
        connectionManager.onVpnEstablished()

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
                        val socksHost = preferencesDataStore.proxyListenAddress.first()
                        val socksPort = preferencesDataStore.proxyListenPort.first()
                        val result = HttpProxyServer.start(
                            socksHost = socksHost,
                            socksPort = socksPort,
                            listenHost = socksHost,
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
                    TunnelType.SSH -> SshTunnelBridge.isRunning()
                    TunnelType.DNSTT_SSH -> try {
                        DnsttBridge.isRunning()
                    } catch (e: Exception) {
                        Log.e(TAG, "Error checking DNSTT state: ${e.message}")
                        true
                    }
                    TunnelType.DOH -> DohBridge.isRunning()
                    TunnelType.SNOWFLAKE -> SnowflakeBridge.isRunning()
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
     * Start periodic health check to detect if the Rust client has crashed
     * or if the connection has become stale.
     */
    private fun startHealthCheck() {
        healthCheckJob?.cancel()
        // Reset traffic monitoring state
        lastTrafficRxBytes = 0L
        lastTrafficTxBytes = 0L
        staleTrafficChecks = 0

        healthCheckJob = serviceScope.launch(Dispatchers.IO) {
            // Give the connection time to establish before monitoring
            delay(HEALTH_CHECK_INTERVAL_MS * 2)

            while (isActive) {
                delay(HEALTH_CHECK_INTERVAL_MS)

                // Re-acquire WakeLock periodically to keep it active
                acquireWakeLock()

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

                // Check traffic stats for stale connection detection (skip in proxy-only mode)
                if (!isProxyOnly) {
                    val stats = HevSocks5Tunnel.getStats()
                    if (stats != null) {
                        val currentRx = stats.rxBytes
                        val currentTx = stats.txBytes

                        // If traffic has changed, reset stale counter
                        if (currentRx != lastTrafficRxBytes || currentTx != lastTrafficTxBytes) {
                            if (staleTrafficChecks > 0) {
                                Log.d(TAG, "Traffic flowing again, resetting stale counter")
                            }
                            staleTrafficChecks = 0
                            lastTrafficRxBytes = currentRx
                            lastTrafficTxBytes = currentTx
                        } else {
                            // Traffic hasn't changed - might be stale
                            staleTrafficChecks++
                            Log.d(TAG, "No traffic change for $staleTrafficChecks checks (rx=$currentRx, tx=$currentTx)")

                            // If traffic has been stale for too long and we have some traffic history,
                            // the connection might be degraded
                            if (staleTrafficChecks >= STALE_TRAFFIC_THRESHOLD && (lastTrafficRxBytes > 0 || lastTrafficTxBytes > 0)) {
                                Log.w(TAG, "Connection appears stale - no traffic for ${staleTrafficChecks * HEALTH_CHECK_INTERVAL_MS}ms")
                                // Don't automatically reconnect on stale traffic alone -
                                // it could just be user not browsing
                                // Instead, we'll use this in combination with other signals
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Register for network connectivity changes to detect when we need to reconnect.
     */
    private fun registerNetworkCallback() {
        unregisterNetworkCallback() // Clean up any existing callback

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            private var currentNetwork: Network? = null
            private var initialized = false

            override fun onAvailable(network: Network) {
                Log.d(TAG, "Network available: $network")
                if (!initialized) {
                    // First callback after registration — just record the existing network
                    Log.d(TAG, "Initial network detected: $network (no reconnection)")
                    currentNetwork = network
                    updateTrackedAddresses(network)
                    initialized = true
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
                if (network == currentNetwork) {
                    currentNetwork = null
                    lastNetworkAddresses = emptySet()
                }
            }

            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                // Network capabilities changed - check if we still have internet
                val hasInternet = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                Log.d(TAG, "Network capabilities changed: $network, hasInternet=$hasInternet")
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                // Link properties changed - check for IP address changes
                val newAddresses = linkProperties.linkAddresses
                    .mapNotNull { it.address?.hostAddress }
                    .toSet()

                Log.d(TAG, "Link properties changed: $network, addresses=$newAddresses")

                // If IP addresses changed, we need to reconnect
                if (lastNetworkAddresses.isNotEmpty() && newAddresses != lastNetworkAddresses) {
                    val added = newAddresses - lastNetworkAddresses
                    val removed = lastNetworkAddresses - newAddresses
                    Log.i(TAG, "IP addresses changed: added=$added, removed=$removed")
                    debouncedReconnect("IP address change")
                }
                lastNetworkAddresses = newAddresses
            }

            private fun updateTrackedAddresses(network: Network) {
                try {
                    val linkProps = connectivityManager?.getLinkProperties(network)
                    lastNetworkAddresses = linkProps?.linkAddresses
                        ?.mapNotNull { it.address?.hostAddress }
                        ?.toSet() ?: emptySet()
                    Log.d(TAG, "Updated tracked addresses: $lastNetworkAddresses")
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
     * Waits 500ms before triggering reconnection in case more changes come in.
     */
    private fun debouncedReconnect(reason: String) {
        reconnectDebounceJob?.cancel()
        reconnectDebounceJob = serviceScope.launch {
            Log.d(TAG, "Debouncing reconnect for: $reason")
            delay(500) // Wait 500ms for network to stabilize
            handleNetworkChange(reason)
        }
    }

    /**
     * Handle network change by restarting the QUIC connection.
     * The Rust client has built-in reconnection logic, but we need to force it
     * when the network changes because the underlying sockets become stale.
     */
    private fun handleNetworkChange(reason: String = "unknown") {
        serviceScope.launch {
            // Prevent concurrent reconnection attempts
            if (isReconnecting) {
                Log.d(TAG, "Skipping reconnection for '$reason' - already reconnecting")
                return@launch
            }
            isReconnecting = true

            try {
                Log.i(TAG, "Handling network change ($reason) - restarting connection")

                // Stop health check during reconnection
                healthCheckJob?.cancel()

                // Get the current profile
                val profile = connectionManager.getProfileById(currentProfileId)
                if (profile == null) {
                    Log.e(TAG, "Cannot reconnect: profile not found")
                    return@launch
                }

                // Stop current tunnels
                if (!isProxyOnly) {
                    HevSocks5Tunnel.stop()
                }
                stopCurrentProxy()

                // Give native code time to clean up
                delay(500)

                val proxyPort = preferencesDataStore.proxyListenPort.first()
                val proxyHost = preferencesDataStore.proxyListenAddress.first()

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
                            useServerDns = profile.useServerDns,
                            sshAuthType = profile.sshAuthType,
                            sshPrivateKey = profile.sshPrivateKey,
                            sshKeyPassphrase = profile.sshKeyPassphrase
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
                } else if (currentTunnelType == TunnelType.DNSTT_SSH) {
                    // DNSTT+SSH: restart DNSTT on internal port, then SSH on proxyPort
                    val dnsttPort = proxyPort + 1

                    val dnsttResult = vpnRepository.startDnsttProxy(profile, portOverride = dnsttPort, hostOverride = "127.0.0.1")
                    if (dnsttResult.isFailure) {
                        Log.e(TAG, "Failed to restart DNSTT after network change", dnsttResult.exceptionOrNull())
                        handleTunnelFailure("failed to reconnect DNSTT+SSH after network change")
                        return@launch
                    }

                    if (!waitForProxyReady(dnsttPort, maxAttempts = 20, delayMs = 50)) {
                        Log.e(TAG, "DNSTT proxy failed to restart")
                        handleTunnelFailure("failed to reconnect DNSTT+SSH after network change")
                        return@launch
                    }

                    vpnRepository.setCurrentTunnelType(TunnelType.DNSTT_SSH)

                    // Connect SSH directly through DNSTT's local tunnel port
                    configureSshBridge()
                    val sshResult = withContext(Dispatchers.IO) {
                        SshTunnelBridge.startOverProxy(
                            sshHost = profile.sshHost,
                            sshPort = profile.sshPort,
                            sshUsername = profile.sshUsername,
                            sshPassword = profile.sshPassword,
                            proxyHost = "127.0.0.1",
                            proxyPort = dnsttPort,
                            listenPort = proxyPort,
                            listenHost = proxyHost,
                            blockDirectDns = true,
                            useServerDns = profile.useServerDns,
                            sshAuthType = profile.sshAuthType,
                            sshPrivateKey = profile.sshPrivateKey,
                            sshKeyPassphrase = profile.sshKeyPassphrase
                        )
                    }
                    if (sshResult.isFailure) {
                        Log.e(TAG, "Failed to restart SSH over DNSTT after network change", sshResult.exceptionOrNull())
                        handleTunnelFailure("failed to reconnect DNSTT+SSH after network change")
                        return@launch
                    }

                    if (!waitForProxyReady(proxyPort, maxAttempts = 30, delayMs = 50)) {
                        Log.e(TAG, "SSH SOCKS5 proxy failed to restart on port $proxyPort")
                        handleTunnelFailure("failed to reconnect DNSTT+SSH after network change")
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

                    if (!waitForProxyReady(slipstreamPort, maxAttempts = 20, delayMs = 50)) {
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
                            proxyPort = slipstreamPort,
                            listenPort = proxyPort,
                            listenHost = proxyHost,
                            blockDirectDns = true,
                            useServerDns = profile.useServerDns,
                            sshAuthType = profile.sshAuthType,
                            sshPrivateKey = profile.sshPrivateKey,
                            sshKeyPassphrase = profile.sshKeyPassphrase
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

                    if (!waitForProxyReady(slipstreamPort, maxAttempts = 20, delayMs = 50)) {
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
                        slipstreamPort = slipstreamPort,
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
                } else {
                    val proxyResult = when (currentTunnelType) {
                        TunnelType.DNSTT -> vpnRepository.startDnsttProxy(profile)
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

                // Restart tun2socks with existing VPN interface (skip in proxy-only mode)
                if (isProxyOnly) {
                    // In proxy-only mode, just mark as connected again
                    vpnRepository.setProxyConnected(profile)
                } else {
                    vpnInterface?.let { pfd ->
                        // All tunnel types now have user-facing SOCKS5 on proxyPort
                        val tun2socksResult = vpnRepository.startTun2Socks(profile, pfd)
                        if (tun2socksResult.isFailure) {
                            Log.e(TAG, "Failed to restart tun2socks", tun2socksResult.exceptionOrNull())
                            handleTunnelFailure("failed to reconnect after network change")
                            return@launch
                        }
                    }
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
                        // Append mode uses 127.0.0.1; hotspot mode uses proxyListenAddress
                        val socksHost = if (appendProxy) "127.0.0.1" else preferencesDataStore.proxyListenAddress.first()
                        val listenHost = if (appendProxy) "127.0.0.1" else socksHost
                        val result = HttpProxyServer.start(
                            socksHost = socksHost,
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
     */
    private fun stopCurrentProxy() {
        // Always stop HTTP proxy (it chains through whatever SOCKS5 proxy is running)
        HttpProxyServer.stop()

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
                Log.d(TAG, "Stopping DNSTT proxy")
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
            TunnelType.DOH -> {
                Log.d(TAG, "Stopping DoH proxy")
                DohBridge.stop()
            }
            TunnelType.SNOWFLAKE -> {
                Log.d(TAG, "Stopping Snowflake: TorSocksBridge first, then Snowflake+Tor")
                TorSocksBridge.stop()
                SnowflakeBridge.stopClient()
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
            TunnelType.SSH -> { /* SSH-only: no bridge reference to clear */ }
            TunnelType.DNSTT_SSH -> DnsttBridge.setVpnService(null)
            TunnelType.DOH -> { /* DOH: no bridge reference to clear */ }
            TunnelType.SNOWFLAKE -> { /* Snowflake: no bridge reference to clear */ }
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
            TunnelType.DNSTT -> DnsttBridge.isClientHealthy()
            TunnelType.SSH -> SshTunnelBridge.isClientHealthy()
            TunnelType.DNSTT_SSH -> DnsttBridge.isClientHealthy() && SshTunnelBridge.isClientHealthy()
            TunnelType.DOH -> DohBridge.isClientHealthy()
            TunnelType.SNOWFLAKE -> SnowflakeBridge.isClientHealthy() && TorSocksBridge.isClientHealthy()
        }
    }

    private suspend fun establishVpnInterface(dnsServer: String): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("SlipNet VPN")
            .setMtu(VPN_MTU)
            .addAddress(VPN_ADDRESS, 32)
            .addRoute(VPN_ROUTE, 0)
            .addDnsServer(dnsServer)
            .setBlocking(false)

        val needsSelfExclusion = currentTunnelType == TunnelType.DNSTT ||
                currentTunnelType == TunnelType.SSH ||
                currentTunnelType == TunnelType.DNSTT_SSH ||
                currentTunnelType == TunnelType.DOH ||
                currentTunnelType == TunnelType.SLIPSTREAM ||
                currentTunnelType == TunnelType.SNOWFLAKE

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
                // Always use 127.0.0.1 for SOCKS5 upstream — the tunnel bridge is local.
                // Using proxyListenAddress (0.0.0.0) as a connection target is unreliable.
                if (!HttpProxyServer.isRunning()) {
                    val result = HttpProxyServer.start(
                        socksHost = "127.0.0.1",
                        socksPort = socksPort,
                        listenHost = "127.0.0.1",
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

        // Cancel any in-progress connection attempt
        connectJob?.cancel()
        connectJob = null

        // Cancel any in-progress reconnection immediately — before the coroutine.
        // This prevents a race where the reconnect coroutine is mid-flight in native
        // code (e.g., starting Slipstream on port 1081) while disconnect also tries
        // to stop/start, leading to "port already in use" on the next connect.
        reconnectDebounceJob?.cancel()
        reconnectDebounceJob = null
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
            releaseWakeLock()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    /**
     * Handle tunnel failure with kill switch support.
     * If kill switch is enabled and we have a VPN interface, enters kill switch mode
     * (keeps TUN alive to block traffic). Otherwise, does the original teardown.
     */
    private suspend fun handleTunnelFailure(reason: String) {
        val killSwitchEnabled = preferencesDataStore.killSwitch.first()
        if (killSwitchEnabled && !isProxyOnly && vpnInterface != null) {
            enterKillSwitchMode(reason)
        } else {
            connectionManager.onVpnError("VPN connection lost - $reason")
            cleanupConnection()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
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
     * Clean up all resources - must be called before stopping service.
     * This is a suspend function to run blocking operations on IO dispatcher.
     */
    private suspend fun cleanupConnection() {
        Log.d(TAG, "Cleaning up connection resources")

        // Stop health monitoring
        healthCheckJob?.cancel()
        healthCheckJob = null

        // Cancel any pending reconnect
        reconnectDebounceJob?.cancel()
        reconnectDebounceJob = null
        isReconnecting = false

        // Unregister network callback (must be on main thread)
        unregisterNetworkCallback()
        lastNetworkAddresses = emptySet()

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
        connectJob?.cancel()
        connectJob = null
        reconnectDebounceJob?.cancel()
        reconnectDebounceJob = null
        isReconnecting = false
        stateObserverJob?.cancel()
        stateObserverJob = null
        disconnectJob = serviceScope.launch {
            Log.i(TAG, "Disconnecting VPN (revoked)")
            clearConnectionState()
            cleanupConnection()
            connectionManager.onVpnDisconnected()
            releaseWakeLock()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
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
        if (wasActive && !isUserInitiatedDisconnect && !isKillSwitchActive && !isReconnecting) {
            Log.i(TAG, "Unexpected disconnect detected, showing notification")
            val notification = notificationHelper.createDisconnectedNotification(profileName, profileId)
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.notify(NotificationHelper.DISCONNECT_NOTIFICATION_ID, notification)
        }

        // Release WakeLock
        releaseWakeLock()

        serviceScope.cancel()
        super.onDestroy()
    }

    /**
     * Synchronous cleanup that doesn't wait for native threads.
     * Used in onDestroy where we can't suspend.
     */
    private fun cleanupConnectionSync() {
        Log.d(TAG, "Quick cleanup (sync)")

        // Stop health monitoring
        healthCheckJob?.cancel()
        healthCheckJob = null

        // Cancel any pending reconnect
        reconnectDebounceJob?.cancel()
        reconnectDebounceJob = null
        isReconnecting = false

        // Unregister network callback
        unregisterNetworkCallback()
        lastNetworkAddresses = emptySet()

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
