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
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.util.Log
import app.slipnet.data.repository.VpnRepositoryImpl
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.TunnelType
import app.slipnet.tunnel.DnsttBridge
import app.slipnet.tunnel.HevSocks5Tunnel
import app.slipnet.tunnel.SlipstreamBridge
import app.slipnet.tunnel.SshTunnelBridge
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
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

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var healthCheckJob: Job? = null
    private var currentProfileId: Long = -1
    private var currentTunnelType: TunnelType = TunnelType.SLIPSTREAM
    private var sshEnabled = false
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastNetworkAddresses: Set<String> = emptySet()
    private var reconnectDebounceJob: Job? = null
    @Volatile
    private var isReconnecting = false

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
        serviceScope.launch {
            val profile = connectionManager.getProfileById(profileId)
            if (profile == null) {
                connectionManager.onVpnError("Profile not found")
                stopSelf()
                return@launch
            }

            currentProfileId = profileId

            // Show connecting notification
            val notification = notificationHelper.createVpnNotification(ConnectionState.Connecting)
            startForeground(NotificationHelper.VPN_NOTIFICATION_ID, notification)

            try {
                // Track the tunnel type for this connection
                currentTunnelType = profile.tunnelType
                Log.i(TAG, "Starting VPN with tunnel type: $currentTunnelType")

                val dnsServer = profile.resolvers.firstOrNull()?.host ?: DEFAULT_DNS

                // The startup order differs between tunnel types:
                // - Slipstream: Start proxy first (Rust uses protect_socket JNI callback)
                // - DNSTT: Establish VPN first (uses addDisallowedApplication for socket protection)
                when (currentTunnelType) {
                    TunnelType.SLIPSTREAM -> connectSlipstream(profile, dnsServer)
                    TunnelType.DNSTT -> connectDnstt(profile, dnsServer)
                }

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
     * Order: Set VpnService ref -> Start proxy -> Wait for ready -> VPN interface -> tun2socks -> wait QUIC
     */
    private suspend fun connectSlipstream(profile: app.slipnet.domain.model.ServerProfile, dnsServer: String) {
        sshEnabled = false

        // Step 1: Set VpnService reference for socket protection via JNI
        SlipstreamBridge.setVpnService(this@SlipNetVpnService)

        // Step 2: Start Slipstream proxy first
        val proxyResult = vpnRepository.startSlipstreamProxy(profile)
        if (proxyResult.isFailure) {
            connectionManager.onVpnError(proxyResult.exceptionOrNull()?.message ?: "Failed to start proxy")
            SlipstreamBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 2.5: Verify proxy is listening
        if (!waitForProxyReady(profile.tcpListenPort, maxAttempts = 20, delayMs = 100)) {
            handleProxyStartupFailure(profile.tcpListenPort)
            return
        }

        // Step 2.6: Wait for QUIC handshake before VPN setup
        val quicReady = waitForQuicReady(maxAttempts = 50, delayMs = 100)
        if (!quicReady) {
            Log.w(TAG, "QUIC connection not ready within timeout, continuing anyway")
        }

        // Step 3: Establish VPN interface
        vpnInterface = establishVpnInterface(dnsServer)
        if (vpnInterface == null) {
            connectionManager.onVpnError("Failed to establish VPN interface")
            stopCurrentProxy()
            SlipstreamBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 4: Start tun2socks
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
     * Connect using DNSTT tunnel type.
     * Order: Establish VPN interface (with app exclusion) -> Start proxy -> Wait for ready -> tun2socks
     *
     * IMPORTANT: VPN must be established BEFORE starting DNSTT so that addDisallowedApplication
     * is in effect when DNSTT creates its UDP sockets. This prevents a routing loop where
     * DNSTT's DNS queries would be captured by the VPN.
     */
    private suspend fun connectDnstt(profile: app.slipnet.domain.model.ServerProfile, dnsServer: String) {
        sshEnabled = profile.sshEnabled
        // When SSH is enabled, DNS tunnel listens on internal port
        val proxyPort = if (sshEnabled) profile.tcpListenPort + 1 else profile.tcpListenPort

        // Step 1: Set VpnService reference (for potential future use)
        DnsttBridge.setVpnService(this@SlipNetVpnService)

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

        // Step 3.5: Verify proxy is listening on internal port
        if (!waitForProxyReady(proxyPort, maxAttempts = 20, delayMs = 100)) {
            handleProxyStartupFailure(proxyPort)
            vpnInterface?.close()
            vpnInterface = null
            return
        }

        // Step 3.6: Start SSH tunnel if enabled
        if (sshEnabled) {
            val sshResult = startSshTunnel(profile)
            if (sshResult.isFailure) {
                connectionManager.onVpnError(sshResult.exceptionOrNull()?.message ?: "Failed to start SSH tunnel")
                stopCurrentProxy()
                vpnInterface?.close()
                vpnInterface = null
                DnsttBridge.setVpnService(null)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            // Wait for SSH SOCKS5 proxy on user-facing port
            if (!waitForProxyReady(profile.tcpListenPort, maxAttempts = 30, delayMs = 100)) {
                Log.e(TAG, "SSH SOCKS5 proxy failed to become ready")
                connectionManager.onVpnError("SSH tunnel failed to start")
                SshTunnelBridge.stop()
                stopCurrentProxy()
                vpnInterface?.close()
                vpnInterface = null
                DnsttBridge.setVpnService(null)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }
        }

        // Step 4: Start tun2socks
        val tun2socksResult = vpnRepository.startTun2Socks(profile, vpnInterface!!)
        if (tun2socksResult.isFailure) {
            connectionManager.onVpnError(tun2socksResult.exceptionOrNull()?.message ?: "Failed to start tunnel")
            vpnInterface?.close()
            vpnInterface = null
            if (sshEnabled) SshTunnelBridge.stop()
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
     * Handle proxy startup failure - common to both tunnel types.
     */
    private suspend fun handleProxyStartupFailure(port: Int) {
        val nativeRunning = when (currentTunnelType) {
            TunnelType.SLIPSTREAM -> try { SlipstreamBridge.isNativeRunning() } catch (e: Exception) { false }
            TunnelType.DNSTT -> try { DnsttBridge.isRunning() } catch (e: Exception) { false }
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
     * Start the SSH tunnel through the DNSTT tunnel.
     * DNSTT forwards raw TCP through the DNS tunnel to the remote SSH server.
     * JSch connects directly to the DNSTT port (no SOCKS5 handshake needed).
     * SSH is only supported for DNSTT tunnel type.
     */
    private suspend fun startSshTunnel(profile: app.slipnet.domain.model.ServerProfile): Result<Unit> {
        return withContext(Dispatchers.IO) {
            Log.i(TAG, "Starting SSH tunnel through DNSTT (direct mode)")
            SshTunnelBridge.startDirect(
                tunnelHost = profile.tcpListenHost,
                tunnelPort = profile.tcpListenPort + 1,
                sshUsername = profile.sshUsername,
                sshPassword = profile.sshPassword,
                listenPort = profile.tcpListenPort,
                listenHost = profile.tcpListenHost
            )
        }
    }

    /**
     * Finish connection setup - common to both tunnel types.
     */
    private fun finishConnection() {
        // Notify connection manager for bookkeeping (profile preferences, etc.)
        connectionManager.onVpnEstablished()

        // Save connection state for auto-restart if killed by system
        saveConnectionState(currentProfileId, connected = true)

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
                    TunnelType.DNSTT -> try {
                        DnsttBridge.isRunning()
                    } catch (e: Exception) {
                        Log.e(TAG, "Error checking DNSTT state: ${e.message}")
                        true // Assume it's running if we can't check
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
                val tunnelRunning = HevSocks5Tunnel.isRunning()

                if (!proxyHealthy || !tunnelRunning) {
                    Log.e(TAG, "Health check failed: proxy=$proxyHealthy (type=$currentTunnelType), tunnel=$tunnelRunning")
                    launch(Dispatchers.Main) {
                        connectionManager.onVpnError("VPN connection lost - native client stopped unexpectedly")
                        cleanupConnection()
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                    }
                    break
                }

                // Check traffic stats for stale connection detection
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

            override fun onAvailable(network: Network) {
                Log.d(TAG, "Network available: $network")
                if (currentNetwork != null && currentNetwork != network) {
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
                HevSocks5Tunnel.stop()
                stopCurrentProxy()

                // Give native code time to clean up
                delay(500)

                // When SSH is enabled (DNSTT only), DNS tunnel listens on internal port
                val proxyPort = if (sshEnabled && currentTunnelType == TunnelType.DNSTT) profile.tcpListenPort + 1 else profile.tcpListenPort

                // Restart the appropriate proxy
                val proxyResult = when (currentTunnelType) {
                    TunnelType.SLIPSTREAM -> vpnRepository.startSlipstreamProxy(profile)
                    TunnelType.DNSTT -> vpnRepository.startDnsttProxy(profile)
                }
                if (proxyResult.isFailure) {
                    Log.e(TAG, "Failed to restart proxy after network change", proxyResult.exceptionOrNull())
                    connectionManager.onVpnError("Failed to reconnect after network change")
                    cleanupConnection()
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                    return@launch
                }

                // Wait for proxy to be ready
                if (!waitForProxyReady(proxyPort, maxAttempts = 20, delayMs = 50)) {
                    Log.e(TAG, "Proxy failed to restart")
                    connectionManager.onVpnError("Failed to reconnect after network change")
                    cleanupConnection()
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                    return@launch
                }

                // Restart SSH tunnel if enabled (DNSTT only)
                if (sshEnabled && currentTunnelType == TunnelType.DNSTT) {
                    val sshResult = startSshTunnel(profile)
                    if (sshResult.isFailure) {
                        Log.e(TAG, "Failed to restart SSH tunnel after network change", sshResult.exceptionOrNull())
                        connectionManager.onVpnError("Failed to reconnect SSH after network change")
                        cleanupConnection()
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                        return@launch
                    }

                    // Wait for SSH SOCKS5 proxy on user-facing port
                    if (!waitForProxyReady(profile.tcpListenPort, maxAttempts = 30, delayMs = 50)) {
                        Log.e(TAG, "SSH SOCKS5 proxy failed to restart")
                        connectionManager.onVpnError("Failed to reconnect SSH after network change")
                        cleanupConnection()
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                        return@launch
                    }
                }

                // Restart tun2socks with existing VPN interface
                vpnInterface?.let { pfd ->
                    val tun2socksResult = vpnRepository.startTun2Socks(profile, pfd)
                    if (tun2socksResult.isFailure) {
                        Log.e(TAG, "Failed to restart tun2socks", tun2socksResult.exceptionOrNull())
                        connectionManager.onVpnError("Failed to reconnect after network change")
                        cleanupConnection()
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                        return@launch
                    }
                }

                // Wait for tunnel to be re-established
                if (currentTunnelType == TunnelType.SLIPSTREAM) {
                    val quicReady = waitForQuicReady(maxAttempts = 50, delayMs = 100)
                    if (!quicReady) {
                        Log.w(TAG, "QUIC connection not ready after reconnect, continuing anyway")
                    }
                } else {
                    // For DNSTT, give it a moment to re-establish
                    delay(500)
                }

                // Restart health check
                startHealthCheck()

                Log.i(TAG, "Successfully reconnected after network change (tunnel type: $currentTunnelType)")
            } finally {
                isReconnecting = false
            }
        }
    }

    /**
     * Stop the currently running proxy based on tunnel type.
     * Stops SSH first if enabled (DNSTT only), then the DNS tunnel.
     */
    private fun stopCurrentProxy() {
        // Stop SSH tunnel first if enabled
        if (sshEnabled) {
            Log.d(TAG, "Stopping SSH tunnel")
            SshTunnelBridge.stop()
        }

        when (currentTunnelType) {
            TunnelType.SLIPSTREAM -> {
                Log.d(TAG, "Stopping Slipstream proxy")
                SlipstreamBridge.stopClient()
            }
            TunnelType.DNSTT -> {
                Log.d(TAG, "Stopping DNSTT proxy")
                DnsttBridge.stopClient()
            }
        }
    }

    /**
     * Clear VPN service reference from the current bridge.
     */
    private fun clearVpnServiceRef() {
        when (currentTunnelType) {
            TunnelType.SLIPSTREAM -> SlipstreamBridge.setVpnService(null)
            TunnelType.DNSTT -> DnsttBridge.setVpnService(null)
        }
    }

    /**
     * Check if the current proxy is healthy.
     * When SSH is enabled, also checks SSH tunnel health.
     */
    private fun isCurrentProxyHealthy(): Boolean {
        // Check SSH health if enabled
        if (sshEnabled && !SshTunnelBridge.isClientHealthy()) {
            Log.w(TAG, "SSH tunnel is unhealthy")
            return false
        }

        return when (currentTunnelType) {
            TunnelType.SLIPSTREAM -> SlipstreamBridge.isClientHealthy()
            TunnelType.DNSTT -> DnsttBridge.isClientHealthy()
        }
    }

    private fun establishVpnInterface(dnsServer: String): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("SlipNet VPN")
            .setMtu(VPN_MTU)
            .addAddress(VPN_ADDRESS, 32)
            .addRoute(VPN_ROUTE, 0)
            .addDnsServer(dnsServer)
            .setBlocking(false)

        // Add secondary DNS servers for failover
        if (dnsServer != "8.8.8.8") {
            builder.addDnsServer("8.8.8.8")
        }
        if (dnsServer != "1.1.1.1") {
            builder.addDnsServer("1.1.1.1")
        }

        // For DNSTT tunnel type, exclude our own app from the VPN.
        // This is necessary because the Go DNSTT library doesn't have socket protection
        // callbacks like the Rust Slipstream client. By excluding our app, DNSTT's
        // UDP sockets to the DNS resolver automatically bypass the VPN tunnel.
        // For Slipstream, this isn't needed because Rust uses VpnService.protect() via JNI.
        if (currentTunnelType == TunnelType.DNSTT) {
            try {
                builder.addDisallowedApplication(packageName)
                Log.d(TAG, "Excluded app from VPN for DNSTT: $packageName")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to exclude app from VPN", e)
            }
        }

        return builder.establish()
    }

    private fun observeConnectionState() {
        serviceScope.launch {
            vpnRepository.connectionState.collect { state ->
                val notification = notificationHelper.createVpnNotification(state)
                val notificationManager = getSystemService(NotificationManager::class.java)
                notificationManager.notify(NotificationHelper.VPN_NOTIFICATION_ID, notification)

                when (state) {
                    is ConnectionState.Disconnected,
                    is ConnectionState.Error -> {
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                    }
                    else -> { }
                }
            }
        }
    }

    private fun disconnect() {
        serviceScope.launch {
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
            try {
                HevSocks5Tunnel.stop()
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping HevSocks5Tunnel", e)
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

        sshEnabled = false
        currentProfileId = -1
    }

    override fun onRevoke() {
        super.onRevoke()
        Log.i(TAG, "VPN permission revoked")
        disconnect()
    }

    override fun onDestroy() {
        Log.i(TAG, "Service onDestroy")

        // Quick non-blocking cleanup for onDestroy
        // Don't wait for native threads - they'll clean up themselves
        cleanupConnectionSync()

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

        // Request native tunnels to stop (non-blocking)
        // The native code will handle the actual shutdown
        try {
            HevSocks5Tunnel.stop()
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping HevSocks5Tunnel", e)
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

        sshEnabled = false
        currentProfileId = -1
    }
}
