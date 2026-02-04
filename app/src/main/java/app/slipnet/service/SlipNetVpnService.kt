package app.slipnet.service

import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import app.slipnet.data.repository.VpnRepositoryImpl
import app.slipnet.domain.model.ConnectionState
import app.slipnet.tunnel.SlipstreamBridge
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class SlipNetVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "app.slipnet.CONNECT"
        const val ACTION_DISCONNECT = "app.slipnet.DISCONNECT"
        const val EXTRA_PROFILE_ID = "profile_id"

        private const val VPN_MTU = 1500
        private const val VPN_ADDRESS = "10.255.255.1"
        private const val VPN_ROUTE = "0.0.0.0"
        private const val DEFAULT_DNS = "8.8.8.8"
    }

    @Inject
    lateinit var connectionManager: VpnConnectionManager

    @Inject
    lateinit var vpnRepository: VpnRepositoryImpl

    @Inject
    lateinit var notificationHelper: NotificationHelper

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
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
        }

        return START_STICKY
    }

    private fun connect(profileId: Long) {
        serviceScope.launch {
            val profile = connectionManager.getProfileById(profileId)
            if (profile == null) {
                connectionManager.onVpnError("Profile not found")
                stopSelf()
                return@launch
            }

            // Show connecting notification
            val notification = notificationHelper.createVpnNotification(ConnectionState.Connecting)
            startForeground(NotificationHelper.VPN_NOTIFICATION_ID, notification)

            try {
                // Step 1: Set VpnService reference for socket protection BEFORE starting tunnel
                SlipstreamBridge.setVpnService(this@SlipNetVpnService)

                // Step 2: Start Slipstream SOCKS5 proxy FIRST, before establishing VPN interface
                // This ensures the proxy is ready when traffic starts flowing
                val proxyResult = vpnRepository.startSlipstreamProxy(profile)
                if (proxyResult.isFailure) {
                    connectionManager.onVpnError(proxyResult.exceptionOrNull()?.message ?: "Failed to start proxy")
                    SlipstreamBridge.setVpnService(null)
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                    return@launch
                }

                // Step 3: Now establish VPN interface - traffic will start routing through it
                val dnsServer = profile.resolvers.firstOrNull()?.host ?: DEFAULT_DNS
                vpnInterface = establishVpnInterface(dnsServer)

                if (vpnInterface == null) {
                    connectionManager.onVpnError("Failed to establish VPN interface")
                    SlipstreamBridge.stopClient()
                    SlipstreamBridge.setVpnService(null)
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                    return@launch
                }

                // Step 4: Start tun2socks to route TUN traffic through the SOCKS5 proxy
                val tun2socksResult = vpnRepository.startTun2Socks(profile, vpnInterface!!)
                if (tun2socksResult.isFailure) {
                    connectionManager.onVpnError(tun2socksResult.exceptionOrNull()?.message ?: "Failed to start tunnel")
                    vpnInterface?.close()
                    vpnInterface = null
                    SlipstreamBridge.setVpnService(null)
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                    return@launch
                }

                // Notify connection manager for bookkeeping (profile preferences, etc.)
                connectionManager.onVpnEstablished()

                // Update notification to connected state
                observeConnectionState()

            } catch (e: Exception) {
                connectionManager.onVpnError(e.message ?: "Unknown error")
                SlipstreamBridge.setVpnService(null)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun establishVpnInterface(dnsServer: String): ParcelFileDescriptor? {
        return Builder()
            .setSession("Slipstream VPN")
            .setMtu(VPN_MTU)
            .addAddress(VPN_ADDRESS, 32)
            .addRoute(VPN_ROUTE, 0)
            .addDnsServer(dnsServer)
            .setBlocking(false)
            .establish()
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
            connectionManager.onVpnDisconnected()
            SlipstreamBridge.setVpnService(null)
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    override fun onRevoke() {
        super.onRevoke()
        disconnect()
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
        vpnInterface?.close()
    }
}
