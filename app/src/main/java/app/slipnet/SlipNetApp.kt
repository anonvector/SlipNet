package app.slipnet

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import app.slipnet.data.local.datastore.PreferencesDataStore
import dagger.hilt.android.HiltAndroidApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltAndroidApp
class SlipNetApp : Application() {

    @Inject lateinit var preferencesDataStore: PreferencesDataStore

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
        appScope.launch { preferencesDataStore.ensureProxyPortInitialized() }
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val notificationManager = getSystemService(NotificationManager::class.java)

            // VPN Status Channel
            val vpnChannel = NotificationChannel(
                CHANNEL_VPN_STATUS,
                "VPN Status",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows current VPN connection status"
                setShowBadge(false)
            }
            notificationManager.createNotificationChannel(vpnChannel)

            // Connection Events Channel
            val eventsChannel = NotificationChannel(
                CHANNEL_CONNECTION_EVENTS,
                "Connection Events",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Notifications for VPN connection events"
            }
            notificationManager.createNotificationChannel(eventsChannel)

            // DNS Scan Status Channel
            val scanChannel = NotificationChannel(
                CHANNEL_SCAN_STATUS,
                "DNS Scan",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows DNS resolver scan progress"
                setShowBadge(false)
            }
            notificationManager.createNotificationChannel(scanChannel)
        }
    }

    companion object {
        const val CHANNEL_VPN_STATUS = "vpn_status"
        const val CHANNEL_CONNECTION_EVENTS = "connection_events"
        const val CHANNEL_SCAN_STATUS = "scan_status"
    }
}
