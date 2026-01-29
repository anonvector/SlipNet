package app.slipnet

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import dagger.hilt.android.HiltAndroidApp

@HiltAndroidApp
class SlipNetApp : Application() {

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
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
        }
    }

    companion object {
        const val CHANNEL_VPN_STATUS = "vpn_status"
        const val CHANNEL_CONNECTION_EVENTS = "connection_events"
    }
}
