package app.slipnet.service

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import app.slipnet.R
import app.slipnet.SlipNetApp
import app.slipnet.domain.model.ConnectionState
import app.slipnet.presentation.MainActivity
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class NotificationHelper @Inject constructor(
    @ApplicationContext private val context: Context
) {
    companion object {
        const val VPN_NOTIFICATION_ID = 1
        const val RECONNECT_NOTIFICATION_ID = 2
        const val DISCONNECT_NOTIFICATION_ID = 3
        private const val REQUEST_CODE_MAIN = 100
        private const val REQUEST_CODE_DISCONNECT = 101
        private const val REQUEST_CODE_RECONNECT = 102
        private const val REQUEST_CODE_RECONNECT_DISCONNECT = 103
    }

    fun createVpnNotification(
        state: ConnectionState,
        isProxyOnly: Boolean = false
    ): Notification {
        val mainIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val mainPendingIntent = PendingIntent.getActivity(
            context,
            REQUEST_CODE_MAIN,
            mainIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val builder = NotificationCompat.Builder(context, SlipNetApp.CHANNEL_VPN_STATUS)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setContentIntent(mainPendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)

        when (state) {
            is ConnectionState.Disconnected -> {
                builder
                    .setContentTitle("Slipstream VPN")
                    .setContentText("Disconnected")
            }
            is ConnectionState.Connecting -> {
                builder
                    .setContentTitle("Slipstream VPN")
                    .setContentText("Connecting...")
                    .setProgress(0, 0, true)
            }
            is ConnectionState.Connected -> {
                val disconnectIntent = Intent(context, SlipNetVpnService::class.java).apply {
                    action = SlipNetVpnService.ACTION_DISCONNECT
                }
                val disconnectPendingIntent = PendingIntent.getService(
                    context,
                    REQUEST_CODE_DISCONNECT,
                    disconnectIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )

                builder
                    .setContentTitle("Connected: ${state.profile.name}")
                    .setContentText(if (isProxyOnly) "Proxy is active" else "VPN is active")
                    .addAction(
                        R.drawable.ic_vpn_key,
                        "Disconnect",
                        disconnectPendingIntent
                    )
            }
            is ConnectionState.Disconnecting -> {
                builder
                    .setContentTitle("Slipstream VPN")
                    .setContentText("Disconnecting...")
                    .setProgress(0, 0, true)
            }
            is ConnectionState.Error -> {
                builder
                    .setContentTitle("Slipstream VPN")
                    .setContentText("Error: ${state.message}")
            }
        }

        return builder.build()
    }

    fun createKillSwitchNotification(profileName: String): Notification {
        val mainIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val mainPendingIntent = PendingIntent.getActivity(
            context,
            REQUEST_CODE_MAIN,
            mainIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val disconnectIntent = Intent(context, SlipNetVpnService::class.java).apply {
            action = SlipNetVpnService.ACTION_DISCONNECT
        }
        val disconnectPendingIntent = PendingIntent.getService(
            context,
            REQUEST_CODE_DISCONNECT,
            disconnectIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(context, SlipNetApp.CHANNEL_VPN_STATUS)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setContentTitle("Traffic blocked \u2014 Kill switch active")
            .setContentText("Reconnecting to $profileName\u2026")
            .setContentIntent(mainPendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .addAction(R.drawable.ic_vpn_key, "Disconnect", disconnectPendingIntent)
            .build()
    }

    fun createReconnectNotification(
        message: String,
        profileId: Long
    ): Notification {
        val mainIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val mainPendingIntent = PendingIntent.getActivity(
            context,
            REQUEST_CODE_MAIN,
            mainIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val reconnectIntent = Intent(context, SlipNetVpnService::class.java).apply {
            action = SlipNetVpnService.ACTION_CONNECT
            putExtra(SlipNetVpnService.EXTRA_PROFILE_ID, profileId)
        }
        val reconnectPendingIntent = PendingIntent.getService(
            context,
            REQUEST_CODE_RECONNECT,
            reconnectIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(context, SlipNetApp.CHANNEL_CONNECTION_EVENTS)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setContentTitle("Connection Lost")
            .setContentText(message)
            .setContentIntent(mainPendingIntent)
            .addAction(R.drawable.ic_vpn_key, "Reconnect", reconnectPendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
    }

    fun createSmartConnectNotification(
        transportName: String,
        attempt: Int,
        total: Int
    ): Notification {
        val mainIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val mainPendingIntent = PendingIntent.getActivity(
            context,
            REQUEST_CODE_MAIN,
            mainIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(context, SlipNetApp.CHANNEL_VPN_STATUS)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setContentTitle("Smart Connect: Trying $transportName...")
            .setContentText("Attempt $attempt of $total")
            .setContentIntent(mainPendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setProgress(total, attempt, false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    fun createDisconnectedNotification(
        profileName: String,
        profileId: Long
    ): Notification {
        val mainIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val mainPendingIntent = PendingIntent.getActivity(
            context,
            REQUEST_CODE_MAIN,
            mainIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val reconnectIntent = Intent(context, SlipNetVpnService::class.java).apply {
            action = SlipNetVpnService.ACTION_CONNECT
            putExtra(SlipNetVpnService.EXTRA_PROFILE_ID, profileId)
        }
        val reconnectPendingIntent = PendingIntent.getService(
            context,
            REQUEST_CODE_RECONNECT_DISCONNECT,
            reconnectIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(context, SlipNetApp.CHANNEL_CONNECTION_EVENTS)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setContentTitle("VPN Disconnected")
            .setContentText("Connection to $profileName was interrupted")
            .setContentIntent(mainPendingIntent)
            .addAction(R.drawable.ic_vpn_key, "Reconnect", reconnectPendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
    }

    fun createConnectionEventNotification(
        title: String,
        message: String
    ): Notification {
        val mainIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val mainPendingIntent = PendingIntent.getActivity(
            context,
            REQUEST_CODE_MAIN,
            mainIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(context, SlipNetApp.CHANNEL_CONNECTION_EVENTS)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setContentTitle(title)
            .setContentText(message)
            .setContentIntent(mainPendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .build()
    }
}
