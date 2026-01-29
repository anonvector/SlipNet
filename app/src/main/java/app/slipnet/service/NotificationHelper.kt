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
        private const val REQUEST_CODE_MAIN = 100
        private const val REQUEST_CODE_DISCONNECT = 101
    }

    fun createVpnNotification(
        state: ConnectionState
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
                    .setContentText("VPN is active")
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
