package app.slipnet.service

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import app.slipnet.R
import app.slipnet.SlipNetApp
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.TrafficStats
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
        private const val REQUEST_CODE_AUTO_RECONNECT_CANCEL = 104
        const val AUTO_RECONNECT_NOTIFICATION_ID = 4
        const val PROBE_FAIL_NOTIFICATION_ID = 5
        private const val REQUEST_CODE_PROBE_RECONNECT = 105
        const val SCAN_NOTIFICATION_ID = 6
        private const val REQUEST_CODE_SCAN_STOP = 106
        private const val REQUEST_CODE_BOOT_RETRY_CANCEL = 107
    }

    private fun createServicePendingIntent(
        requestCode: Int,
        intent: Intent,
        foreground: Boolean = false
    ): PendingIntent {
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        return if (foreground && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            PendingIntent.getForegroundService(context, requestCode, intent, flags)
        } else {
            PendingIntent.getService(context, requestCode, intent, flags)
        }
    }

    fun createVpnNotification(
        state: ConnectionState,
        isProxyOnly: Boolean = false,
        trafficStats: TrafficStats? = null,
        uploadSpeed: Long = 0,
        downloadSpeed: Long = 0
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
            .setSmallIcon(R.drawable.ic_shield)
            .setContentIntent(mainPendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setSortKey("0") // Pin position so frequent updates don't cause reordering
            .setWhen(0) // Fixed timestamp prevents MIUI/HyperOS from reordering on update
            .setShowWhen(false)

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
                val disconnectPendingIntent = createServicePendingIntent(
                    requestCode = REQUEST_CODE_DISCONNECT,
                    intent = disconnectIntent
                )

                val reconnectIntent = Intent(context, SlipNetVpnService::class.java).apply {
                    action = SlipNetVpnService.ACTION_RECONNECT
                }
                val reconnectPendingIntent = createServicePendingIntent(
                    requestCode = REQUEST_CODE_RECONNECT,
                    intent = reconnectIntent
                )

                val bodyText = if (trafficStats != null && trafficStats.totalBytes > 0) {
                    "\u2191 ${trafficStats.formatBytesSent()}  \u2193 ${trafficStats.formatBytesReceived()}"
                } else {
                    if (isProxyOnly) "Proxy is active" else "VPN is active"
                }

                if (trafficStats != null && (uploadSpeed > 0 || downloadSpeed > 0)) {
                    builder.setSubText("\u2191 ${TrafficStats.formatSpeed(uploadSpeed)}  \u2193 ${TrafficStats.formatSpeed(downloadSpeed)}")
                }

                builder
                    .setContentTitle("Connected: ${state.profile.name}")
                    .setContentText(bodyText)
                    .addAction(
                        R.drawable.ic_shield,
                        "Reconnect",
                        reconnectPendingIntent
                    )
                    .addAction(
                        R.drawable.ic_shield,
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
        val disconnectPendingIntent = createServicePendingIntent(
            requestCode = REQUEST_CODE_DISCONNECT,
            intent = disconnectIntent
        )

        return NotificationCompat.Builder(context, SlipNetApp.CHANNEL_VPN_STATUS)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("Traffic blocked \u2014 Kill switch active")
            .setContentText("Reconnecting to $profileName\u2026")
            .setContentIntent(mainPendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .addAction(R.drawable.ic_shield, "Disconnect", disconnectPendingIntent)
            .build()
    }

    fun createAutoReconnectNotification(
        profileName: String,
        attempt: Int,
        maxAttempts: Int
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

        val disconnectIntent = Intent(context, SlipNetVpnService::class.java).apply {
            action = SlipNetVpnService.ACTION_DISCONNECT
        }
        val disconnectPendingIntent = createServicePendingIntent(
            requestCode = REQUEST_CODE_AUTO_RECONNECT_CANCEL,
            intent = disconnectIntent
        )

        return NotificationCompat.Builder(context, SlipNetApp.CHANNEL_VPN_STATUS)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("Reconnecting to $profileName\u2026")
            .setContentText("Attempt $attempt of $maxAttempts")
            .setContentIntent(mainPendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .addAction(R.drawable.ic_shield, "Cancel", disconnectPendingIntent)
            .build()
    }

    fun createBootRetryNotification(
        profileName: String,
        attempt: Int,
        maxAttempts: Int
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

        val disconnectIntent = Intent(context, SlipNetVpnService::class.java).apply {
            action = SlipNetVpnService.ACTION_DISCONNECT
        }
        val disconnectPendingIntent = createServicePendingIntent(
            requestCode = REQUEST_CODE_BOOT_RETRY_CANCEL,
            intent = disconnectIntent
        )

        return NotificationCompat.Builder(context, SlipNetApp.CHANNEL_VPN_STATUS)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("Waiting for network\u2026")
            .setContentText("Attempt $attempt of $maxAttempts \u2014 ${profileName.ifEmpty { "VPN" }}")
            .setContentIntent(mainPendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .addAction(R.drawable.ic_shield, "Cancel", disconnectPendingIntent)
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
        val reconnectPendingIntent = createServicePendingIntent(
            requestCode = REQUEST_CODE_RECONNECT,
            intent = reconnectIntent,
            foreground = true
        )

        return NotificationCompat.Builder(context, SlipNetApp.CHANNEL_CONNECTION_EVENTS)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("Connection Lost")
            .setContentText(message)
            .setContentIntent(mainPendingIntent)
            .addAction(R.drawable.ic_shield, "Reconnect", reconnectPendingIntent)
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
            .setSmallIcon(R.drawable.ic_shield)
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
        val reconnectPendingIntent = createServicePendingIntent(
            requestCode = REQUEST_CODE_RECONNECT_DISCONNECT,
            intent = reconnectIntent,
            foreground = true
        )

        return NotificationCompat.Builder(context, SlipNetApp.CHANNEL_CONNECTION_EVENTS)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("VPN Disconnected")
            .setContentText("Connection to $profileName was interrupted")
            .setContentIntent(mainPendingIntent)
            .addAction(R.drawable.ic_shield, "Reconnect", reconnectPendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
    }

    fun createProbeFailNotification(profileId: Long): Notification {
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
        val reconnectPendingIntent = createServicePendingIntent(
            requestCode = REQUEST_CODE_PROBE_RECONNECT,
            intent = reconnectIntent,
            foreground = true
        )

        return NotificationCompat.Builder(context, SlipNetApp.CHANNEL_CONNECTION_EVENTS)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("Tunnel not passing traffic")
            .setContentText("The VPN tunnel appears to be broken")
            .setContentIntent(mainPendingIntent)
            .addAction(R.drawable.ic_shield, "Reconnect", reconnectPendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
    }

    fun createScanNotification(
        scannedCount: Int,
        totalCount: Int,
        workingCount: Int,
        isE2eRunning: Boolean = false
    ): Notification {
        val mainIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val mainPendingIntent = PendingIntent.getActivity(
            context,
            REQUEST_CODE_MAIN,
            mainIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = Intent(context, ScanService::class.java).apply {
            action = ScanService.ACTION_STOP
        }
        val stopPendingIntent = createServicePendingIntent(
            requestCode = REQUEST_CODE_SCAN_STOP,
            intent = stopIntent
        )

        val title = when {
            isE2eRunning && scannedCount >= totalCount && totalCount > 0 -> "Testing tunnel connections"
            isE2eRunning -> "Scanning & testing resolvers"
            else -> "Scanning DNS resolvers"
        }
        val text = if (totalCount > 0) {
            "$scannedCount / $totalCount checked  \u2022  $workingCount working"
        } else {
            "Starting scan\u2026"
        }

        return NotificationCompat.Builder(context, SlipNetApp.CHANNEL_SCAN_STATUS)
            .setSmallIcon(R.drawable.ic_search)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(mainPendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setProgress(totalCount, scannedCount, totalCount == 0)
            .addAction(R.drawable.ic_search, "Stop", stopPendingIntent)
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
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(title)
            .setContentText(message)
            .setContentIntent(mainPendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .build()
    }
}
