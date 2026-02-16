package app.slipnet.widget

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.view.View
import android.widget.RemoteViews
import app.slipnet.R
import app.slipnet.domain.model.ConnectionState
import app.slipnet.presentation.MainActivity
import app.slipnet.service.VpnConnectionManager
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class VpnWidgetCompactProvider : AppWidgetProvider() {

    @Inject
    lateinit var connectionManager: VpnConnectionManager

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onUpdate(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetIds: IntArray
    ) {
        val state = if (::connectionManager.isInitialized) {
            connectionManager.connectionState.value
        } else {
            ConnectionState.Disconnected
        }

        for (appWidgetId in appWidgetIds) {
            val views = buildRemoteViews(context, state)
            appWidgetManager.updateAppWidget(appWidgetId, views)
        }
    }

    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)

        if (intent.action == ACTION_TOGGLE_VPN_COMPACT) {
            handleToggle(context)
        }
    }

    private fun handleToggle(context: Context) {
        if (!::connectionManager.isInitialized) return

        scope.launch {
            val currentState = connectionManager.connectionState.value

            when (currentState) {
                is ConnectionState.Connected,
                is ConnectionState.Connecting -> {
                    connectionManager.disconnect()
                }
                is ConnectionState.Disconnected,
                is ConnectionState.Error -> {
                    val profile = connectionManager.getActiveProfile()
                        ?: connectionManager.getLastConnectedProfile()
                        ?: return@launch

                    val vpnIntent = VpnService.prepare(context)
                    if (vpnIntent != null) {
                        val appIntent = Intent(context, MainActivity::class.java).apply {
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        }
                        context.startActivity(appIntent)
                        return@launch
                    }

                    connectionManager.connect(profile)
                }
                is ConnectionState.Disconnecting -> {
                    // Wait for disconnect to complete
                }
            }
        }
    }

    companion object {
        const val ACTION_TOGGLE_VPN_COMPACT = "app.slipnet.widget.TOGGLE_VPN_COMPACT"

        fun notifyStateChanged(context: Context, state: ConnectionState) {
            val appWidgetManager = AppWidgetManager.getInstance(context) ?: return
            val componentName = ComponentName(context, VpnWidgetCompactProvider::class.java)
            val appWidgetIds = appWidgetManager.getAppWidgetIds(componentName)

            if (appWidgetIds.isEmpty()) return

            val views = buildRemoteViews(context, state)
            for (appWidgetId in appWidgetIds) {
                appWidgetManager.updateAppWidget(appWidgetId, views)
            }
        }

        private fun buildRemoteViews(context: Context, state: ConnectionState): RemoteViews {
            val views = RemoteViews(context.packageName, R.layout.widget_vpn_compact)

            // Set tap action
            val toggleIntent = Intent(context, VpnWidgetCompactProvider::class.java).apply {
                action = ACTION_TOGGLE_VPN_COMPACT
            }
            val pendingIntent = PendingIntent.getBroadcast(
                context, 1, toggleIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            views.setOnClickPendingIntent(R.id.widget_compact_root, pendingIntent)

            // Update UI based on state
            when (state) {
                is ConnectionState.Disconnected -> {
                    views.setInt(R.id.widget_compact_root, "setBackgroundResource", R.drawable.widget_compact_bg_disconnected)
                    views.setInt(R.id.widget_compact_icon, "setColorFilter", 0xFF333333.toInt())
                    views.setViewVisibility(R.id.widget_compact_progress, View.GONE)
                }
                is ConnectionState.Connecting -> {
                    views.setInt(R.id.widget_compact_root, "setBackgroundResource", R.drawable.widget_compact_bg_connecting)
                    views.setInt(R.id.widget_compact_icon, "setColorFilter", 0xFFFFFFFF.toInt())
                    views.setViewVisibility(R.id.widget_compact_progress, View.VISIBLE)
                }
                is ConnectionState.Connected -> {
                    views.setInt(R.id.widget_compact_root, "setBackgroundResource", R.drawable.widget_compact_bg_connected)
                    views.setInt(R.id.widget_compact_icon, "setColorFilter", 0xFFFFFFFF.toInt())
                    views.setViewVisibility(R.id.widget_compact_progress, View.GONE)
                }
                is ConnectionState.Disconnecting -> {
                    views.setInt(R.id.widget_compact_root, "setBackgroundResource", R.drawable.widget_compact_bg_disconnected)
                    views.setInt(R.id.widget_compact_icon, "setColorFilter", 0xFF333333.toInt())
                    views.setViewVisibility(R.id.widget_compact_progress, View.VISIBLE)
                }
                is ConnectionState.Error -> {
                    views.setInt(R.id.widget_compact_root, "setBackgroundResource", R.drawable.widget_compact_bg_error)
                    views.setInt(R.id.widget_compact_icon, "setColorFilter", 0xFFFFFFFF.toInt())
                    views.setViewVisibility(R.id.widget_compact_progress, View.GONE)
                }
            }

            return views
        }
    }
}
