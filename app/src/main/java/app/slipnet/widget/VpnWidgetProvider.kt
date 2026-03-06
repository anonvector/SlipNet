package app.slipnet.widget

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.view.View
import android.widget.RemoteViews
import app.slipnet.R
import app.slipnet.domain.model.ConnectionState
import app.slipnet.service.VpnConnectionManager
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

@AndroidEntryPoint
class VpnWidgetProvider : AppWidgetProvider() {

    @Inject
    lateinit var connectionManager: VpnConnectionManager

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

    companion object {
        fun notifyStateChanged(context: Context, state: ConnectionState) {
            val appWidgetManager = AppWidgetManager.getInstance(context) ?: return
            val componentName = ComponentName(context, VpnWidgetProvider::class.java)
            val appWidgetIds = appWidgetManager.getAppWidgetIds(componentName)

            if (appWidgetIds.isEmpty()) return

            val views = buildRemoteViews(context, state)
            for (appWidgetId in appWidgetIds) {
                appWidgetManager.updateAppWidget(appWidgetId, views)
            }
        }

        private fun buildRemoteViews(context: Context, state: ConnectionState): RemoteViews {
            val views = RemoteViews(context.packageName, R.layout.widget_vpn_toggle)

            // Set tap action
            val toggleIntent = Intent(context, VpnWidgetToggleReceiver::class.java).apply {
                action = VpnWidgetToggleReceiver.ACTION_TOGGLE_VPN
            }
            val pendingIntent = PendingIntent.getBroadcast(
                context, 0, toggleIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            views.setOnClickPendingIntent(R.id.widget_root, pendingIntent)

            // Update UI based on state
            when (state) {
                is ConnectionState.Disconnected -> {
                    views.setInt(R.id.widget_root, "setBackgroundResource", R.drawable.widget_bg_disconnected)
                    views.setTextViewText(R.id.widget_status_text, "Disconnected")
                    views.setTextColor(R.id.widget_status_text, 0xFF333333.toInt())
                    views.setInt(R.id.widget_status_icon, "setColorFilter", 0xFF333333.toInt())
                    views.setInt(R.id.widget_icon_badge, "setBackgroundResource", R.drawable.widget_icon_circle_dark)
                    views.setViewVisibility(R.id.widget_profile_name, View.GONE)
                    views.setViewVisibility(R.id.widget_progress, View.GONE)
                }
                is ConnectionState.Connecting -> {
                    views.setInt(R.id.widget_root, "setBackgroundResource", R.drawable.widget_bg_connecting)
                    views.setTextViewText(R.id.widget_status_text, "Connecting...")
                    views.setTextColor(R.id.widget_status_text, 0xFFFFFFFF.toInt())
                    views.setInt(R.id.widget_status_icon, "setColorFilter", 0xFFFFFFFF.toInt())
                    views.setInt(R.id.widget_icon_badge, "setBackgroundResource", R.drawable.widget_icon_circle)
                    views.setViewVisibility(R.id.widget_profile_name, View.GONE)
                    views.setViewVisibility(R.id.widget_progress, View.VISIBLE)
                }
                is ConnectionState.Connected -> {
                    views.setInt(R.id.widget_root, "setBackgroundResource", R.drawable.widget_bg_connected)
                    views.setTextViewText(R.id.widget_status_text, "Connected")
                    views.setTextColor(R.id.widget_status_text, 0xFFFFFFFF.toInt())
                    views.setTextColor(R.id.widget_profile_name, 0xB3FFFFFF.toInt())
                    views.setInt(R.id.widget_status_icon, "setColorFilter", 0xFFFFFFFF.toInt())
                    views.setInt(R.id.widget_icon_badge, "setBackgroundResource", R.drawable.widget_icon_circle)
                    views.setTextViewText(R.id.widget_profile_name, state.profile.name)
                    views.setViewVisibility(R.id.widget_profile_name, View.VISIBLE)
                    views.setViewVisibility(R.id.widget_progress, View.GONE)
                }
                is ConnectionState.Disconnecting -> {
                    views.setInt(R.id.widget_root, "setBackgroundResource", R.drawable.widget_bg_disconnected)
                    views.setTextViewText(R.id.widget_status_text, "Disconnecting...")
                    views.setTextColor(R.id.widget_status_text, 0xFF333333.toInt())
                    views.setInt(R.id.widget_status_icon, "setColorFilter", 0xFF333333.toInt())
                    views.setInt(R.id.widget_icon_badge, "setBackgroundResource", R.drawable.widget_icon_circle_dark)
                    views.setViewVisibility(R.id.widget_profile_name, View.GONE)
                    views.setViewVisibility(R.id.widget_progress, View.VISIBLE)
                }
                is ConnectionState.Error -> {
                    views.setInt(R.id.widget_root, "setBackgroundResource", R.drawable.widget_bg_error)
                    views.setTextViewText(R.id.widget_status_text, "Error")
                    views.setTextColor(R.id.widget_status_text, 0xFFFFFFFF.toInt())
                    views.setInt(R.id.widget_status_icon, "setColorFilter", 0xFFFFFFFF.toInt())
                    views.setInt(R.id.widget_icon_badge, "setBackgroundResource", R.drawable.widget_icon_circle)
                    views.setViewVisibility(R.id.widget_profile_name, View.GONE)
                    views.setViewVisibility(R.id.widget_progress, View.GONE)
                }
            }

            return views
        }
    }
}
