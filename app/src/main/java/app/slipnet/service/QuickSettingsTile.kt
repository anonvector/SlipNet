package app.slipnet.service

import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import app.slipnet.domain.model.ConnectionState
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class QuickSettingsTile : TileService() {

    @Inject
    lateinit var connectionManager: VpnConnectionManager

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var stateObserverJob: Job? = null

    override fun onStartListening() {
        super.onStartListening()
        observeConnectionState()
    }

    override fun onStopListening() {
        super.onStopListening()
        stateObserverJob?.cancel()
        stateObserverJob = null
    }

    private fun observeConnectionState() {
        stateObserverJob?.cancel()
        stateObserverJob = serviceScope.launch {
            connectionManager.connectionState.collect { state ->
                updateTile(state)
            }
        }
    }

    private fun updateTile(state: ConnectionState) {
        qsTile?.let { tile ->
            when (state) {
                is ConnectionState.Disconnected -> {
                    tile.state = Tile.STATE_INACTIVE
                    tile.label = "Slipstream"
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        tile.subtitle = "Disconnected"
                    }
                }
                is ConnectionState.Connecting -> {
                    tile.state = Tile.STATE_ACTIVE
                    tile.label = "Slipstream"
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        tile.subtitle = "Connecting..."
                    }
                }
                is ConnectionState.Connected -> {
                    tile.state = Tile.STATE_ACTIVE
                    tile.label = "Slipstream"
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        tile.subtitle = state.profile.name
                    }
                }
                is ConnectionState.Disconnecting -> {
                    tile.state = Tile.STATE_INACTIVE
                    tile.label = "Slipstream"
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        tile.subtitle = "Disconnecting..."
                    }
                }
                is ConnectionState.Error -> {
                    tile.state = Tile.STATE_INACTIVE
                    tile.label = "Slipstream"
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        tile.subtitle = "Error"
                    }
                }
            }
            tile.updateTile()
        }
    }

    override fun onClick() {
        super.onClick()

        serviceScope.launch {
            val currentState = connectionManager.connectionState.value

            when (currentState) {
                is ConnectionState.Connected,
                is ConnectionState.Connecting -> {
                    connectionManager.disconnect()
                }
                is ConnectionState.Disconnected,
                is ConnectionState.Error -> {
                    // Try to connect to active or last connected profile
                    val profile = connectionManager.getActiveProfile()
                        ?: connectionManager.getLastConnectedProfile()

                    if (profile != null) {
                        // Check VPN permission
                        val vpnIntent = android.net.VpnService.prepare(this@QuickSettingsTile)
                        if (vpnIntent != null) {
                            // Need to request VPN permission - can't do from tile
                            // User needs to open the app
                            return@launch
                        }

                        connectionManager.connect(profile)
                    }
                }
                is ConnectionState.Disconnecting -> {
                    // Wait for disconnect to complete
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
    }
}
