package app.slipnet.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.domain.repository.ProfileRepository
import app.slipnet.util.AppLog as Log
import dagger.hilt.android.AndroidEntryPoint
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import javax.inject.Inject

@AndroidEntryPoint
class BootReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "BootReceiver"
    }

    @Inject
    lateinit var preferencesDataStore: PreferencesDataStore

    @Inject
    lateinit var profileRepository: ProfileRepository

    @Inject
    lateinit var connectionManager: VpnConnectionManager

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) {
            return
        }

        val pendingResult = goAsync()
        val appContext = context.applicationContext

        scope.launch {
            try {
                val autoConnect = preferencesDataStore.autoConnectOnBoot.first()
                if (!autoConnect) {
                    return@launch
                }

                // Get active or last connected profile
                val profile = profileRepository.getActiveProfile().first()
                    ?: getLastConnectedProfile()
                    ?: return@launch

                // Check if we have VPN permission (must have been granted before)
                val vpnIntent = VpnService.prepare(appContext)
                if (vpnIntent != null) {
                    // VPN permission not granted, can't auto-connect
                    return@launch
                }

                // Start VPN service (tagged as boot-triggered so the service can
                // retry with backoff if network isn't available yet)
                val serviceIntent = Intent(appContext, SlipNetVpnService::class.java).apply {
                    action = SlipNetVpnService.ACTION_CONNECT
                    putExtra(SlipNetVpnService.EXTRA_PROFILE_ID, profile.id)
                    putExtra(SlipNetVpnService.EXTRA_BOOT_TRIGGERED, true)
                }
                ContextCompat.startForegroundService(appContext, serviceIntent)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to auto-connect on boot", e)
            } finally {
                pendingResult.finish()
            }
        }
    }

    private suspend fun getLastConnectedProfile() =
        preferencesDataStore.lastConnectedProfileId.first()?.let { id ->
            profileRepository.getProfileById(id)
        }
}
