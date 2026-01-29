package app.slipnet.service

import android.content.Context
import android.content.Intent
import android.os.ParcelFileDescriptor
import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.data.repository.VpnRepositoryImpl
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.LogEventType
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.repository.ConnectionLogRepository
import app.slipnet.domain.repository.ProfileRepository
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class VpnConnectionManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val vpnRepository: VpnRepositoryImpl,
    private val profileRepository: ProfileRepository,
    private val logRepository: ConnectionLogRepository,
    private val preferencesDataStore: PreferencesDataStore
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    private val _connectionState = MutableStateFlow<ConnectionState>(ConnectionState.Disconnected)
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    private var pendingProfile: ServerProfile? = null

    init {
        // Observe VPN repository state
        scope.launch {
            vpnRepository.connectionState.collect { state ->
                _connectionState.value = state
            }
        }
    }

    fun connect(profile: ServerProfile) {
        if (_connectionState.value is ConnectionState.Connected ||
            _connectionState.value is ConnectionState.Connecting) {
            return
        }

        pendingProfile = profile
        _connectionState.value = ConnectionState.Connecting

        // Start VPN service
        val intent = Intent(context, SlipNetVpnService::class.java).apply {
            action = SlipNetVpnService.ACTION_CONNECT
            putExtra(SlipNetVpnService.EXTRA_PROFILE_ID, profile.id)
        }
        context.startForegroundService(intent)

        scope.launch {
            logRepository.addLog(
                profileId = profile.id,
                profileName = profile.name,
                eventType = LogEventType.CONNECT_START,
                message = "Initiating connection to ${profile.domain}"
            )
        }
    }

    fun disconnect() {
        if (_connectionState.value is ConnectionState.Disconnected) {
            return
        }

        _connectionState.value = ConnectionState.Disconnecting

        val intent = Intent(context, SlipNetVpnService::class.java).apply {
            action = SlipNetVpnService.ACTION_DISCONNECT
        }
        context.startService(intent)
    }

    fun onVpnEstablished(pfd: ParcelFileDescriptor, vpnProtect: ((java.net.DatagramSocket) -> Boolean)?) {
        val profile = pendingProfile ?: return

        scope.launch {
            val result = vpnRepository.startWithFd(profile, pfd, vpnProtect)
            if (result.isSuccess) {
                _connectionState.value = ConnectionState.Connected(profile)
                preferencesDataStore.setLastConnectedProfileId(profile.id)
                profileRepository.setActiveProfile(profile.id)

                logRepository.addLog(
                    profileId = profile.id,
                    profileName = profile.name,
                    eventType = LogEventType.CONNECT_SUCCESS,
                    message = "Connected to ${profile.domain}"
                )
            } else {
                _connectionState.value = ConnectionState.Error(
                    result.exceptionOrNull()?.message ?: "Unknown error"
                )

                logRepository.addLog(
                    profileId = profile.id,
                    profileName = profile.name,
                    eventType = LogEventType.CONNECT_FAILED,
                    message = "Failed to connect",
                    details = result.exceptionOrNull()?.message
                )
            }
        }
    }

    fun onVpnDisconnected() {
        val currentState = _connectionState.value
        val profile = when (currentState) {
            is ConnectionState.Connected -> currentState.profile
            else -> pendingProfile
        }

        scope.launch {
            vpnRepository.disconnect()
            _connectionState.value = ConnectionState.Disconnected
            pendingProfile = null

            if (profile != null) {
                logRepository.addLog(
                    profileId = profile.id,
                    profileName = profile.name,
                    eventType = LogEventType.DISCONNECT,
                    message = "Disconnected from ${profile.domain}"
                )
            }
        }
    }

    fun onVpnError(error: String) {
        val profile = pendingProfile

        scope.launch {
            _connectionState.value = ConnectionState.Error(error)

            if (profile != null) {
                logRepository.addLog(
                    profileId = profile.id,
                    profileName = profile.name,
                    eventType = LogEventType.ERROR,
                    message = "VPN Error",
                    details = error
                )
            }
        }
    }

    suspend fun getProfileById(id: Long): ServerProfile? {
        return profileRepository.getProfileById(id)
    }

    suspend fun getActiveProfile(): ServerProfile? {
        return profileRepository.getActiveProfile().first()
    }

    suspend fun shouldAutoConnect(): Boolean {
        return preferencesDataStore.autoConnectOnBoot.first()
    }

    suspend fun getLastConnectedProfile(): ServerProfile? {
        val lastProfileId = preferencesDataStore.lastConnectedProfileId.first() ?: return null
        return profileRepository.getProfileById(lastProfileId)
    }
}
