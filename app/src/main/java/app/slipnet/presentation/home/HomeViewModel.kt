package app.slipnet.presentation.home

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TunnelType
import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.tunnel.SnowflakeBridge
import app.slipnet.domain.usecase.ConnectVpnUseCase
import app.slipnet.domain.usecase.DisconnectVpnUseCase
import app.slipnet.domain.usecase.GetActiveProfileUseCase
import app.slipnet.domain.usecase.GetProfilesUseCase
import app.slipnet.domain.usecase.SetActiveProfileUseCase
import app.slipnet.service.VpnConnectionManager
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

data class HomeUiState(
    val connectionState: ConnectionState = ConnectionState.Disconnected,
    val activeProfile: ServerProfile? = null,
    val profiles: List<ServerProfile> = emptyList(),
    val isLoading: Boolean = false,
    val error: String? = null,
    val proxyOnlyMode: Boolean = false,
    val debugLogging: Boolean = false,
    val snowflakeBootstrapProgress: Int = -1
)

@HiltViewModel
class HomeViewModel @Inject constructor(
    private val connectionManager: VpnConnectionManager,
    private val getProfilesUseCase: GetProfilesUseCase,
    private val getActiveProfileUseCase: GetActiveProfileUseCase,
    private val connectVpnUseCase: ConnectVpnUseCase,
    private val disconnectVpnUseCase: DisconnectVpnUseCase,
    private val setActiveProfileUseCase: SetActiveProfileUseCase,
    private val preferencesDataStore: PreferencesDataStore
) : ViewModel() {

    private val _uiState = MutableStateFlow(HomeUiState())
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()

    private var bootstrapPollingJob: Job? = null

    init {
        observeConnectionState()
        observeProfiles()
        observeProxyOnlyMode()
        observeDebugLogging()
    }

    private fun observeConnectionState() {
        viewModelScope.launch {
            connectionManager.connectionState.collect { state ->
                _uiState.value = _uiState.value.copy(
                    connectionState = state,
                    error = if (state is ConnectionState.Error) state.message else null
                )
                // Start/stop Snowflake bootstrap progress polling
                if (state is ConnectionState.Connecting) {
                    startBootstrapPolling()
                } else {
                    stopBootstrapPolling()
                }
            }
        }
    }

    private fun startBootstrapPolling() {
        bootstrapPollingJob?.cancel()
        bootstrapPollingJob = viewModelScope.launch {
            while (true) {
                val progress = SnowflakeBridge.torBootstrapProgress
                _uiState.value = _uiState.value.copy(
                    snowflakeBootstrapProgress = if (progress > 0) progress else -1
                )
                delay(500)
            }
        }
    }

    private fun stopBootstrapPolling() {
        bootstrapPollingJob?.cancel()
        bootstrapPollingJob = null
        _uiState.value = _uiState.value.copy(snowflakeBootstrapProgress = -1)
    }

    private fun observeProxyOnlyMode() {
        viewModelScope.launch {
            preferencesDataStore.proxyOnlyMode.collect { enabled ->
                _uiState.value = _uiState.value.copy(proxyOnlyMode = enabled)
            }
        }
    }

    private fun observeDebugLogging() {
        viewModelScope.launch {
            preferencesDataStore.debugLogging.collect { enabled ->
                _uiState.value = _uiState.value.copy(debugLogging = enabled)
            }
        }
    }

    private fun observeProfiles() {
        viewModelScope.launch {
            combine(
                getProfilesUseCase(),
                getActiveProfileUseCase()
            ) { profiles, activeProfile ->
                Pair(profiles, activeProfile)
            }.collect { (profiles, activeProfile) ->
                _uiState.value = _uiState.value.copy(
                    profiles = profiles,
                    activeProfile = activeProfile
                )
            }
        }
    }

    fun connect(profile: ServerProfile? = null) {
        val targetProfile = profile ?: _uiState.value.activeProfile ?: _uiState.value.profiles.firstOrNull()

        if (targetProfile == null) {
            _uiState.value = _uiState.value.copy(error = "No profile available to connect")
            return
        }

        connectionManager.connect(targetProfile)
    }

    fun disconnect() {
        connectionManager.disconnect()
    }

    fun toggleConnection() {
        when (_uiState.value.connectionState) {
            is ConnectionState.Connected,
            is ConnectionState.Connecting -> disconnect()
            else -> connect()
        }
    }

    fun setActiveProfile(profile: ServerProfile) {
        viewModelScope.launch {
            setActiveProfileUseCase(profile.id)
        }
    }

    fun clearError() {
        _uiState.value = _uiState.value.copy(error = null)
    }
}
