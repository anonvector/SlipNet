package app.slipnet.presentation.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.slipnet.data.local.datastore.BufferSize
import app.slipnet.data.local.datastore.DarkMode
import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.domain.usecase.ClearLogsUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import javax.inject.Inject

data class SettingsUiState(
    val autoConnectOnBoot: Boolean = false,
    val darkMode: DarkMode = DarkMode.SYSTEM,
    val debugLogging: Boolean = false,
    val isLoading: Boolean = true,
    val showClearLogsConfirmation: Boolean = false,
    val logsCleared: Boolean = false,
    // Network Optimization Settings
    val dnsTimeout: Int = 5000,
    val connectionTimeout: Int = 30000,
    val bufferSize: BufferSize = BufferSize.MEDIUM,
    val connectionPoolSize: Int = 10
)

@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val preferencesDataStore: PreferencesDataStore,
    private val clearLogsUseCase: ClearLogsUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(SettingsUiState())
    val uiState: StateFlow<SettingsUiState> = _uiState.asStateFlow()

    init {
        loadSettings()
    }

    private fun loadSettings() {
        viewModelScope.launch {
            combine(
                preferencesDataStore.autoConnectOnBoot,
                preferencesDataStore.darkMode,
                preferencesDataStore.debugLogging,
                preferencesDataStore.dnsTimeout,
                preferencesDataStore.connectionTimeout,
                preferencesDataStore.bufferSize,
                preferencesDataStore.connectionPoolSize
            ) { values ->
                SettingsUiState(
                    autoConnectOnBoot = values[0] as Boolean,
                    darkMode = values[1] as DarkMode,
                    debugLogging = values[2] as Boolean,
                    isLoading = false,
                    showClearLogsConfirmation = _uiState.value.showClearLogsConfirmation,
                    logsCleared = _uiState.value.logsCleared,
                    dnsTimeout = values[3] as Int,
                    connectionTimeout = values[4] as Int,
                    bufferSize = values[5] as BufferSize,
                    connectionPoolSize = values[6] as Int
                )
            }.collect { newState ->
                _uiState.value = newState
            }
        }
    }

    fun setAutoConnectOnBoot(enabled: Boolean) {
        viewModelScope.launch {
            preferencesDataStore.setAutoConnectOnBoot(enabled)
        }
    }

    fun setDarkMode(mode: DarkMode) {
        viewModelScope.launch {
            preferencesDataStore.setDarkMode(mode)
        }
    }

    fun setDebugLogging(enabled: Boolean) {
        viewModelScope.launch {
            preferencesDataStore.setDebugLogging(enabled)
        }
    }

    fun showClearLogsConfirmation() {
        _uiState.value = _uiState.value.copy(showClearLogsConfirmation = true)
    }

    fun dismissClearLogsConfirmation() {
        _uiState.value = _uiState.value.copy(showClearLogsConfirmation = false)
    }

    fun clearLogs() {
        viewModelScope.launch {
            clearLogsUseCase()
            _uiState.value = _uiState.value.copy(
                showClearLogsConfirmation = false,
                logsCleared = true
            )
        }
    }

    fun resetLogsClearedFlag() {
        _uiState.value = _uiState.value.copy(logsCleared = false)
    }

    // Network Optimization Settings
    fun setDnsTimeout(timeout: Int) {
        viewModelScope.launch {
            preferencesDataStore.setDnsTimeout(timeout)
        }
    }

    fun setConnectionTimeout(timeout: Int) {
        viewModelScope.launch {
            preferencesDataStore.setConnectionTimeout(timeout)
        }
    }

    fun setBufferSize(size: BufferSize) {
        viewModelScope.launch {
            preferencesDataStore.setBufferSize(size)
        }
    }

    fun setConnectionPoolSize(size: Int) {
        viewModelScope.launch {
            preferencesDataStore.setConnectionPoolSize(size)
        }
    }
}
