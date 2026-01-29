package app.slipnet.presentation.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
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
    val logsCleared: Boolean = false
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
                preferencesDataStore.debugLogging
            ) { autoConnect, darkMode, debugLogging ->
                Triple(autoConnect, darkMode, debugLogging)
            }.collect { (autoConnect, darkMode, debugLogging) ->
                _uiState.value = _uiState.value.copy(
                    autoConnectOnBoot = autoConnect,
                    darkMode = darkMode,
                    debugLogging = debugLogging,
                    isLoading = false
                )
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
}
