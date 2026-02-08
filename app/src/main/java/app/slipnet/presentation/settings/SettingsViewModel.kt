package app.slipnet.presentation.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.slipnet.data.local.datastore.DarkMode
import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.data.local.datastore.SshCipher
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
    // Proxy Settings
    val proxyListenAddress: String = "0.0.0.0",
    val proxyListenPort: Int = 1080,
    // Network Settings
    val disableQuic: Boolean = true,
    // SSH Tunnel Settings
    val sshCipher: SshCipher = SshCipher.AUTO,
    val sshCompression: Boolean = false,
    val sshMaxChannels: Int = 16
)

@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val preferencesDataStore: PreferencesDataStore
) : ViewModel() {

    private val _uiState = MutableStateFlow(SettingsUiState())
    val uiState: StateFlow<SettingsUiState> = _uiState.asStateFlow()

    init {
        loadSettings()
    }

    private fun loadSettings() {
        viewModelScope.launch {
            val mainFlow = combine(
                preferencesDataStore.autoConnectOnBoot,
                preferencesDataStore.darkMode,
                preferencesDataStore.debugLogging,
                preferencesDataStore.proxyListenAddress,
                preferencesDataStore.proxyListenPort,
                preferencesDataStore.disableQuic
            ) { values ->
                arrayOf(values[0], values[1], values[2], values[3], values[4], values[5])
            }

            val sshFlow = combine(
                preferencesDataStore.sshCipher,
                preferencesDataStore.sshCompression,
                preferencesDataStore.sshMaxChannels
            ) { cipher, compression, maxChannels ->
                Triple(cipher, compression, maxChannels)
            }

            combine(mainFlow, sshFlow) { main, ssh ->
                SettingsUiState(
                    autoConnectOnBoot = main[0] as Boolean,
                    darkMode = main[1] as DarkMode,
                    debugLogging = main[2] as Boolean,
                    isLoading = false,
                    proxyListenAddress = main[3] as String,
                    proxyListenPort = main[4] as Int,
                    disableQuic = main[5] as Boolean,
                    sshCipher = ssh.first,
                    sshCompression = ssh.second,
                    sshMaxChannels = ssh.third
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

    // Network Settings
    fun setDisableQuic(enabled: Boolean) {
        viewModelScope.launch {
            preferencesDataStore.setDisableQuic(enabled)
        }
    }

    // Proxy Settings
    fun setProxyListenAddress(address: String) {
        viewModelScope.launch {
            preferencesDataStore.setProxyListenAddress(address)
        }
    }

    fun setProxyListenPort(port: Int) {
        viewModelScope.launch {
            preferencesDataStore.setProxyListenPort(port)
        }
    }

    // SSH Tunnel Settings
    fun setSshCipher(cipher: SshCipher) {
        viewModelScope.launch {
            preferencesDataStore.setSshCipher(cipher)
        }
    }

    fun setSshCompression(enabled: Boolean) {
        viewModelScope.launch {
            preferencesDataStore.setSshCompression(enabled)
        }
    }

    fun setSshMaxChannels(count: Int) {
        viewModelScope.launch {
            preferencesDataStore.setSshMaxChannels(count)
        }
    }
}
