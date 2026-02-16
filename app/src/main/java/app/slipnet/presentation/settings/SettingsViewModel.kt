package app.slipnet.presentation.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.slipnet.data.local.datastore.DarkMode
import app.slipnet.data.local.datastore.DomainRoutingMode
import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.data.local.datastore.SplitTunnelingMode
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
    val proxyOnlyMode: Boolean = false,
    val killSwitch: Boolean = false,
    // HTTP Proxy Settings
    val httpProxyEnabled: Boolean = false,
    val httpProxyPort: Int = 8080,
    val appendHttpProxyToVpn: Boolean = false,
    // Network Settings
    val disableQuic: Boolean = true,
    // Split Tunneling Settings
    val splitTunnelingEnabled: Boolean = false,
    val splitTunnelingMode: SplitTunnelingMode = SplitTunnelingMode.DISALLOW,
    val splitTunnelingApps: Set<String> = emptySet(),
    // SSH Tunnel Settings
    val sshCipher: SshCipher = SshCipher.AUTO,
    val sshCompression: Boolean = false,
    val sshMaxChannels: Int = 16,
    // Domain Routing Settings
    val domainRoutingEnabled: Boolean = false,
    val domainRoutingMode: DomainRoutingMode = DomainRoutingMode.BYPASS,
    val domainRoutingDomains: Set<String> = emptySet()
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

            val splitFlow = combine(
                preferencesDataStore.splitTunnelingEnabled,
                preferencesDataStore.splitTunnelingMode,
                preferencesDataStore.splitTunnelingApps
            ) { enabled, mode, apps ->
                Triple(enabled, mode, apps)
            }

            val proxyOnlyFlow = combine(
                preferencesDataStore.proxyOnlyMode,
                preferencesDataStore.killSwitch
            ) { proxyOnly, killSwitch ->
                Pair(proxyOnly, killSwitch)
            }

            val httpProxyFlow = combine(
                preferencesDataStore.httpProxyEnabled,
                preferencesDataStore.httpProxyPort,
                preferencesDataStore.appendHttpProxyToVpn
            ) { enabled, port, appendToVpn ->
                Triple(enabled, port, appendToVpn)
            }

            val domainRoutingFlow = combine(
                preferencesDataStore.domainRoutingEnabled,
                preferencesDataStore.domainRoutingMode,
                preferencesDataStore.domainRoutingDomains
            ) { enabled, mode, domains ->
                Triple(enabled, mode, domains)
            }

            val baseFlow = combine(mainFlow, sshFlow, splitFlow, proxyOnlyFlow, httpProxyFlow) { main, ssh, split, proxyOnlyPair, httpProxy ->
                SettingsUiState(
                    autoConnectOnBoot = main[0] as Boolean,
                    darkMode = main[1] as DarkMode,
                    debugLogging = main[2] as Boolean,
                    isLoading = false,
                    proxyListenAddress = main[3] as String,
                    proxyListenPort = main[4] as Int,
                    proxyOnlyMode = proxyOnlyPair.first,
                    killSwitch = proxyOnlyPair.second,
                    httpProxyEnabled = httpProxy.first,
                    httpProxyPort = httpProxy.second,
                    appendHttpProxyToVpn = httpProxy.third,
                    disableQuic = main[5] as Boolean,
                    splitTunnelingEnabled = split.first,
                    splitTunnelingMode = split.second,
                    splitTunnelingApps = split.third,
                    sshCipher = ssh.first,
                    sshCompression = ssh.second,
                    sshMaxChannels = ssh.third
                )
            }

            combine(baseFlow, domainRoutingFlow) { base, domainRouting ->
                base.copy(
                    domainRoutingEnabled = domainRouting.first,
                    domainRoutingMode = domainRouting.second,
                    domainRoutingDomains = domainRouting.third
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

    // Proxy-Only Mode
    fun setProxyOnlyMode(enabled: Boolean) {
        viewModelScope.launch {
            preferencesDataStore.setProxyOnlyMode(enabled)
        }
    }

    // Kill Switch
    fun setKillSwitch(enabled: Boolean) {
        viewModelScope.launch {
            preferencesDataStore.setKillSwitch(enabled)
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

    // Split Tunneling Settings
    fun setSplitTunnelingEnabled(enabled: Boolean) {
        viewModelScope.launch {
            preferencesDataStore.setSplitTunnelingEnabled(enabled)
        }
    }

    fun setSplitTunnelingMode(mode: SplitTunnelingMode) {
        viewModelScope.launch {
            preferencesDataStore.setSplitTunnelingMode(mode)
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

    // HTTP Proxy Settings
    fun setHttpProxyEnabled(enabled: Boolean) {
        viewModelScope.launch {
            preferencesDataStore.setHttpProxyEnabled(enabled)
        }
    }

    fun setHttpProxyPort(port: Int) {
        viewModelScope.launch {
            preferencesDataStore.setHttpProxyPort(port)
        }
    }

    fun setAppendHttpProxyToVpn(enabled: Boolean) {
        viewModelScope.launch {
            preferencesDataStore.setAppendHttpProxyToVpn(enabled)
        }
    }

    // Domain Routing Settings
    fun setDomainRoutingEnabled(enabled: Boolean) {
        viewModelScope.launch {
            preferencesDataStore.setDomainRoutingEnabled(enabled)
        }
    }

    fun setDomainRoutingMode(mode: DomainRoutingMode) {
        viewModelScope.launch {
            preferencesDataStore.setDomainRoutingMode(mode)
        }
    }

    fun addDomainRoutingDomain(domain: String) {
        viewModelScope.launch {
            val current = _uiState.value.domainRoutingDomains
            val normalized = domain.lowercase().trim().trimEnd('.')
            if (normalized.isNotEmpty()) {
                preferencesDataStore.setDomainRoutingDomains(current + normalized)
            }
        }
    }

    fun removeDomainRoutingDomain(domain: String) {
        viewModelScope.launch {
            val current = _uiState.value.domainRoutingDomains
            preferencesDataStore.setDomainRoutingDomains(current - domain)
        }
    }
}
