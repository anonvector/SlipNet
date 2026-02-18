package app.slipnet.presentation.main

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.slipnet.data.export.ConfigExporter
import app.slipnet.data.export.ConfigImporter
import app.slipnet.data.export.ImportResult
import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.PingResult
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TrafficStats
import app.slipnet.domain.model.TunnelType
import app.slipnet.domain.repository.ProfileRepository
import app.slipnet.domain.usecase.ConnectVpnUseCase
import app.slipnet.domain.usecase.DeleteProfileUseCase
import app.slipnet.domain.usecase.DisconnectVpnUseCase
import app.slipnet.domain.usecase.GetActiveProfileUseCase
import app.slipnet.domain.usecase.GetProfilesUseCase
import app.slipnet.domain.usecase.SaveProfileUseCase
import app.slipnet.domain.usecase.SetActiveProfileUseCase
import app.slipnet.service.VpnConnectionManager
import app.slipnet.tunnel.SnowflakeBridge
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket
import javax.inject.Inject

data class ImportPreview(
    val profiles: List<ServerProfile>,
    val warnings: List<String>
)

data class QrCodeData(
    val profileName: String,
    val configUri: String
)

data class MainUiState(
    // Connection state
    val connectionState: ConnectionState = ConnectionState.Disconnected,
    val activeProfile: ServerProfile? = null,
    val proxyOnlyMode: Boolean = false,
    val debugLogging: Boolean = false,
    val snowflakeBootstrapProgress: Int = -1,
    // Profile list state
    val profiles: List<ServerProfile> = emptyList(),
    val connectedProfileId: Long? = null,
    val isLoading: Boolean = false,
    val error: String? = null,
    val exportedJson: String? = null,
    val importPreview: ImportPreview? = null,
    val qrCodeData: QrCodeData? = null,
    val showFirstLaunchAbout: Boolean = false,
    val trafficStats: TrafficStats = TrafficStats.EMPTY,
    val uploadSpeed: Long = 0,
    val downloadSpeed: Long = 0,
    // Session totals shown after disconnect
    val sessionTotalUpload: Long = 0,
    val sessionTotalDownload: Long = 0,
    // Ping results per profile ID
    val pingResults: Map<Long, PingResult> = emptyMap(),
    val isPingRunning: Boolean = false
)

@HiltViewModel
class MainViewModel @Inject constructor(
    private val connectionManager: VpnConnectionManager,
    private val getProfilesUseCase: GetProfilesUseCase,
    private val getActiveProfileUseCase: GetActiveProfileUseCase,
    private val connectVpnUseCase: ConnectVpnUseCase,
    private val disconnectVpnUseCase: DisconnectVpnUseCase,
    private val setActiveProfileUseCase: SetActiveProfileUseCase,
    private val deleteProfileUseCase: DeleteProfileUseCase,
    private val saveProfileUseCase: SaveProfileUseCase,
    private val profileRepository: ProfileRepository,
    private val configExporter: ConfigExporter,
    private val configImporter: ConfigImporter,
    private val preferencesDataStore: PreferencesDataStore
) : ViewModel() {

    private val _uiState = MutableStateFlow(MainUiState())
    val uiState: StateFlow<MainUiState> = _uiState.asStateFlow()

    private var bootstrapPollingJob: Job? = null
    private var trafficPollingJob: Job? = null
    private var pingJob: Job? = null

    init {
        observeConnectionState()
        observeProfiles()
        observeProxyOnlyMode()
        observeDebugLogging()
        checkFirstLaunch()
    }

    // ── Connection ──────────────────────────────────────────────────────

    private fun observeConnectionState() {
        viewModelScope.launch {
            connectionManager.connectionState.collect { state ->
                val connectedId = when (state) {
                    is ConnectionState.Connected -> state.profile.id
                    else -> null
                }
                _uiState.value = _uiState.value.copy(
                    connectionState = state,
                    connectedProfileId = connectedId,
                    error = if (state is ConnectionState.Error) state.message else _uiState.value.error
                )
                if (state is ConnectionState.Connecting) {
                    startBootstrapPolling()
                } else {
                    stopBootstrapPolling()
                }
                if (state is ConnectionState.Connected) {
                    startTrafficPolling()
                } else {
                    stopTrafficPolling()
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

    private var previousStats: TrafficStats = TrafficStats.EMPTY

    private fun startTrafficPolling() {
        trafficPollingJob?.cancel()
        previousStats = TrafficStats.EMPTY
        // Clear previous session totals when a new connection starts
        _uiState.value = _uiState.value.copy(sessionTotalUpload = 0, sessionTotalDownload = 0)
        trafficPollingJob = viewModelScope.launch {
            while (true) {
                connectionManager.refreshTrafficStats()
                val current = connectionManager.trafficStats.value
                val upSpeed = (current.bytesSent - previousStats.bytesSent).coerceAtLeast(0)
                val downSpeed = (current.bytesReceived - previousStats.bytesReceived).coerceAtLeast(0)
                previousStats = current
                _uiState.value = _uiState.value.copy(
                    trafficStats = current,
                    uploadSpeed = upSpeed,
                    downloadSpeed = downSpeed
                )
                delay(1000)
            }
        }
    }

    private fun stopTrafficPolling() {
        trafficPollingJob?.cancel()
        trafficPollingJob = null
        // Save session totals before clearing, but only if there are actual stats.
        // State transitions Connected→Disconnecting→Disconnected call this twice;
        // the second call must not overwrite saved totals with zeros.
        val lastStats = _uiState.value.trafficStats
        val hasStats = lastStats.bytesSent > 0 || lastStats.bytesReceived > 0
        previousStats = TrafficStats.EMPTY
        _uiState.value = _uiState.value.copy(
            trafficStats = TrafficStats.EMPTY,
            uploadSpeed = 0,
            downloadSpeed = 0,
            sessionTotalUpload = if (hasStats) lastStats.bytesSent else _uiState.value.sessionTotalUpload,
            sessionTotalDownload = if (hasStats) lastStats.bytesReceived else _uiState.value.sessionTotalDownload
        )
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

    private fun checkFirstLaunch() {
        viewModelScope.launch {
            val done = preferencesDataStore.firstLaunchDone.first()
            if (!done) {
                _uiState.value = _uiState.value.copy(showFirstLaunchAbout = true)
            }
        }
    }

    fun dismissFirstLaunchAbout() {
        _uiState.value = _uiState.value.copy(showFirstLaunchAbout = false)
        viewModelScope.launch {
            preferencesDataStore.setFirstLaunchDone()
        }
    }

    private fun observeProfiles() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true)
            combine(
                getProfilesUseCase(),
                getActiveProfileUseCase()
            ) { profiles, activeProfile ->
                Pair(profiles, activeProfile)
            }.collect { (profiles, activeProfile) ->
                _uiState.value = _uiState.value.copy(
                    profiles = profiles,
                    activeProfile = activeProfile,
                    isLoading = false
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
        val state = _uiState.value.connectionState
        val isConnectedOrConnecting = state is ConnectionState.Connected ||
                state is ConnectionState.Connecting

        viewModelScope.launch {
            setActiveProfileUseCase(profile.id)
        }

        if (isConnectedOrConnecting && _uiState.value.connectedProfileId != profile.id) {
            connectionManager.reconnect(profile)
        }
    }

    fun clearError() {
        _uiState.value = _uiState.value.copy(error = null)
    }

    // ── Profile Management ──────────────────────────────────────────────

    fun moveProfile(fromIndex: Int, toIndex: Int) {
        val currentList = _uiState.value.profiles.toMutableList()
        if (fromIndex < 0 || fromIndex >= currentList.size ||
            toIndex < 0 || toIndex >= currentList.size) return

        val item = currentList.removeAt(fromIndex)
        currentList.add(toIndex, item)
        _uiState.value = _uiState.value.copy(profiles = currentList)

        viewModelScope.launch {
            profileRepository.updateProfileOrder(currentList.map { it.id })
        }
    }

    fun deleteProfile(profile: ServerProfile) {
        viewModelScope.launch {
            val result = deleteProfileUseCase(profile.id)
            if (result.isFailure) {
                _uiState.value = _uiState.value.copy(
                    error = result.exceptionOrNull()?.message ?: "Failed to delete profile"
                )
            }
        }
    }

    fun deleteAllProfiles() {
        viewModelScope.launch {
            val connectedId = _uiState.value.connectedProfileId
            val profilesToDelete = _uiState.value.profiles.filter { it.id != connectedId }
            for (profile in profilesToDelete) {
                deleteProfileUseCase(profile.id)
            }
        }
    }

    // ── Import / Export ─────────────────────────────────────────────────

    fun exportProfile(profile: ServerProfile) {
        val json = configExporter.exportSingleProfile(profile)
        _uiState.value = _uiState.value.copy(exportedJson = json)
    }

    fun exportAllProfiles() {
        val profiles = _uiState.value.profiles
        if (profiles.isEmpty()) {
            _uiState.value = _uiState.value.copy(error = "No profiles to export")
            return
        }
        val json = configExporter.exportAllProfiles(profiles)
        _uiState.value = _uiState.value.copy(exportedJson = json)
    }

    fun clearExportedJson() {
        _uiState.value = _uiState.value.copy(exportedJson = null)
    }

    fun parseImportConfig(json: String) {
        when (val result = configImporter.parseAndImport(json)) {
            is ImportResult.Success -> {
                _uiState.value = _uiState.value.copy(
                    importPreview = ImportPreview(result.profiles, result.warnings)
                )
            }
            is ImportResult.Error -> {
                _uiState.value = _uiState.value.copy(error = result.message)
            }
        }
    }

    fun confirmImport() {
        val preview = _uiState.value.importPreview ?: return
        viewModelScope.launch {
            try {
                for (profile in preview.profiles) {
                    saveProfileUseCase(profile)
                }
                _uiState.value = _uiState.value.copy(
                    importPreview = null,
                    error = null
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    error = "Failed to import profiles: ${e.message}",
                    importPreview = null
                )
            }
        }
    }

    fun cancelImport() {
        _uiState.value = _uiState.value.copy(importPreview = null)
    }

    fun showQrCode(profile: ServerProfile) {
        val configUri = configExporter.exportSingleProfile(profile)
        _uiState.value = _uiState.value.copy(
            qrCodeData = QrCodeData(profile.name, configUri)
        )
    }

    fun clearQrCode() {
        _uiState.value = _uiState.value.copy(qrCodeData = null)
    }

    // ── Test Server Reachability (SSH-only) ────────────────────────────

    fun pingAllProfiles() {
        if (_uiState.value.isPingRunning) {
            cancelPing()
            return
        }

        val profiles = _uiState.value.profiles
        if (profiles.isEmpty()) return

        // Only SSH profiles can be tested directly; others tunnel through
        // DNS/Tor/etc. so a direct ping is misleading.
        val initial = profiles.associate { profile ->
            profile.id to if (profile.tunnelType == TunnelType.SSH) {
                PingResult.Pending
            } else {
                PingResult.Skipped
            }
        }
        _uiState.value = _uiState.value.copy(pingResults = initial, isPingRunning = true)

        pingJob = viewModelScope.launch {
            try {
                for (profile in profiles) {
                    if (profile.tunnelType != TunnelType.SSH) continue

                    val result = pingProfile(profile)
                    _uiState.value = _uiState.value.copy(
                        pingResults = _uiState.value.pingResults + (profile.id to result)
                    )
                }
            } finally {
                _uiState.value = _uiState.value.copy(isPingRunning = false)
            }
        }
    }

    fun cancelPing() {
        pingJob?.cancel()
        pingJob = null
        _uiState.value = _uiState.value.copy(isPingRunning = false)
    }

    private sealed class PingTarget {
        data class Tcp(val host: String, val port: Int) : PingTarget()
    }

    private suspend fun pingProfile(profile: ServerProfile): PingResult {
        val target = getPingTarget(profile) ?: return PingResult.Error("No target")

        return withContext(Dispatchers.IO) {
            try {
                when (target) {
                    is PingTarget.Tcp -> pingTcp(target.host, target.port)
                }
            } catch (e: Exception) {
                val msg = when (e) {
                    is java.net.SocketTimeoutException -> "Timeout"
                    is java.net.ConnectException -> "Refused"
                    is java.net.UnknownHostException -> "DNS failed"
                    else -> e.message?.take(20) ?: "Failed"
                }
                PingResult.Error(msg)
            }
        }
    }

    private fun pingTcp(host: String, port: Int): PingResult {
        val socket = Socket()
        val start = System.nanoTime()
        socket.connect(InetSocketAddress(host, port), 5000)
        val elapsed = (System.nanoTime() - start) / 1_000_000
        socket.close()
        return PingResult.Success(elapsed)
    }


    private fun getPingTarget(profile: ServerProfile): PingTarget? {
        return when (profile.tunnelType) {
            TunnelType.SSH -> PingTarget.Tcp(profile.domain, profile.sshPort)
            else -> null
        }
    }
}
