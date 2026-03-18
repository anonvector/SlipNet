package app.slipnet.presentation.main

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.slipnet.data.export.ConfigExporter
import app.slipnet.data.export.ConfigImporter
import app.slipnet.data.export.ImportResult
import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.domain.model.ChainValidation
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.PingResult
import app.slipnet.domain.model.ProfileChain
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TrafficStats
import app.slipnet.domain.model.TunnelType
import app.slipnet.domain.model.isAvailable
import app.slipnet.domain.model.E2eTestResult
import app.slipnet.domain.repository.ChainRepository
import app.slipnet.domain.repository.ProfileRepository
import app.slipnet.domain.repository.ResolverScannerRepository
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
    val chains: List<ProfileChain> = emptyList(),
    val connectedProfileId: Long? = null,
    val connectedChainId: Long? = null,
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
    val isPingRunning: Boolean = false,
    val sleepTimerRemainingSeconds: Int = 0,
    // Update checker
    val availableUpdate: app.slipnet.util.AppUpdate? = null,
    // DNS warning
    val dnsWarning: String? = null
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
    private val chainRepository: ChainRepository,
    private val resolverScannerRepository: ResolverScannerRepository,
    private val configExporter: ConfigExporter,
    private val configImporter: ConfigImporter,
    private val preferencesDataStore: PreferencesDataStore
) : ViewModel() {

    private val _uiState = MutableStateFlow(MainUiState())
    val uiState: StateFlow<MainUiState> = _uiState.asStateFlow()

    private var bootstrapPollingJob: Job? = null
    private var trafficPollingJob: Job? = null
    private var sleepTimerJob: Job? = null
    private var pingJob: Job? = null

    init {
        observeConnectionState()
        observeDnsWarning()
        observeProfiles()
        observeChains()
        observeProxyOnlyMode()
        observeDebugLogging()
        checkFirstLaunch()
        checkForUpdate()
    }

    // ── Connection ──────────────────────────────────────────────────────

    private fun observeConnectionState() {
        viewModelScope.launch {
            connectionManager.connectionState.collect { state ->
                val connectedId = when (state) {
                    is ConnectionState.Connected -> state.profile.id
                    else -> null
                }
                val chainId = when (state) {
                    is ConnectionState.Connected -> if (state.chainId > 0) state.chainId else null
                    else -> null
                }
                _uiState.value = _uiState.value.copy(
                    connectionState = state,
                    connectedProfileId = if (chainId != null) null else connectedId,
                    connectedChainId = chainId,
                    error = if (state is ConnectionState.Error) state.message else _uiState.value.error
                )
                if (state is ConnectionState.Connecting) {
                    startBootstrapPolling()
                } else {
                    stopBootstrapPolling()
                }
                if (state is ConnectionState.Connected) {
                    startTrafficPolling()
                    startSleepTimer()
                } else {
                    stopTrafficPolling()
                    cancelSleepTimer()
                }
            }
        }
    }

    private fun observeDnsWarning() {
        viewModelScope.launch {
            connectionManager.dnsWarning.collect { warning ->
                _uiState.value = _uiState.value.copy(dnsWarning = warning)
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

    private fun startSleepTimer() {
        sleepTimerJob?.cancel()
        sleepTimerJob = viewModelScope.launch {
            val minutes = preferencesDataStore.sleepTimerMinutes.first()
            if (minutes <= 0) return@launch
            var remaining = minutes * 60
            _uiState.value = _uiState.value.copy(sleepTimerRemainingSeconds = remaining)
            while (remaining > 0) {
                delay(1000)
                remaining--
                _uiState.value = _uiState.value.copy(sleepTimerRemainingSeconds = remaining)
            }
            disconnect()
        }
    }

    private fun cancelSleepTimer() {
        sleepTimerJob?.cancel()
        sleepTimerJob = null
        _uiState.value = _uiState.value.copy(sleepTimerRemainingSeconds = 0)
    }

    fun userCancelSleepTimer() {
        cancelSleepTimer()
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

    // ── Update Checker ──────────────────────────────────────────────────

    private fun checkForUpdate() {
        viewModelScope.launch {
            // Throttle: skip if checked recently
            val lastCheck = preferencesDataStore.lastUpdateCheckTime.first()
            val now = System.currentTimeMillis()
            if (now - lastCheck < app.slipnet.util.UpdateChecker.CHECK_INTERVAL_MS) return@launch
            preferencesDataStore.setLastUpdateCheckTime(now)

            val skipped = preferencesDataStore.skippedUpdateVersion.first()
            val current = app.slipnet.BuildConfig.VERSION_NAME

            val update = app.slipnet.util.UpdateChecker.check(current) ?: return@launch

            // Don't show if user already skipped this version
            if (update.versionName == skipped) return@launch

            _uiState.value = _uiState.value.copy(availableUpdate = update)
        }
    }

    fun dismissUpdate() {
        _uiState.value = _uiState.value.copy(availableUpdate = null)
    }

    fun skipUpdate() {
        val version = _uiState.value.availableUpdate?.versionName ?: return
        _uiState.value = _uiState.value.copy(availableUpdate = null)
        viewModelScope.launch {
            preferencesDataStore.setSkippedUpdateVersion(version)
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
        if (targetProfile.isExpired) {
            _uiState.value = _uiState.value.copy(error = "This profile has expired")
            return
        }
        if (!targetProfile.tunnelType.isAvailable()) {
            _uiState.value = _uiState.value.copy(
                error = "${targetProfile.tunnelType.displayName} is not available in this edition"
            )
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
            is ConnectionState.Connecting,
            is ConnectionState.Error -> disconnect()
            else -> connect()
        }
    }

    private fun observeChains() {
        viewModelScope.launch {
            chainRepository.getAllChains().collect { chains ->
                _uiState.value = _uiState.value.copy(chains = chains)
            }
        }
    }

    fun connectChain(chain: ProfileChain) {
        viewModelScope.launch {
            val profiles = chain.profileIds.mapNotNull { profileRepository.getProfileById(it) }
            if (profiles.size != chain.profileIds.size) {
                _uiState.value = _uiState.value.copy(error = "Some profiles in chain were deleted")
                return@launch
            }
            val validationError = ChainValidation.validate(profiles)
            if (validationError != null) {
                _uiState.value = _uiState.value.copy(error = validationError)
                return@launch
            }
            connectionManager.connectChain(chain, profiles.first())
        }
    }

    fun deleteChain(chain: ProfileChain) {
        viewModelScope.launch {
            chainRepository.deleteChain(chain.id)
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

    fun deleteDuplicateProfiles() {
        viewModelScope.launch {
            val profiles = _uiState.value.profiles
            val connectedId = (_uiState.value.connectionState as? ConnectionState.Connected)
                ?.profile?.id

            // Group by connection-relevant fields; keep the first (oldest by sortOrder) in each group
            val seen = mutableSetOf<String>()
            val duplicateIds = mutableListOf<Long>()
            for (profile in profiles) {
                val key = profile.duplicateKey()
                if (!seen.add(key)) {
                    // Skip the currently connected profile
                    if (profile.id != connectedId) {
                        duplicateIds.add(profile.id)
                    }
                }
            }
            for (id in duplicateIds) {
                deleteProfileUseCase(id)
            }
        }
    }

    private fun ServerProfile.duplicateKey(): String = listOf(
        tunnelType.value, domain, dnsttPublicKey, dohUrl,
        sshHost, sshPort, sshUsername, sshPassword, sshAuthType.name, sshPrivateKey,
        resolvers.map { "${it.host}:${it.port}" }.sorted().joinToString(","),
        naivePort, naiveUsername, naivePassword,
        socksUsername.orEmpty(), socksPassword.orEmpty(),
        torBridgeLines
    ).joinToString("|")

    fun deleteAllProfiles() {
        viewModelScope.launch {
            // Disconnect first so no profile is protected from deletion
            if (_uiState.value.connectionState is ConnectionState.Connected ||
                _uiState.value.connectionState is ConnectionState.Connecting) {
                connectionManager.disconnect()
                // Give VPN service time to clean up so connectedProfile is cleared
                kotlinx.coroutines.delay(500)
            }
            for (profile in _uiState.value.profiles) {
                deleteProfileUseCase(profile.id)
            }
        }
    }

    // ── Import / Export ─────────────────────────────────────────────────

    fun exportProfile(profile: ServerProfile, hideResolvers: Boolean = false) {
        if (profile.isLocked) {
            _uiState.value = _uiState.value.copy(error = "Cannot export a locked profile")
            return
        }
        val json = configExporter.exportSingleProfile(profile, hideResolvers)
        _uiState.value = _uiState.value.copy(exportedJson = json)
    }

    fun exportProfileLocked(
        profile: ServerProfile,
        password: String,
        expirationDate: Long = 0,
        allowSharing: Boolean = false,
        boundDeviceId: String = "",
        hideResolvers: Boolean = false
    ) {
        val json = configExporter.exportSingleProfileLocked(
            profile, password, expirationDate, allowSharing, boundDeviceId, hideResolvers
        )
        _uiState.value = _uiState.value.copy(exportedJson = json)
    }

    fun exportAllProfiles() {
        val profiles = _uiState.value.profiles.filter { !it.isLocked }
        if (profiles.isEmpty()) {
            _uiState.value = _uiState.value.copy(error = "No exportable profiles")
            return
        }
        val json = configExporter.exportAllProfiles(profiles)
        _uiState.value = _uiState.value.copy(exportedJson = json)
    }

    fun clearExportedJson() {
        _uiState.value = _uiState.value.copy(exportedJson = null)
    }

    fun parseImportConfig(json: String) {
        when (val result = configImporter.parseAndImport(json, connectionManager.getDeviceId())) {
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
                for (profile in preview.profiles.reversed()) {
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

    fun showQrCode(profile: ServerProfile, hideResolvers: Boolean = false) {
        if (profile.isLocked) {
            _uiState.value = _uiState.value.copy(error = "Cannot export a locked profile")
            return
        }
        val configUri = configExporter.exportSingleProfile(profile, hideResolvers)
        _uiState.value = _uiState.value.copy(
            qrCodeData = QrCodeData(profile.name, configUri)
        )
    }

    fun clearQrCode() {
        _uiState.value = _uiState.value.copy(qrCodeData = null)
    }

    fun showQrCodeLocked(
        profile: ServerProfile,
        password: String,
        expirationDate: Long = 0,
        allowSharing: Boolean = false,
        boundDeviceId: String = "",
        hideResolvers: Boolean = false
    ) {
        val configUri = configExporter.exportSingleProfileLocked(
            profile, password, expirationDate, allowSharing, boundDeviceId, hideResolvers
        )
        _uiState.value = _uiState.value.copy(
            qrCodeData = QrCodeData(profile.name, configUri)
        )
    }

    fun reExportLockedProfile(profile: ServerProfile) {
        try {
            val json = configExporter.reExportLockedProfile(profile)
            _uiState.value = _uiState.value.copy(exportedJson = json)
        } catch (e: Exception) {
            _uiState.value = _uiState.value.copy(error = e.message ?: "Re-export failed")
        }
    }

    fun showQrCodeLockedReExport(profile: ServerProfile) {
        try {
            val configUri = configExporter.reExportLockedProfile(profile)
            _uiState.value = _uiState.value.copy(
                qrCodeData = QrCodeData(profile.name, configUri)
            )
        } catch (e: Exception) {
            _uiState.value = _uiState.value.copy(error = e.message ?: "Re-export failed")
        }
    }

    fun getDeviceId(): String = connectionManager.getDeviceId()

    // ── Test Server Reachability ────────────────────────────────────────

    companion object {
        /** Tunnel types that use DNS tunneling and support E2E testing */
        private val E2E_TUNNEL_TYPES = setOf(
            TunnelType.DNSTT, TunnelType.DNSTT_SSH,
            TunnelType.NOIZDNS, TunnelType.NOIZDNS_SSH,
            TunnelType.SLIPSTREAM, TunnelType.SLIPSTREAM_SSH
        )
        private const val E2E_TEST_URL = "http://www.gstatic.com/generate_204"
        private const val E2E_TIMEOUT_MS = 7000L
    }

    fun pingAllProfiles() {
        if (_uiState.value.isPingRunning) {
            cancelPing()
            return
        }

        val profiles = _uiState.value.profiles
        if (profiles.isEmpty()) return

        val skipped = setOf(TunnelType.SNOWFLAKE)
        val initial = profiles.associate { profile ->
            profile.id to if (profile.tunnelType in skipped) {
                PingResult.Skipped
            } else {
                PingResult.Pending
            }
        }
        _uiState.value = _uiState.value.copy(pingResults = initial, isPingRunning = true)

        pingJob = viewModelScope.launch {
            try {
                val tcpProfiles = profiles.filter {
                    it.tunnelType !in skipped && it.tunnelType !in E2E_TUNNEL_TYPES
                }
                val e2eProfiles = profiles.filter {
                    it.tunnelType in E2E_TUNNEL_TYPES
                }

                // Launch all TCP pings in parallel
                val tcpJobs = tcpProfiles.map { profile ->
                    launch {
                        val result = pingProfileTcp(profile)
                        _uiState.value = _uiState.value.copy(
                            pingResults = _uiState.value.pingResults + (profile.id to result)
                        )
                    }
                }

                // E2E tests must be sequential (bridges are singletons)
                val e2eJob = launch {
                    for (profile in e2eProfiles) {
                        val result = testProfileE2e(profile)
                        _uiState.value = _uiState.value.copy(
                            pingResults = _uiState.value.pingResults + (profile.id to result)
                        )
                    }
                }

                tcpJobs.forEach { it.join() }
                e2eJob.join()
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

    /**
     * E2E test for DNS-tunneled profiles: starts a real tunnel with the first resolver,
     * performs a handshake and HTTP/SSH verification, then reports total latency.
     */
    private suspend fun testProfileE2e(profile: ServerProfile): PingResult {
        val resolver = profile.resolvers.firstOrNull()
            ?: return PingResult.Error("No resolver")

        return try {
            val result: E2eTestResult = resolverScannerRepository.testResolverE2e(
                resolverHost = resolver.host,
                resolverPort = resolver.port,
                profile = profile,
                testUrl = E2E_TEST_URL,
                timeoutMs = E2E_TIMEOUT_MS,
                fullVerification = true
            ) { phase ->
                // Update UI with current phase while test runs
                _uiState.value = _uiState.value.copy(
                    pingResults = _uiState.value.pingResults + (profile.id to PingResult.Testing(phase))
                )
            }

            if (result.success) {
                PingResult.Success(result.totalMs)
            } else {
                PingResult.Error(result.errorMessage?.take(25) ?: "Failed")
            }
        } catch (e: Exception) {
            PingResult.Error(e.message?.take(25) ?: "Failed")
        }
    }

    /**
     * Simple TCP ping for non-tunnel profiles (SSH, Naive, DOH).
     */
    private suspend fun pingProfileTcp(profile: ServerProfile): PingResult {
        val target = getTcpTarget(profile) ?: return PingResult.Error("No target")

        return withContext(Dispatchers.IO) {
            try {
                val socket = Socket()
                val start = System.nanoTime()
                socket.connect(InetSocketAddress(target.first, target.second), 5000)
                val elapsed = (System.nanoTime() - start) / 1_000_000
                socket.close()
                PingResult.Success(elapsed)
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

    private fun getTcpTarget(profile: ServerProfile): Pair<String, Int>? {
        return when (profile.tunnelType) {
            TunnelType.SSH -> profile.domain to profile.sshPort
            TunnelType.NAIVE_SSH -> profile.domain to profile.naivePort
            TunnelType.NAIVE -> profile.domain to profile.naivePort
            TunnelType.DOH -> {
                val host = try {
                    java.net.URL(profile.dohUrl).host
                } catch (_: Exception) { return null }
                host to 443
            }
            TunnelType.SOCKS5 -> profile.domain to profile.socks5ServerPort
            else -> null
        }
    }
}
