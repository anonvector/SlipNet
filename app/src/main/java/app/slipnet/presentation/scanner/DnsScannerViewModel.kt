package app.slipnet.presentation.scanner

import android.os.PowerManager
import android.util.Log
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.slipnet.domain.model.DnsTransport
import app.slipnet.domain.model.DnsTunnelTestResult
import app.slipnet.domain.model.E2eScannerState
import app.slipnet.domain.model.E2eTestResult
import app.slipnet.domain.model.ResolverScanResult
import app.slipnet.domain.model.ResolverStatus
import app.slipnet.domain.model.ScannerState
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.SimpleModeE2eState
import app.slipnet.domain.model.TunnelType
import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.domain.repository.ProfileRepository
import app.slipnet.domain.repository.ResolverScannerRepository
import app.slipnet.domain.repository.VpnRepository
import app.slipnet.tunnel.DnsttBridge
import app.slipnet.tunnel.DomainRouter
import app.slipnet.tunnel.GeoBypassCountry
import app.slipnet.tunnel.SlipstreamBridge
import com.google.gson.Gson
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

data class CidrGroup(
    val firstOctet: Int,
    val label: String,
    val rangeCount: Int,
    val totalIps: Long,
    val ranges: List<Pair<Long, Long>>
)

data class DnsScannerUiState(
    val profileId: Long? = null,
    val testDomain: String = "google.com",
    val timeoutMs: String = "3000",
    val concurrency: String = "50",
    val resolverList: List<String> = emptyList(),
    val scannerState: ScannerState = ScannerState(),
    val selectedResolvers: Set<String> = emptySet(),
    val recentDnsResolvers: List<String> = emptyList(),
    val isLoadingList: Boolean = false,
    val error: String? = null,
    val listSource: ListSource = ListSource.DEFAULT,
    val importedFileName: String? = null,
    val selectedCountry: GeoBypassCountry = GeoBypassCountry.IR,
    val sampleCount: Int = 2000,
    val customRangeInput: String = "",
    val useCustomSampleCount: Boolean = false,
    val customSampleCountText: String = "",
    val cidrGroups: List<CidrGroup> = emptyList(),
    val selectedOctets: Set<Int> = emptySet(),
    val shuffleList: Boolean = true,
    val expandNeighbors: Boolean = true,
    val showResumeDialog: Boolean = false,
    val transparentProxyDetected: Boolean = false,
    // E2E tunnel test state
    val e2eScannerState: E2eScannerState = E2eScannerState(),
    val testUrl: String = "http://www.gstatic.com/generate_204",
    val e2eTimeoutMs: String = "7000",
    val isVpnActive: Boolean = false,
    val profile: ServerProfile? = null,
    // Simple scan mode
    val scanMode: ScanMode = ScanMode.SIMPLE,
    val simpleModeE2eState: SimpleModeE2eState = SimpleModeE2eState(),
    val e2eMinScore: Int = 2
) {
    companion object {
        const val MAX_SELECTED_RESOLVERS = 8
        const val MAX_SAMPLE_COUNT = 100_000
        private val E2E_SUPPORTED_TUNNEL_TYPES = setOf(
            TunnelType.SLIPSTREAM, TunnelType.SLIPSTREAM_SSH,
            TunnelType.DNSTT, TunnelType.DNSTT_SSH,
            TunnelType.NOIZDNS, TunnelType.NOIZDNS_SSH
        )
    }

    val effectiveTestDomain: String
        get() = testDomain.ifBlank { profile?.domain ?: "google.com" }

    val effectiveSampleCount: Int
        get() = if (useCustomSampleCount) {
            customSampleCountText.toIntOrNull()?.coerceIn(1, MAX_SAMPLE_COUNT) ?: sampleCount
        } else sampleCount

    val countryTotalIps: Long
        get() = cidrGroups.sumOf { it.totalIps }

    val selectedTotalIps: Long
        get() = cidrGroups.filter { it.firstOctet in selectedOctets }.sumOf { it.totalIps }

    val isSelectionLimitReached: Boolean
        get() = selectedResolvers.size >= MAX_SELECTED_RESOLVERS

    val selectionLimitMessage: String
        get() = "Maximum $MAX_SELECTED_RESOLVERS resolvers can be selected"

    val canUseSimpleMode: Boolean
        get() {
            if (profileId == null || profile == null) return false
            if (profile.tunnelType !in E2E_SUPPORTED_TUNNEL_TYPES) return false
            if ((profile.tunnelType == TunnelType.DNSTT || profile.tunnelType == TunnelType.DNSTT_SSH)
                && profile.dnsTransport == DnsTransport.DOH) return false
            return true
        }

    /** True when the profile supports E2E testing (ignoring scan progress) */
    val e2eSupported: Boolean
        get() {
            if (scanMode == ScanMode.SIMPLE) return false
            if (profileId == null || profile == null) return false
            if (profile.tunnelType !in E2E_SUPPORTED_TUNNEL_TYPES) return false
            if ((profile.tunnelType == TunnelType.DNSTT || profile.tunnelType == TunnelType.DNSTT_SSH)
                && profile.dnsTransport == DnsTransport.DOH) return false
            return true
        }

    val canRunE2e: Boolean
        get() {
            if (!e2eSupported) return false
            if (isVpnActive) return false
            if (e2eScannerState.isRunning) return false
            val workingResolvers = scannerState.results.count { it.status == ResolverStatus.WORKING }
            return workingResolvers > 0
        }

    /** True when some working resolvers have E2E results but others don't (paused mid-test) */
    val canResumeE2e: Boolean
        get() {
            if (!canRunE2e) return false
            val working = scannerState.results.filter { it.status == ResolverStatus.WORKING }
            val tested = working.count { it.e2eTestResult != null }
            return tested > 0 && tested < working.size
        }

    /** True when all working resolvers already have E2E results */
    val e2eComplete: Boolean
        get() {
            val working = scannerState.results.filter { it.status == ResolverStatus.WORKING }
            return working.isNotEmpty() && working.all { it.e2eTestResult != null }
        }
}

enum class ListSource {
    DEFAULT,
    IMPORTED,
    COUNTRY_RANGE,
    CUSTOM_RANGE
}

/**
 * Generate all IPs in the /24 subnet of the given IP, excluding the IP itself.
 * E.g., "2.177.150.38" → ["2.177.150.1", "2.177.150.2", ..., "2.177.150.254"]
 */
private fun expandSlash24(ip: String): List<String> {
    val parts = ip.split(".")
    if (parts.size != 4) return emptyList()
    val prefix = "${parts[0]}.${parts[1]}.${parts[2]}"
    return (1..254).map { "$prefix.$it" }.filter { it != ip }
}

enum class ScanMode {
    ADVANCED,
    SIMPLE
}

private data class ScannerSettings(
    val timeoutMs: String,
    val concurrency: String,
    val e2eTimeoutMs: String,
    val testUrl: String
)

// Lightweight models for JSON serialization of scan sessions.
private data class SavedScanSession(
    val resolverList: List<String>,
    val testDomain: String,
    val timeoutMs: String,
    val concurrency: String,
    val listSource: String,
    val scannedCount: Int,
    val workingCount: Int,
    val results: List<SavedResult>,
    val customRangeInput: String? = null,
    val scanMode: String? = null
)

private data class SavedResult(
    val host: String,
    val status: String,
    val responseTimeMs: Long?,
    val errorMessage: String?,
    val nsSupport: Boolean?,
    val txtSupport: Boolean?,
    val randomSub: Boolean?,
    val tunnelRealism: Boolean?,
    val edns0Support: Boolean?,
    // E2E fields (simple mode)
    val e2eSuccess: Boolean? = null,
    val e2eTotalMs: Long? = null,
    val e2eTunnelSetupMs: Long? = null,
    val e2eHttpLatencyMs: Long? = null,
    val e2eHttpStatusCode: Int? = null,
    val e2eErrorMessage: String? = null
)

@HiltViewModel
class DnsScannerViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val scannerRepository: ResolverScannerRepository,
    private val profileRepository: ProfileRepository,
    private val preferencesDataStore: PreferencesDataStore,
    private val vpnRepository: VpnRepository,
    @ApplicationContext private val appContext: android.content.Context
) : ViewModel() {

    private val profileId: Long? = savedStateHandle.get<Long>("profileId")?.takeIf { it != -1L }

    private val _uiState = MutableStateFlow(DnsScannerUiState(
        profileId = profileId,
        scanMode = if (profileId != null) ScanMode.SIMPLE else ScanMode.ADVANCED
    ))
    val uiState: StateFlow<DnsScannerUiState> = _uiState.asStateFlow()

    private var scanJob: Job? = null
    private var e2eJob: Job? = null
    private var simpleModeChannel: Channel<Pair<String, Int>>? = null
    private var simpleModeE2eJob: Job? = null
    private val gson = Gson()

    // Wake lock to keep CPU alive during scanning when app is backgrounded
    private var wakeLock: PowerManager.WakeLock? = null

    private fun acquireWakeLock() {
        if (wakeLock?.isHeld == true) return
        val pm = appContext.getSystemService(android.content.Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "SlipNet:ScanWakeLock").apply {
            acquire(60 * 60 * 1000L) // 60-min safety timeout
        }
        Log.d("DnsScanner", "WakeLock acquired")
    }

    private fun releaseWakeLock() {
        wakeLock?.let {
            if (it.isHeld) it.release()
            Log.d("DnsScanner", "WakeLock released")
        }
        wakeLock = null
    }

    init {
        loadSavedSession()
        loadRecentDns()
        loadCountryCidrInfo()
        loadProfile()
        observeVpnState()
    }

    /** One-shot read of persisted scanner settings. Must be called before session restore. */
    private suspend fun loadScannerSettings() {
        try {
            combine(
                preferencesDataStore.scannerTimeoutMs,
                preferencesDataStore.scannerConcurrency,
                preferencesDataStore.scannerE2eTimeoutMs,
                preferencesDataStore.scannerTestUrl
            ) { timeout, concurrency, e2eTimeout, testUrl ->
                ScannerSettings(timeout, concurrency, e2eTimeout, testUrl)
            }.first().let { s ->
                _uiState.value = _uiState.value.copy(
                    timeoutMs = s.timeoutMs,
                    concurrency = s.concurrency,
                    e2eTimeoutMs = s.e2eTimeoutMs,
                    testUrl = s.testUrl
                )
            }
        } catch (e: Exception) {
            Log.w("DnsScanner", "Failed to load scanner settings", e)
        }
        // Load last resolver list selection
        try {
            val source = preferencesDataStore.scannerListSource.first()
            val country = preferencesDataStore.scannerCountry.first()
            val sampleCount = preferencesDataStore.scannerSampleCount.first()
            val customRange = preferencesDataStore.scannerCustomRange.first()
            val listSource = try { ListSource.valueOf(source) } catch (_: Exception) { ListSource.DEFAULT }
            val geoCountry = GeoBypassCountry.fromCode(country)
            _uiState.value = _uiState.value.copy(
                listSource = listSource,
                selectedCountry = geoCountry,
                sampleCount = sampleCount,
                customRangeInput = customRange
            )
        } catch (e: Exception) {
            Log.w("DnsScanner", "Failed to load scanner list selection", e)
        }
    }

    private fun saveScannerSettings() {
        val state = _uiState.value
        viewModelScope.launch {
            try {
                preferencesDataStore.saveScannerSettings(
                    timeoutMs = state.timeoutMs,
                    concurrency = state.concurrency,
                    e2eTimeoutMs = state.e2eTimeoutMs,
                    testUrl = state.testUrl
                )
            } catch (e: Exception) {
                Log.w("DnsScanner", "Failed to save scanner settings", e)
            }
        }
    }

    private fun saveListSelection() {
        val state = _uiState.value
        viewModelScope.launch {
            try {
                preferencesDataStore.saveScannerListSelection(
                    listSource = state.listSource.name,
                    country = state.selectedCountry.code,
                    sampleCount = state.sampleCount,
                    customRange = state.customRangeInput
                )
            } catch (e: Exception) {
                Log.w("DnsScanner", "Failed to save list selection", e)
            }
        }
    }

    private fun loadRecentDns() {
        viewModelScope.launch {
            preferencesDataStore.recentDnsResolvers.collect { resolvers ->
                _uiState.value = _uiState.value.copy(recentDnsResolvers = resolvers)
            }
        }
    }

    private fun loadProfile() {
        val id = profileId ?: return
        viewModelScope.launch {
            try {
                val profile = profileRepository.getProfileById(id)
                if (profile != null) {
                    _uiState.value = _uiState.value.copy(
                        profile = profile
                    )
                }
            } catch (e: Exception) {
                Log.w("DnsScanner", "Failed to load profile", e)
            }
        }
    }

    private fun observeVpnState() {
        viewModelScope.launch {
            vpnRepository.connectionState.collect {
                _uiState.value = _uiState.value.copy(isVpnActive = vpnRepository.isConnected())
            }
        }
    }

    private suspend fun loadProfileDomain() {
        val id = profileId ?: return
        try {
            val profile = profileRepository.getProfileById(id) ?: return
            if (profile.domain.isNotBlank()) {
                if (profile.isLocked) {
                    // Keep testDomain empty — effectiveTestDomain falls back to profile.domain
                    _uiState.value = _uiState.value.copy(testDomain = "")
                } else {
                    _uiState.value = _uiState.value.copy(testDomain = profile.domain)
                }
            }
        } catch (e: Exception) {
            Log.w("DnsScanner", "Failed to load profile domain", e)
        }
    }

    fun saveRecentDns() {
        val selected = _uiState.value.selectedResolvers.toList()
        viewModelScope.launch {
            withContext(NonCancellable) {
                preferencesDataStore.addRecentDnsResolvers(selected)
            }
        }
    }

    // --- Saved session persistence ---

    private fun loadSavedSession() {
        viewModelScope.launch {
            // Load persisted scanner settings first (timeout, concurrency, etc.)
            // so they serve as defaults. A restored session will override them.
            loadScannerSettings()
            try {
                val json = preferencesDataStore.getSavedScanSession()
                if (json != null) {
                    val session = gson.fromJson(json, SavedScanSession::class.java)
                    val savedMode = try { session.scanMode?.let { ScanMode.valueOf(it) } } catch (_: Exception) { null }
                    val isSimple = savedMode == ScanMode.SIMPLE
                    // In simple mode, a completed DNS scan is still resumable (E2E may be partial)
                    val isResumable = if (isSimple) {
                        session != null && session.resolverList.isNotEmpty() && session.scannedCount > 0
                    } else {
                        session != null && session.resolverList.isNotEmpty() &&
                            session.scannedCount > 0 && session.scannedCount < session.resolverList.size
                    }
                    if (isResumable && session != null) {
                        // Restore the previous scan state.
                        val results = session.resolverList.map { host ->
                            val saved = session.results.find { it.host == host }
                            saved?.toScanResult() ?: ResolverScanResult(host = host)
                        }
                        // Rebuild simpleModeE2eState from restored results
                        val simpleModeE2e = if (isSimple) {
                            val working = results.filter { it.status == ResolverStatus.WORKING }
                            SimpleModeE2eState(
                                queuedCount = working.size,
                                testedCount = working.count { it.e2eTestResult != null },
                                passedCount = working.count { it.e2eTestResult?.success == true }
                            )
                        } else SimpleModeE2eState()

                        _uiState.value = _uiState.value.copy(
                            resolverList = session.resolverList,
                            testDomain = session.testDomain,
                            timeoutMs = session.timeoutMs,
                            concurrency = session.concurrency,
                            listSource = try { ListSource.valueOf(session.listSource) } catch (_: Exception) { ListSource.DEFAULT },
                            scannerState = ScannerState(
                                isScanning = false,
                                totalCount = session.resolverList.size,
                                scannedCount = session.scannedCount,
                                workingCount = session.workingCount,
                                results = results
                            ),
                            selectedResolvers = emptySet(),
                            customRangeInput = session.customRangeInput ?: "",
                            scanMode = savedMode ?: _uiState.value.scanMode,
                            simpleModeE2eState = simpleModeE2e
                        )
                        // Override testDomain with profile domain (profile takes priority)
                        loadProfileDomain()
                        return@launch
                    }
                }
            } catch (e: Exception) {
                Log.w("DnsScanner", "Failed to load saved session", e)
            }
            // No valid saved session — load resolver list based on last selection.
            when (_uiState.value.listSource) {
                ListSource.COUNTRY_RANGE, ListSource.CUSTOM_RANGE -> {
                    // Only restore the selection state (country/custom panel);
                    // the actual IP list must be regenerated by the user.
                    _uiState.value = _uiState.value.copy(
                        resolverList = scannerRepository.getDefaultResolvers(),
                        scannerState = ScannerState(),
                        selectedResolvers = emptySet()
                    )
                }
                else -> loadDefaultList()
            }
            loadProfileDomain()
        }
    }

    private fun saveScanSessionToStore() {
        val state = _uiState.value
        val scanState = state.scannerState
        // In simple mode, save whenever there's partial progress (DNS or E2E)
        if (state.scanMode == ScanMode.SIMPLE) {
            if (scanState.scannedCount <= 0) return
        } else {
            if (scanState.scannedCount <= 0 || scanState.scannedCount >= scanState.totalCount + scanState.focusRangeCount) return
        }

        val savedResults = scanState.results
            .filter { it.status != ResolverStatus.PENDING && it.status != ResolverStatus.SCANNING }
            .map { it.toSavedResult() }

        val session = SavedScanSession(
            resolverList = state.resolverList,
            testDomain = state.effectiveTestDomain,
            timeoutMs = state.timeoutMs,
            concurrency = state.concurrency,
            listSource = state.listSource.name,
            scannedCount = scanState.scannedCount,
            workingCount = scanState.workingCount,
            results = savedResults,
            customRangeInput = state.customRangeInput.ifEmpty { null },
            scanMode = state.scanMode.name
        )

        viewModelScope.launch {
            withContext(NonCancellable) {
                try {
                    preferencesDataStore.saveScanSession(gson.toJson(session))
                } catch (e: Exception) {
                    Log.w("DnsScanner", "Failed to save scan session", e)
                }
            }
        }
    }

    private fun clearSavedSession() {
        viewModelScope.launch {
            try {
                preferencesDataStore.clearScanSession()
            } catch (_: Exception) {}
        }
    }

    // --- List loading ---

    fun loadDefaultList() {
        clearSavedSession()
        _uiState.value = _uiState.value.copy(
            resolverList = scannerRepository.getDefaultResolvers(),
            listSource = ListSource.DEFAULT,
            scannerState = ScannerState(),
            selectedResolvers = emptySet()
        )
        saveListSelection()
    }

    fun importList(content: String, fileName: String? = null) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoadingList = true)
            try {
                val resolvers = scannerRepository.parseResolverList(content)
                if (resolvers.isEmpty()) {
                    _uiState.value = _uiState.value.copy(
                        isLoadingList = false,
                        error = "No valid IP addresses found in file"
                    )
                } else {
                    clearSavedSession()
                    _uiState.value = _uiState.value.copy(
                        resolverList = resolvers,
                        listSource = ListSource.IMPORTED,
                        importedFileName = fileName,
                        scannerState = ScannerState(),
                        selectedResolvers = emptySet(),
                        isLoadingList = false
                    )
                    saveListSelection()
                }
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isLoadingList = false,
                    error = "Failed to parse file: ${e.message}"
                )
            }
        }
    }

    fun updateTestDomain(domain: String) {
        _uiState.value = _uiState.value.copy(testDomain = domain)
    }

    fun updateTimeout(timeout: String) {
        _uiState.value = _uiState.value.copy(timeoutMs = timeout)
        saveScannerSettings()
    }

    fun updateConcurrency(concurrency: String) {
        _uiState.value = _uiState.value.copy(concurrency = concurrency)
        saveScannerSettings()
    }

    fun updateSelectedCountry(country: GeoBypassCountry) {
        _uiState.value = _uiState.value.copy(
            selectedCountry = country,
            cidrGroups = emptyList(),
            selectedOctets = emptySet()
        )
        saveListSelection()
        loadCountryCidrInfo()
    }

    fun updateSampleCount(count: Int) {
        _uiState.value = _uiState.value.copy(
            sampleCount = count,
            useCustomSampleCount = false
        )
        saveListSelection()
    }

    fun setUseCustomSampleCount(use: Boolean) {
        _uiState.value = _uiState.value.copy(useCustomSampleCount = use)
    }

    fun updateCustomSampleCount(text: String) {
        _uiState.value = _uiState.value.copy(
            customSampleCountText = text.filter { it.isDigit() },
            useCustomSampleCount = true
        )
    }

    fun loadCountryCidrInfo() {
        val state = _uiState.value
        viewModelScope.launch(Dispatchers.Default) {
            val ranges = scannerRepository.loadCountryCidrRanges(appContext, state.selectedCountry.code)
            val groups = ranges.groupBy { ((it.first shr 24) and 0xFF).toInt() }
                .map { (octet, rangeList) ->
                    CidrGroup(
                        firstOctet = octet,
                        label = "$octet.x.x.x",
                        rangeCount = rangeList.size,
                        totalIps = rangeList.sumOf { it.second - it.first + 1 },
                        ranges = rangeList
                    )
                }
                .sortedBy { it.firstOctet }

            _uiState.value = _uiState.value.copy(
                cidrGroups = groups,
                selectedOctets = groups.map { it.firstOctet }.toSet()
            )
        }
    }

    fun toggleOctetGroup(octet: Int) {
        val current = _uiState.value.selectedOctets
        _uiState.value = _uiState.value.copy(
            selectedOctets = if (octet in current) current - octet else current + octet
        )
    }

    fun selectAllOctetGroups() {
        _uiState.value = _uiState.value.copy(
            selectedOctets = _uiState.value.cidrGroups.map { it.firstOctet }.toSet()
        )
    }

    fun deselectAllOctetGroups() {
        _uiState.value = _uiState.value.copy(selectedOctets = emptySet())
    }

    fun loadCountryRangeList() {
        val state = _uiState.value
        val effectiveCount = state.effectiveSampleCount
        _uiState.value = state.copy(isLoadingList = true)

        viewModelScope.launch(Dispatchers.Default) {
            try {
                val selectedRanges = if (state.cidrGroups.isNotEmpty()) {
                    state.cidrGroups
                        .filter { it.firstOctet in state.selectedOctets }
                        .flatMap { it.ranges }
                } else {
                    scannerRepository.loadCountryCidrRanges(appContext, state.selectedCountry.code)
                }

                if (selectedRanges.isEmpty()) {
                    _uiState.value = _uiState.value.copy(
                        isLoadingList = false,
                        error = "No IP ranges selected"
                    )
                    return@launch
                }

                val ips = scannerRepository.generateFromRanges(selectedRanges, effectiveCount)
                if (ips.isEmpty()) {
                    _uiState.value = _uiState.value.copy(
                        isLoadingList = false,
                        error = "No CIDR ranges found for ${state.selectedCountry.displayName}"
                    )
                } else {
                    clearSavedSession()
                    _uiState.value = _uiState.value.copy(
                        resolverList = ips,
                        listSource = ListSource.COUNTRY_RANGE,
                        scannerState = ScannerState(),
                        selectedResolvers = emptySet(),
                        isLoadingList = false,
                        timeoutMs = "1500"
                    )
                    saveListSelection()
                }
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isLoadingList = false,
                    error = "Failed to generate IPs: ${e.message}"
                )
            }
        }
    }

    fun updateCustomRangeInput(text: String) {
        _uiState.value = _uiState.value.copy(customRangeInput = text)
        saveListSelection()
    }

    fun updateShuffleList(enabled: Boolean) {
        _uiState.value = _uiState.value.copy(shuffleList = enabled)
    }

    fun updateExpandNeighbors(enabled: Boolean) {
        _uiState.value = _uiState.value.copy(expandNeighbors = enabled)
    }

    fun setScanMode(mode: ScanMode) {
        val state = _uiState.value
        if (state.scannerState.isScanning || state.e2eScannerState.isRunning || state.simpleModeE2eState.isRunning) return
        _uiState.value = state.copy(scanMode = mode)
    }

    fun loadCustomRangeList() {
        val input = _uiState.value.customRangeInput
        val ranges = mutableListOf<Pair<Long, Long>>()

        for (line in input.lines()) {
            val trimmed = line.trim()
            if (trimmed.isBlank()) continue
            val range = parseIpRange(trimmed)
            if (range != null) {
                ranges.add(range)
            }
        }

        if (ranges.isEmpty()) {
            _uiState.value = _uiState.value.copy(
                error = "No valid IP ranges found. Use CIDR (8.8.8.0/24), range (8.8.8.1-8.8.8.254), or single IP."
            )
            return
        }

        // Safety cap check
        var totalCount = 0L
        for ((start, end) in ranges) {
            totalCount += (end - start + 1)
            if (totalCount > 100_000) {
                _uiState.value = _uiState.value.copy(
                    error = "Too many IPs (over 100,000). Use smaller ranges."
                )
                return
            }
        }

        _uiState.value = _uiState.value.copy(isLoadingList = true)

        viewModelScope.launch(Dispatchers.Default) {
            try {
                val ips = scannerRepository.expandIpRanges(ranges)
                clearSavedSession()
                _uiState.value = _uiState.value.copy(
                    resolverList = ips,
                    listSource = ListSource.CUSTOM_RANGE,
                    scannerState = ScannerState(),
                    selectedResolvers = emptySet(),
                    isLoadingList = false,
                    timeoutMs = "1500"
                )
                saveListSelection()
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isLoadingList = false,
                    error = "Failed to expand IP ranges: ${e.message}"
                )
            }
        }
    }

    private fun parseIpRange(line: String): Pair<Long, Long>? {
        // Try CIDR first (e.g. 8.8.8.0/24)
        DomainRouter.parseCidr(line)?.let { return it }

        // Try range format (e.g. 8.8.8.1-8.8.8.254)
        if ('-' in line) {
            val parts = line.split('-', limit = 2)
            if (parts.size == 2) {
                val start = DomainRouter.ipToLong(parts[0].trim())
                val end = DomainRouter.ipToLong(parts[1].trim())
                if (start != null && end != null && start <= end) {
                    return Pair(start, end)
                }
            }
        }

        // Try single IP (e.g. 8.8.8.8)
        DomainRouter.ipToLong(line)?.let { ip ->
            return Pair(ip, ip)
        }

        return null
    }

    fun toggleResolverSelection(host: String) {
        val current = _uiState.value.selectedResolvers
        if (current.contains(host)) {
            _uiState.value = _uiState.value.copy(selectedResolvers = current - host)
        } else if (current.size < DnsScannerUiState.MAX_SELECTED_RESOLVERS) {
            _uiState.value = _uiState.value.copy(selectedResolvers = current + host)
        }
    }

    fun clearSelection() {
        _uiState.value = _uiState.value.copy(selectedResolvers = emptySet())
    }

    // --- Scan control ---

    fun startScan() {
        val state = _uiState.value
        if (state.resolverList.isEmpty()) {
            _uiState.value = _uiState.value.copy(error = "No resolvers to scan")
            return
        }

        if (state.effectiveTestDomain.isBlank()) {
            _uiState.value = _uiState.value.copy(error = "Test domain is required")
            return
        }

        // Simple mode requires VPN to be off (E2E needs direct connectivity)
        if (state.scanMode == ScanMode.SIMPLE && vpnRepository.isConnected()) {
            _uiState.value = _uiState.value.copy(error = "Disconnect VPN before running Simple Scan")
            return
        }

        // Check for resumable partial scan
        val ss = state.scannerState
        val hasPartialDns = ss.scannedCount > 0 && ss.scannedCount < ss.totalCount + ss.focusRangeCount
        val hasPartialE2e = state.scanMode == ScanMode.SIMPLE &&
            ss.scannedCount > 0 &&
            ss.results.any { it.status == ResolverStatus.WORKING && it.e2eTestResult == null }
        if (!ss.isScanning && (hasPartialDns || hasPartialE2e)) {
            _uiState.value = _uiState.value.copy(showResumeDialog = true)
            return
        }

        startFreshScan()
    }

    fun dismissResumeDialog() {
        _uiState.value = _uiState.value.copy(showResumeDialog = false)
    }

    fun startFreshScan() {
        acquireWakeLock()
        _uiState.value = _uiState.value.copy(showResumeDialog = false)
        clearSavedSession()

        val state = _uiState.value
        val timeout = state.timeoutMs.toLongOrNull() ?: 3000L
        val concurrency = state.concurrency.toIntOrNull() ?: 50

        // Shuffle the list if enabled, then persist the order so resume works correctly.
        // For the default list, always fetch original order so famous resolvers stay at the top.
        val resolvers = if (state.shuffleList && state.listSource == ListSource.DEFAULT) {
            val defaultResolvers = scannerRepository.getDefaultResolvers()
            val priorityCount = scannerRepository.getDefaultResolverPriorityCount()
            val secondaryCount = scannerRepository.getDefaultResolverSecondaryCount()
            Log.d("DnsScanner", "Shuffle default: priorityCount=$priorityCount, secondaryCount=$secondaryCount, total=${defaultResolvers.size}, first5=${defaultResolvers.take(5)}")
            defaultResolvers.take(priorityCount) +
                defaultResolvers.drop(priorityCount).take(secondaryCount).shuffled() +
                defaultResolvers.drop(priorityCount + secondaryCount).shuffled()
        } else if (state.shuffleList) {
            state.resolverList.shuffled()
        } else {
            state.resolverList
        }
        Log.d("DnsScanner", "Scan order first10=${resolvers.take(10)}")

        // Initialize scanner state
        val initialResults = resolvers.map { host ->
            ResolverScanResult(host = host, status = ResolverStatus.PENDING)
        }

        _uiState.value = _uiState.value.copy(
            resolverList = resolvers,
            scannerState = ScannerState(
                isScanning = true,
                totalCount = resolvers.size,
                scannedCount = 0,
                workingCount = 0,
                results = initialResults
            ),
            selectedResolvers = emptySet(),
            error = null,
            transparentProxyDetected = false,
            simpleModeE2eState = SimpleModeE2eState()
        )

        if (state.scanMode == ScanMode.SIMPLE) {
            launchSimpleScan(
                hosts = resolvers,
                allHosts = resolvers,
                testDomain = state.effectiveTestDomain,
                timeout = timeout,
                concurrency = concurrency,
                minScore = _uiState.value.e2eMinScore
            )
        } else {
            launchScan(
                hosts = resolvers,
                allHosts = resolvers,
                testDomain = state.effectiveTestDomain,
                timeout = timeout,
                concurrency = concurrency,
                existingResults = emptyMap(),
                startScannedCount = 0,
                startWorkingCount = 0
            )
        }
    }

    fun resumeScan() {
        acquireWakeLock()
        _uiState.value = _uiState.value.copy(showResumeDialog = false)
        clearSavedSession()

        val state = _uiState.value

        if (state.scanMode == ScanMode.SIMPLE) {
            resumeSimpleScan()
            return
        }

        val timeout = state.timeoutMs.toLongOrNull() ?: 3000L
        val concurrency = state.concurrency.toIntOrNull() ?: 50

        // Determine which hosts were already scanned.
        val existingResults = mutableMapOf<String, ResolverScanResult>()
        var startWorkingCount = 0
        for (result in state.scannerState.results) {
            if (result.status != ResolverStatus.PENDING && result.status != ResolverStatus.SCANNING) {
                existingResults[result.host] = result
                if (result.status == ResolverStatus.WORKING) startWorkingCount++
            }
        }
        val scannedHosts = existingResults.keys
        val remainingHosts = state.resolverList.filter { it !in scannedHosts }

        if (remainingHosts.isEmpty()) {
            // Nothing left to scan — just mark complete.
            _uiState.value = _uiState.value.copy(
                scannerState = state.scannerState.copy(isScanning = false)
            )
            releaseWakeLock()
            return
        }

        // Update state: mark remaining as SCANNING, keep scanned results.
        val resumeResults = state.resolverList.map { host ->
            existingResults[host] ?: ResolverScanResult(host = host, status = ResolverStatus.PENDING)
        }
        _uiState.value = _uiState.value.copy(
            scannerState = ScannerState(
                isScanning = true,
                totalCount = state.resolverList.size,
                scannedCount = existingResults.size,
                workingCount = startWorkingCount,
                results = resumeResults
            ),
            selectedResolvers = emptySet(),
            error = null
        )

        launchScan(
            hosts = remainingHosts,
            allHosts = state.resolverList,
            testDomain = state.effectiveTestDomain,
            timeout = timeout,
            concurrency = concurrency,
            existingResults = existingResults,
            startScannedCount = existingResults.size,
            startWorkingCount = startWorkingCount
        )
    }

    private fun resumeSimpleScan() {
        val state = _uiState.value
        val profile = state.profile ?: run {
            _uiState.value = state.copy(error = "No profile loaded")
            releaseWakeLock()
            return
        }

        if (vpnRepository.isConnected()) {
            _uiState.value = state.copy(error = "Disconnect VPN before running Simple Scan")
            releaseWakeLock()
            return
        }

        val timeout = state.timeoutMs.toLongOrNull() ?: 3000L
        val concurrency = state.concurrency.toIntOrNull() ?: 50

        // Gather already-scanned results (preserving E2E data)
        val existingResults = mutableMapOf<String, ResolverScanResult>()
        var startWorkingCount = 0
        for (result in state.scannerState.results) {
            if (result.status != ResolverStatus.PENDING && result.status != ResolverStatus.SCANNING) {
                existingResults[result.host] = result
                if (result.status == ResolverStatus.WORKING) startWorkingCount++
            }
        }

        val scannedHosts = existingResults.keys
        val remainingDnsHosts = state.resolverList.filter { it !in scannedHosts }

        // Working resolvers that still need E2E testing (filtered by score)
        val minScore = state.e2eMinScore
        val untestedE2e = existingResults.values
            .filter { it.status == ResolverStatus.WORKING && it.e2eTestResult == null && (it.tunnelTestResult?.score ?: 0) >= minScore }
            .map { it.host to it.port }

        val hasDnsWork = remainingDnsHosts.isNotEmpty()
        val hasE2eWork = untestedE2e.isNotEmpty()

        if (!hasDnsWork && !hasE2eWork) {
            _uiState.value = state.copy(
                scannerState = state.scannerState.copy(isScanning = false),
                simpleModeE2eState = state.simpleModeE2eState.copy(isRunning = false)
            )
            releaseWakeLock()
            return
        }

        val startTestedCount = existingResults.values.count {
            it.status == ResolverStatus.WORKING && it.e2eTestResult != null
        }
        val startPassedCount = existingResults.values.count {
            it.e2eTestResult?.success == true
        }

        val channel = Channel<Pair<String, Int>>(Channel.UNLIMITED)
        simpleModeChannel = channel

        // Shared map for both coroutines
        val resultsMap = mutableMapOf<String, ResolverScanResult>()
        resultsMap.putAll(existingResults)
        var scannedCount = existingResults.size
        var workingCount = startWorkingCount

        fun rebuildResultsList() = resultsMap.values.filter { it.status == ResolverStatus.WORKING }.toList()

        // Update state for resume
        _uiState.value = state.copy(
            scannerState = ScannerState(
                isScanning = hasDnsWork,
                totalCount = state.resolverList.size,
                scannedCount = scannedCount,
                workingCount = workingCount,
                results = rebuildResultsList()
            ),
            simpleModeE2eState = SimpleModeE2eState(
                isRunning = true,
                queuedCount = startWorkingCount,
                testedCount = startTestedCount,
                passedCount = startPassedCount
            ),
            selectedResolvers = emptySet(),
            error = null
        )

        // Seed channel with already-working but untested resolvers
        untestedE2e.forEach { channel.trySend(it) }

        // Coroutine 1: DNS scan for remaining hosts
        if (hasDnsWork) {
            scanJob = viewModelScope.launch {
                val scannedSet = state.resolverList.toMutableSet()
                val useFocusRange = state.expandNeighbors && state.listSource in listOf(ListSource.COUNTRY_RANGE, ListSource.CUSTOM_RANGE)
                val focusRangeQueue = mutableListOf<String>()
                val expandedSubnets = mutableSetOf<String>()
                val maxFocusRange = 5000
                var uiUpdateCounter = 0

                fun emitState(scanning: Boolean) {
                    _uiState.value = _uiState.value.copy(
                        scannerState = ScannerState(
                            isScanning = scanning,
                            totalCount = state.resolverList.size,
                            focusRangeCount = focusRangeQueue.size,
                            scannedCount = scannedCount,
                            workingCount = workingCount,
                            results = rebuildResultsList()
                        )
                    )
                }

                fun handleResult(result: ResolverScanResult) {
                    scannedCount++
                    if (result.status == ResolverStatus.WORKING) {
                        resultsMap[result.host] = result
                        workingCount++
                        if ((result.tunnelTestResult?.score ?: 0) >= minScore) {
                            channel.trySend(result.host to result.port)
                            _uiState.value = _uiState.value.copy(
                                simpleModeE2eState = _uiState.value.simpleModeE2eState.copy(
                                    queuedCount = _uiState.value.simpleModeE2eState.queuedCount + 1
                                )
                            )
                        }
                        if (useFocusRange && focusRangeQueue.size < maxFocusRange) {
                            val parts = result.host.split(".")
                            if (parts.size == 4) {
                                val subnet = "${parts[0]}.${parts[1]}.${parts[2]}"
                                if (subnet !in expandedSubnets) {
                                    expandedSubnets.add(subnet)
                                    val neighbors = expandSlash24(result.host).filter { it !in scannedSet }
                                    if (neighbors.isNotEmpty()) {
                                        val capped = neighbors.take(maxFocusRange - focusRangeQueue.size)
                                        focusRangeQueue.addAll(capped)
                                        scannedSet.addAll(capped)
                                    }
                                }
                            }
                        }
                    }
                    uiUpdateCounter++
                    if (result.status == ResolverStatus.WORKING || uiUpdateCounter >= 10) {
                        uiUpdateCounter = 0
                        emitState(true)
                    }
                }

                scannerRepository.scanResolvers(
                    hosts = remainingDnsHosts,
                    testDomain = state.effectiveTestDomain,
                    timeoutMs = timeout,
                    concurrency = concurrency
                ).collect { handleResult(it) }
                emitState(true)

                if (focusRangeQueue.isNotEmpty()) {
                    val neighborIps = focusRangeQueue.toList()
                    _uiState.value = _uiState.value.copy(
                        resolverList = _uiState.value.resolverList + neighborIps
                    )
                    scannerRepository.scanResolvers(
                        hosts = neighborIps,
                        testDomain = state.effectiveTestDomain,
                        timeoutMs = timeout,
                        concurrency = concurrency
                    ).collect { handleResult(it) }
                }

                channel.close()
                emitState(false)
            }
        } else {
            // DNS is already complete — close channel after seeding
            channel.close()
        }

        // Coroutine 2: E2E validation
        simpleModeE2eJob = viewModelScope.launch {
            var testedCount = startTestedCount
            var passedCount = startPassedCount
            val testUrl = _uiState.value.testUrl
            val e2eTimeout = _uiState.value.e2eTimeoutMs.toLongOrNull() ?: 7000L

            for ((host, port) in channel) {
                _uiState.value = _uiState.value.copy(
                    simpleModeE2eState = _uiState.value.simpleModeE2eState.copy(
                        currentResolver = host,
                        currentPhase = "Starting..."
                    )
                )

                val e2eResult = scannerRepository.testResolverE2e(
                    resolverHost = host,
                    resolverPort = port,
                    profile = profile,
                    testUrl = testUrl,
                    timeoutMs = e2eTimeout,
                    onPhaseUpdate = { phase ->
                        _uiState.value = _uiState.value.copy(
                            simpleModeE2eState = _uiState.value.simpleModeE2eState.copy(
                                currentPhase = phase
                            )
                        )
                    }
                )

                testedCount++
                if (e2eResult.success) passedCount++

                resultsMap[host]?.let { resultsMap[host] = it.copy(e2eTestResult = e2eResult) }

                _uiState.value = _uiState.value.copy(
                    scannerState = _uiState.value.scannerState.copy(results = rebuildResultsList()),
                    simpleModeE2eState = _uiState.value.simpleModeE2eState.copy(
                        testedCount = testedCount,
                        passedCount = passedCount,
                        currentResolver = null,
                        currentPhase = ""
                    )
                )
            }

            _uiState.value = _uiState.value.copy(
                simpleModeE2eState = _uiState.value.simpleModeE2eState.copy(
                    isRunning = false,
                    currentResolver = null,
                    currentPhase = ""
                )
            )
        }
    }

    private fun launchScan(
        hosts: List<String>,
        allHosts: List<String>,
        testDomain: String,
        timeout: Long,
        concurrency: Int,
        existingResults: Map<String, ResolverScanResult>,
        startScannedCount: Int,
        startWorkingCount: Int
    ) {
        // Run transparent proxy detection concurrently
        viewModelScope.launch {
            try {
                val detected = scannerRepository.detectTransparentProxy(testDomain)
                if (detected) {
                    _uiState.value = _uiState.value.copy(transparentProxyDetected = true)
                }
            } catch (_: Exception) { }
        }

        scanJob = viewModelScope.launch {
            // Only WORKING results kept in memory; failed results tracked as counters only
            val workingResults = mutableListOf<ResolverScanResult>()
            existingResults.values.filter { it.status == ResolverStatus.WORKING }.let { workingResults.addAll(it) }
            var scannedCount = startScannedCount
            var workingCount = startWorkingCount
            var timeoutCount = 0
            var errorCount = 0
            val scannedSet = allHosts.toMutableSet()
            var uiUpdateCounter = 0

            // Focus range: collect /24 neighbors of working resolvers (capped at 5000)
            val useFocusRange = _uiState.value.expandNeighbors && _uiState.value.listSource in listOf(ListSource.COUNTRY_RANGE, ListSource.CUSTOM_RANGE)
            val focusRangeQueue = mutableListOf<String>()
            val expandedSubnets = mutableSetOf<String>()
            val maxFocusRange = 5000

            fun emitState(scanning: Boolean) {
                _uiState.value = _uiState.value.copy(
                    scannerState = ScannerState(
                        isScanning = scanning,
                        totalCount = allHosts.size,
                        focusRangeCount = focusRangeQueue.size,
                        scannedCount = scannedCount,
                        workingCount = workingCount,
                        timeoutCount = timeoutCount,
                        errorCount = errorCount,
                        results = workingResults.toList()
                    )
                )
            }

            fun handleResult(result: ResolverScanResult) {
                scannedCount++
                when (result.status) {
                    ResolverStatus.WORKING -> {
                        workingCount++
                        workingResults.add(result)
                        // Focus range: expand /24 subnet
                        if (useFocusRange && focusRangeQueue.size < maxFocusRange) {
                            val parts = result.host.split(".")
                            if (parts.size == 4) {
                                val subnet = "${parts[0]}.${parts[1]}.${parts[2]}"
                                if (subnet !in expandedSubnets) {
                                    expandedSubnets.add(subnet)
                                    val neighbors = expandSlash24(result.host).filter { it !in scannedSet }
                                    if (neighbors.isNotEmpty()) {
                                        val capped = neighbors.take(maxFocusRange - focusRangeQueue.size)
                                        focusRangeQueue.addAll(capped)
                                        scannedSet.addAll(capped)
                                        Log.d("DnsScanner", "Focus range: expanding $subnet.0/24 (+${capped.size} IPs)")
                                    }
                                }
                            }
                        }
                    }
                    ResolverStatus.TIMEOUT -> timeoutCount++
                    ResolverStatus.ERROR, ResolverStatus.CENSORED -> errorCount++
                    else -> {}
                }
                // Batch UI updates: every 10 results or on working result
                uiUpdateCounter++
                if (result.status == ResolverStatus.WORKING || uiUpdateCounter >= 10) {
                    uiUpdateCounter = 0
                    emitState(true)
                }
            }

            scannerRepository.scanResolvers(
                hosts = hosts,
                testDomain = testDomain,
                timeoutMs = timeout,
                concurrency = concurrency
            ).collect { handleResult(it) }
            emitState(true)

            // Phase 2: scan focus range neighbors
            if (focusRangeQueue.isNotEmpty()) {
                val neighborIps = focusRangeQueue.toList()
                Log.d("DnsScanner", "Focus range: scanning ${neighborIps.size} neighbor IPs from ${expandedSubnets.size} subnets")
                // Persist neighbors in resolverList so resume works
                _uiState.value = _uiState.value.copy(
                    resolverList = _uiState.value.resolverList + neighborIps
                )
                scannerRepository.scanResolvers(
                    hosts = neighborIps,
                    testDomain = testDomain,
                    timeoutMs = timeout,
                    concurrency = concurrency
                ).collect { handleResult(it) }
            }

            emitState(false)
            clearSavedSession()
            releaseWakeLock()
        }
    }

    private fun launchSimpleScan(
        hosts: List<String>,
        allHosts: List<String>,
        testDomain: String,
        timeout: Long,
        concurrency: Int,
        minScore: Int = 1
    ) {
        val profile = _uiState.value.profile ?: run {
            _uiState.value = _uiState.value.copy(error = "No profile loaded")
            return
        }

        val channel = Channel<Pair<String, Int>>(Channel.UNLIMITED)
        simpleModeChannel = channel

        _uiState.value = _uiState.value.copy(
            simpleModeE2eState = SimpleModeE2eState(isRunning = true)
        )

        // Shared mutable map — both coroutines run on Main so no concurrent writes.
        // DNS scan writes scan results; E2E coroutine merges e2eTestResult onto existing entries.
        val resultsMap = mutableMapOf<String, ResolverScanResult>()
        var scannedCount = 0
        var workingCount = 0
        val allHostsMutable = allHosts.toMutableList()

        // Only return WORKING results (non-working are tracked as counters)
        fun rebuildResultsList() = resultsMap.values.filter { it.status == ResolverStatus.WORKING }.toList()

        // Run transparent proxy detection concurrently
        viewModelScope.launch {
            try {
                val detected = scannerRepository.detectTransparentProxy(testDomain)
                if (detected) {
                    _uiState.value = _uiState.value.copy(transparentProxyDetected = true)
                }
            } catch (_: Exception) { }
        }

        // Coroutine 1: DNS scan — produces working resolver candidates
        scanJob = viewModelScope.launch {
            val scannedSet = allHostsMutable.toMutableSet()
            val useFocusRange = _uiState.value.expandNeighbors && _uiState.value.listSource in listOf(ListSource.COUNTRY_RANGE, ListSource.CUSTOM_RANGE)
            val focusRangeQueue = mutableListOf<String>()
            val expandedSubnets = mutableSetOf<String>()
            val maxFocusRange = 5000
            var timeoutCount = 0
            var errorCount = 0
            var uiUpdateCounter = 0

            fun emitState(scanning: Boolean) {
                _uiState.value = _uiState.value.copy(
                    scannerState = ScannerState(
                        isScanning = scanning,
                        totalCount = allHosts.size,
                        focusRangeCount = focusRangeQueue.size,
                        scannedCount = scannedCount,
                        workingCount = workingCount,
                        timeoutCount = timeoutCount,
                        errorCount = errorCount,
                        results = resultsMap.values.filter { it.status == ResolverStatus.WORKING }.toList()
                    )
                )
            }

            fun handleResult(result: ResolverScanResult) {
                scannedCount++
                when (result.status) {
                    ResolverStatus.WORKING -> {
                        resultsMap[result.host] = result
                        workingCount++
                        if ((result.tunnelTestResult?.score ?: 0) >= minScore) {
                            channel.trySend(result.host to result.port)
                            _uiState.value = _uiState.value.copy(
                                simpleModeE2eState = _uiState.value.simpleModeE2eState.copy(
                                    queuedCount = _uiState.value.simpleModeE2eState.queuedCount + 1
                                )
                            )
                        }
                        // Focus range: expand /24 subnet
                        if (useFocusRange && focusRangeQueue.size < maxFocusRange) {
                            val parts = result.host.split(".")
                            if (parts.size == 4) {
                                val subnet = "${parts[0]}.${parts[1]}.${parts[2]}"
                                if (subnet !in expandedSubnets) {
                                    expandedSubnets.add(subnet)
                                    val neighbors = expandSlash24(result.host).filter { it !in scannedSet }
                                    if (neighbors.isNotEmpty()) {
                                        val capped = neighbors.take(maxFocusRange - focusRangeQueue.size)
                                        focusRangeQueue.addAll(capped)
                                        scannedSet.addAll(capped)
                                        Log.d("DnsScanner", "Focus range: expanding $subnet.0/24 (+${capped.size} IPs)")
                                    }
                                }
                            }
                        }
                    }
                    ResolverStatus.TIMEOUT -> timeoutCount++
                    ResolverStatus.ERROR, ResolverStatus.CENSORED -> errorCount++
                    else -> {}
                }
                uiUpdateCounter++
                if (result.status == ResolverStatus.WORKING || uiUpdateCounter >= 10) {
                    uiUpdateCounter = 0
                    emitState(true)
                }
            }

            scannerRepository.scanResolvers(
                hosts = hosts,
                testDomain = testDomain,
                timeoutMs = timeout,
                concurrency = concurrency
            ).collect { handleResult(it) }
            emitState(true)

            // Phase 2: scan focus range neighbors
            if (focusRangeQueue.isNotEmpty()) {
                val neighborIps = focusRangeQueue.toList()
                Log.d("DnsScanner", "Focus range: scanning ${neighborIps.size} neighbor IPs")
                // Persist neighbors in resolverList so resume works
                _uiState.value = _uiState.value.copy(
                    resolverList = _uiState.value.resolverList + neighborIps
                )
                scannerRepository.scanResolvers(
                    hosts = neighborIps,
                    testDomain = testDomain,
                    timeoutMs = timeout,
                    concurrency = concurrency
                ).collect { handleResult(it) }
            }

            // DNS scan done — close channel so E2E coroutine finishes
            channel.close()
            emitState(false)
        }

        // Coroutine 2: E2E validation — consumes working resolvers from channel
        simpleModeE2eJob = viewModelScope.launch {
            var testedCount = 0
            var passedCount = 0
            val testUrl = _uiState.value.testUrl
            val e2eTimeout = _uiState.value.e2eTimeoutMs.toLongOrNull() ?: 7000L

            for ((host, port) in channel) {
                _uiState.value = _uiState.value.copy(
                    simpleModeE2eState = _uiState.value.simpleModeE2eState.copy(
                        currentResolver = host,
                        currentPhase = "Starting..."
                    )
                )

                val e2eResult = scannerRepository.testResolverE2e(
                    resolverHost = host,
                    resolverPort = port,
                    profile = profile,
                    testUrl = testUrl,
                    timeoutMs = e2eTimeout,
                    onPhaseUpdate = { phase ->
                        _uiState.value = _uiState.value.copy(
                            simpleModeE2eState = _uiState.value.simpleModeE2eState.copy(
                                currentPhase = phase
                            )
                        )
                    }
                )

                testedCount++
                if (e2eResult.success) passedCount++

                // Merge E2E result into the shared map and rebuild
                resultsMap[host]?.let { resultsMap[host] = it.copy(e2eTestResult = e2eResult) }

                _uiState.value = _uiState.value.copy(
                    scannerState = _uiState.value.scannerState.copy(results = rebuildResultsList()),
                    simpleModeE2eState = _uiState.value.simpleModeE2eState.copy(
                        testedCount = testedCount,
                        passedCount = passedCount,
                        currentResolver = null,
                        currentPhase = ""
                    )
                )
            }

            // E2E pipeline done
            _uiState.value = _uiState.value.copy(
                simpleModeE2eState = _uiState.value.simpleModeE2eState.copy(
                    isRunning = false,
                    currentResolver = null,
                    currentPhase = ""
                )
            )
            releaseWakeLock()
        }
    }

    fun stopScan() {
        releaseWakeLock()
        val isSimpleMode = _uiState.value.scanMode == ScanMode.SIMPLE
        scanJob?.cancel()
        if (isSimpleMode) {
            simpleModeChannel?.close()
            simpleModeE2eJob?.cancel()
            _uiState.value = _uiState.value.copy(
                scannerState = _uiState.value.scannerState.copy(isScanning = false),
                simpleModeE2eState = _uiState.value.simpleModeE2eState.copy(
                    isRunning = false,
                    currentResolver = null,
                    currentPhase = ""
                )
            )
            cleanupBridge()
        } else {
            _uiState.value = _uiState.value.copy(
                scannerState = _uiState.value.scannerState.copy(isScanning = false)
            )
        }
        saveScanSessionToStore()
    }

    // --- E2E tunnel testing ---

    fun updateTestUrl(url: String) {
        _uiState.value = _uiState.value.copy(testUrl = url)
        saveScannerSettings()
    }

    fun updateE2eTimeout(value: String) {
        _uiState.value = _uiState.value.copy(e2eTimeoutMs = value)
        saveScannerSettings()
    }

    fun updateE2eMinScore(minScore: Int) {
        _uiState.value = _uiState.value.copy(e2eMinScore = minScore)
    }

    fun startE2eTest(fresh: Boolean = false, minScore: Int = 0) {
        val state = _uiState.value
        val profile = state.profile ?: run {
            _uiState.value = state.copy(error = "No profile loaded")
            return
        }

        if (vpnRepository.isConnected()) {
            _uiState.value = state.copy(error = "Disconnect VPN before running E2E test")
            return
        }

        val allWorking = state.scannerState.results
            .filter { it.status == ResolverStatus.WORKING && (it.tunnelTestResult?.score ?: 0) >= minScore }

        if (allWorking.isEmpty()) {
            _uiState.value = state.copy(error = "No working resolvers to test")
            return
        }

        // Determine which resolvers still need testing (resume support)
        val alreadyTested = if (fresh) emptySet()
        else allWorking.filter { it.e2eTestResult != null }.map { it.host }.toSet()

        val remaining = allWorking
            .filter { it.host !in alreadyTested }
            .map { it.host to it.port }

        if (remaining.isEmpty()) {
            _uiState.value = state.copy(error = "All working resolvers already tested")
            return
        }

        // If fresh, clear existing E2E results
        if (fresh) {
            val clearedResults = state.scannerState.results.map { r ->
                if (r.status == ResolverStatus.WORKING) r.copy(e2eTestResult = null) else r
            }
            _uiState.value = _uiState.value.copy(
                scannerState = state.scannerState.copy(results = clearedResults)
            )
        }

        val startTestedCount = alreadyTested.size
        val startPassedCount = if (fresh) 0
        else allWorking.count { it.e2eTestResult?.success == true }

        acquireWakeLock()
        _uiState.value = _uiState.value.copy(
            e2eScannerState = E2eScannerState(
                isRunning = true,
                totalCount = allWorking.size,
                testedCount = startTestedCount,
                passedCount = startPassedCount
            )
        )

        e2eJob = viewModelScope.launch {
            var testedCount = startTestedCount
            var passedCount = startPassedCount

            scannerRepository.testResolversE2e(
                resolvers = remaining,
                profile = profile,
                testUrl = _uiState.value.testUrl,
                timeoutMs = _uiState.value.e2eTimeoutMs.toLongOrNull() ?: 5000L,
                onPhaseUpdate = { resolver, phase ->
                    _uiState.value = _uiState.value.copy(
                        e2eScannerState = _uiState.value.e2eScannerState.copy(
                            currentResolver = resolver,
                            currentPhase = phase
                        )
                    )
                }
            ).collect { (host, e2eResult) ->
                testedCount++
                if (e2eResult.success) passedCount++

                // Update the scan result with the E2E result
                val updatedResults = _uiState.value.scannerState.results.map { r ->
                    if (r.host == host) r.copy(e2eTestResult = e2eResult) else r
                }

                _uiState.value = _uiState.value.copy(
                    scannerState = _uiState.value.scannerState.copy(results = updatedResults),
                    e2eScannerState = _uiState.value.e2eScannerState.copy(
                        testedCount = testedCount,
                        passedCount = passedCount,
                        currentResolver = null,
                        currentPhase = ""
                    )
                )
            }

            // Done
            _uiState.value = _uiState.value.copy(
                e2eScannerState = _uiState.value.e2eScannerState.copy(isRunning = false)
            )
            releaseWakeLock()
        }
    }

    fun stopE2eTest() {
        releaseWakeLock()
        e2eJob?.cancel()
        _uiState.value = _uiState.value.copy(
            e2eScannerState = _uiState.value.e2eScannerState.copy(
                isRunning = false,
                currentResolver = null,
                currentPhase = ""
            )
        )
        cleanupBridge()
    }

    private fun cleanupBridge() {
        val profile = _uiState.value.profile ?: return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                when (profile.tunnelType) {
                    TunnelType.SLIPSTREAM, TunnelType.SLIPSTREAM_SSH -> {
                        SlipstreamBridge.stopClient()
                        SlipstreamBridge.proxyOnlyMode = false
                    }
                    TunnelType.DNSTT, TunnelType.DNSTT_SSH,
                    TunnelType.NOIZDNS, TunnelType.NOIZDNS_SSH -> {
                        DnsttBridge.stopClient()
                    }
                    else -> {}
                }
            } catch (_: Exception) {}
        }
    }

    fun getSelectedResolversString(): String {
        return _uiState.value.selectedResolvers.joinToString(",") { "$it:53" }
    }

    fun clearError() {
        _uiState.value = _uiState.value.copy(error = null)
    }

    override fun onCleared() {
        super.onCleared()
        releaseWakeLock()
        scanJob?.cancel()
        e2eJob?.cancel()
        simpleModeChannel?.close()
        simpleModeE2eJob?.cancel()

        // Save partial results so the user can resume after navigating away.
        val state = _uiState.value
        val ss = state.scannerState
        val isSimple = state.scanMode == ScanMode.SIMPLE

        // In simple mode, save whenever there's any scanned progress
        // In advanced mode, save only if DNS scan is partial
        val shouldSave = if (isSimple) {
            ss.scannedCount > 0
        } else {
            ss.scannedCount > 0 && ss.scannedCount < ss.totalCount + ss.focusRangeCount
        }

        if (shouldSave) {
            val savedResults = ss.results
                .filter { it.status != ResolverStatus.PENDING && it.status != ResolverStatus.SCANNING }
                .map { it.toSavedResult() }
            val session = SavedScanSession(
                resolverList = state.resolverList,
                testDomain = state.effectiveTestDomain,
                timeoutMs = state.timeoutMs,
                concurrency = state.concurrency,
                listSource = state.listSource.name,
                scannedCount = ss.scannedCount,
                workingCount = ss.workingCount,
                results = savedResults,
                customRangeInput = state.customRangeInput.ifEmpty { null },
                scanMode = state.scanMode.name
            )
            try {
                val file = java.io.File(appContext.cacheDir, "scan_session.json")
                file.writeText(gson.toJson(session))
            } catch (_: Exception) {}
        }
    }
}

// --- Conversion helpers ---

private fun ResolverScanResult.toSavedResult() = SavedResult(
    host = host,
    status = status.name,
    responseTimeMs = responseTimeMs,
    errorMessage = errorMessage,
    nsSupport = tunnelTestResult?.nsSupport,
    txtSupport = tunnelTestResult?.txtSupport,
    randomSub = tunnelTestResult?.randomSubdomain,
    tunnelRealism = tunnelTestResult?.tunnelRealism,
    edns0Support = tunnelTestResult?.edns0Support,
    e2eSuccess = e2eTestResult?.success,
    e2eTotalMs = e2eTestResult?.totalMs,
    e2eTunnelSetupMs = e2eTestResult?.tunnelSetupMs,
    e2eHttpLatencyMs = e2eTestResult?.httpLatencyMs,
    e2eHttpStatusCode = e2eTestResult?.httpStatusCode,
    e2eErrorMessage = e2eTestResult?.errorMessage
)

private fun SavedResult.toScanResult() = ResolverScanResult(
    host = host,
    status = try { ResolverStatus.valueOf(status) } catch (_: Exception) { ResolverStatus.PENDING },
    responseTimeMs = responseTimeMs,
    errorMessage = errorMessage,
    tunnelTestResult = if (nsSupport != null) {
        DnsTunnelTestResult(
            nsSupport = nsSupport,
            txtSupport = txtSupport ?: false,
            randomSubdomain = randomSub ?: false,
            tunnelRealism = tunnelRealism ?: false,
            edns0Support = edns0Support ?: false
        )
    } else null,
    e2eTestResult = if (e2eSuccess != null) {
        E2eTestResult(
            success = e2eSuccess,
            totalMs = e2eTotalMs ?: 0,
            tunnelSetupMs = e2eTunnelSetupMs ?: 0,
            httpLatencyMs = e2eHttpLatencyMs ?: 0,
            httpStatusCode = e2eHttpStatusCode ?: 0,
            errorMessage = e2eErrorMessage
        )
    } else null
)
