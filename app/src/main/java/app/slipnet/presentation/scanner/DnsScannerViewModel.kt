package app.slipnet.presentation.scanner

import android.util.Log
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.slipnet.domain.model.DnsTunnelTestResult
import app.slipnet.domain.model.ResolverScanResult
import app.slipnet.domain.model.ResolverStatus
import app.slipnet.domain.model.ScanMode
import app.slipnet.domain.model.ScannerState
import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.domain.repository.ResolverScannerRepository
import app.slipnet.tunnel.DomainRouter
import app.slipnet.tunnel.GeoBypassCountry
import com.google.gson.Gson
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

data class DnsScannerUiState(
    val profileId: Long? = null,
    val testDomain: String = "google.com",
    val timeoutMs: String = "3000",
    val concurrency: String = "50",
    val scanMode: ScanMode = ScanMode.DNS_TUNNEL,
    val resolverList: List<String> = emptyList(),
    val scannerState: ScannerState = ScannerState(),
    val selectedResolvers: Set<String> = emptySet(),
    val recentDnsResolvers: List<String> = emptyList(),
    val isLoadingList: Boolean = false,
    val error: String? = null,
    val listSource: ListSource = ListSource.DEFAULT,
    val selectedCountry: GeoBypassCountry = GeoBypassCountry.IR,
    val sampleCount: Int = 2000,
    val customRangeInput: String = "",
    val showResumeDialog: Boolean = false
) {
    companion object {
        const val MAX_SELECTED_RESOLVERS = 8
    }

    val isSelectionLimitReached: Boolean
        get() = selectedResolvers.size >= MAX_SELECTED_RESOLVERS

    val selectionLimitMessage: String
        get() = "Maximum $MAX_SELECTED_RESOLVERS resolvers can be selected"
}

enum class ListSource {
    DEFAULT,
    IMPORTED,
    COUNTRY_RANGE,
    CUSTOM_RANGE
}

// Lightweight models for JSON serialization of scan sessions.
private data class SavedScanSession(
    val resolverList: List<String>,
    val testDomain: String,
    val timeoutMs: String,
    val concurrency: String,
    val scanMode: String,
    val listSource: String,
    val scannedCount: Int,
    val workingCount: Int,
    val results: List<SavedResult>,
    val customRangeInput: String? = null
)

private data class SavedResult(
    val host: String,
    val status: String,
    val responseTimeMs: Long?,
    val errorMessage: String?,
    val nsSupport: Boolean?,
    val txtSupport: Boolean?,
    val randomSub1: Boolean?,
    val randomSub2: Boolean?
)

@HiltViewModel
class DnsScannerViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val scannerRepository: ResolverScannerRepository,
    private val preferencesDataStore: PreferencesDataStore,
    @ApplicationContext private val appContext: android.content.Context
) : ViewModel() {

    private val profileId: Long? = savedStateHandle.get<Long>("profileId")?.takeIf { it != -1L }

    private val _uiState = MutableStateFlow(DnsScannerUiState(profileId = profileId))
    val uiState: StateFlow<DnsScannerUiState> = _uiState.asStateFlow()

    private var scanJob: Job? = null
    private val gson = Gson()

    init {
        loadSavedSession()
        loadRecentDns()
    }

    private fun loadRecentDns() {
        viewModelScope.launch {
            preferencesDataStore.recentDnsResolvers.collect { resolvers ->
                _uiState.value = _uiState.value.copy(recentDnsResolvers = resolvers)
            }
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
            try {
                val json = preferencesDataStore.getSavedScanSession()
                if (json != null) {
                    val session = gson.fromJson(json, SavedScanSession::class.java)
                    if (session != null && session.resolverList.isNotEmpty() &&
                        session.scannedCount > 0 && session.scannedCount < session.resolverList.size
                    ) {
                        // Restore the previous scan state.
                        val results = session.resolverList.map { host ->
                            val saved = session.results.find { it.host == host }
                            saved?.toScanResult() ?: ResolverScanResult(host = host)
                        }
                        _uiState.value = _uiState.value.copy(
                            resolverList = session.resolverList,
                            testDomain = session.testDomain,
                            timeoutMs = session.timeoutMs,
                            concurrency = session.concurrency,
                            scanMode = try { ScanMode.valueOf(session.scanMode) } catch (_: Exception) { ScanMode.DNS_TUNNEL },
                            listSource = try { ListSource.valueOf(session.listSource) } catch (_: Exception) { ListSource.DEFAULT },
                            scannerState = ScannerState(
                                isScanning = false,
                                totalCount = session.resolverList.size,
                                scannedCount = session.scannedCount,
                                workingCount = session.workingCount,
                                results = results
                            ),
                            selectedResolvers = emptySet(),
                            customRangeInput = session.customRangeInput ?: ""
                        )
                        return@launch
                    }
                }
            } catch (e: Exception) {
                Log.w("DnsScanner", "Failed to load saved session", e)
            }
            // No valid saved session — load default list.
            loadDefaultList()
        }
    }

    private fun saveScanSessionToStore() {
        val state = _uiState.value
        val scanState = state.scannerState
        if (scanState.scannedCount <= 0 || scanState.scannedCount >= scanState.totalCount) return

        val savedResults = scanState.results
            .filter { it.status != ResolverStatus.PENDING && it.status != ResolverStatus.SCANNING }
            .map { it.toSavedResult() }

        val session = SavedScanSession(
            resolverList = state.resolverList,
            testDomain = state.testDomain,
            timeoutMs = state.timeoutMs,
            concurrency = state.concurrency,
            scanMode = state.scanMode.name,
            listSource = state.listSource.name,
            scannedCount = scanState.scannedCount,
            workingCount = scanState.workingCount,
            results = savedResults,
            customRangeInput = state.customRangeInput.ifEmpty { null }
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
    }

    fun importList(content: String) {
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
                        scannerState = ScannerState(),
                        selectedResolvers = emptySet(),
                        isLoadingList = false
                    )
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
    }

    fun updateConcurrency(concurrency: String) {
        _uiState.value = _uiState.value.copy(concurrency = concurrency)
    }

    fun updateScanMode(scanMode: ScanMode) {
        _uiState.value = _uiState.value.copy(scanMode = scanMode)
    }

    fun updateSelectedCountry(country: GeoBypassCountry) {
        _uiState.value = _uiState.value.copy(selectedCountry = country)
    }

    fun updateSampleCount(count: Int) {
        _uiState.value = _uiState.value.copy(sampleCount = count)
    }

    fun loadCountryRangeList() {
        val state = _uiState.value
        _uiState.value = state.copy(isLoadingList = true)

        viewModelScope.launch(Dispatchers.Default) {
            try {
                val ips = scannerRepository.generateCountryRangeIps(
                    context = appContext,
                    countryCode = state.selectedCountry.code,
                    count = state.sampleCount
                )
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

        if (state.testDomain.isBlank()) {
            _uiState.value = _uiState.value.copy(error = "Test domain is required")
            return
        }

        // Check for resumable partial scan.
        val ss = state.scannerState
        if (!ss.isScanning && ss.scannedCount > 0 && ss.scannedCount < ss.totalCount) {
            _uiState.value = _uiState.value.copy(showResumeDialog = true)
            return
        }

        startFreshScan()
    }

    fun dismissResumeDialog() {
        _uiState.value = _uiState.value.copy(showResumeDialog = false)
    }

    fun startFreshScan() {
        _uiState.value = _uiState.value.copy(showResumeDialog = false)
        clearSavedSession()

        val state = _uiState.value
        val timeout = state.timeoutMs.toLongOrNull() ?: 3000L
        val concurrency = state.concurrency.toIntOrNull() ?: 50

        // Initialize scanner state
        val initialResults = state.resolverList.map { host ->
            ResolverScanResult(host = host, status = ResolverStatus.PENDING)
        }

        _uiState.value = _uiState.value.copy(
            scannerState = ScannerState(
                isScanning = true,
                totalCount = state.resolverList.size,
                scannedCount = 0,
                workingCount = 0,
                results = initialResults
            ),
            selectedResolvers = emptySet(),
            error = null
        )

        launchScan(
            hosts = state.resolverList,
            allHosts = state.resolverList,
            testDomain = state.testDomain,
            timeout = timeout,
            concurrency = concurrency,
            scanMode = state.scanMode,
            existingResults = emptyMap(),
            startScannedCount = 0,
            startWorkingCount = 0
        )
    }

    fun resumeScan() {
        _uiState.value = _uiState.value.copy(showResumeDialog = false)
        clearSavedSession()

        val state = _uiState.value
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
            testDomain = state.testDomain,
            timeout = timeout,
            concurrency = concurrency,
            scanMode = state.scanMode,
            existingResults = existingResults,
            startScannedCount = existingResults.size,
            startWorkingCount = startWorkingCount
        )
    }

    private fun launchScan(
        hosts: List<String>,
        allHosts: List<String>,
        testDomain: String,
        timeout: Long,
        concurrency: Int,
        scanMode: ScanMode,
        existingResults: Map<String, ResolverScanResult>,
        startScannedCount: Int,
        startWorkingCount: Int
    ) {
        scanJob = viewModelScope.launch {
            val resultsMap = mutableMapOf<String, ResolverScanResult>()
            resultsMap.putAll(existingResults)
            var scannedCount = startScannedCount
            var workingCount = startWorkingCount

            // Mark hosts to scan as SCANNING.
            hosts.forEach { host ->
                resultsMap[host] = ResolverScanResult(host = host, status = ResolverStatus.SCANNING)
            }

            scannerRepository.scanResolvers(
                hosts = hosts,
                testDomain = testDomain,
                timeoutMs = timeout,
                concurrency = concurrency,
                scanMode = scanMode
            ).collect { result ->
                resultsMap[result.host] = result
                scannedCount++

                if (result.status == ResolverStatus.WORKING) {
                    workingCount++
                }

                _uiState.value = _uiState.value.copy(
                    scannerState = ScannerState(
                        isScanning = scannedCount < allHosts.size,
                        totalCount = allHosts.size,
                        scannedCount = scannedCount,
                        workingCount = workingCount,
                        results = allHosts.map { host ->
                            resultsMap[host] ?: ResolverScanResult(host = host, status = ResolverStatus.PENDING)
                        }
                    )
                )
            }

            // Scan completed — clear saved session.
            _uiState.value = _uiState.value.copy(
                scannerState = _uiState.value.scannerState.copy(isScanning = false)
            )
            clearSavedSession()
        }
    }

    fun stopScan() {
        scanJob?.cancel()
        _uiState.value = _uiState.value.copy(
            scannerState = _uiState.value.scannerState.copy(isScanning = false)
        )
        saveScanSessionToStore()
    }

    fun getSelectedResolversString(): String {
        return _uiState.value.selectedResolvers.joinToString(",") { "$it:53" }
    }

    fun clearError() {
        _uiState.value = _uiState.value.copy(error = null)
    }

    override fun onCleared() {
        super.onCleared()
        scanJob?.cancel()
        // Save partial results so the user can resume after navigating away.
        val ss = _uiState.value.scannerState
        if (ss.scannedCount > 0 && ss.scannedCount < ss.totalCount) {
            // Use a blocking approach since viewModelScope is cancelled.
            val state = _uiState.value
            val savedResults = ss.results
                .filter { it.status != ResolverStatus.PENDING && it.status != ResolverStatus.SCANNING }
                .map { it.toSavedResult() }
            val session = SavedScanSession(
                resolverList = state.resolverList,
                testDomain = state.testDomain,
                timeoutMs = state.timeoutMs,
                concurrency = state.concurrency,
                scanMode = state.scanMode.name,
                listSource = state.listSource.name,
                scannedCount = ss.scannedCount,
                workingCount = ss.workingCount,
                results = savedResults,
                customRangeInput = state.customRangeInput.ifEmpty { null }
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
    randomSub1 = tunnelTestResult?.randomSubdomain1,
    randomSub2 = tunnelTestResult?.randomSubdomain2
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
            randomSubdomain1 = randomSub1 ?: false,
            randomSubdomain2 = randomSub2 ?: false
        )
    } else null
)
