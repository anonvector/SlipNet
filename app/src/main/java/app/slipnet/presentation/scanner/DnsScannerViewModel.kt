package app.slipnet.presentation.scanner

import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.slipnet.domain.model.ResolverScanResult
import app.slipnet.domain.model.ResolverStatus
import app.slipnet.domain.model.ScanMode
import app.slipnet.domain.model.ScannerState
import app.slipnet.domain.repository.ResolverScannerRepository
import dagger.hilt.android.lifecycle.HiltViewModel
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
    val scanMode: ScanMode = ScanMode.SIMPLE,
    val resolverList: List<String> = emptyList(),
    val scannerState: ScannerState = ScannerState(),
    val selectedResolvers: Set<String> = emptySet(),
    val isLoadingList: Boolean = false,
    val error: String? = null,
    val listSource: ListSource = ListSource.DEFAULT
) {
    companion object {
        const val MAX_SELECTED_RESOLVERS = 1
    }

    val isSelectionLimitReached: Boolean
        get() = selectedResolvers.size >= MAX_SELECTED_RESOLVERS

    val selectionLimitMessage: String
        get() = "Only one resolver can be selected"
}

enum class ListSource {
    DEFAULT,
    IMPORTED
}

@HiltViewModel
class DnsScannerViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val scannerRepository: ResolverScannerRepository
) : ViewModel() {

    private val profileId: Long? = savedStateHandle.get<Long>("profileId")?.takeIf { it != -1L }

    private val _uiState = MutableStateFlow(DnsScannerUiState(profileId = profileId))
    val uiState: StateFlow<DnsScannerUiState> = _uiState.asStateFlow()

    private var scanJob: Job? = null

    init {
        loadDefaultList()
    }

    fun loadDefaultList() {
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

    fun toggleResolverSelection(host: String) {
        val current = _uiState.value.selectedResolvers
        if (current.contains(host)) {
            // Deselect if already selected
            _uiState.value = _uiState.value.copy(selectedResolvers = emptySet())
        } else {
            // Replace selection with new resolver (only 1 allowed)
            _uiState.value = _uiState.value.copy(selectedResolvers = setOf(host))
        }
    }

    fun clearSelection() {
        _uiState.value = _uiState.value.copy(selectedResolvers = emptySet())
    }

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

        scanJob = viewModelScope.launch {
            val resultsMap = mutableMapOf<String, ResolverScanResult>()
            var scannedCount = 0
            var workingCount = 0

            // Mark all as scanning initially
            state.resolverList.forEach { host ->
                resultsMap[host] = ResolverScanResult(host = host, status = ResolverStatus.SCANNING)
            }

            scannerRepository.scanResolvers(
                hosts = state.resolverList,
                testDomain = state.testDomain,
                timeoutMs = timeout,
                concurrency = concurrency,
                scanMode = state.scanMode
            ).collect { result ->
                resultsMap[result.host] = result
                scannedCount++

                if (result.status == ResolverStatus.WORKING) {
                    workingCount++
                }

                // Update UI state with current results
                _uiState.value = _uiState.value.copy(
                    scannerState = ScannerState(
                        isScanning = scannedCount < state.resolverList.size,
                        totalCount = state.resolverList.size,
                        scannedCount = scannedCount,
                        workingCount = workingCount,
                        results = state.resolverList.map { host ->
                            resultsMap[host] ?: ResolverScanResult(host = host, status = ResolverStatus.PENDING)
                        }
                    )
                )
            }

            // Final update when done
            _uiState.value = _uiState.value.copy(
                scannerState = _uiState.value.scannerState.copy(isScanning = false)
            )
        }
    }

    fun stopScan() {
        scanJob?.cancel()
        _uiState.value = _uiState.value.copy(
            scannerState = _uiState.value.scannerState.copy(isScanning = false)
        )
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
    }
}
