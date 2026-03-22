package app.slipnet.presentation.scanner

import android.content.Intent
import android.os.PowerManager
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.slipnet.service.ScanService
import app.slipnet.service.ScanServiceState
import app.slipnet.service.ScanStateHolder
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
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import javax.inject.Inject

data class CidrGroup(
    val firstOctet: Int,
    val label: String,
    val rangeCount: Int,
    val totalIps: Long,
    val ranges: List<Pair<Long, Long>>
)

enum class E2eSortOption {
    NONE, SPEED, IP, SCORE, E2E_SPEED, PRISM_SCORE
}

data class DnsScannerUiState(
    val profileId: Long? = null,
    val testDomain: String = "google.com",
    val scanPort: String = "53",
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
    val customRangePreviewCount: Long = 0,
    val useCustomSampleCount: Boolean = false,
    val customSampleCountText: String = "",
    val cidrGroups: List<CidrGroup> = emptyList(),
    val selectedOctets: Set<Int> = emptySet(),
    val shuffleList: Boolean = true,
    val expandNeighbors: Boolean = false,
    val showResumeDialog: Boolean = false,
    val transparentProxyDetected: Boolean = false,
    // E2E tunnel test state
    val e2eScannerState: E2eScannerState = E2eScannerState(),
    val testUrl: String = "http://www.gstatic.com/generate_204",
    val e2eTimeoutMs: String = "15000",
    val isVpnActive: Boolean = false,
    val profile: ServerProfile? = null,
    // Simple scan mode
    val scanMode: ScanMode = ScanMode.SIMPLE,
    val simpleModeE2eState: SimpleModeE2eState = SimpleModeE2eState(),
    val e2eMinScore: Int = 2,
    val e2eSortOption: E2eSortOption = E2eSortOption.NONE,
    val e2eConcurrency: String = "3",
    val e2eFullVerification: Boolean = true,
    // Prism probe settings
    val prismTimeoutMs: String = "2000",
    val prismProbeCount: String = "5",
    val prismPassThreshold: String = "2",
    val prismResponseSize: String = "0",
    val prismPrefilter: Boolean = false,
    val prismPrefilterTimeoutMs: String = "1500",
    // Last scan IPs dialog
    val showLastScanIpsDialog: Boolean = false,
) {
    companion object {
        const val MAX_SELECTED_RESOLVERS = 8
        const val MAX_SAMPLE_COUNT = 100_000
        private val E2E_SUPPORTED_TUNNEL_TYPES = setOf(
            TunnelType.SLIPSTREAM, TunnelType.SLIPSTREAM_SSH,
            TunnelType.DNSTT, TunnelType.DNSTT_SSH,
            TunnelType.NOIZDNS, TunnelType.NOIZDNS_SSH
        )

        /** Check if a hex string is a valid 32-byte Noise public key. */
        fun isValidPubkey(key: String): Boolean =
            key.length == 64 && key.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }
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

    /** The profile's public key, used directly for Prism mode. */
    val profilePubkey: String get() = profile?.dnsttPublicKey.orEmpty()

    /** True when the profile has a valid 32-byte hex public key for Prism. */
    val profilePubkeyValid: Boolean get() = isValidPubkey(profilePubkey)

    /** Prism requires a profile with a valid Noise public key. */
    val canUsePrismMode: Boolean get() = profile != null && profilePubkeyValid

    /** Per-probe timeout for Prism mode. */
    val prismPerProbeMs: Long get() {
        val timeout = prismTimeoutMs.toLongOrNull() ?: 2000L
        val threshold = prismPassThreshold.toIntOrNull()?.coerceAtLeast(1) ?: 2
        return timeout / threshold
    }

    /** True when prism settings would result in per-probe timeout below 200ms. */
    val prismSettingsInvalid: Boolean get() = prismPerProbeMs < 200

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

    /** IPs from the last scan that passed stage-1 (WORKING status). */
    val lastScanWorkingIps: List<String>
        get() = scannerState.results
            .filter { it.status == ResolverStatus.WORKING }
            .map { it.host }

    /** IPs from the last scan that passed E2E testing. */
    val lastScanE2ePassedIps: List<String>
        get() = scannerState.results
            .filter { it.e2eTestResult?.success == true }
            .map { it.host }

    /** True when there are any last-scan results to load. */
    val hasLastScanIps: Boolean
        get() = lastScanWorkingIps.isNotEmpty()
}

enum class ListSource {
    DEFAULT,
    IMPORTED,
    COUNTRY_RANGE,
    CUSTOM_RANGE,
    IR_DNS_RANGE
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

/**
 * Expand the /24 subnet of [host] if it hasn't been expanded yet,
 * adding up to [maxFocusRange] - current queue size neighbor IPs.
 */
private fun tryExpandSubnet(
    host: String,
    focusRangeQueue: MutableList<String>,
    expandedSubnets: MutableSet<String>,
    scannedSet: MutableSet<String>,
    maxFocusRange: Int = 5000
) {
    if (focusRangeQueue.size >= maxFocusRange) return
    val parts = host.split(".")
    if (parts.size != 4) return
    val subnet = "${parts[0]}.${parts[1]}.${parts[2]}"
    if (subnet in expandedSubnets) return
    expandedSubnets.add(subnet)
    val neighbors = expandSlash24(host).filter { it !in scannedSet }
    if (neighbors.isNotEmpty()) {
        val capped = neighbors.take(maxFocusRange - focusRangeQueue.size)
        focusRangeQueue.addAll(capped)
        scannedSet.addAll(capped)
        Log.d("DnsScanner", "Focus range: expanding $subnet.0/24 (+${capped.size} IPs)")
    }
}

enum class ScanMode {
    ADVANCED,
    SIMPLE,
    PRISM
}

private data class ScannerSettings(
    val timeoutMs: String,
    val concurrency: String,
    val e2eTimeoutMs: String,
    val testUrl: String,
    val e2eConcurrency: String,
    val prismProbeCount: String,
    val prismPassThreshold: String,
    val prismResponseSize: String
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
    val scanMode: String? = null,
    val prismPubkey: String? = null
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
    val e2eErrorMessage: String? = null,
    // Prism mode
    val prismVerified: Boolean? = null
)

/**
 * Thread-safe queue that can be re-sorted mid-flight.
 * Used to control E2E test order based on the user's sort selection.
 */
private class SortableQueue<T>(
    initial: List<T> = emptyList(),
    private var comparator: Comparator<T>? = null
) {
    private val lock = java.util.concurrent.locks.ReentrantLock()
    private val notEmpty = lock.newCondition()
    private val items = java.util.LinkedList<T>()
    @Volatile private var closed = false

    init {
        if (initial.isNotEmpty()) {
            items.addAll(if (comparator != null) initial.sortedWith(comparator!!) else initial)
        }
    }

    fun add(item: T) {
        lock.lock()
        try {
            if (comparator != null) {
                // Insert in sorted position
                val idx = items.indexOfFirst { comparator!!.compare(item, it) < 0 }
                if (idx >= 0) items.add(idx, item) else items.addLast(item)
            } else {
                items.addLast(item)
            }
            notEmpty.signal()
        } finally {
            lock.unlock()
        }
    }

    /** Blocks until an item is available. Returns null when closed and empty
     *  or when the thread is interrupted (coroutine cancellation). */
    fun take(): T? {
        lock.lock()
        try {
            while (items.isEmpty()) {
                if (closed || Thread.currentThread().isInterrupted) return null
                try {
                    notEmpty.await()
                } catch (_: InterruptedException) {
                    return null
                }
            }
            return items.removeFirst()
        } finally {
            lock.unlock()
        }
    }

    /** Re-sort pending items. Uses tryLock to avoid blocking the caller
     *  (typically UI thread) when the consumer holds the lock in take(). */
    fun resort(newComparator: Comparator<T>?) {
        if (!lock.tryLock(50, java.util.concurrent.TimeUnit.MILLISECONDS)) return
        try {
            comparator = newComparator
            if (newComparator != null && items.size > 1) {
                val sorted = items.sortedWith(newComparator)
                items.clear()
                items.addAll(sorted)
            }
        } finally {
            lock.unlock()
        }
    }

    fun close() {
        lock.lock()
        try {
            closed = true
            notEmpty.signalAll()
        } finally {
            lock.unlock()
        }
    }
}

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
    private var simpleModeE2eJob: Job? = null
    private var e2ePendingQueue: SortableQueue<Pair<String, Int>>? = null
    private val gson = Gson()
    @Volatile private var lastPeriodicSaveMs = 0L
    private val periodicSaveIntervalMs = 30_000L

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
        restoreFromScanStateHolder()
        loadSavedSession()
        loadRecentDns()
        loadCountryCidrInfo()
        loadProfile()
        observeVpnState()
        observeScanServiceState()
    }

    /**
     * If a scan is still running (activity was recreated but process survived),
     * restore results from ScanStateHolder so progress isn't lost.
     */
    private fun restoreFromScanStateHolder() {
        val holder = ScanStateHolder.state.value
        if ((holder.isScanning || holder.isE2eRunning) && holder.results.isNotEmpty()) {
            Log.i("DnsScanner", "Restoring ${holder.results.size} results from ScanStateHolder (profileId=${holder.profileId})")
            _uiState.update { s ->
                s.copy(
                    profileId = s.profileId ?: holder.profileId,
                    scannerState = s.scannerState.copy(
                        isScanning = holder.isScanning,
                        scannedCount = holder.scannedCount,
                        totalCount = holder.totalCount,
                        workingCount = holder.workingCount,
                        results = holder.results
                    )
                )
            }
            // Load profile if not already set from nav args
            if (profileId == null && holder.profileId != null) {
                viewModelScope.launch {
                    try {
                        val profile = profileRepository.getProfileById(holder.profileId)
                        if (profile != null) {
                            _uiState.update { it.copy(profile = profile) }
                        }
                    } catch (e: Exception) {
                        Log.w("DnsScanner", "Failed to restore profile from ScanStateHolder", e)
                    }
                }
            }
        }
    }

    private fun observeScanServiceState() {
        viewModelScope.launch {
            ScanStateHolder.state.collect { s ->
                if (s.stopRequested) {
                    ScanStateHolder.update { it.copy(stopRequested = false) }
                    stopScan()
                }
            }
        }
        // Sync results to ScanStateHolder so they survive activity recreation.
        viewModelScope.launch {
            var lastResultsHash = 0
            _uiState.collect { state ->
                val results = state.scannerState.results
                val hash = results.hashCode()
                if (hash != lastResultsHash) {
                    lastResultsHash = hash
                    ScanStateHolder.update { it.copy(
                        results = results,
                        profileId = state.profileId
                    ) }
                }
            }
        }
    }

    /** One-shot read of persisted scanner settings. Must be called before session restore. */
    private suspend fun loadScannerSettings() {
        try {
            val timeout = preferencesDataStore.scannerTimeoutMs.first()
            val concurrency = preferencesDataStore.scannerConcurrency.first()
            val e2eTimeout = preferencesDataStore.scannerE2eTimeoutMs.first()
            val testUrl = preferencesDataStore.scannerTestUrl.first()
            val e2eConcurrency = preferencesDataStore.scannerE2eConcurrency.first()
            val prismTimeoutMs = preferencesDataStore.scannerPrismTimeoutMs.first()
            val prismProbeCount = preferencesDataStore.scannerPrismProbeCount.first()
            val prismPassThreshold = preferencesDataStore.scannerPrismPassThreshold.first()
            val prismResponseSize = preferencesDataStore.scannerPrismResponseSize.first()
            val prismPrefilter = preferencesDataStore.scannerPrismPrefilter.first()
            val prismPrefilterTimeoutMs = preferencesDataStore.scannerPrismPrefilterTimeoutMs.first()
            _uiState.value = _uiState.value.copy(
                timeoutMs = timeout,
                concurrency = concurrency,
                e2eTimeoutMs = e2eTimeout,
                testUrl = testUrl,
                e2eConcurrency = e2eConcurrency,
                prismTimeoutMs = prismTimeoutMs,
                prismProbeCount = prismProbeCount,
                prismPassThreshold = prismPassThreshold,
                prismResponseSize = prismResponseSize,
                prismPrefilter = prismPrefilter,
                prismPrefilterTimeoutMs = prismPrefilterTimeoutMs
            )
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
                    testUrl = state.testUrl,
                    e2eConcurrency = state.e2eConcurrency,
                    prismTimeoutMs = state.prismTimeoutMs,
                    prismProbeCount = state.prismProbeCount,
                    prismPassThreshold = state.prismPassThreshold,
                    prismResponseSize = state.prismResponseSize,
                    prismPrefilter = state.prismPrefilter,
                    prismPrefilterTimeoutMs = state.prismPrefilterTimeoutMs
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
                    _uiState.value = _uiState.value.copy(profile = profile)
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
                    ?: try {
                        // Fallback: read from cache file (written synchronously in onCleared
                        // as a safety net in case the DataStore write didn't complete).
                        val cacheFile = java.io.File(appContext.cacheDir, "scan_session.json")
                        if (cacheFile.exists()) cacheFile.readText().also {
                            // Migrate to DataStore so subsequent loads are consistent
                            preferencesDataStore.saveScanSession(it)
                            cacheFile.delete()
                        } else null
                    } catch (_: Exception) { null }
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
                        val savedByHost = session.results.associateBy { it.host }
                        val results = session.resolverList.map { host ->
                            savedByHost[host]?.toScanResult() ?: ResolverScanResult(host = host)
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

                        // Don't restore PRISM mode from a saved session — Prism depends
                        // on a loaded profile (for pubkey + domain) which isn't available yet.
                        // The profile loads asynchronously; restoring PRISM before it loads
                        // causes the scan to use stale/empty keys. Fall back to ADVANCED.
                        val restoredMode = if (savedMode == ScanMode.PRISM) {
                            ScanMode.ADVANCED
                        } else {
                            savedMode ?: _uiState.value.scanMode
                        }

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
                            scanMode = restoredMode,
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
                ListSource.COUNTRY_RANGE, ListSource.CUSTOM_RANGE, ListSource.IR_DNS_RANGE -> {
                    // Only restore the selection state (country/custom/IR DNS panel);
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
        // In simple/prism mode, save whenever there's partial progress
        if (state.scanMode == ScanMode.SIMPLE || state.scanMode == ScanMode.PRISM) {
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

    /** Throttled periodic save — call from hot paths (emitState). */
    private fun periodicSaveIfNeeded() {
        val now = System.currentTimeMillis()
        if (now - lastPeriodicSaveMs < periodicSaveIntervalMs) return
        lastPeriodicSaveMs = now
        saveScanSessionToStore()
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
        e2eJob?.cancel()
        simpleModeE2eJob?.cancel()
        _uiState.value = _uiState.value.copy(
            resolverList = scannerRepository.getDefaultResolvers(),
            listSource = ListSource.DEFAULT,
            scannerState = ScannerState(),
            selectedResolvers = emptySet(),
            e2eScannerState = E2eScannerState(),
            simpleModeE2eState = SimpleModeE2eState()
        )
        saveListSelection()
    }

    fun importList(uri: android.net.Uri) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoadingList = true)
            try {
                val (resolvers, fileName) = withContext(Dispatchers.IO) {
                    val name = try {
                        appContext.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                            val idx = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                            if (cursor.moveToFirst() && idx >= 0) cursor.getString(idx) else null
                        }
                    } catch (_: Exception) { null }
                    val parsed = appContext.contentResolver.openInputStream(uri)?.use { stream ->
                        scannerRepository.parseResolverList(stream.bufferedReader())
                    } ?: emptyList()
                    Pair(parsed, name)
                }
                if (resolvers.isEmpty()) {
                    _uiState.value = _uiState.value.copy(
                        isLoadingList = false,
                        error = "No valid IP addresses found in file"
                    )
                } else {
                    clearSavedSession()
                    e2eJob?.cancel()
                    simpleModeE2eJob?.cancel()
                    _uiState.value = _uiState.value.copy(
                        resolverList = resolvers,
                        listSource = ListSource.IMPORTED,
                        importedFileName = fileName,
                        scannerState = ScannerState(),
                        selectedResolvers = emptySet(),
                        e2eScannerState = E2eScannerState(),
                        simpleModeE2eState = SimpleModeE2eState(),
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

    fun updateScanPort(port: String) {
        _uiState.value = _uiState.value.copy(scanPort = port)
    }

    fun updateTimeout(timeout: String) {
        _uiState.value = _uiState.value.copy(timeoutMs = timeout)
        saveScannerSettings()
    }

    fun updateConcurrency(concurrency: String) {
        _uiState.value = _uiState.value.copy(concurrency = concurrency)
        saveScannerSettings()
    }

    fun updatePrismTimeout(value: String) {
        _uiState.value = _uiState.value.copy(prismTimeoutMs = value)
        saveScannerSettings()
    }

    fun updatePrismProbeCount(value: String) {
        val clamped = value.toIntOrNull()?.let { if (it > 30) "30" else value } ?: value
        _uiState.value = _uiState.value.copy(prismProbeCount = clamped)
        saveScannerSettings()
    }

    fun updatePrismPassThreshold(value: String) {
        _uiState.value = _uiState.value.copy(prismPassThreshold = value)
        saveScannerSettings()
    }

    fun updatePrismResponseSize(value: String) {
        val clamped = value.toIntOrNull()?.let { if (it > 4096) "4096" else value } ?: value
        _uiState.value = _uiState.value.copy(prismResponseSize = clamped)
        saveScannerSettings()
    }

    fun resetPrismSettings() {
        _uiState.value = _uiState.value.copy(
            prismTimeoutMs = "2000",
            prismProbeCount = "5",
            prismPassThreshold = "2",
            prismResponseSize = "0",
            prismPrefilter = false,
            prismPrefilterTimeoutMs = "1500"
        )
        saveScannerSettings()
    }

    fun updatePrismPrefilter(enabled: Boolean) {
        _uiState.value = _uiState.value.copy(prismPrefilter = enabled)
        saveScannerSettings()
    }

    fun updatePrismPrefilterTimeout(value: String) {
        val clamped = value.toIntOrNull()?.let { if (it < 200) "200" else value } ?: value
        _uiState.value = _uiState.value.copy(prismPrefilterTimeoutMs = clamped)
        saveScannerSettings()
    }

    fun showLastScanIpsDialog() {
        _uiState.value = _uiState.value.copy(showLastScanIpsDialog = true)
    }

    fun dismissLastScanIpsDialog() {
        _uiState.value = _uiState.value.copy(showLastScanIpsDialog = false)
    }

    fun loadLastScanWorkingIps() {
        val ips = _uiState.value.lastScanWorkingIps
        if (ips.isEmpty()) return
        clearSavedSession()
        _uiState.value = _uiState.value.copy(
            resolverList = ips,
            listSource = ListSource.IMPORTED,
            scannerState = ScannerState(),
            selectedResolvers = emptySet(),
            showLastScanIpsDialog = false
        )
    }

    fun loadLastScanE2ePassedIps() {
        val ips = _uiState.value.lastScanE2ePassedIps
        if (ips.isEmpty()) return
        clearSavedSession()
        _uiState.value = _uiState.value.copy(
            resolverList = ips,
            listSource = ListSource.IMPORTED,
            scannerState = ScannerState(),
            selectedResolvers = emptySet(),
            showLastScanIpsDialog = false
        )
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
                    e2eJob?.cancel()
                    simpleModeE2eJob?.cancel()
                    _uiState.value = _uiState.value.copy(
                        resolverList = ips,
                        listSource = ListSource.COUNTRY_RANGE,
                        scannerState = ScannerState(),
                        selectedResolvers = emptySet(),
                        e2eScannerState = E2eScannerState(),
                        simpleModeE2eState = SimpleModeE2eState(),
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

    fun loadIrDnsCidrInfo() {
        viewModelScope.launch(Dispatchers.Default) {
            val ranges = scannerRepository.loadCountryCidrRanges(appContext, "ir_dns")
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

    fun loadIrDnsRangeList() {
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
                    scannerRepository.loadCountryCidrRanges(appContext, "ir_dns")
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
                        error = "No CIDR ranges found in IR DNS list"
                    )
                } else {
                    clearSavedSession()
                    e2eJob?.cancel()
                    simpleModeE2eJob?.cancel()
                    _uiState.value = _uiState.value.copy(
                        resolverList = ips,
                        listSource = ListSource.IR_DNS_RANGE,
                        scannerState = ScannerState(),
                        selectedResolvers = emptySet(),
                        e2eScannerState = E2eScannerState(),
                        simpleModeE2eState = SimpleModeE2eState(),
                        isLoadingList = false,
                        timeoutMs = "1500"
                    )
                    saveListSelection()
                }
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isLoadingList = false,
                    error = "Failed to load IR DNS IPs: ${e.message}"
                )
            }
        }
    }

    fun updateCustomRangeInput(text: String) {
        var count = 0L
        for (line in text.lines()) {
            val trimmed = line.trim()
            if (trimmed.isBlank() || trimmed.startsWith("#")) continue
            val range = parseIpRange(trimmed)
            if (range != null) count += (range.second - range.first + 1)
        }
        _uiState.value = _uiState.value.copy(
            customRangeInput = text,
            customRangePreviewCount = count
        )
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
            if (trimmed.isBlank() || trimmed.startsWith("#")) continue
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
                e2eJob?.cancel()
                simpleModeE2eJob?.cancel()
                _uiState.value = _uiState.value.copy(
                    resolverList = ips,
                    listSource = ListSource.CUSTOM_RANGE,
                    scannerState = ScannerState(),
                    selectedResolvers = emptySet(),
                    e2eScannerState = E2eScannerState(),
                    simpleModeE2eState = SimpleModeE2eState(),
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

    private val cidrRegex = Regex("""\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})\b""")
    private val rangeRegex = Regex("""\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*-\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b""")
    private val singleIpRegex = Regex("""\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b""")

    private fun parseIpRange(line: String): Pair<Long, Long>? {
        // Try CIDR first (e.g. 8.8.8.0/24)
        cidrRegex.find(line)?.let { match ->
            DomainRouter.parseCidr(match.groupValues[1])?.let { return it }
        }

        // Try range format (e.g. 8.8.8.1-8.8.8.254)
        rangeRegex.find(line)?.let { match ->
            val start = DomainRouter.ipToLong(match.groupValues[1])
            val end = DomainRouter.ipToLong(match.groupValues[2])
            if (start != null && end != null && start <= end) {
                return Pair(start, end)
            }
        }

        // Try single IP (e.g. 8.8.8.8)
        singleIpRegex.find(line)?.let { match ->
            DomainRouter.ipToLong(match.groupValues[1])?.let { ip ->
                return Pair(ip, ip)
            }
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

        // Prism mode requires a profile with a valid Noise public key
        if (state.scanMode == ScanMode.PRISM && !state.profilePubkeyValid) {
            _uiState.value = _uiState.value.copy(error = "Prism requires a VPN profile with a valid server public key")
            return
        }
        if (state.scanMode == ScanMode.PRISM && state.prismSettingsInvalid) {
            _uiState.value = _uiState.value.copy(error = "Per-probe timeout too low (${state.prismPerProbeMs}ms). Increase timeout or lower pass threshold.")
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
        // Cancel any previous scan/E2E jobs before starting fresh
        scanJob?.cancel()
        e2eJob?.cancel()
        simpleModeE2eJob?.cancel()
        e2ePendingQueue?.close()

        acquireWakeLock()
        _uiState.value = _uiState.value.copy(showResumeDialog = false)
        clearSavedSession()

        val state = _uiState.value
        val timeout = state.timeoutMs.toLongOrNull() ?: 3000L
        val concurrency = state.concurrency.toIntOrNull() ?: 50
        val scanPort = state.scanPort.toIntOrNull()?.coerceIn(1, 65535) ?: 53

        // Shuffle the list if enabled, then persist the order so resume works correctly.
        // For the default list, always fetch original order so famous resolvers stay at the top.
        val resolvers = if (state.shuffleList && state.listSource == ListSource.DEFAULT) {
            val defaultResolvers = scannerRepository.getDefaultResolvers()
            val boundaries = scannerRepository.getDefaultResolverTierBoundaries()
            Log.d("DnsScanner", "Shuffle default: tiers=${boundaries.size + 1}, boundaries=$boundaries, total=${defaultResolvers.size}")
            // First tier (before first marker) stays in order; all others are shuffled
            val indices = listOf(0) + boundaries + listOf(defaultResolvers.size)
            indices.zipWithNext().flatMapIndexed { i, (from, to) ->
                val tier = defaultResolvers.subList(from, to)
                if (i == 0) tier else tier.shuffled()
            }
        } else if (state.shuffleList) {
            state.resolverList.shuffled()
        } else {
            state.resolverList
        }
        Log.d("DnsScanner", "Scan order first10=${resolvers.take(10)}")

        // Initialize scanner state — don't pre-allocate PENDING results to avoid OOM on large lists
        _uiState.value = _uiState.value.copy(
            resolverList = resolvers,
            scannerState = ScannerState(
                isScanning = true,
                totalCount = resolvers.size,
                scannedCount = 0,
                workingCount = 0,
                results = emptyList()
            ),
            selectedResolvers = emptySet(),
            error = null,
            transparentProxyDetected = false,
            simpleModeE2eState = SimpleModeE2eState(),
            e2eScannerState = E2eScannerState()
        )

        ScanStateHolder.update { it.copy(
            isScanning = true,
            isE2eRunning = state.scanMode == ScanMode.SIMPLE,
            scannedCount = 0,
            totalCount = resolvers.size,
            workingCount = 0,
            stopRequested = false
        ) }
        ContextCompat.startForegroundService(appContext, Intent(appContext, ScanService::class.java))

        when (state.scanMode) {
            ScanMode.SIMPLE -> launchSimpleScan(
                hosts = resolvers,
                allHosts = resolvers,
                testDomain = state.effectiveTestDomain,
                timeout = timeout,
                concurrency = concurrency,
                minScore = _uiState.value.e2eMinScore,
                port = scanPort
            )
            ScanMode.PRISM -> {
                val pubkeyBytes = state.profilePubkey.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                val prismDomain = state.profile?.domain ?: state.effectiveTestDomain
                val prismTimeout = state.prismTimeoutMs.toLongOrNull() ?: 2000L
                val probeCount = state.prismProbeCount.toIntOrNull()?.coerceIn(1, 30) ?: 5
                val passThreshold = state.prismPassThreshold.toIntOrNull()?.coerceIn(1, probeCount) ?: 2
                val responseSize = state.prismResponseSize.toIntOrNull()?.let { if (it == 0) 0 else it.coerceIn(200, 4096) } ?: 0
                launchPrismScan(
                    hosts = resolvers,
                    allHosts = resolvers,
                    testDomain = prismDomain,
                    timeout = prismTimeout,
                    concurrency = concurrency,
                    pubkey = pubkeyBytes,
                    port = scanPort,
                    probeCount = probeCount,
                    passThreshold = passThreshold,
                    responseSize = responseSize,
                    prefilter = state.prismPrefilter
                )
            }
            ScanMode.ADVANCED -> launchScan(
                hosts = resolvers,
                allHosts = resolvers,
                testDomain = state.effectiveTestDomain,
                timeout = timeout,
                concurrency = concurrency,
                existingResults = emptyMap(),
                startScannedCount = 0,
                startWorkingCount = 0,
                port = scanPort,
                querySize = state.profile?.dnsPayloadSize ?: 0
            )
        }
    }

    fun resumeScan() {
        // Cancel any previous scan/E2E jobs before resuming
        scanJob?.cancel()
        e2eJob?.cancel()
        simpleModeE2eJob?.cancel()
        e2ePendingQueue?.close()

        acquireWakeLock()
        _uiState.value = _uiState.value.copy(showResumeDialog = false)
        clearSavedSession()

        val state = _uiState.value

        if (state.scanMode == ScanMode.SIMPLE) {
            resumeSimpleScan()
            return
        }

        if (state.scanMode == ScanMode.PRISM) {
            if (!state.profilePubkeyValid) {
                _uiState.value = _uiState.value.copy(error = "Prism requires a VPN profile with a valid server public key")
                releaseWakeLock()
                return
            }
            val prismTimeout = state.prismTimeoutMs.toLongOrNull() ?: 2000L
            val concurrency = state.concurrency.toIntOrNull() ?: 50
            val scanPort = state.scanPort.toIntOrNull()?.coerceIn(1, 65535) ?: 53
            val probeCount = state.prismProbeCount.toIntOrNull()?.coerceIn(1, 30) ?: 5
            val passThreshold = state.prismPassThreshold.toIntOrNull()?.coerceIn(1, probeCount) ?: 2
            val pubkeyBytes = state.profilePubkey.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val responseSize = state.prismResponseSize.toIntOrNull()?.let { if (it == 0) 0 else it.coerceIn(200, 4096) } ?: 0
            val existingResults = state.scannerState.results
                .filter { it.status != ResolverStatus.PENDING && it.status != ResolverStatus.SCANNING }
                .associateBy { it.host }
            val remainingHosts = state.resolverList.filter { it !in existingResults }
            val startWorking = existingResults.values.count { it.prismVerified == true }
            ScanStateHolder.update { it.copy(isScanning = true, stopRequested = false) }
            ContextCompat.startForegroundService(appContext, Intent(appContext, ScanService::class.java))
            val prismDomain = state.profile?.domain ?: state.effectiveTestDomain
            launchPrismScan(
                hosts = remainingHosts,
                allHosts = state.resolverList,
                testDomain = prismDomain,
                timeout = prismTimeout,
                concurrency = concurrency,
                pubkey = pubkeyBytes,
                port = scanPort,
                probeCount = probeCount,
                passThreshold = passThreshold,
                responseSize = responseSize,
                prefilter = state.prismPrefilter,
                existingResults = existingResults,
                startScannedCount = existingResults.size,
                startWorkingCount = startWorking
            )
            return
        }

        val timeout = state.timeoutMs.toLongOrNull() ?: 3000L
        val concurrency = state.concurrency.toIntOrNull() ?: 50
        val scanPort = state.scanPort.toIntOrNull()?.coerceIn(1, 65535) ?: 53

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

        ScanStateHolder.update { it.copy(
            isScanning = true,
            isE2eRunning = false,
            scannedCount = existingResults.size,
            totalCount = state.resolverList.size,
            workingCount = startWorkingCount,
            stopRequested = false
        ) }
        ContextCompat.startForegroundService(appContext, Intent(appContext, ScanService::class.java))

        launchScan(
            hosts = remainingHosts,
            allHosts = state.resolverList,
            testDomain = state.effectiveTestDomain,
            timeout = timeout,
            concurrency = concurrency,
            existingResults = existingResults,
            startScannedCount = existingResults.size,
            startWorkingCount = startWorkingCount,
            port = scanPort,
            querySize = state.profile?.dnsPayloadSize ?: 0
        )
    }

    private fun resumeSimpleScan() {
        val state = _uiState.value
        val profile = state.profile ?: run {
            _uiState.value = state.copy(error = "No profile loaded")
            releaseWakeLock()
            return
        }

        val timeout = state.timeoutMs.toLongOrNull() ?: 3000L
        val concurrency = state.concurrency.toIntOrNull() ?: 50
        val resumeScanPort = state.scanPort.toIntOrNull()?.coerceIn(1, 65535) ?: 53

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

        val queue = SortableQueue(untestedE2e, buildE2eComparator(_uiState.value.e2eSortOption))
        e2ePendingQueue = queue

        // Thread-safe map — DNS scan (Main) and E2E workers (IO→Main) both access this.
        val resultsMap = java.util.concurrent.ConcurrentHashMap<String, ResolverScanResult>()
        resultsMap.putAll(existingResults)
        var scannedCount = existingResults.size
        var workingCount = startWorkingCount

        fun rebuildResultsList() = resultsMap.values.filter { it.status == ResolverStatus.WORKING }.toList()

        ScanStateHolder.update { it.copy(
            isScanning = hasDnsWork,
            isE2eRunning = true,
            scannedCount = scannedCount,
            totalCount = state.resolverList.size,
            workingCount = workingCount,
            stopRequested = false
        ) }
        ContextCompat.startForegroundService(appContext, Intent(appContext, ScanService::class.java))

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

        // Coroutine 1: DNS scan for remaining hosts
        if (hasDnsWork) {
            scanJob = viewModelScope.launch {
                val scannedSet = state.resolverList.toMutableSet()
                val useFocusRange = state.expandNeighbors && state.listSource in listOf(ListSource.COUNTRY_RANGE, ListSource.CUSTOM_RANGE, ListSource.IR_DNS_RANGE)
                val focusRangeQueue = mutableListOf<String>()
                val expandedSubnets = mutableSetOf<String>()
                val maxFocusRange = 5000
                var uiUpdateCounter = 0
                var lastEmitTimeMs = 0L

                fun emitState(scanning: Boolean, force: Boolean = false) {
                    if (!force) {
                        val now = System.currentTimeMillis()
                        if (now - lastEmitTimeMs < 150L) return
                        lastEmitTimeMs = now
                    }
                    _uiState.update { s ->
                        s.copy(
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
                    ScanStateHolder.update { it.copy(
                        isScanning = scanning,
                        scannedCount = scannedCount,
                        totalCount = state.resolverList.size,
                        workingCount = workingCount
                    ) }
                    periodicSaveIfNeeded()
                }

                fun handleResult(result: ResolverScanResult) {
                    scannedCount++
                    if (result.status == ResolverStatus.WORKING) {
                        resultsMap[result.host] = result
                        workingCount++
                        if ((result.tunnelTestResult?.score ?: 0) >= minScore) {
                            queue.add(result.host to result.port)
                            _uiState.update { s ->
                                s.copy(simpleModeE2eState = s.simpleModeE2eState.copy(
                                    queuedCount = s.simpleModeE2eState.queuedCount + 1
                                ))
                            }
                        }
                        if (useFocusRange) {
                            tryExpandSubnet(result.host, focusRangeQueue, expandedSubnets, scannedSet, maxFocusRange)
                        }
                    }
                    uiUpdateCounter++
                    if (result.status == ResolverStatus.WORKING || uiUpdateCounter >= 20) {
                        uiUpdateCounter = 0
                        emitState(true)
                    }
                }

                scannerRepository.scanResolvers(
                    hosts = remainingDnsHosts,
                    port = resumeScanPort,
                    testDomain = state.effectiveTestDomain,
                    timeoutMs = timeout,
                    concurrency = concurrency,
                    querySize = profile.dnsPayloadSize
                ).collect { handleResult(it) }
                emitState(true, force = true)

                if (focusRangeQueue.isNotEmpty()) {
                    val neighborIps = focusRangeQueue.toList()
                    _uiState.update { s -> s.copy(resolverList = s.resolverList + neighborIps) }
                    scannerRepository.scanResolvers(
                        hosts = neighborIps,
                        port = resumeScanPort,
                        testDomain = state.effectiveTestDomain,
                        timeoutMs = timeout,
                        concurrency = concurrency,
                        querySize = profile.dnsPayloadSize
                    ).collect { handleResult(it) }
                }

                queue.close()
                emitState(false, force = true)
            }
        } else {
            // DNS is already complete — close queue after seeding
            queue.close()
        }

        // Coroutine 2: E2E validation — N parallel consumers
        simpleModeE2eJob = viewModelScope.launch(Dispatchers.IO) {
            launchE2eWorkers(
                queue = queue, profile = profile,
                testUrl = _uiState.value.testUrl,
                e2eTimeout = _uiState.value.e2eTimeoutMs.toLongOrNull() ?: 15000L,
                fullVerification = _uiState.value.e2eFullVerification,
                startTestedCount = startTestedCount, startPassedCount = startPassedCount,
                onActiveChanged = { transform -> updateSimpleModeActive(transform) },
                onResult = { host, result, tested, passed ->
                    resultsMap.compute(host) { _, existing -> existing?.copy(e2eTestResult = result) }
                    updateSimpleModeResult(rebuildResultsList(), tested, passed)
                },
                onComplete = {
                    _uiState.update { s ->
                        s.copy(simpleModeE2eState = s.simpleModeE2eState.copy(
                            isRunning = false, currentResolver = null, currentPhase = "",
                            activeResolvers = emptyMap()
                        ))
                    }
                    ScanStateHolder.update { it.copy(isE2eRunning = false) }
                    cleanupBridge()
                    saveScanSessionToStore()
                    releaseWakeLock()
                }
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
        startWorkingCount: Int,
        port: Int = 53,
        querySize: Int = 0
    ) {
        // Run transparent proxy detection concurrently
        viewModelScope.launch {
            try {
                val detected = scannerRepository.detectTransparentProxy(testDomain)
                if (detected) {
                    _uiState.update { s -> s.copy(transparentProxyDetected = true) }
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
            var lastEmitTimeMs = 0L

            // Focus range: collect /24 neighbors of working resolvers (capped at 5000)
            val useFocusRange = _uiState.value.expandNeighbors && _uiState.value.listSource in listOf(ListSource.COUNTRY_RANGE, ListSource.CUSTOM_RANGE, ListSource.IR_DNS_RANGE)
            val focusRangeQueue = mutableListOf<String>()
            val expandedSubnets = mutableSetOf<String>()
            val maxFocusRange = 5000

            fun emitState(scanning: Boolean, force: Boolean = false) {
                if (!force) {
                    val now = System.currentTimeMillis()
                    if (now - lastEmitTimeMs < 150L) return
                    lastEmitTimeMs = now
                }
                _uiState.update { s ->
                    s.copy(
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
                ScanStateHolder.update { it.copy(
                    isScanning = scanning,
                    scannedCount = scannedCount,
                    totalCount = allHosts.size,
                    workingCount = workingCount
                ) }
                periodicSaveIfNeeded()
            }

            fun handleResult(result: ResolverScanResult) {
                scannedCount++
                when (result.status) {
                    ResolverStatus.WORKING -> {
                        workingCount++
                        workingResults.add(result)
                        if (useFocusRange) {
                            tryExpandSubnet(result.host, focusRangeQueue, expandedSubnets, scannedSet, maxFocusRange)
                        }
                    }
                    ResolverStatus.TIMEOUT -> timeoutCount++
                    ResolverStatus.ERROR, ResolverStatus.CENSORED -> errorCount++
                    else -> {}
                }
                // Batch UI updates: every 20 results or on working result (throttled to max ~7 fps)
                uiUpdateCounter++
                if (result.status == ResolverStatus.WORKING || uiUpdateCounter >= 20) {
                    uiUpdateCounter = 0
                    emitState(true)
                }
            }

            scannerRepository.scanResolvers(
                hosts = hosts,
                port = port,
                testDomain = testDomain,
                timeoutMs = timeout,
                concurrency = concurrency,
                querySize = querySize
            ).collect { handleResult(it) }
            emitState(true, force = true)

            // Phase 2: scan focus range neighbors
            if (focusRangeQueue.isNotEmpty()) {
                val neighborIps = focusRangeQueue.toList()
                Log.d("DnsScanner", "Focus range: scanning ${neighborIps.size} neighbor IPs from ${expandedSubnets.size} subnets")
                // Persist neighbors in resolverList so resume works
                _uiState.update { s -> s.copy(resolverList = s.resolverList + neighborIps) }
                scannerRepository.scanResolvers(
                    hosts = neighborIps,
                    port = port,
                    testDomain = testDomain,
                    timeoutMs = timeout,
                    concurrency = concurrency,
                    querySize = querySize
                ).collect { handleResult(it) }
            }

            emitState(false, force = true)
            saveScanSessionToStore()
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
        minScore: Int = 1,
        port: Int = 53
    ) {
        val profile = _uiState.value.profile ?: run {
            _uiState.value = _uiState.value.copy(error = "No profile loaded")
            return
        }

        val queue2 = SortableQueue<Pair<String, Int>>(comparator = buildE2eComparator(_uiState.value.e2eSortOption))
        e2ePendingQueue = queue2

        _uiState.value = _uiState.value.copy(
            simpleModeE2eState = SimpleModeE2eState(isRunning = true)
        )

        // Thread-safe map — DNS scan (Main) and E2E workers (IO→Main) both access this.
        val resultsMap = java.util.concurrent.ConcurrentHashMap<String, ResolverScanResult>()
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
                    _uiState.update { s -> s.copy(transparentProxyDetected = true) }
                }
            } catch (_: Exception) { }
        }

        // Coroutine 1: DNS scan — produces working resolver candidates
        scanJob = viewModelScope.launch {
            val scannedSet = allHostsMutable.toMutableSet()
            val useFocusRange = _uiState.value.expandNeighbors && _uiState.value.listSource in listOf(ListSource.COUNTRY_RANGE, ListSource.CUSTOM_RANGE, ListSource.IR_DNS_RANGE)
            val focusRangeQueue = mutableListOf<String>()
            val expandedSubnets = mutableSetOf<String>()
            val maxFocusRange = 5000
            var timeoutCount = 0
            var errorCount = 0
            var uiUpdateCounter = 0
            var lastEmitTimeMs = 0L

            fun emitState(scanning: Boolean, force: Boolean = false) {
                if (!force) {
                    val now = System.currentTimeMillis()
                    if (now - lastEmitTimeMs < 150L) return
                    lastEmitTimeMs = now
                }
                _uiState.update { s ->
                    s.copy(
                        scannerState = ScannerState(
                            isScanning = scanning,
                            totalCount = allHosts.size,
                            focusRangeCount = focusRangeQueue.size,
                            scannedCount = scannedCount,
                            workingCount = workingCount,
                            timeoutCount = timeoutCount,
                            errorCount = errorCount,
                            results = rebuildResultsList()
                        )
                    )
                }
                ScanStateHolder.update { it.copy(
                    isScanning = scanning,
                    scannedCount = scannedCount,
                    totalCount = allHosts.size,
                    workingCount = workingCount
                ) }
                periodicSaveIfNeeded()
            }

            fun handleResult(result: ResolverScanResult) {
                scannedCount++
                when (result.status) {
                    ResolverStatus.WORKING -> {
                        resultsMap[result.host] = result
                        workingCount++
                        if ((result.tunnelTestResult?.score ?: 0) >= minScore) {
                            queue2.add(result.host to result.port)
                            _uiState.update { s ->
                                s.copy(simpleModeE2eState = s.simpleModeE2eState.copy(
                                    queuedCount = s.simpleModeE2eState.queuedCount + 1
                                ))
                            }
                        }
                        if (useFocusRange) {
                            tryExpandSubnet(result.host, focusRangeQueue, expandedSubnets, scannedSet, maxFocusRange)
                        }
                    }
                    ResolverStatus.TIMEOUT -> timeoutCount++
                    ResolverStatus.ERROR, ResolverStatus.CENSORED -> errorCount++
                    else -> {}
                }
                uiUpdateCounter++
                if (result.status == ResolverStatus.WORKING || uiUpdateCounter >= 20) {
                    uiUpdateCounter = 0
                    emitState(true)
                }
            }

            scannerRepository.scanResolvers(
                hosts = hosts,
                port = port,
                testDomain = testDomain,
                timeoutMs = timeout,
                concurrency = concurrency,
                querySize = profile.dnsPayloadSize
            ).collect { handleResult(it) }
            emitState(true, force = true)

            // Phase 2: scan focus range neighbors
            if (focusRangeQueue.isNotEmpty()) {
                val neighborIps = focusRangeQueue.toList()
                Log.d("DnsScanner", "Focus range: scanning ${neighborIps.size} neighbor IPs")
                // Persist neighbors in resolverList so resume works
                _uiState.update { s -> s.copy(resolverList = s.resolverList + neighborIps) }
                scannerRepository.scanResolvers(
                    hosts = neighborIps,
                    port = port,
                    testDomain = testDomain,
                    timeoutMs = timeout,
                    concurrency = concurrency,
                    querySize = profile.dnsPayloadSize
                ).collect { handleResult(it) }
            }

            // DNS scan done — close queue so E2E coroutine finishes
            queue2.close()
            emitState(false, force = true)
        }

        // Coroutine 2: E2E validation — N parallel consumers from sorted queue
        simpleModeE2eJob = viewModelScope.launch(Dispatchers.IO) {
            launchE2eWorkers(
                queue = queue2, profile = profile,
                testUrl = _uiState.value.testUrl,
                e2eTimeout = _uiState.value.e2eTimeoutMs.toLongOrNull() ?: 15000L,
                fullVerification = _uiState.value.e2eFullVerification,
                startTestedCount = 0, startPassedCount = 0,
                onActiveChanged = { transform -> updateSimpleModeActive(transform) },
                onResult = { host, result, tested, passed ->
                    resultsMap.compute(host) { _, existing -> existing?.copy(e2eTestResult = result) }
                    updateSimpleModeResult(rebuildResultsList(), tested, passed)
                },
                onComplete = {
                    _uiState.update { s ->
                        s.copy(simpleModeE2eState = s.simpleModeE2eState.copy(
                            isRunning = false, currentResolver = null, currentPhase = "",
                            activeResolvers = emptyMap()
                        ))
                    }
                    ScanStateHolder.update { it.copy(isE2eRunning = false) }
                    cleanupBridge()
                    saveScanSessionToStore()
                    releaseWakeLock()
                }
            )
        }
    }

    private fun launchPrismScan(
        hosts: List<String>,
        allHosts: List<String>,
        testDomain: String,
        timeout: Long,
        concurrency: Int,
        pubkey: ByteArray,
        port: Int = 53,
        probeCount: Int = 5,
        passThreshold: Int = 2,
        responseSize: Int = 0,
        prefilter: Boolean = false,
        existingResults: Map<String, ResolverScanResult> = emptyMap(),
        startScannedCount: Int = 0,
        startWorkingCount: Int = 0
    ) {
        scanJob = viewModelScope.launch {
            val workingResults = mutableListOf<ResolverScanResult>()
            existingResults.values.filter { it.prismVerified == true }.let { workingResults.addAll(it) }
            var scannedCount = startScannedCount
            var workingCount = startWorkingCount
            var timeoutCount = 0
            var errorCount = 0
            var uiUpdateCounter = 0
            var lastEmitTimeMs = 0L

            fun emitState(scanning: Boolean, force: Boolean = false) {
                // If the job was cancelled (stop pressed), never set isScanning back to true
                val actuallyScanning = scanning && scanJob?.isActive == true
                if (!force) {
                    val now = System.currentTimeMillis()
                    if (now - lastEmitTimeMs < 150L) return
                    lastEmitTimeMs = now
                }
                _uiState.update { s ->
                    s.copy(scannerState = ScannerState(
                        isScanning = actuallyScanning,
                        totalCount = allHosts.size,
                        scannedCount = scannedCount,
                        workingCount = workingCount,
                        timeoutCount = timeoutCount,
                        errorCount = errorCount,
                        results = workingResults.toList()
                    ))
                }
                ScanStateHolder.update { it.copy(
                    isScanning = actuallyScanning,
                    scannedCount = scannedCount,
                    totalCount = allHosts.size,
                    workingCount = workingCount
                ) }
                periodicSaveIfNeeded()
            }

            // Per-resolver: optional alive check then prism probes, all in one pass.
            val prefilterDomain = testDomain
            val semaphore = kotlinx.coroutines.sync.Semaphore(concurrency)
            val jobs = hosts.map { host ->
                launch {
                    semaphore.acquire()
                    try {
                        // Optional pre-filter: skip dead IPs with a quick DNS check
                        if (prefilter) {
                            val pfTimeout = _uiState.value.prismPrefilterTimeoutMs.toLongOrNull()?.coerceAtLeast(200) ?: 1500L
                            val alive = scannerRepository.isResolverAlive(host, port, prefilterDomain, pfTimeout)
                            if (!alive) {
                                scannedCount++
                                timeoutCount++
                                uiUpdateCounter++
                                if (uiUpdateCounter >= 10) { uiUpdateCounter = 0; emitState(true) }
                                return@launch
                            }
                        }

                        val start = System.currentTimeMillis()
                        val passedProbes = withTimeoutOrNull(timeout) {
                            scannerRepository.verifyResolver(host, port, testDomain, pubkey, timeout, probeCount, passThreshold, responseSize)
                        }
                        val ms = System.currentTimeMillis() - start
                        val verified = passedProbes != null && passedProbes >= passThreshold
                        scannedCount++
                        if (verified) {
                            workingCount++
                            workingResults.add(ResolverScanResult(
                                host = host, port = port,
                                status = ResolverStatus.WORKING,
                                responseTimeMs = ms,
                                prismVerified = true,
                                prismPassedProbes = passedProbes!!,
                                prismTotalProbes = probeCount
                            ))
                        } else {
                            timeoutCount++
                        }
                        uiUpdateCounter++
                        if (verified || uiUpdateCounter >= 10) {
                            uiUpdateCounter = 0; emitState(true)
                        }
                    } catch (e: Exception) {
                        if (e is kotlinx.coroutines.CancellationException) throw e
                        scannedCount++; errorCount++
                    } finally {
                        semaphore.release()
                    }
                }
            }
            jobs.forEach { it.join() }
            emitState(false, force = true)
            saveScanSessionToStore()
            clearSavedSession()
            releaseWakeLock()
        }
    }

    fun stopScan() {
        releaseWakeLock()
        val isSimpleMode = _uiState.value.scanMode == ScanMode.SIMPLE
        scanJob?.cancel()
        if (isSimpleMode) {
            e2ePendingQueue?.close()
            simpleModeE2eJob?.cancel()
            _uiState.value = _uiState.value.copy(
                scannerState = _uiState.value.scannerState.copy(isScanning = false),
                simpleModeE2eState = _uiState.value.simpleModeE2eState.copy(
                    isRunning = false,
                    currentResolver = null,
                    currentPhase = "",
                    activeResolvers = emptyMap()
                )
            )
            cleanupBridge()
        } else {
            _uiState.value = _uiState.value.copy(
                scannerState = _uiState.value.scannerState.copy(isScanning = false)
            )
        }
        ScanStateHolder.update { it.copy(isScanning = false, isE2eRunning = false) }
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

    fun updateE2eConcurrency(value: String) {
        _uiState.value = _uiState.value.copy(e2eConcurrency = value)
        saveScannerSettings()
    }

    fun updateE2eFullVerification(enabled: Boolean) {
        _uiState.value = _uiState.value.copy(e2eFullVerification = enabled)
    }

    /** Effective E2E concurrency, clamped by tunnel type limits. */
    private fun effectiveE2eConcurrency(): Int {
        val profile = _uiState.value.profile ?: return 1
        val requested = _uiState.value.e2eConcurrency.toIntOrNull()?.coerceIn(1, 3) ?: 3
        val max = scannerRepository.maxE2eConcurrency(profile)
        return requested.coerceAtMost(max)
    }

    /**
     * Shared E2E parallel worker launcher. Spawns N coroutines that consume
     * from [queue], run E2E tests, and report results via callbacks.
     * Fixes the race condition by using [_uiState.update] for thread-safe CAS.
     *
     * @param onActiveChanged   Called (on any thread) when a resolver starts/updates phase or finishes.
     *                          The lambda receives a transform function to apply to activeResolvers.
     * @param onResult          Called on Main to merge a single E2E result into UI state.
     * @param onComplete        Called on Main when all workers are done.
     */
    private fun kotlinx.coroutines.CoroutineScope.launchE2eWorkers(
        queue: SortableQueue<Pair<String, Int>>,
        profile: ServerProfile,
        testUrl: String,
        e2eTimeout: Long,
        fullVerification: Boolean,
        startTestedCount: Int,
        startPassedCount: Int,
        onActiveChanged: (transform: (Map<String, String>) -> Map<String, String>) -> Unit,
        onResult: suspend (host: String, result: E2eTestResult, testedCount: Int, passedCount: Int) -> Unit,
        onComplete: suspend () -> Unit
    ): List<Job> {
        val e2eConcurrency = effectiveE2eConcurrency()
        val testedCount = java.util.concurrent.atomic.AtomicInteger(startTestedCount)
        val passedCount = java.util.concurrent.atomic.AtomicInteger(startPassedCount)
        val useIsolated = e2eConcurrency > 1

        return (1..e2eConcurrency).map {
            launch {
                while (true) {
                    val (host, port) = queue.take() ?: break
                    onActiveChanged { it + (host to "Starting...") }

                    val e2eResult = try {
                        if (useIsolated) {
                            scannerRepository.testResolverE2eIsolated(
                                resolverHost = host, resolverPort = port,
                                profile = profile, testUrl = testUrl, timeoutMs = e2eTimeout,
                                fullVerification = fullVerification,
                                onPhaseUpdate = { phase -> onActiveChanged { it + (host to phase) } }
                            )
                        } else {
                            scannerRepository.testResolverE2e(
                                resolverHost = host, resolverPort = port,
                                profile = profile, testUrl = testUrl, timeoutMs = e2eTimeout,
                                fullVerification = fullVerification,
                                onPhaseUpdate = { phase -> onActiveChanged { it + (host to phase) } }
                            )
                        }
                    } catch (e: kotlinx.coroutines.CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        E2eTestResult(errorMessage = e.message ?: "Worker error")
                    }

                    val newTested = testedCount.incrementAndGet()
                    val newPassed = if (e2eResult.success) passedCount.incrementAndGet() else passedCount.get()
                    onActiveChanged { it - host }
                    withContext(Dispatchers.Main) {
                        onResult(host, e2eResult, newTested, newPassed)
                    }
                }
            }
        }.also { workers ->
            launch {
                workers.forEach { it.join() }
                withContext(Dispatchers.Main) { onComplete() }
            }
        }
    }

    // --- Thread-safe state update helpers for parallel E2E workers ---

    /** Thread-safe CAS update of simpleModeE2eState.activeResolvers. */
    private fun updateSimpleModeActive(transform: (Map<String, String>) -> Map<String, String>) {
        _uiState.update { s ->
            val active = transform(s.simpleModeE2eState.activeResolvers)
            s.copy(simpleModeE2eState = s.simpleModeE2eState.copy(
                activeResolvers = active,
                currentResolver = active.keys.firstOrNull(),
                currentPhase = active.values.firstOrNull() ?: ""
            ))
        }
    }

    /** Update simpleModeE2eState counters and results. Thread-safe via CAS. */
    private fun updateSimpleModeResult(results: List<ResolverScanResult>, tested: Int, passed: Int) {
        _uiState.update { s ->
            s.copy(
                scannerState = s.scannerState.copy(results = results),
                simpleModeE2eState = s.simpleModeE2eState.copy(
                    testedCount = tested, passedCount = passed,
                    currentResolver = s.simpleModeE2eState.activeResolvers.keys.firstOrNull(),
                    currentPhase = s.simpleModeE2eState.activeResolvers.values.firstOrNull() ?: ""
                )
            )
        }
    }

    /** Thread-safe CAS update of e2eScannerState.activeResolvers. */
    private fun updateE2eActive(transform: (Map<String, String>) -> Map<String, String>) {
        _uiState.update { s ->
            val active = transform(s.e2eScannerState.activeResolvers)
            s.copy(e2eScannerState = s.e2eScannerState.copy(
                activeResolvers = active,
                currentResolver = active.keys.firstOrNull(),
                currentPhase = active.values.firstOrNull() ?: ""
            ))
        }
    }

    /** Update e2eScannerState counters and results. Thread-safe via CAS. */
    private fun updateE2eResult(results: List<ResolverScanResult>, tested: Int, passed: Int) {
        _uiState.update { s ->
            s.copy(
                scannerState = s.scannerState.copy(results = results),
                e2eScannerState = s.e2eScannerState.copy(
                    testedCount = tested, passedCount = passed,
                    currentResolver = s.e2eScannerState.activeResolvers.keys.firstOrNull(),
                    currentPhase = s.e2eScannerState.activeResolvers.values.firstOrNull() ?: ""
                )
            )
        }
    }

    fun updateE2eSortOption(option: E2eSortOption) {
        _uiState.value = _uiState.value.copy(e2eSortOption = option)
        // Re-sort pending E2E queue mid-test
        e2ePendingQueue?.resort(buildE2eComparator(option))
    }

    private fun buildE2eComparator(option: E2eSortOption): Comparator<Pair<String, Int>>? {
        val results = _uiState.value.scannerState.results
        val lookup = results.associateBy { it.host }
        return when (option) {
            E2eSortOption.NONE -> null
            E2eSortOption.SPEED -> compareBy { lookup[it.first]?.responseTimeMs ?: Long.MAX_VALUE }
            E2eSortOption.IP -> compareBy {
                it.first.split(".").map { p -> p.toIntOrNull() ?: 0 }
                    .fold(0L) { acc, i -> acc * 256 + i }
            }
            E2eSortOption.SCORE -> compareByDescending { lookup[it.first]?.tunnelTestResult?.score ?: 0 }
            E2eSortOption.E2E_SPEED -> Comparator { a, b ->
                val aResult = lookup[a.first]?.e2eTestResult
                val bResult = lookup[b.first]?.e2eTestResult
                val aSuccess = aResult?.success == true
                val bSuccess = bResult?.success == true
                if (aSuccess != bSuccess) return@Comparator if (bSuccess) 1 else -1
                val aMs = aResult?.totalMs ?: Long.MAX_VALUE
                val bMs = bResult?.totalMs ?: Long.MAX_VALUE
                aMs.compareTo(bMs)
            }
            E2eSortOption.PRISM_SCORE -> compareByDescending { lookup[it.first]?.prismPassedProbes ?: 0 }
        }
    }

    fun startE2eTest(fresh: Boolean = false, minScore: Int = 0) {
        // Cancel any previous E2E test to prevent its onComplete/cleanupBridge
        // from interfering with the new test's first batch of workers.
        e2eJob?.cancel()
        e2ePendingQueue?.close()

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
            .filter {
                it.status == ResolverStatus.WORKING &&
                    // Prism-verified resolvers don't have tunnelTestResult scores — include them directly
                    (it.prismVerified == true || (it.tunnelTestResult?.score ?: 0) >= minScore)
            }

        if (allWorking.isEmpty()) {
            _uiState.value = state.copy(error = "No working resolvers to test")
            return
        }

        // Determine which resolvers still need testing (resume support)
        val alreadyTested = if (fresh) emptySet()
        else allWorking.filter { it.e2eTestResult != null }.map { it.host }.toSet()

        val remainingUnsorted = allWorking
            .filter { it.host !in alreadyTested }
            .map { it.host to it.port }

        val comparator = buildE2eComparator(state.e2eSortOption)
        val remaining = if (comparator != null) remainingUnsorted.sortedWith(comparator) else remainingUnsorted

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
        ScanStateHolder.update { it.copy(isE2eRunning = true, stopRequested = false) }
        ContextCompat.startForegroundService(appContext, Intent(appContext, ScanService::class.java))

        e2eJob = viewModelScope.launch(Dispatchers.IO) {
            // Use SortableQueue for parallel consumption
            val queue = SortableQueue(remaining, buildE2eComparator(state.e2eSortOption))
            e2ePendingQueue = queue
            queue.close() // Pre-close since all items are already seeded

            launchE2eWorkers(
                queue = queue, profile = profile,
                testUrl = _uiState.value.testUrl,
                e2eTimeout = _uiState.value.e2eTimeoutMs.toLongOrNull() ?: 15000L,
                fullVerification = _uiState.value.e2eFullVerification,
                startTestedCount = startTestedCount, startPassedCount = startPassedCount,
                onActiveChanged = { transform -> updateE2eActive(transform) },
                onResult = { host, result, tested, passed ->
                    // Build updated results inside CAS to avoid stale reads
                    _uiState.update { s ->
                        val updatedResults = s.scannerState.results.map { r ->
                            if (r.host == host) r.copy(e2eTestResult = result) else r
                        }
                        s.copy(
                            scannerState = s.scannerState.copy(results = updatedResults),
                            e2eScannerState = s.e2eScannerState.copy(
                                testedCount = tested, passedCount = passed,
                                currentResolver = s.e2eScannerState.activeResolvers.keys.firstOrNull(),
                                currentPhase = s.e2eScannerState.activeResolvers.values.firstOrNull() ?: ""
                            )
                        )
                    }
                },
                onComplete = {
                    _uiState.update { s ->
                        s.copy(e2eScannerState = s.e2eScannerState.copy(
                            isRunning = false, activeResolvers = emptyMap()
                        ))
                    }
                    ScanStateHolder.update { it.copy(isE2eRunning = false) }
                    cleanupBridge()
                    releaseWakeLock()
                }
            )
        }
    }

    fun stopE2eTest() {
        releaseWakeLock()
        e2eJob?.cancel()
        e2ePendingQueue?.close()
        _uiState.value = _uiState.value.copy(
            e2eScannerState = _uiState.value.e2eScannerState.copy(
                isRunning = false,
                currentResolver = null,
                currentPhase = "",
                activeResolvers = emptyMap()
            )
        )
        ScanStateHolder.update { it.copy(isE2eRunning = false) }
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
        val port = _uiState.value.scanPort.toIntOrNull()?.coerceIn(1, 65535) ?: 53
        return _uiState.value.selectedResolvers.joinToString(",") { "$it:$port" }
    }

    fun clearError() {
        _uiState.value = _uiState.value.copy(error = null)
    }

    override fun onCleared() {
        super.onCleared()
        releaseWakeLock()
        scanJob?.cancel()
        e2eJob?.cancel()
        e2ePendingQueue?.close()
        simpleModeE2eJob?.cancel()
        cleanupBridge()
        ScanStateHolder.reset()

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
            val json = gson.toJson(session)
            // Write to cache file synchronously as a safety net (survives even if
            // the DataStore coroutine doesn't complete before the scope is cancelled).
            try {
                java.io.File(appContext.cacheDir, "scan_session.json").writeText(json)
            } catch (_: Exception) {}
            // Also persist to DataStore (primary source read on next launch).
            // viewModelScope is still active during onCleared, but cancelled right
            // after — use NonCancellable so the write completes.
            viewModelScope.launch {
                withContext(NonCancellable) {
                    try {
                        preferencesDataStore.saveScanSession(json)
                    } catch (_: Exception) {}
                }
            }
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
    e2eErrorMessage = e2eTestResult?.errorMessage,
    prismVerified = prismVerified
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
    } else null,
    prismVerified = prismVerified
)
