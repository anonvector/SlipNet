package app.slipnet.presentation.scanner

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.activity.compose.BackHandler
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.SearchOff
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.CloudOff
import androidx.compose.material.icons.outlined.Error
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.SwipeToDismissBox
import androidx.compose.material3.SwipeToDismissBoxValue
import androidx.compose.material3.rememberSwipeToDismissBoxState
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Switch
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavBackStackEntry
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.yield
import app.slipnet.domain.model.E2eScannerState
import app.slipnet.domain.model.E2eTestResult
import app.slipnet.domain.model.ResolverScanResult
import app.slipnet.domain.model.ResolverStatus
import app.slipnet.domain.model.SimpleModeE2eState

private val WorkingGreen = Color(0xFF4CAF50)
private val CensoredOrange = Color(0xFFFF9800)
private val TimeoutGray = Color(0xFF9E9E9E)
private val ErrorRed = Color(0xFFE53935)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanResultsScreen(
    profileId: Long? = null,
    fromProfile: Boolean = false,
    parentBackStackEntry: NavBackStackEntry,
    onNavigateBack: () -> Unit,
    onResolversSelected: (String, String?) -> Unit,
    viewModel: DnsScannerViewModel = hiltViewModel(parentBackStackEntry)
) {
    val uiState by viewModel.uiState.collectAsState()

    // Throttle the results list during active scanning so the main thread stays
    // responsive for back-press and other input.  Counts/progress update in real-time
    // (they're cheap), but the expensive filter+sort of the full results list only
    // runs when this throttled snapshot changes (~500ms interval during scanning).
    val isScanning = uiState.scannerState.isScanning || uiState.simpleModeE2eState.isRunning || uiState.e2eScannerState.isRunning
    var throttledResults by remember { mutableStateOf(uiState.scannerState.results) }
    // Single LaunchedEffect handles both scanning (poll) and idle (deferred update).
    // Never update throttledResults synchronously during composition — always yield
    // first so back-press and stop-button input can be processed between frames.
    LaunchedEffect(isScanning, uiState.scannerState.results) {
        if (isScanning) {
            delay(500)
        } else {
            yield() // let pending input (back button, stop) run before heavy recomposition
        }
        throttledResults = uiState.scannerState.results
    }

    val canApply = fromProfile
    val snackbarHostState = remember { SnackbarHostState() }
    val navBarPadding = WindowInsets.navigationBars.asPaddingValues()
    var proxyWarningDismissed by remember { mutableStateOf(false) }
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences("scanner_ui", Context.MODE_PRIVATE) }
    var sortOption by remember {
        val initial = SortOption.entries.find { it.name == prefs.getString("sort_option", null) } ?: SortOption.NONE
        viewModel.updateE2eSortOption(E2eSortOption.entries.find { it.name == initial.name } ?: E2eSortOption.NONE)
        mutableStateOf(initial)
    }
    var scoreFilter by remember {
        mutableStateOf(
            ScoreFilter.entries.find { it.name == prefs.getString("score_filter", null) } ?: ScoreFilter.SCORE_2_PLUS
        )
    }
    var probeFilter by remember {
        mutableStateOf(
            prefs.getStringSet("probe_filter", emptySet())?.let { stored ->
                ProbeFilter.entries.filter { it.name in stored }.toSet()
            } ?: emptySet()
        )
    }
    var showSortMenu by remember { mutableStateOf(false) }
    var showFilterMenu by remember { mutableStateOf(false) }
    var showProbeMenu by remember { mutableStateOf(false) }
    var showPrismFilterDialog by remember { mutableStateOf(false) }
    var prismMinProbes by remember {
        mutableStateOf(
            prefs.getInt("prism_min_probes", 0)
        )
    }
    var showAllWorking by remember { mutableStateOf(uiState.scanMode != ScanMode.SIMPLE && uiState.scanMode != ScanMode.E2E) }
    var searchQuery by remember { mutableStateOf("") }
    var showSearch by remember { mutableStateOf(false) }
    // null = no dialog, "copy" or "export" = pending action
    var pendingAction by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    BackHandler {
        onNavigateBack()
        viewModel.stopAll()
    }

    if (showPrismFilterDialog) {
        var inputValue by remember { mutableStateOf(prismMinProbes.toString()) }
        AlertDialog(
            onDismissRequest = { showPrismFilterDialog = false },
            title = { Text("Filter by passed probes") },
            text = {
                Column {
                    Text(
                        "Show only resolvers with at least this many passed probes. Enter 0 to show all.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    OutlinedTextField(
                        value = inputValue,
                        onValueChange = { inputValue = it.filter { c -> c.isDigit() } },
                        label = { Text("Min passed probes") },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp)
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val value = inputValue.toIntOrNull()?.coerceIn(0, 30) ?: 0
                    prismMinProbes = value
                    prefs.edit().putInt("prism_min_probes", value).apply()
                    showPrismFilterDialog = false
                }) { Text("Apply") }
            },
            dismissButton = {
                TextButton(onClick = { showPrismFilterDialog = false }) { Text("Cancel") }
            }
        )
    }

    LaunchedEffect(uiState.error) {
        uiState.error?.let { error ->
            snackbarHostState.showSnackbar(error)
            viewModel.clearError()
        }
    }

    // Single-pass filter: visible E2E-passed and Stage 1 working IPs (respects search/score)
    val isPrism = uiState.scanMode == ScanMode.PRISM
    val isE2eOnly = uiState.scanMode == ScanMode.E2E
    val (visibleE2eIps, visibleStage1Ips) = remember(throttledResults, scoreFilter, probeFilter, searchQuery, isPrism, isE2eOnly, prismMinProbes) {
        val query = searchQuery.trim()
        val e2e = mutableListOf<String>()
        val stage1 = mutableListOf<String>()
        for (result in throttledResults) {
            // Prism and E2E-only results have no tunnelTestResult (score), skip score filter for them
            val matchesFilters = if (isPrism) {
                result.prismVerified == true &&
                    (result.prismPassedProbes ?: 0) >= prismMinProbes &&
                    (query.isEmpty() || result.host.contains(query))
            } else if (isE2eOnly) {
                result.e2eTestResult?.success == true &&
                    (query.isEmpty() || result.host.contains(query))
            } else {
                (result.tunnelTestResult?.score ?: 0) >= scoreFilter.minScore &&
                    result.passesProbeFilter(probeFilter) &&
                    (query.isEmpty() || result.host.contains(query))
            }
            if (!matchesFilters) continue
            if (result.status == ResolverStatus.WORKING) stage1.add(result.host)
            if (result.e2eTestResult?.success == true) e2e.add(result.host)
        }
        e2e as List<String> to (stage1 as List<String>)
    }

    val hasE2eResults = remember(throttledResults) {
        throttledResults.any { it.e2eTestResult != null }
    }

    fun copyIpsToClipboard(ips: List<String>) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("DNS Resolvers", ips.joinToString(", ")))
        scope.launch {
            snackbarHostState.currentSnackbarData?.dismiss()
            launch { snackbarHostState.showSnackbar("Copied ${ips.size} IPs") }
            delay(1500)
            snackbarHostState.currentSnackbarData?.dismiss()
        }
    }

    // Dialog for choosing which IPs to copy/export
    if (pendingAction != null) {
        val action = pendingAction
        val selectedIps = uiState.selectedResolvers.toList()

        fun doCopy(ips: List<String>) {
            pendingAction = null
            copyIpsToClipboard(ips)
        }

        fun doExport(ips: List<String>) {
            pendingAction = null
            performExport(context, ips, scope, snackbarHostState)
        }

        AlertDialog(
            onDismissRequest = { pendingAction = null },
            title = { Text(if (action == "copy") "Copy IPs" else "Export IPs") },
            text = { Text("Which IPs do you want to ${if (action == "copy") "copy" else "export"}?") },
            confirmButton = {
                Column(horizontalAlignment = Alignment.End) {
                    if (hasE2eResults && visibleE2eIps.isNotEmpty()) {
                        TextButton(onClick = {
                            if (action == "copy") doCopy(visibleE2eIps) else doExport(visibleE2eIps)
                        }) {
                            Text("E2E passed (${visibleE2eIps.size})")
                        }
                    }
                    if (visibleStage1Ips.isNotEmpty()) {
                        TextButton(onClick = {
                            if (action == "copy") doCopy(visibleStage1Ips) else doExport(visibleStage1Ips)
                        }) {
                            Text("Stage 1 working (${visibleStage1Ips.size})")
                        }
                    }
                    if (selectedIps.isNotEmpty()) {
                        TextButton(onClick = {
                            if (action == "copy") doCopy(selectedIps) else doExport(selectedIps)
                        }) {
                            Text("Selected only (${selectedIps.size})")
                        }
                    }
                }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        "Scan Results",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.SemiBold
                    )
                },
                navigationIcon = {
                    IconButton(onClick = { onNavigateBack(); viewModel.stopAll() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    val isIdle = !uiState.scannerState.isScanning &&
                        (uiState.scanMode !in listOf(ScanMode.SIMPLE, ScanMode.E2E) || !uiState.simpleModeE2eState.isRunning)
                    if (uiState.scannerState.results.isNotEmpty()) {
                        IconButton(
                            onClick = {
                                showSearch = !showSearch
                                if (!showSearch) searchQuery = ""
                            }
                        ) {
                            Icon(
                                if (showSearch) Icons.Default.SearchOff else Icons.Default.Search,
                                contentDescription = if (showSearch) "Hide search" else "Search"
                            )
                        }
                    }
                    if ((visibleStage1Ips.isNotEmpty() || visibleE2eIps.isNotEmpty()) && isIdle) {
                        IconButton(
                            onClick = {
                                when {
                                    hasE2eResults || uiState.selectedResolvers.isNotEmpty() -> pendingAction = "copy"
                                    visibleStage1Ips.isNotEmpty() -> copyIpsToClipboard(visibleStage1Ips)
                                    else -> copyIpsToClipboard(visibleE2eIps)
                                }
                            }
                        ) {
                            Icon(Icons.Default.ContentCopy, contentDescription = "Copy visible IPs")
                        }
                        IconButton(
                            onClick = {
                                when {
                                    hasE2eResults || uiState.selectedResolvers.isNotEmpty() -> pendingAction = "export"
                                    visibleStage1Ips.isNotEmpty() -> performExport(context, visibleStage1Ips, scope, snackbarHostState)
                                    else -> performExport(context, visibleE2eIps, scope, snackbarHostState)
                                }
                            }
                        ) {
                            Icon(Icons.Default.Share, contentDescription = "Export DNS list")
                        }
                    }
                    if (canApply && uiState.selectedResolvers.isNotEmpty()) {
                        TextButton(
                            onClick = {
                                viewModel.saveRecentDns()
                                onResolversSelected(
                                    viewModel.getSelectedResolversString(),
                                    viewModel.getRecommendedTransportHint()
                                )
                            }
                        ) {
                            Text("Apply", fontWeight = FontWeight.SemiBold)
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        snackbarHost = {
            SnackbarHost(
                snackbarHostState,
                modifier = Modifier.padding(bottom = 120.dp)
            )
        },
        contentWindowInsets = WindowInsets(0, 0, 0, 0)
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
        ) {
            val isPrismMode = uiState.scanMode == ScanMode.PRISM

            // Progress
            if (uiState.scanMode == ScanMode.SIMPLE || uiState.scanMode == ScanMode.E2E) {
                val showProgress = uiState.scannerState.isScanning ||
                    uiState.simpleModeE2eState.isRunning ||
                    uiState.simpleModeE2eState.testedCount > 0 ||
                    uiState.scannerState.scannedCount > 0
                if (showProgress) {
                    SimpleModeProgressSection(
                        scannerState = uiState.scannerState,
                        simpleModeE2eState = uiState.simpleModeE2eState,
                        isE2eOnlyMode = uiState.scanMode == ScanMode.E2E,
                        e2eConcurrency = uiState.e2eConcurrency.toIntOrNull()?.coerceIn(1, 10) ?: 6,
                        onStopScan = { viewModel.stopScan() },
                        onResumeScan = { viewModel.resumeScan() }
                    )
                }
            } else {
                if (uiState.scannerState.isScanning || uiState.scannerState.results.isNotEmpty() || uiState.scannerState.scannedCount > 0 || uiState.e2eScannerState.isRunning) {
                    val workingCount = remember(throttledResults, isPrismMode) {
                        if (isPrismMode) {
                            throttledResults.count { it.prismVerified == true }
                        } else {
                            throttledResults.count {
                                it.status == ResolverStatus.WORKING &&
                                    (it.tunnelTestResult?.score ?: 0) >= 1
                            }
                        }
                    }
                    ResultsProgressSection(
                        isScanning = uiState.scannerState.isScanning,
                        progress = uiState.scannerState.progress,
                        totalCount = uiState.scannerState.totalCount,
                        scannedCount = uiState.scannerState.scannedCount,
                        workingCount = workingCount,
                        onStopScan = { viewModel.stopScan() },
                        onResumeScan = { viewModel.resumeScan() },
                        e2eSupported = uiState.e2eSupported,
                        canRunE2e = uiState.canRunE2e,
                        canResumeE2e = uiState.canResumeE2e,
                        e2eComplete = uiState.e2eComplete,
                        isE2eRunning = uiState.e2eScannerState.isRunning,
                        onStartE2eFresh = { viewModel.startE2eTest(fresh = true, minScore = scoreFilter.minScore) },
                        onResumeE2e = { viewModel.startE2eTest(fresh = false, minScore = scoreFilter.minScore) },
                        onStopE2e = { viewModel.stopE2eTest() }
                    )
                }

                // E2E progress
                AnimatedVisibility(
                    visible = uiState.e2eScannerState.isRunning || uiState.e2eScannerState.testedCount > 0,
                    enter = expandVertically() + fadeIn(),
                    exit = shrinkVertically() + fadeOut()
                ) {
                    E2eProgressSection(e2eScannerState = uiState.e2eScannerState, e2eConcurrency = uiState.e2eConcurrency.toIntOrNull()?.coerceIn(1, 10) ?: 6)
                }
            }

            // VPN active warning for E2E
            AnimatedVisibility(
                visible = !isPrismMode && uiState.isVpnActive && uiState.profileId != null &&
                        !uiState.scannerState.isScanning && uiState.scannerState.workingCount > 0,
                enter = expandVertically() + fadeIn(),
                exit = shrinkVertically() + fadeOut()
            ) {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 4.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = CensoredOrange.copy(alpha = 0.12f)
                    ),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.Warning,
                            contentDescription = null,
                            tint = CensoredOrange,
                            modifier = Modifier.size(20.dp)
                        )
                        Text(
                            text = "Disconnect VPN to run tunnel test",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                }
            }

            // Transparent proxy warning
            AnimatedVisibility(
                visible = uiState.transparentProxyDetected && !proxyWarningDismissed,
                enter = expandVertically() + fadeIn(),
                exit = shrinkVertically() + fadeOut()
            ) {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 8.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer
                    ),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        Icon(
                            Icons.Default.Warning,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.error,
                            modifier = Modifier.size(20.dp)
                        )
                        Text(
                            text = "Transparent DNS interception detected \u2014 your ISP may be redirecting all DNS traffic. Results may be unreliable.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            modifier = Modifier.weight(1f)
                        )
                        IconButton(
                            onClick = { proxyWarningDismissed = true },
                            modifier = Modifier.size(20.dp)
                        ) {
                            Icon(
                                Icons.Default.Close,
                                contentDescription = "Dismiss",
                                tint = MaterialTheme.colorScheme.onErrorContainer,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }
                }
            }

            // Selection Controls
            if (canApply) {
                ResultsSelectionControls(
                    selectedCount = uiState.selectedResolvers.size,
                    maxCount = DnsScannerUiState.MAX_SELECTED_RESOLVERS,
                    onClearSelection = { viewModel.clearSelection() }
                )
            }

            // Search bar
            AnimatedVisibility(
                visible = showSearch && uiState.scannerState.results.isNotEmpty(),
                enter = expandVertically() + fadeIn(),
                exit = shrinkVertically() + fadeOut()
            ) {
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    placeholder = { Text("Search IP...", style = MaterialTheme.typography.bodySmall) },
                    leadingIcon = {
                        Icon(
                            Icons.Default.Search,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp)
                        )
                    },
                    trailingIcon = {
                        if (searchQuery.isNotEmpty()) {
                            IconButton(onClick = { searchQuery = "" }, modifier = Modifier.size(24.dp)) {
                                Icon(Icons.Default.Close, contentDescription = "Clear", modifier = Modifier.size(16.dp))
                            }
                        }
                    },
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp)
                        .height(44.dp),
                    shape = RoundedCornerShape(10.dp)
                )
            }

            // Results
            val isSimpleMode = uiState.scanMode == ScanMode.SIMPLE
            val isE2eOnlyMode = uiState.scanMode == ScanMode.E2E
            val displayResults = remember(throttledResults, scoreFilter, probeFilter, sortOption, isSimpleMode, isE2eOnlyMode, isPrismMode, showAllWorking, searchQuery, hasE2eResults, prismMinProbes) {
                val query = searchQuery.trim()
                val filtered = if (isE2eOnlyMode) {
                    // E2E mode only has E2E-passed results
                    throttledResults.filter {
                        it.e2eTestResult?.success == true &&
                            (query.isEmpty() || it.host.contains(query))
                    }
                } else if (isPrismMode && !showAllWorking && hasE2eResults) {
                    throttledResults.filter {
                        it.prismVerified == true &&
                            (it.prismPassedProbes ?: 0) >= prismMinProbes &&
                            it.e2eTestResult?.success == true &&
                            (query.isEmpty() || it.host.contains(query))
                    }
                } else if (isPrismMode) {
                    throttledResults.filter {
                        it.prismVerified == true &&
                            (it.prismPassedProbes ?: 0) >= prismMinProbes &&
                            (query.isEmpty() || it.host.contains(query))
                    }
                } else if (isSimpleMode && !showAllWorking) {
                    throttledResults.filter {
                        it.e2eTestResult?.success == true &&
                            (it.tunnelTestResult?.score ?: 0) >= scoreFilter.minScore &&
                            (query.isEmpty() || it.host.contains(query))
                    }
                } else if (isSimpleMode) {
                    throttledResults.filter {
                        it.status == ResolverStatus.WORKING &&
                            (it.tunnelTestResult?.score ?: 0) >= scoreFilter.minScore &&
                            (query.isEmpty() || it.host.contains(query))
                    }
                } else if (!showAllWorking && hasE2eResults) {
                    throttledResults.filter {
                        it.status == ResolverStatus.WORKING &&
                            it.e2eTestResult?.success == true &&
                            (it.tunnelTestResult?.score ?: 0) >= scoreFilter.minScore &&
                            it.passesProbeFilter(probeFilter) &&
                            (query.isEmpty() || it.host.contains(query))
                    }
                } else {
                    throttledResults.filter {
                        it.status == ResolverStatus.WORKING &&
                            (it.tunnelTestResult?.score ?: 0) >= scoreFilter.minScore &&
                            it.passesProbeFilter(probeFilter) &&
                            (query.isEmpty() || it.host.contains(query))
                    }
                }

                when (sortOption) {
                    SortOption.SPEED -> filtered.sortedBy { it.responseTimeMs ?: Long.MAX_VALUE }
                    SortOption.IP -> filtered.sortedWith(compareBy {
                        it.host.split(".").map { part -> part.toIntOrNull() ?: 0 }
                            .fold(0L) { acc, i -> acc * 256 + i }
                    })
                    SortOption.SCORE -> filtered.sortedByDescending {
                        it.tunnelTestResult?.score ?: 0
                    }
                    SortOption.E2E_SPEED -> filtered.sortedWith(
                        compareByDescending<ResolverScanResult> { it.e2eTestResult?.success == true }
                            .thenBy { it.e2eTestResult?.totalMs ?: Long.MAX_VALUE }
                    )
                    SortOption.PRISM_SCORE -> filtered.sortedByDescending {
                        it.prismPassedProbes ?: 0
                    }
                    SortOption.NONE -> if (isSimpleMode) {
                        filtered.sortedBy { it.e2eTestResult?.totalMs ?: Long.MAX_VALUE }
                    } else filtered
                }
            }

            if (displayResults.isEmpty()) {
                Box(modifier = Modifier.weight(1f)) {
                    ResultsEmptyState(
                        isScanning = uiState.scannerState.isScanning,
                        isSimpleMode = isSimpleMode,
                        isSimpleModeRunning = uiState.simpleModeE2eState.isRunning,
                        workingCount = uiState.scannerState.workingCount,
                        e2eTestedCount = uiState.simpleModeE2eState.testedCount
                    )
                }
            } else {
                LazyColumn(
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(
                        start = 16.dp,
                        end = 16.dp,
                        top = 8.dp,
                        bottom = 8.dp
                    ),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    item {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 4.dp),
                            horizontalArrangement = Arrangement.End,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "\u2190 Swipe left to copy IP",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                            )
                        }
                    }
                    items(displayResults.size, key = { index -> "${displayResults[index].host}_$index" }) { index ->
                        val result = displayResults[index]
                        val isSelected = uiState.selectedResolvers.contains(result.host)
                        val dismissState = rememberSwipeToDismissBoxState(
                            confirmValueChange = { value ->
                                if (value == SwipeToDismissBoxValue.EndToStart) {
                                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    clipboard.setPrimaryClip(ClipData.newPlainText("DNS", result.host))
                                    if (android.os.Build.VERSION.SDK_INT < 33) {
                                        scope.launch {
                                            snackbarHostState.currentSnackbarData?.dismiss()
                                            launch { snackbarHostState.showSnackbar("Copied ${result.host}") }
                                            delay(1200)
                                            snackbarHostState.currentSnackbarData?.dismiss()
                                        }
                                    }
                                    false // don't dismiss, snap back
                                } else false
                            }
                        )
                        SwipeToDismissBox(
                            state = dismissState,
                            enableDismissFromStartToEnd = false,
                            backgroundContent = {
                                Box(
                                    modifier = Modifier
                                        .fillMaxSize()
                                        .clip(RoundedCornerShape(12.dp))
                                        .background(MaterialTheme.colorScheme.primaryContainer),
                                    contentAlignment = Alignment.CenterEnd
                                ) {
                                    Row(
                                        modifier = Modifier.padding(end = 20.dp),
                                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            "Copy",
                                            style = MaterialTheme.typography.labelLarge,
                                            fontWeight = FontWeight.SemiBold,
                                            color = MaterialTheme.colorScheme.primary
                                        )
                                        Icon(
                                            Icons.Default.ContentCopy,
                                            contentDescription = "Copy IP",
                                            tint = MaterialTheme.colorScheme.primary,
                                            modifier = Modifier.size(20.dp)
                                        )
                                    }
                                }
                            }
                        ) {
                            ResultsResolverItem(
                                result = result,
                                isSelected = isSelected,
                                isLimitReached = uiState.isSelectionLimitReached,
                                showSelection = canApply,
                                isE2eTesting = (uiState.e2eScannerState.isRunning && (result.host in uiState.e2eScannerState.activeResolvers || uiState.e2eScannerState.currentResolver == result.host)) ||
                                    (uiState.simpleModeE2eState.isRunning && (result.host in uiState.simpleModeE2eState.activeResolvers || uiState.simpleModeE2eState.currentResolver == result.host)),
                                e2ePhase = uiState.e2eScannerState.activeResolvers[result.host]
                                    ?: uiState.simpleModeE2eState.activeResolvers[result.host]
                                    ?: if (uiState.e2eScannerState.currentResolver == result.host) uiState.e2eScannerState.currentPhase
                                    else if (uiState.simpleModeE2eState.currentResolver == result.host) uiState.simpleModeE2eState.currentPhase
                                    else null,
                                onToggleSelection = if (canApply) {
                                    { viewModel.toggleResolverSelection(result.host) }
                                } else null,
                                transportSupport = uiState.hostTransportSupport[result.host]
                            )
                        }
                    }
                }
            }

            // Compact sort/filter bar — visible when there are results to display
            if (uiState.scannerState.results.isNotEmpty()) {
                Surface(
                    color = MaterialTheme.colorScheme.surfaceContainerLow,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 6.dp)
                            .padding(bottom = navBarPadding.calculateBottomPadding()),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        // Sort dropdown
                        Box {
                            FilterChip(
                                selected = sortOption != SortOption.NONE,
                                onClick = { showSortMenu = true },
                                label = {
                                    Text(when (sortOption) {
                                        SortOption.NONE -> "Sort"
                                        SortOption.SPEED -> "Speed"
                                        SortOption.IP -> "IP"
                                        SortOption.SCORE -> "Score"
                                        SortOption.E2E_SPEED -> "E2E"
                                        SortOption.PRISM_SCORE -> "Prism"
                                    })
                                },
                                trailingIcon = {
                                    Icon(Icons.Default.KeyboardArrowDown, null, modifier = Modifier.size(16.dp))
                                },
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                                    selectedLabelColor = MaterialTheme.colorScheme.primary,
                                    selectedTrailingIconColor = MaterialTheme.colorScheme.primary
                                )
                            )
                            DropdownMenu(
                                expanded = showSortMenu,
                                onDismissRequest = { showSortMenu = false }
                            ) {
                                val sortOptions = if (isPrismMode) listOfNotNull(
                                    SortOption.NONE to "None",
                                    SortOption.SPEED to "Speed",
                                    SortOption.IP to "IP",
                                    SortOption.PRISM_SCORE to "Prism Score",
                                    if (hasE2eResults) SortOption.E2E_SPEED to "E2E" else null
                                ) else listOf(
                                    SortOption.NONE to "None",
                                    SortOption.SPEED to "Speed",
                                    SortOption.IP to "IP",
                                    SortOption.SCORE to "Score",
                                    SortOption.E2E_SPEED to "E2E"
                                )
                                sortOptions.forEach { (option, label) ->
                                    DropdownMenuItem(
                                        text = { Text(label) },
                                        onClick = {
                                            sortOption = option
                                            prefs.edit().putString("sort_option", option.name).apply()
                                            viewModel.updateE2eSortOption(E2eSortOption.entries.find { it.name == option.name } ?: E2eSortOption.NONE)
                                            showSortMenu = false
                                        },
                                        leadingIcon = if (sortOption == option) ({
                                            Icon(Icons.Default.Check, null, modifier = Modifier.size(16.dp))
                                        }) else null
                                    )
                                }
                            }
                        }

                        // Prism probe filter
                        if (isPrismMode) {
                            FilterChip(
                                selected = prismMinProbes > 0,
                                onClick = { showPrismFilterDialog = true },
                                label = { Text(if (prismMinProbes > 0) "Probes ${prismMinProbes}+" else "All probes") },
                                trailingIcon = {
                                    Icon(Icons.Default.KeyboardArrowDown, null, modifier = Modifier.size(16.dp))
                                },
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = MaterialTheme.colorScheme.secondaryContainer,
                                    selectedLabelColor = MaterialTheme.colorScheme.secondary,
                                    selectedTrailingIconColor = MaterialTheme.colorScheme.secondary
                                )
                            )
                        }

                        // Score filter dropdown
                        if (!isPrismMode) Box {
                            FilterChip(
                                selected = true,
                                onClick = { showFilterMenu = true },
                                label = { Text("Score ${scoreFilter.label}") },
                                trailingIcon = {
                                    Icon(Icons.Default.KeyboardArrowDown, null, modifier = Modifier.size(16.dp))
                                },
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = MaterialTheme.colorScheme.secondaryContainer,
                                    selectedLabelColor = MaterialTheme.colorScheme.secondary,
                                    selectedTrailingIconColor = MaterialTheme.colorScheme.secondary
                                )
                            )
                            DropdownMenu(
                                expanded = showFilterMenu,
                                onDismissRequest = { showFilterMenu = false }
                            ) {
                                ScoreFilter.entries.forEach { filter ->
                                    DropdownMenuItem(
                                        text = { Text("Score ${filter.label}") },
                                        onClick = {
                                            scoreFilter = filter
                                            prefs.edit().putString("score_filter", filter.name).apply()
                                            viewModel.updateE2eMinScore(filter.minScore)
                                            showFilterMenu = false
                                        },
                                        leadingIcon = if (scoreFilter == filter) ({
                                            Icon(Icons.Default.Check, null, modifier = Modifier.size(16.dp))
                                        }) else null
                                    )
                                }
                            }
                        }

                        // Probe-pass filter (ADVANCED mode only): require specific DNS probes to pass
                        if (uiState.scanMode == ScanMode.ADVANCED) Box {
                            val probeLabel = when {
                                probeFilter.isEmpty() -> "Probes"
                                probeFilter.size == 1 -> probeFilter.first().label
                                else -> "Probes ${probeFilter.size}/6"
                            }
                            FilterChip(
                                selected = probeFilter.isNotEmpty(),
                                onClick = { showProbeMenu = true },
                                label = { Text(probeLabel) },
                                trailingIcon = {
                                    Icon(Icons.Default.KeyboardArrowDown, null, modifier = Modifier.size(16.dp))
                                },
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = MaterialTheme.colorScheme.secondaryContainer,
                                    selectedLabelColor = MaterialTheme.colorScheme.secondary,
                                    selectedTrailingIconColor = MaterialTheme.colorScheme.secondary
                                )
                            )
                            DropdownMenu(
                                expanded = showProbeMenu,
                                onDismissRequest = { showProbeMenu = false }
                            ) {
                                ProbeFilter.entries.forEach { probe ->
                                    val checked = probe in probeFilter
                                    DropdownMenuItem(
                                        text = { Text(probe.label) },
                                        onClick = {
                                            probeFilter = if (checked) probeFilter - probe else probeFilter + probe
                                            prefs.edit().putStringSet(
                                                "probe_filter",
                                                probeFilter.map { it.name }.toSet()
                                            ).apply()
                                        },
                                        leadingIcon = if (checked) ({
                                            Icon(Icons.Default.Check, null, modifier = Modifier.size(16.dp))
                                        }) else null
                                    )
                                }
                                if (probeFilter.isNotEmpty()) {
                                    HorizontalDivider()
                                    DropdownMenuItem(
                                        text = { Text("Clear") },
                                        onClick = {
                                            probeFilter = emptySet()
                                            prefs.edit().remove("probe_filter").apply()
                                            showProbeMenu = false
                                        }
                                    )
                                }
                            }
                        }

                        // Toggle E2E-passed-only vs all working (not shown for E2E-only since all results are E2E-passed)
                        if ((uiState.scanMode == ScanMode.SIMPLE || hasE2eResults) && uiState.scanMode != ScanMode.E2E) {
                            FilterChip(
                                selected = showAllWorking,
                                onClick = { showAllWorking = !showAllWorking },
                                label = { Text("All working") },
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = MaterialTheme.colorScheme.tertiaryContainer,
                                    selectedLabelColor = MaterialTheme.colorScheme.tertiary
                                )
                            )
                        }
                    }
                }
            }
        }
    }
}

private fun performExport(
    context: Context,
    ips: List<String>,
    scope: kotlinx.coroutines.CoroutineScope,
    snackbarHostState: SnackbarHostState
) {
    try {
        val content = ips.joinToString("\n")
        val cacheDir = java.io.File(context.cacheDir, "shared")
        cacheDir.mkdirs()
        val file = java.io.File(cacheDir, "dns-resolvers.txt")
        file.writeText(content)
        val uri = androidx.core.content.FileProvider.getUriForFile(
            context, "${context.packageName}.fileprovider", file
        )
        val intent = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(android.content.Intent.EXTRA_STREAM, uri)
            addFlags(android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(android.content.Intent.createChooser(intent, "Export DNS list"))
    } catch (e: Exception) {
        scope.launch {
            snackbarHostState.showSnackbar("Export failed: ${e.message}")
        }
    }
}

private enum class ScoreFilter(val label: String, val minScore: Int) {
    SCORE_1_PLUS("1+", 1),
    SCORE_2_PLUS("2+", 2),
    SCORE_3_PLUS("3+", 3),
    SCORE_4_PLUS("4+", 4),
    SCORE_5_PLUS("5+", 5),
    SCORE_6("6/6", 6)
}

/** Individual DNS-probe filter: only resolvers whose [matches] returns true pass. */
private enum class ProbeFilter(val label: String) {
    NS("NS"),
    TXT("TXT"),
    RND("RND"),
    DPI("DPI"),
    EDNS("EDNS"),
    NXD("NXD");

    fun matches(result: app.slipnet.domain.model.DnsTunnelTestResult): Boolean = when (this) {
        NS -> result.nsSupport
        TXT -> result.txtSupport
        RND -> result.randomSubdomain
        DPI -> result.tunnelRealism
        EDNS -> result.edns0Support
        NXD -> result.nxdomainCorrect
    }
}

/** True iff every probe in [probes] passed. Empty set = no filtering. */
private fun app.slipnet.domain.model.ResolverScanResult.passesProbeFilter(probes: Set<ProbeFilter>): Boolean {
    if (probes.isEmpty()) return true
    val t = tunnelTestResult ?: return false
    return probes.all { it.matches(t) }
}

private enum class SortOption {
    NONE, SPEED, IP, SCORE, E2E_SPEED, PRISM_SCORE
}


@Composable
private fun ResultsProgressSection(
    isScanning: Boolean,
    progress: Float,
    totalCount: Int,
    scannedCount: Int,
    workingCount: Int,
    onStopScan: () -> Unit,
    onResumeScan: () -> Unit,
    e2eSupported: Boolean = false,
    canRunE2e: Boolean = false,
    canResumeE2e: Boolean = false,
    e2eComplete: Boolean = false,
    isE2eRunning: Boolean = false,
    onStartE2eFresh: () -> Unit = {},
    onResumeE2e: () -> Unit = {},
    onStopE2e: () -> Unit = {}
) {
    val animatedProgress by animateFloatAsState(
        targetValue = progress,
        label = "progress"
    )
    val canResume = !isScanning && scannedCount > 0 && scannedCount < totalCount

    Surface(
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    ResultsStatChip(
                        icon = Icons.Default.Dns,
                        label = "Total",
                        value = totalCount.toString(),
                        color = MaterialTheme.colorScheme.primary
                    )
                    ResultsStatChip(
                        icon = Icons.Default.Search,
                        label = "Scanned",
                        value = scannedCount.toString(),
                        color = MaterialTheme.colorScheme.secondary
                    )
                    ResultsStatChip(
                        icon = Icons.Default.CheckCircle,
                        label = "Working",
                        value = workingCount.toString(),
                        color = WorkingGreen
                    )
                }

                ScanControlButton(
                    isRunning = isScanning,
                    canResume = canResume,
                    onStop = onStopScan,
                    onResume = onResumeScan
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                LinearProgressIndicator(
                    progress = { animatedProgress },
                    modifier = Modifier
                        .weight(1f)
                        .height(5.dp)
                        .clip(RoundedCornerShape(3.dp)),
                    strokeCap = StrokeCap.Round
                )
                Text(
                    text = "${(animatedProgress * 100).toInt()}%",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.primary
                )
            }

            // E2E Test Tunnel buttons — compact row
            if (isE2eRunning) {
                Button(
                    onClick = onStopE2e,
                    colors = ButtonDefaults.buttonColors(containerColor = ErrorRed),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth(),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
                ) {
                    Icon(Icons.Default.Stop, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Stop Tunnel Test", style = MaterialTheme.typography.labelMedium)
                }
            } else if (canResumeE2e) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = onResumeE2e,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.tertiary
                        ),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.weight(1f),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
                    ) {
                        Icon(Icons.Default.PlayArrow, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Continue", style = MaterialTheme.typography.labelMedium)
                    }
                    OutlinedButton(
                        onClick = onStartE2eFresh,
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.weight(1f),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
                    ) {
                        Icon(Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Restart", style = MaterialTheme.typography.labelMedium)
                    }
                }
            } else if (e2eComplete) {
                OutlinedButton(
                    onClick = onStartE2eFresh,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth(),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
                ) {
                    Icon(Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Re-test Tunnel", style = MaterialTheme.typography.labelMedium)
                }
            } else if (e2eSupported) {
                Button(
                    onClick = onStartE2eFresh,
                    enabled = canRunE2e,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.tertiary
                    ),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth(),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
                ) {
                    Icon(Icons.Default.Speed, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(
                        if (canRunE2e) "Test Tunnel" else "Test Tunnel (waiting for results…)",
                        style = MaterialTheme.typography.labelMedium
                    )
                }
            }
        }
    }
}

@Composable
private fun ResultsStatChip(
    icon: ImageVector,
    label: String,
    value: String,
    color: Color
) {
    Row(
        horizontalArrangement = Arrangement.spacedBy(5.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            icon,
            contentDescription = null,
            tint = color,
            modifier = Modifier.size(14.dp)
        )
        Column {
            Text(
                text = value,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                color = color
            )
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun E2eProgressSection(e2eScannerState: E2eScannerState, e2eConcurrency: Int = 6) {
    val progress = if (e2eScannerState.totalCount > 0) {
        e2eScannerState.testedCount.toFloat() / e2eScannerState.totalCount
    } else 0f
    val animatedProgress by animateFloatAsState(targetValue = progress, label = "e2eProgress")

    Surface(
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    if (e2eScannerState.isRunning) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.tertiary
                        )
                    }
                    Text(
                        text = "Tunnel Test: ${e2eScannerState.testedCount}/${e2eScannerState.totalCount}",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.tertiary
                    )
                    if (e2eScannerState.passedCount > 0) {
                        Text(
                            text = "${e2eScannerState.passedCount} passed",
                            style = MaterialTheme.typography.labelSmall,
                            color = WorkingGreen
                        )
                    }
                }
            }

            if (e2eScannerState.isRunning) {
                ActiveResolversList(e2eScannerState.activeResolvers, maxSlots = e2eConcurrency)
            }

            LinearProgressIndicator(
                progress = { animatedProgress },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(4.dp)
                    .clip(RoundedCornerShape(2.dp)),
                strokeCap = StrokeCap.Round,
                color = MaterialTheme.colorScheme.tertiary
            )
        }
    }
}

@Composable
private fun SimpleModeProgressSection(
    scannerState: app.slipnet.domain.model.ScannerState,
    simpleModeE2eState: SimpleModeE2eState,
    isE2eOnlyMode: Boolean = false,
    e2eConcurrency: Int = 6,
    onStopScan: () -> Unit,
    onResumeScan: () -> Unit
) {
    val dnsProgress = scannerState.progress
    val e2eProgress = if (simpleModeE2eState.queuedCount > 0) {
        simpleModeE2eState.testedCount.toFloat() / simpleModeE2eState.queuedCount
    } else 0f
    val animatedDnsProgress by animateFloatAsState(targetValue = dnsProgress, label = "dnsProgress")
    val animatedE2eProgress by animateFloatAsState(targetValue = e2eProgress, label = "e2eProgress")
    val isRunning = scannerState.isScanning || simpleModeE2eState.isRunning
    val hasPartialDns = !isE2eOnlyMode && scannerState.scannedCount > 0 &&
        scannerState.scannedCount < scannerState.totalCount + scannerState.focusRangeCount
    val hasPartialE2eSimple = remember(scannerState.results) {
        scannerState.results.any { it.status == ResolverStatus.WORKING && it.e2eTestResult == null }
    }
    val hasPartialE2e = if (isE2eOnlyMode) {
        simpleModeE2eState.testedCount > 0 && simpleModeE2eState.testedCount < simpleModeE2eState.queuedCount
    } else {
        hasPartialE2eSimple
    }
    val canResume = !isRunning && (hasPartialDns || hasPartialE2e)

    Surface(
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            if (!isE2eOnlyMode) {
                // DNS scan row
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        ResultsStatChip(
                            icon = Icons.Default.Search,
                            label = "Scanned",
                            value = "${scannerState.scannedCount}/${scannerState.totalCount}${if (scannerState.focusRangeCount > 0) " + ${scannerState.focusRangeCount}" else ""}",
                            color = MaterialTheme.colorScheme.secondary
                        )
                        ResultsStatChip(
                            icon = Icons.Default.CheckCircle,
                            label = "Working",
                            value = scannerState.workingCount.toString(),
                            color = WorkingGreen
                        )
                    }
                    ScanControlButton(
                        isRunning = isRunning,
                        canResume = canResume,
                        onStop = onStopScan,
                        onResume = onResumeScan
                    )
                }

                LinearProgressIndicator(
                    progress = { animatedDnsProgress },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(4.dp)
                        .clip(RoundedCornerShape(2.dp)),
                    strokeCap = StrokeCap.Round
                )
            }

            // E2E row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    if (simpleModeE2eState.isRunning) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.tertiary
                        )
                    }
                    Text(
                        text = "E2E: ${simpleModeE2eState.testedCount}/${simpleModeE2eState.queuedCount}",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.tertiary
                    )
                    if (simpleModeE2eState.passedCount > 0) {
                        Text(
                            text = "${simpleModeE2eState.passedCount} passed",
                            style = MaterialTheme.typography.labelSmall,
                            color = WorkingGreen
                        )
                    }
                }
                if (isE2eOnlyMode) {
                    ScanControlButton(
                        isRunning = isRunning,
                        canResume = canResume,
                        onStop = onStopScan,
                        onResume = onResumeScan
                    )
                }
            }

            if (simpleModeE2eState.isRunning) {
                ActiveResolversList(simpleModeE2eState.activeResolvers, maxSlots = e2eConcurrency)
            }

            LinearProgressIndicator(
                progress = { animatedE2eProgress },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(4.dp)
                    .clip(RoundedCornerShape(2.dp)),
                strokeCap = StrokeCap.Round,
                color = MaterialTheme.colorScheme.tertiary
            )
        }
    }
}

@Composable
private fun ResultsSelectionControls(
    selectedCount: Int,
    maxCount: Int,
    onClearSelection: () -> Unit
) {
    AnimatedVisibility(
        visible = selectedCount > 0,
        enter = expandVertically() + fadeIn(),
        exit = shrinkVertically() + fadeOut()
    ) {
        val isLimitReached = selectedCount >= maxCount

        Surface(
            color = MaterialTheme.colorScheme.surface,
            tonalElevation = 1.dp,
            modifier = Modifier.fillMaxWidth()
        ) {
            Column {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(8.dp))
                            .background(
                                if (isLimitReached) CensoredOrange.copy(alpha = 0.15f)
                                else MaterialTheme.colorScheme.primaryContainer
                            )
                            .padding(horizontal = 10.dp, vertical = 4.dp)
                    ) {
                        Text(
                            text = "$selectedCount / $maxCount selected",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = if (isLimitReached) CensoredOrange
                                    else MaterialTheme.colorScheme.primary
                        )
                    }

                    if (isLimitReached) {
                        Text(
                            text = "Limit reached",
                            style = MaterialTheme.typography.labelSmall,
                            color = CensoredOrange
                        )
                    }

                    Spacer(modifier = Modifier.weight(1f))

                    TextButton(onClick = onClearSelection) {
                        Text("Clear")
                    }
                }

                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
            }
        }
    }
}

@Composable
private fun ActiveResolversList(activeResolvers: Map<String, String>, maxSlots: Int = 6) {
    val entries = activeResolvers.entries.toList()
    val rows = (maxSlots + 1) / 2 // 2 columns
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        for (row in 0 until rows) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                for (col in 0 until 2) {
                    val i = row * 2 + col
                    if (i < maxSlots) {
                        val entry = entries.getOrNull(i)
                        Text(
                            text = if (entry != null) "${entry.key} - ${entry.value}" else "Waiting...",
                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                            color = if (entry != null) MaterialTheme.colorScheme.onSurfaceVariant
                                else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.3f),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ScanControlButton(
    isRunning: Boolean,
    canResume: Boolean,
    onStop: () -> Unit,
    onResume: () -> Unit
) {
    if (isRunning) {
        Button(
            onClick = onStop,
            colors = ButtonDefaults.buttonColors(containerColor = ErrorRed),
            shape = RoundedCornerShape(10.dp),
            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
        ) {
            Icon(Icons.Default.Stop, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(Modifier.width(4.dp))
            Text("Stop", style = MaterialTheme.typography.labelMedium)
        }
    } else if (canResume) {
        Button(
            onClick = onResume,
            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
            shape = RoundedCornerShape(10.dp),
            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
        ) {
            Icon(Icons.Default.PlayArrow, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(Modifier.width(4.dp))
            Text("Continue", style = MaterialTheme.typography.labelMedium)
        }
    }
}

@Composable
private fun ResultsEmptyState(
    isScanning: Boolean = false,
    isSimpleMode: Boolean = false,
    isSimpleModeRunning: Boolean = false,
    workingCount: Int = 0,
    e2eTestedCount: Int = 0
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            if (isScanning || (isSimpleMode && isSimpleModeRunning)) {
                CircularProgressIndicator(
                    modifier = Modifier.size(48.dp),
                    strokeWidth = 3.dp,
                    color = MaterialTheme.colorScheme.primary
                )
                Text(
                    text = if (isSimpleMode) "Scanning for working resolvers\u2026" else "Scanning\u2026",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = if (isSimpleMode && workingCount > 0)
                        "$workingCount working so far, testing E2E ($e2eTestedCount tested)\u2026"
                    else if (isSimpleMode)
                        "Resolvers that pass the tunnel test will appear here"
                    else if (workingCount > 0)
                        "$workingCount working so far, waiting for filters to match\u2026"
                    else
                        "Working resolvers will appear here",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                    textAlign = TextAlign.Center
                )
            } else {
                Box(
                    modifier = Modifier
                        .size(64.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.surfaceVariant),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        Icons.Default.SearchOff,
                        contentDescription = null,
                        modifier = Modifier.size(32.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Text(
                    text = if (isSimpleMode)
                        "No resolvers passed the tunnel test"
                    else
                        "No working resolvers found",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = "Try running a new scan or importing a different list",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                    textAlign = TextAlign.Center
                )
            }
        }
    }
}

@Composable
private fun ResultsResolverItem(
    result: ResolverScanResult,
    isSelected: Boolean,
    isLimitReached: Boolean = false,
    showSelection: Boolean = true,
    isE2eTesting: Boolean = false,
    e2ePhase: String? = null,
    onToggleSelection: (() -> Unit)? = null,
    /** (udpOk, tcpOk) — non-null only for BOTH-mode scans. */
    transportSupport: Pair<Boolean, Boolean>? = null
) {
    val isDisabled = isLimitReached && !isSelected
    val canInteract = showSelection && result.status == ResolverStatus.WORKING && onToggleSelection != null && !isDisabled

    val backgroundColor by animateColorAsState(
        targetValue = when {
            isE2eTesting -> MaterialTheme.colorScheme.tertiaryContainer
            isSelected && showSelection -> MaterialTheme.colorScheme.primaryContainer
            else -> MaterialTheme.colorScheme.surfaceContainerLow
        },
        label = "backgroundColor"
    )

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .then(
                if (canInteract && onToggleSelection != null) {
                    Modifier.clickable(onClick = onToggleSelection)
                } else {
                    Modifier
                }
            ),
        colors = CardDefaults.cardColors(containerColor = backgroundColor),
        shape = RoundedCornerShape(12.dp),
        elevation = CardDefaults.cardElevation(
            defaultElevation = if (isSelected && showSelection) 1.dp else 0.dp
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Status icon stays out of WORKING rows: the score/latency already tell the story,
            // and dropping the green check cleans up the common case.
            if (result.status != ResolverStatus.WORKING) {
                ResultsStatusIcon(status = result.status)
            }

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = result.host,
                    style = MaterialTheme.typography.bodyMedium.copy(
                        fontFamily = FontFamily.Monospace,
                        letterSpacing = 0.5.sp
                    ),
                    fontWeight = FontWeight.Medium
                )
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    if (result.status != ResolverStatus.WORKING) {
                        ResultsStatusLabel(status = result.status)
                    }

                    transportSupport?.let { (udpOk, tcpOk) ->
                        if (udpOk) TransportBadge("UDP")
                        if (tcpOk) TransportBadge("TCP")
                    }

                    result.responseTimeMs?.let { ms ->
                        Text(
                            text = "${ms}ms",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }

                    if (result.prismPassedProbes != null && result.prismTotalProbes != null) {
                        Text(
                            text = "${result.prismPassedProbes}/${result.prismTotalProbes}",
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = when {
                                result.prismPassedProbes == result.prismTotalProbes -> WorkingGreen
                                result.prismPassedProbes >= result.prismTotalProbes - 1 -> CensoredOrange
                                else -> MaterialTheme.colorScheme.onSurfaceVariant
                            }
                        )
                    }

                    result.tunnelTestResult?.let { tunnelResult ->
                        Text(
                            text = "${tunnelResult.score}/${tunnelResult.maxScore}",
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = when {
                                tunnelResult.score >= (tunnelResult.maxScore * 0.8f) -> WorkingGreen
                                tunnelResult.score >= (tunnelResult.maxScore * 0.6f) -> CensoredOrange
                                else -> ErrorRed
                            }
                        )
                    }
                }

                result.tunnelTestResult?.let { tunnelResult ->
                    Text(
                        text = tunnelResult.details,
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace
                        ),
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                result.errorMessage?.takeIf { result.tunnelTestResult == null }?.let { error ->
                    Text(
                        text = error,
                        style = MaterialTheme.typography.labelSmall,
                        color = ErrorRed,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                // E2E tunnel test: currently testing indicator
                if (isE2eTesting) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(12.dp),
                            strokeWidth = 1.5.dp,
                            color = MaterialTheme.colorScheme.tertiary
                        )
                        Text(
                            text = "E2E: ${e2ePhase ?: "testing..."}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.tertiary
                        )
                    }
                }

                // E2E tunnel test result
                result.e2eTestResult?.let { e2e ->
                    E2eResultChip(e2e)
                }


            }

            if (showSelection && result.status == ResolverStatus.WORKING && onToggleSelection != null) {
                Checkbox(
                    checked = isSelected,
                    onCheckedChange = { if (!isDisabled) onToggleSelection() },
                    enabled = !isDisabled
                )
            }
        }
    }
}

@Composable
private fun TransportBadge(label: String) {
    Text(
        text = label,
        style = MaterialTheme.typography.labelSmall,
        fontWeight = FontWeight.SemiBold,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier
            .background(
                color = MaterialTheme.colorScheme.primaryContainer,
                shape = RoundedCornerShape(4.dp)
            )
            .padding(horizontal = 6.dp, vertical = 1.dp)
    )
}

@Composable
private fun E2eResultChip(e2e: E2eTestResult) {
    val bgColor = if (e2e.success) WorkingGreen.copy(alpha = 0.12f) else ErrorRed.copy(alpha = 0.12f)
    val textColor = if (e2e.success) WorkingGreen else ErrorRed

    Surface(
        shape = RoundedCornerShape(6.dp),
        color = bgColor
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
            horizontalArrangement = Arrangement.spacedBy(4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (e2e.success) {
                Text(
                    text = "E2E ${e2e.totalMs}ms",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = textColor
                )
            } else {
                Text(
                    text = "E2E",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = textColor
                )
                Text(
                    text = e2e.errorMessage ?: "Failed",
                    style = MaterialTheme.typography.labelSmall,
                    color = textColor,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}


@Composable
private fun ResultsStatusIcon(status: ResolverStatus) {
    val (icon, color, bgColor) = when (status) {
        ResolverStatus.PENDING -> Triple(
            Icons.Outlined.Schedule,
            MaterialTheme.colorScheme.outline,
            MaterialTheme.colorScheme.surfaceVariant
        )
        ResolverStatus.SCANNING -> Triple(
            Icons.Default.Search,
            MaterialTheme.colorScheme.primary,
            MaterialTheme.colorScheme.primaryContainer
        )
        ResolverStatus.WORKING -> Triple(
            Icons.Default.CheckCircle,
            WorkingGreen,
            WorkingGreen.copy(alpha = 0.1f)
        )
        ResolverStatus.CENSORED -> Triple(
            Icons.Default.Warning,
            CensoredOrange,
            CensoredOrange.copy(alpha = 0.1f)
        )
        ResolverStatus.TIMEOUT -> Triple(
            Icons.Outlined.CloudOff,
            TimeoutGray,
            TimeoutGray.copy(alpha = 0.1f)
        )
        ResolverStatus.ERROR -> Triple(
            Icons.Outlined.Error,
            ErrorRed,
            ErrorRed.copy(alpha = 0.1f)
        )
    }

    Box(
        modifier = Modifier
            .size(36.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(bgColor),
        contentAlignment = Alignment.Center
    ) {
        if (status == ResolverStatus.SCANNING) {
            CircularProgressIndicator(
                modifier = Modifier.size(18.dp),
                strokeWidth = 2.dp,
                color = color
            )
        } else {
            Icon(
                icon,
                contentDescription = null,
                tint = color,
                modifier = Modifier.size(20.dp)
            )
        }
    }
}

@Composable
private fun ResultsStatusLabel(status: ResolverStatus) {
    val (text, color) = when (status) {
        ResolverStatus.PENDING -> "Pending" to MaterialTheme.colorScheme.outline
        ResolverStatus.SCANNING -> "Scanning..." to MaterialTheme.colorScheme.primary
        ResolverStatus.WORKING -> "Working" to WorkingGreen
        ResolverStatus.CENSORED -> "Censored" to CensoredOrange
        ResolverStatus.TIMEOUT -> "Timeout" to TimeoutGray
        ResolverStatus.ERROR -> "Error" to ErrorRed
    }

    Text(
        text = text,
        style = MaterialTheme.typography.labelMedium,
        fontWeight = FontWeight.Medium,
        color = color
    )
}
