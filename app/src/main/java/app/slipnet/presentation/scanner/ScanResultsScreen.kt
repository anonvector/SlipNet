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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
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
import androidx.compose.material.icons.filled.Close
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
import androidx.compose.material3.SwipeToDismissBox
import androidx.compose.material3.SwipeToDismissBoxValue
import androidx.compose.material3.rememberSwipeToDismissBoxState
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
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
    onResolversSelected: (String) -> Unit,
    viewModel: DnsScannerViewModel = hiltViewModel(parentBackStackEntry)
) {
    val uiState by viewModel.uiState.collectAsState()
    val canApply = fromProfile
    val snackbarHostState = remember { SnackbarHostState() }
    val navBarPadding = WindowInsets.navigationBars.asPaddingValues()
    var proxyWarningDismissed by remember { mutableStateOf(false) }
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences("scanner_ui", Context.MODE_PRIVATE) }
    var sortOption by remember {
        mutableStateOf(
            SortOption.entries.find { it.name == prefs.getString("sort_option", null) } ?: SortOption.NONE
        )
    }
    var scoreFilter by remember {
        mutableStateOf(
            ScoreFilter.entries.find { it.name == prefs.getString("score_filter", null) } ?: ScoreFilter.SCORE_2_PLUS
        )
    }
    var showSortFilter by remember { mutableStateOf(prefs.getBoolean("show_sort_filter", true)) }
    var searchQuery by remember { mutableStateOf("") }
    var showSearch by remember { mutableStateOf(false) }
    // null = no dialog, "copy" or "export" = pending action
    var pendingAction by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(uiState.error) {
        uiState.error?.let { error ->
            snackbarHostState.showSnackbar(error)
            viewModel.clearError()
        }
    }

    // Cached list of working IPs — used by dialog, TopAppBar copy/export
    val workingIps = remember(uiState.scannerState.results, uiState.scanMode) {
        if (uiState.scanMode == ScanMode.SIMPLE) {
            uiState.scannerState.results
                .filter { it.e2eTestResult?.success == true }
                .map { it.host }
        } else {
            uiState.scannerState.results
                .filter { it.status == ResolverStatus.WORKING }
                .map { it.host }
        }
    }

    // Dialog for choosing all working IPs vs selected only
    if (pendingAction != null) {
        val selectedIps = uiState.selectedResolvers.toList()
        val action = pendingAction
        AlertDialog(
            onDismissRequest = { pendingAction = null },
            title = { Text(if (action == "copy") "Copy IPs" else "Export IPs") },
            text = { Text("Which IPs do you want to ${if (action == "copy") "copy" else "export"}?") },
            confirmButton = {
                TextButton(onClick = {
                    pendingAction = null
                    if (action == "copy") {
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        clipboard.setPrimaryClip(ClipData.newPlainText("DNS Resolvers", workingIps.joinToString(", ")))
                        scope.launch {
                            snackbarHostState.currentSnackbarData?.dismiss()
                            launch { snackbarHostState.showSnackbar("Copied ${workingIps.size} IPs") }
                            delay(1500)
                            snackbarHostState.currentSnackbarData?.dismiss()
                        }
                    } else {
                        performExport(context, workingIps, scope, snackbarHostState)
                    }
                }) {
                    Text("All working (${workingIps.size})")
                }
            },
            dismissButton = {
                TextButton(onClick = {
                    pendingAction = null
                    if (action == "copy") {
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        clipboard.setPrimaryClip(ClipData.newPlainText("DNS Resolvers", selectedIps.joinToString(", ")))
                        scope.launch {
                            snackbarHostState.currentSnackbarData?.dismiss()
                            launch { snackbarHostState.showSnackbar("Copied ${selectedIps.size} IPs") }
                            delay(1500)
                            snackbarHostState.currentSnackbarData?.dismiss()
                        }
                    } else {
                        performExport(context, selectedIps, scope, snackbarHostState)
                    }
                }) {
                    Text("Selected only (${selectedIps.size})")
                }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            "Scan Results",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.SemiBold
                        )
                        val isSimple = uiState.scanMode == ScanMode.SIMPLE
                        if (isSimple) {
                            val e2e = uiState.simpleModeE2eState
                            val scanState = uiState.scannerState
                            val subtitle = if (scanState.isScanning || e2e.isRunning) {
                                "DNS: ${scanState.scannedCount}/${scanState.totalCount}${if (scanState.focusRangeCount > 0) " + ${scanState.focusRangeCount} neighbors" else ""} — E2E: ${e2e.testedCount}/${e2e.queuedCount} (${e2e.passedCount} passed)"
                            } else if (e2e.testedCount > 0) {
                                "${e2e.passedCount} passed of ${e2e.testedCount} tested"
                            } else null
                            subtitle?.let {
                                Text(
                                    text = it,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.primary
                                )
                            }
                        } else if (uiState.scannerState.isScanning) {
                            Text(
                                text = "Scanning ${uiState.scannerState.scannedCount} of ${uiState.scannerState.totalCount}${if (uiState.scannerState.focusRangeCount > 0) " + ${uiState.scannerState.focusRangeCount} neighbors" else ""}...",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }
                    }
                },
                navigationIcon = {
                    IconButton(
                        onClick = {
                            viewModel.stopScan()
                            onNavigateBack()
                        }
                    ) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    val isIdle = !uiState.scannerState.isScanning &&
                        (uiState.scanMode != ScanMode.SIMPLE || !uiState.simpleModeE2eState.isRunning)
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
                    if (workingIps.isNotEmpty() && isIdle) {
                        IconButton(
                            onClick = {
                                if (uiState.selectedResolvers.isNotEmpty()) {
                                    pendingAction = "copy"
                                } else {
                                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    clipboard.setPrimaryClip(ClipData.newPlainText("DNS Resolvers", workingIps.joinToString(", ")))
                                    scope.launch {
                                        snackbarHostState.currentSnackbarData?.dismiss()
                                        launch { snackbarHostState.showSnackbar("Copied ${workingIps.size} IPs") }
                                        delay(1500)
                                        snackbarHostState.currentSnackbarData?.dismiss()
                                    }
                                }
                            }
                        ) {
                            Icon(Icons.Default.ContentCopy, contentDescription = "Copy all working IPs")
                        }
                        IconButton(
                            onClick = {
                                if (uiState.selectedResolvers.isNotEmpty()) {
                                    pendingAction = "export"
                                } else {
                                    performExport(context, workingIps, scope, snackbarHostState)
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
                                onResolversSelected(viewModel.getSelectedResolversString())
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
            // Progress
            if (uiState.scanMode == ScanMode.SIMPLE) {
                val showProgress = uiState.scannerState.isScanning ||
                    uiState.simpleModeE2eState.isRunning ||
                    uiState.scannerState.scannedCount > 0
                if (showProgress) {
                    SimpleModeProgressSection(
                        scannerState = uiState.scannerState,
                        simpleModeE2eState = uiState.simpleModeE2eState,
                        onStopScan = { viewModel.stopScan() }
                    )
                }
            } else {
                if (uiState.scannerState.isScanning || uiState.scannerState.scannedCount > 0) {
                    ResultsProgressSection(
                        isScanning = uiState.scannerState.isScanning,
                        progress = uiState.scannerState.progress,
                        totalCount = uiState.scannerState.totalCount,
                        scannedCount = uiState.scannerState.scannedCount,
                        workingCount = uiState.scannerState.workingCount,
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
                    E2eProgressSection(e2eScannerState = uiState.e2eScannerState)
                }
            }

            // VPN active warning for E2E
            AnimatedVisibility(
                visible = uiState.isVpnActive && uiState.profileId != null &&
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
            val displayResults = remember(uiState.scannerState.results, scoreFilter, sortOption, isSimpleMode, searchQuery) {
                val query = searchQuery.trim()
                val filtered = if (isSimpleMode) {
                    uiState.scannerState.results.filter {
                        it.e2eTestResult?.success == true &&
                            (it.tunnelTestResult?.score ?: 0) >= scoreFilter.minScore &&
                            (query.isEmpty() || it.host.contains(query))
                    }
                } else {
                    uiState.scannerState.results.filter {
                        it.status == ResolverStatus.WORKING &&
                            (it.tunnelTestResult?.score ?: 0) >= scoreFilter.minScore &&
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
                    SortOption.E2E_SPEED -> filtered.sortedBy {
                        it.e2eTestResult?.totalMs ?: Long.MAX_VALUE
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
                        isSimpleModeRunning = uiState.simpleModeE2eState.isRunning
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
                    items(displayResults.size, key = { index -> displayResults[index].host }) { index ->
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
                                isE2eTesting = uiState.e2eScannerState.isRunning && uiState.e2eScannerState.currentResolver == result.host,
                                e2ePhase = if (uiState.e2eScannerState.currentResolver == result.host) uiState.e2eScannerState.currentPhase else null,
                                onToggleSelection = if (canApply) {
                                    { viewModel.toggleResolverSelection(result.host) }
                                } else null
                            )
                        }
                    }
                }
            }

            // Sort & filter bar — always visible once scan has started
            if (uiState.scannerState.scannedCount > 0) {
                Column(modifier = Modifier.padding(bottom = navBarPadding.calculateBottomPadding())) {
                    // Toggle handle
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceContainerLow,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                showSortFilter = !showSortFilter
                                prefs.edit().putBoolean("show_sort_filter", showSortFilter).apply()
                            }
                    ) {
                        Icon(
                            imageVector = if (showSortFilter) Icons.Default.KeyboardArrowDown
                                          else Icons.Default.KeyboardArrowUp,
                            contentDescription = if (showSortFilter) "Hide sort & filter" else "Show sort & filter",
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp)
                                .size(20.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }

                    AnimatedVisibility(visible = showSortFilter) {
                        SortControlBar(
                            sortOption = sortOption,
                            onSortOptionChange = {
                                sortOption = it
                                prefs.edit().putString("sort_option", it.name).apply()
                            },
                            scoreFilter = scoreFilter,
                            onScoreFilterChange = {
                                scoreFilter = it
                                prefs.edit().putString("score_filter", it.name).apply()
                                viewModel.updateE2eMinScore(it.minScore)
                            },
                            hideScoreFilter = false
                        )
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
    SCORE_5_PLUS("5+", 5)
}

private enum class SortOption {
    NONE, SPEED, IP, SCORE, E2E_SPEED
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SortControlBar(
    sortOption: SortOption,
    onSortOptionChange: (SortOption) -> Unit,
    scoreFilter: ScoreFilter,
    onScoreFilterChange: (ScoreFilter) -> Unit,
    hideScoreFilter: Boolean = false,
    modifier: Modifier = Modifier
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        modifier = modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            // Sort row
            Row(
                modifier = Modifier
                    .horizontalScroll(rememberScrollState())
                    .padding(start = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Sort:",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                FilterChip(
                    selected = sortOption == SortOption.SPEED,
                    onClick = {
                        onSortOptionChange(if (sortOption == SortOption.SPEED) SortOption.NONE else SortOption.SPEED)
                    },
                    label = { Text("Speed") },
                    leadingIcon = {
                        Icon(
                            Icons.Default.Speed,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                    },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                        selectedLabelColor = MaterialTheme.colorScheme.primary,
                        selectedLeadingIconColor = MaterialTheme.colorScheme.primary
                    )
                )

                FilterChip(
                    selected = sortOption == SortOption.IP,
                    onClick = {
                        onSortOptionChange(if (sortOption == SortOption.IP) SortOption.NONE else SortOption.IP)
                    },
                    label = { Text("IP") },
                    leadingIcon = {
                        Icon(
                            Icons.Default.Dns,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                    },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                        selectedLabelColor = MaterialTheme.colorScheme.primary,
                        selectedLeadingIconColor = MaterialTheme.colorScheme.primary
                    )
                )

                FilterChip(
                    selected = sortOption == SortOption.SCORE,
                    onClick = {
                        onSortOptionChange(if (sortOption == SortOption.SCORE) SortOption.NONE else SortOption.SCORE)
                    },
                    label = { Text("Score") },
                    leadingIcon = {
                        Icon(
                            Icons.Default.Star,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                    },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                        selectedLabelColor = MaterialTheme.colorScheme.primary,
                        selectedLeadingIconColor = MaterialTheme.colorScheme.primary
                    )
                )

                FilterChip(
                    selected = sortOption == SortOption.E2E_SPEED,
                    onClick = {
                        onSortOptionChange(if (sortOption == SortOption.E2E_SPEED) SortOption.NONE else SortOption.E2E_SPEED)
                    },
                    label = { Text("E2E") },
                    leadingIcon = {
                        Icon(
                            Icons.Default.Speed,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                    },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = MaterialTheme.colorScheme.tertiaryContainer,
                        selectedLabelColor = MaterialTheme.colorScheme.tertiary,
                        selectedLeadingIconColor = MaterialTheme.colorScheme.tertiary
                    )
                )
            }

            // Filter row (hidden in simple mode)
            if (!hideScoreFilter) {
                Row(
                    modifier = Modifier
                        .horizontalScroll(rememberScrollState())
                        .padding(start = 16.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Filter:",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    ScoreFilter.entries.forEach { filter ->
                        FilterChip(
                            selected = scoreFilter == filter,
                            onClick = { onScoreFilterChange(filter) },
                            label = { Text(filter.label) },
                            colors = FilterChipDefaults.filterChipColors(
                                selectedContainerColor = MaterialTheme.colorScheme.secondaryContainer,
                                selectedLabelColor = MaterialTheme.colorScheme.secondary
                            )
                        )
                    }
                }
            }
        }
    }
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

                if (isScanning) {
                    Button(
                        onClick = onStopScan,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = ErrorRed
                        ),
                        shape = RoundedCornerShape(10.dp),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
                    ) {
                        Icon(
                            Icons.Default.Stop,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(Modifier.width(4.dp))
                        Text("Stop", style = MaterialTheme.typography.labelMedium)
                    }
                } else if (canResume) {
                    Button(
                        onClick = onResumeScan,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.primary
                        ),
                        shape = RoundedCornerShape(10.dp),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
                    ) {
                        Icon(
                            Icons.Default.PlayArrow,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(Modifier.width(4.dp))
                        Text("Continue", style = MaterialTheme.typography.labelMedium)
                    }
                }
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
private fun E2eProgressSection(e2eScannerState: E2eScannerState) {
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

            if (e2eScannerState.isRunning && e2eScannerState.currentResolver != null) {
                Text(
                    text = "${e2eScannerState.currentResolver} - ${e2eScannerState.currentPhase}",
                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
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
    onStopScan: () -> Unit
) {
    val dnsProgress = scannerState.progress
    val e2eProgress = if (simpleModeE2eState.queuedCount > 0) {
        simpleModeE2eState.testedCount.toFloat() / simpleModeE2eState.queuedCount
    } else 0f
    val animatedDnsProgress by animateFloatAsState(targetValue = dnsProgress, label = "dnsProgress")
    val animatedE2eProgress by animateFloatAsState(targetValue = e2eProgress, label = "e2eProgress")
    val isRunning = scannerState.isScanning || simpleModeE2eState.isRunning

    Surface(
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
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
                if (isRunning) {
                    Button(
                        onClick = onStopScan,
                        colors = ButtonDefaults.buttonColors(containerColor = ErrorRed),
                        shape = RoundedCornerShape(10.dp),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
                    ) {
                        Icon(Icons.Default.Stop, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Stop", style = MaterialTheme.typography.labelMedium)
                    }
                }
            }

            LinearProgressIndicator(
                progress = { animatedDnsProgress },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(4.dp)
                    .clip(RoundedCornerShape(2.dp)),
                strokeCap = StrokeCap.Round
            )

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
            }

            if (simpleModeE2eState.isRunning && simpleModeE2eState.currentResolver != null) {
                Text(
                    text = "${simpleModeE2eState.currentResolver} - ${simpleModeE2eState.currentPhase}",
                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
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
private fun ResultsEmptyState(
    isScanning: Boolean = false,
    isSimpleMode: Boolean = false,
    isSimpleModeRunning: Boolean = false
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
                    text = if (isSimpleMode)
                        "Resolvers that pass the tunnel test will appear here"
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
    onToggleSelection: (() -> Unit)? = null
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
                .padding(horizontal = 14.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            ResultsStatusIcon(status = result.status)

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
                    ResultsStatusLabel(status = result.status)

                    result.responseTimeMs?.let { ms ->
                        Text(
                            text = "${ms}ms",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }

                    result.tunnelTestResult?.let { tunnelResult ->
                        Text(
                            text = "${tunnelResult.score}/${tunnelResult.maxScore}",
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = when {
                                tunnelResult.score == tunnelResult.maxScore -> WorkingGreen
                                tunnelResult.score >= tunnelResult.maxScore - 1 -> CensoredOrange
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
