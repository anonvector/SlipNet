package app.slipnet.presentation.scanner

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.SizeTransform
import androidx.compose.animation.togetherWith
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.ShareLocation
import androidx.compose.material.icons.filled.Shuffle
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.hilt.navigation.compose.hiltViewModel
import app.slipnet.tunnel.GeoBypassCountry

private val WorkingGreen = Color(0xFF4CAF50)

private enum class ResolverPanel { NONE, COUNTRY, CUSTOM }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DnsScannerScreen(
    profileId: Long? = null,
    onNavigateBack: () -> Unit,
    onNavigateToResults: () -> Unit,
    onResolversSelected: (String) -> Unit,
    viewModel: DnsScannerViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            try {
                val fileName = try {
                    context.contentResolver.query(it, null, null, null, null)?.use { cursor ->
                        val nameIndex = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                        if (cursor.moveToFirst() && nameIndex >= 0) cursor.getString(nameIndex) else null
                    }
                } catch (_: Exception) { null }
                context.contentResolver.openInputStream(it)?.use { inputStream ->
                    val content = inputStream.bufferedReader().readText()
                    viewModel.importList(content, fileName)
                }
            } catch (e: Exception) {
                // Error handled in ViewModel
            }
        }
    }

    LaunchedEffect(uiState.error) {
        uiState.error?.let { error ->
            snackbarHostState.showSnackbar(error)
            viewModel.clearError()
        }
    }

    LaunchedEffect(uiState.scannerState.isScanning) {
        if (uiState.scannerState.isScanning) {
            onNavigateToResults()
        }
    }

    // Resume dialog
    if (uiState.showResumeDialog) {
        val ss = uiState.scannerState
        val isSimple = uiState.scanMode == ScanMode.SIMPLE
        val dialogText = if (isSimple) {
            val e2e = uiState.simpleModeE2eState
            buildString {
                append("You scanned ${ss.scannedCount} of ${ss.totalCount}${if (ss.focusRangeCount > 0) " + ${ss.focusRangeCount} neighbors" else ""} resolvers")
                append(" and found ${ss.workingCount} working.")
                if (e2e.testedCount > 0) {
                    append(" E2E tested ${e2e.testedCount}, ${e2e.passedCount} passed.")
                }
                append(" Continue from where you left off?")
            }
        } else {
            "You scanned ${ss.scannedCount} of ${ss.totalCount}${if (ss.focusRangeCount > 0) " + ${ss.focusRangeCount} neighbors" else ""} resolvers" +
                    " and found ${ss.workingCount} working." +
                    " Continue from where you left off?"
        }
        AlertDialog(
            onDismissRequest = { viewModel.dismissResumeDialog() },
            title = { Text("Continue Previous Scan?") },
            text = { Text(dialogText) },
            confirmButton = {
                Button(onClick = { viewModel.resumeScan() }) {
                    Text("Continue")
                }
            },
            dismissButton = {
                TextButton(onClick = { viewModel.startFreshScan() }) {
                    Text("Start Fresh")
                }
            }
        )
    }

    val navBarPadding = WindowInsets.navigationBars.asPaddingValues()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("DNS Scanner") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        contentWindowInsets = WindowInsets(0, 0, 0, 0)
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(
                    start = 16.dp,
                    end = 16.dp,
                    top = 8.dp,
                    bottom = 16.dp + navBarPadding.calculateBottomPadding()
                ),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Hero
            HeroCard()

            // Scan Mode Toggle (only when profile supports E2E)
            if (uiState.canUseSimpleMode) {
                ScanModeToggle(
                    scanMode = uiState.scanMode,
                    enabled = !uiState.scannerState.isScanning && !uiState.simpleModeE2eState.isRunning,
                    onModeChange = { viewModel.setScanMode(it) }
                )
            }

            // Start Scan + View Results
            ActionSection(
                canStartScan = uiState.resolverList.isNotEmpty() && !uiState.scannerState.isScanning,
                hasResults = uiState.scannerState.results.isNotEmpty(),
                workingCount = if (uiState.scanMode == ScanMode.SIMPLE) {
                    uiState.scannerState.results.count { it.e2eTestResult?.success == true }
                } else {
                    uiState.scannerState.workingCount
                },
                scanMode = uiState.scanMode,
                onStartScan = { viewModel.startScan() },
                onViewResults = onNavigateToResults
            )

            // Configuration
            val isProfileLocked = uiState.profile?.isLocked == true
            ConfigurationSection(
                testDomain = uiState.testDomain,
                isProfileLocked = isProfileLocked,
                timeoutMs = uiState.timeoutMs,
                concurrency = uiState.concurrency,
                shuffleList = uiState.shuffleList,
                expandNeighbors = uiState.expandNeighbors,
                testUrl = uiState.testUrl,
                e2eTimeoutMs = uiState.e2eTimeoutMs,
                e2eConcurrency = uiState.e2eConcurrency,
                showTestUrl = uiState.profileId != null,
                onTestDomainChange = { viewModel.updateTestDomain(it) },
                onTimeoutChange = { viewModel.updateTimeout(it) },
                onConcurrencyChange = { viewModel.updateConcurrency(it) },
                onShuffleListChange = { viewModel.updateShuffleList(it) },
                onExpandNeighborsChange = { viewModel.updateExpandNeighbors(it) },
                onTestUrlChange = { viewModel.updateTestUrl(it) },
                onE2eTimeoutChange = { viewModel.updateE2eTimeout(it) },
                onE2eConcurrencyChange = { viewModel.updateE2eConcurrency(it) }
            )

            // Resolver List
            ResolverListSection(
                resolverCount = uiState.resolverList.size,
                listSource = uiState.listSource,
                importedFileName = uiState.importedFileName,
                isLoading = uiState.isLoadingList,
                selectedCountry = uiState.selectedCountry,
                sampleCount = uiState.sampleCount,
                effectiveSampleCount = uiState.effectiveSampleCount,
                useCustomSampleCount = uiState.useCustomSampleCount,
                customSampleCountText = uiState.customSampleCountText,
                cidrGroups = uiState.cidrGroups,
                selectedOctets = uiState.selectedOctets,
                countryTotalIps = uiState.countryTotalIps,
                selectedTotalIps = uiState.selectedTotalIps,
                customRangeInput = uiState.customRangeInput,
                customRangePreviewCount = uiState.customRangePreviewCount,
                canStartScan = uiState.resolverList.isNotEmpty() && !uiState.scannerState.isScanning,
                onStartScan = { viewModel.startScan() },
                onLoadDefault = { viewModel.loadDefaultList() },
                onImportFile = { filePickerLauncher.launch("text/*") },
                onSelectCountry = { viewModel.updateSelectedCountry(it) },
                onSelectSampleCount = { viewModel.updateSampleCount(it) },
                onUseCustomSampleCount = { viewModel.setUseCustomSampleCount(it) },
                onCustomSampleCountChange = { viewModel.updateCustomSampleCount(it) },
                onGenerateCountryList = { viewModel.loadCountryRangeList() },
                onToggleOctet = { viewModel.toggleOctetGroup(it) },
                onSelectAllOctets = { viewModel.selectAllOctetGroups() },
                onDeselectAllOctets = { viewModel.deselectAllOctetGroups() },
                onCustomRangeInputChange = { viewModel.updateCustomRangeInput(it) },
                onLoadCustomRange = { viewModel.loadCustomRangeList() }
            )

            // Recent DNS
            if (uiState.recentDnsResolvers.isNotEmpty()) {
                val canSelect = uiState.profileId != null
                RecentDnsSection(
                    recentResolvers = uiState.recentDnsResolvers,
                    selectedResolvers = uiState.selectedResolvers,
                    isLimitReached = uiState.isSelectionLimitReached,
                    maxCount = DnsScannerUiState.MAX_SELECTED_RESOLVERS,
                    canSelect = canSelect,
                    onToggleSelection = { viewModel.toggleResolverSelection(it) },
                    onApply = {
                        viewModel.saveRecentDns()
                        onResolversSelected(viewModel.getSelectedResolversString())
                    }
                )
            }
        }
    }
}

@Composable
private fun HeroCard() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer
        ),
        shape = RoundedCornerShape(16.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.spacedBy(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.primary),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    Icons.Default.NetworkCheck,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onPrimary,
                    modifier = Modifier.size(20.dp)
                )
            }

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Find Working Resolvers",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onPrimaryContainer
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = "Scan DNS servers to find ones that work without censorship.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.8f)
                )
            }
        }
    }
}

@Composable
private fun ActionSection(
    canStartScan: Boolean,
    hasResults: Boolean,
    workingCount: Int,
    scanMode: ScanMode = ScanMode.ADVANCED,
    onStartScan: () -> Unit,
    onViewResults: () -> Unit
) {
    val buttonLabel = if (scanMode == ScanMode.SIMPLE) "Start Simple Scan" else "Start Scan"
    val resultsLabel = if (scanMode == ScanMode.SIMPLE) {
        "View Results ($workingCount passed)"
    } else {
        "View Results ($workingCount working)"
    }

    Column(
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Button(
            onClick = onStartScan,
            enabled = canStartScan,
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.primary
            )
        ) {
            Icon(
                Icons.Default.PlayArrow,
                contentDescription = null,
                modifier = Modifier.size(20.dp)
            )
            Spacer(Modifier.width(10.dp))
            Text(
                buttonLabel,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold
            )
        }

        AnimatedVisibility(
            visible = hasResults,
            enter = fadeIn() + slideInVertically(),
            exit = fadeOut() + slideOutVertically()
        ) {
            FilledTonalButton(
                onClick = onViewResults,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)
            ) {
                Icon(
                    Icons.Default.CheckCircle,
                    contentDescription = null,
                    tint = WorkingGreen,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(Modifier.width(8.dp))
                Text(resultsLabel)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ScanModeToggle(
    scanMode: ScanMode,
    enabled: Boolean,
    onModeChange: (ScanMode) -> Unit
) {
    Column(
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            FilterChip(
                selected = scanMode == ScanMode.SIMPLE,
                onClick = { onModeChange(ScanMode.SIMPLE) },
                enabled = enabled,
                label = { Text("Simple") },
                leadingIcon = if (scanMode == ScanMode.SIMPLE) {
                    { Icon(Icons.Default.Check, contentDescription = null, modifier = Modifier.size(16.dp)) }
                } else null,
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                    selectedLabelColor = MaterialTheme.colorScheme.primary,
                    selectedLeadingIconColor = MaterialTheme.colorScheme.primary
                )
            )
            FilterChip(
                selected = scanMode == ScanMode.ADVANCED,
                onClick = { onModeChange(ScanMode.ADVANCED) },
                enabled = enabled,
                label = { Text("Advanced") },
                leadingIcon = if (scanMode == ScanMode.ADVANCED) {
                    { Icon(Icons.Default.Check, contentDescription = null, modifier = Modifier.size(16.dp)) }
                } else null,
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                    selectedLabelColor = MaterialTheme.colorScheme.primary,
                    selectedLeadingIconColor = MaterialTheme.colorScheme.primary
                )
            )
        }

        Text(
            text = if (scanMode == ScanMode.SIMPLE)
                "Scans DNS resolvers and automatically tests each one through the tunnel. Only resolvers that pass the tunnel test are shown."
            else
                "Scan DNS resolvers first, then optionally run tunnel test separately.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
        )
    }
}

@Composable
private fun ConfigurationSection(
    testDomain: String,
    isProfileLocked: Boolean = false,
    timeoutMs: String,
    concurrency: String,
    shuffleList: Boolean = false,
    expandNeighbors: Boolean = true,
    testUrl: String = "",
    e2eTimeoutMs: String = "9000",
    e2eConcurrency: String = "3",
    showTestUrl: Boolean = false,
    onTestDomainChange: (String) -> Unit,
    onTimeoutChange: (String) -> Unit,
    onConcurrencyChange: (String) -> Unit,
    onShuffleListChange: (Boolean) -> Unit = {},
    onExpandNeighborsChange: (Boolean) -> Unit = {},
    onTestUrlChange: (String) -> Unit = {},
    onE2eTimeoutChange: (String) -> Unit = {},
    onE2eConcurrencyChange: (String) -> Unit = {}
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerLow
        ),
        shape = RoundedCornerShape(16.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            SectionHeader(
                icon = Icons.Default.Settings,
                title = "Configuration"
            )

            OutlinedTextField(
                value = testDomain,
                onValueChange = onTestDomainChange,
                label = { Text("Test Domain") },
                placeholder = {
                    Text(if (isProfileLocked) "Profile domain (default)" else "google.com")
                },
                leadingIcon = {
                    Icon(
                        Icons.Default.Search,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                },
                supportingText = {
                    Text(
                        if (isProfileLocked && testDomain.isBlank()) "Using profile domain — enter a domain to override"
                        else "Domain used to test if resolvers work"
                    )
                },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedTextField(
                    value = timeoutMs,
                    onValueChange = onTimeoutChange,
                    label = { Text("Timeout") },
                    leadingIcon = {
                        Icon(
                            Icons.Default.Schedule,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp)
                        )
                    },
                    suffix = { Text("ms") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(12.dp)
                )

                OutlinedTextField(
                    value = concurrency,
                    onValueChange = onConcurrencyChange,
                    label = { Text("Workers") },
                    leadingIcon = {
                        Icon(
                            Icons.Default.Speed,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp)
                        )
                    },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(12.dp)
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Default.Shuffle,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "Shuffle IP list",
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
                Switch(
                    checked = shuffleList,
                    onCheckedChange = onShuffleListChange
                )
            }

            // Expand neighbors toggle
            Column {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.ShareLocation,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = "Test nearby IPs (/24 subnet)",
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                    Switch(
                        checked = expandNeighbors,
                        onCheckedChange = onExpandNeighborsChange
                    )
                }
                Text(
                    text = "When a working IP is found, also tests all 256 IPs in its /24 subnet. Only applies to country and custom range scans.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            if (showTestUrl) {
                OutlinedTextField(
                    value = testUrl,
                    onValueChange = onTestUrlChange,
                    label = { Text("Test URL (E2E)") },
                    placeholder = { Text("http://www.gstatic.com/generate_204") },
                    leadingIcon = {
                        Icon(
                            Icons.Default.NetworkCheck,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp)
                        )
                    },
                    supportingText = { Text("URL for tunnel connectivity test") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )
                OutlinedTextField(
                    value = e2eTimeoutMs,
                    onValueChange = { onE2eTimeoutChange(it.filter { c -> c.isDigit() }) },
                    label = { Text("E2E Timeout (ms)") },
                    placeholder = { Text("9000") },
                    leadingIcon = {
                        Icon(
                            Icons.Default.Schedule,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp)
                        )
                    },
                    supportingText = { Text("Timeout per resolver for tunnel test") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )
                OutlinedTextField(
                    value = e2eConcurrency,
                    onValueChange = { onE2eConcurrencyChange(it.filter { c -> c.isDigit() }.take(2)) },
                    label = { Text("E2E Concurrency") },
                    placeholder = { Text("3") },
                    leadingIcon = {
                        Icon(
                            Icons.Default.Speed,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp)
                        )
                    },
                    supportingText = { Text("Parallel tunnel tests (1-3, Slipstream max 1)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ResolverListSection(
    resolverCount: Int,
    listSource: ListSource,
    importedFileName: String?,
    isLoading: Boolean,
    selectedCountry: GeoBypassCountry,
    sampleCount: Int,
    effectiveSampleCount: Int,
    useCustomSampleCount: Boolean,
    customSampleCountText: String,
    cidrGroups: List<CidrGroup>,
    selectedOctets: Set<Int>,
    countryTotalIps: Long,
    selectedTotalIps: Long,
    customRangeInput: String,
    customRangePreviewCount: Long = 0,
    canStartScan: Boolean,
    onStartScan: () -> Unit,
    onLoadDefault: () -> Unit,
    onImportFile: () -> Unit,
    onSelectCountry: (GeoBypassCountry) -> Unit,
    onSelectSampleCount: (Int) -> Unit,
    onUseCustomSampleCount: (Boolean) -> Unit,
    onCustomSampleCountChange: (String) -> Unit,
    onGenerateCountryList: () -> Unit,
    onToggleOctet: (Int) -> Unit,
    onSelectAllOctets: () -> Unit,
    onDeselectAllOctets: () -> Unit,
    onCustomRangeInputChange: (String) -> Unit,
    onLoadCustomRange: () -> Unit
) {
    var activePanel by remember {
        mutableStateOf(
            when (listSource) {
                ListSource.COUNTRY_RANGE -> ResolverPanel.COUNTRY
                ListSource.CUSTOM_RANGE -> ResolverPanel.CUSTOM
                else -> ResolverPanel.NONE
            }
        )
    }

    // Sync panel when listSource changes after async restore
    LaunchedEffect(listSource) {
        val expected = when (listSource) {
            ListSource.COUNTRY_RANGE -> ResolverPanel.COUNTRY
            ListSource.CUSTOM_RANGE -> ResolverPanel.CUSTOM
            else -> null
        }
        if (expected != null && activePanel == ResolverPanel.NONE) {
            activePanel = expected
        }
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerLow
        ),
        shape = RoundedCornerShape(16.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            SectionHeader(
                icon = Icons.Default.Storage,
                title = "Resolver List"
            )

            // Resolver count row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)),
                    contentAlignment = Alignment.Center
                ) {
                    if (isLoading) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp
                        )
                    } else {
                        Icon(
                            Icons.Default.Dns,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }

                Column {
                    Text(
                        text = "$resolverCount resolvers",
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = when (listSource) {
                            ListSource.DEFAULT -> "Built-in list"
                            ListSource.IMPORTED -> if (importedFileName != null) "Imported: $importedFileName" else "Imported from file"
                            ListSource.COUNTRY_RANGE -> "${selectedCountry.displayName} IP range ($effectiveSampleCount random IPs)"
                            ListSource.CUSTOM_RANGE -> "Custom range ($resolverCount IPs)"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = {
                        activePanel = ResolverPanel.NONE
                        onLoadDefault()
                    },
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(12.dp),
                    contentPadding = PaddingValues(vertical = 10.dp)
                ) {
                    Icon(
                        Icons.Default.Refresh,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(Modifier.width(6.dp))
                    Text("Default", maxLines = 1)
                }

                OutlinedButton(
                    onClick = {
                        activePanel = ResolverPanel.NONE
                        onImportFile()
                    },
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(12.dp),
                    contentPadding = PaddingValues(vertical = 10.dp)
                ) {
                    Icon(
                        Icons.Default.FileUpload,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(Modifier.width(6.dp))
                    Text("Import", maxLines = 1)
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = {
                        activePanel = if (activePanel == ResolverPanel.COUNTRY) ResolverPanel.NONE else ResolverPanel.COUNTRY
                    },
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(12.dp),
                    contentPadding = PaddingValues(vertical = 10.dp),
                    colors = if (activePanel == ResolverPanel.COUNTRY || listSource == ListSource.COUNTRY_RANGE) {
                        ButtonDefaults.outlinedButtonColors(
                            containerColor = MaterialTheme.colorScheme.primaryContainer
                        )
                    } else {
                        ButtonDefaults.outlinedButtonColors()
                    }
                ) {
                    Icon(
                        Icons.Default.Search,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(Modifier.width(6.dp))
                    Text("Country", maxLines = 1)
                }

                OutlinedButton(
                    onClick = {
                        activePanel = if (activePanel == ResolverPanel.CUSTOM) ResolverPanel.NONE else ResolverPanel.CUSTOM
                    },
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(12.dp),
                    contentPadding = PaddingValues(vertical = 10.dp),
                    colors = if (activePanel == ResolverPanel.CUSTOM || listSource == ListSource.CUSTOM_RANGE) {
                        ButtonDefaults.outlinedButtonColors(
                            containerColor = MaterialTheme.colorScheme.primaryContainer
                        )
                    } else {
                        ButtonDefaults.outlinedButtonColors()
                    }
                ) {
                    Icon(
                        Icons.Default.Dns,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(Modifier.width(6.dp))
                    Text("Custom", maxLines = 1)
                }
            }

            // Country / Custom range panel (single AnimatedContent to avoid double-layout)
            AnimatedContent(
                targetState = activePanel,
                transitionSpec = {
                    fadeIn(tween(250)) togetherWith fadeOut(tween(150)) using
                            SizeTransform(clip = false, sizeAnimationSpec = { _, _ -> tween(300) })
                },
                label = "resolverPanel"
            ) { panel ->
                when (panel) {
                    ResolverPanel.CUSTOM -> {
                        Column(
                            verticalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            OutlinedTextField(
                                value = customRangeInput,
                                onValueChange = onCustomRangeInputChange,
                                label = { Text("IP Ranges") },
                                placeholder = { Text("8.8.8.0/24\n1.1.1.1-1.1.1.10\n9.9.9.9") },
                                supportingText = {
                                    Text(
                                        if (customRangePreviewCount > 0) "~%,d IPs \u2022 CIDR, range, or single IP".format(customRangePreviewCount)
                                        else "One per line: CIDR, range, or single IP"
                                    )
                                },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(140.dp),
                                shape = RoundedCornerShape(12.dp),
                                maxLines = 8
                            )

                            FilledTonalButton(
                                onClick = onLoadCustomRange,
                                enabled = !isLoading && customRangeInput.isNotBlank(),
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp)
                            ) {
                                if (isLoading) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(18.dp),
                                        strokeWidth = 2.dp
                                    )
                                } else {
                                    Icon(
                                        Icons.Default.PlayArrow,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp)
                                    )
                                }
                                Spacer(Modifier.width(8.dp))
                                Text("Load IPs")
                            }

                            AnimatedVisibility(
                                visible = listSource == ListSource.CUSTOM_RANGE && !isLoading && resolverCount > 0
                            ) {
                                Button(
                                    onClick = onStartScan,
                                    enabled = canStartScan,
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(12.dp),
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = MaterialTheme.colorScheme.primary
                                    )
                                ) {
                                    Icon(
                                        Icons.Default.PlayArrow,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp)
                                    )
                                    Spacer(Modifier.width(8.dp))
                                    Text("Start Scan", fontWeight = FontWeight.SemiBold)
                                }
                            }
                        }
                    }

                    ResolverPanel.COUNTRY -> {
                        Column(
                            verticalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            // Country selector
                            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text(
                                    text = "Country",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                FlowRow(
                                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                                    verticalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    GeoBypassCountry.entries.forEach { country ->
                                        OptionChip(
                                            selected = selectedCountry == country,
                                            onClick = { onSelectCountry(country) },
                                            label = country.displayName
                                        )
                                    }
                                }
                            }

                            // Stats row
                            if (cidrGroups.isNotEmpty()) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .background(
                                            MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
                                            RoundedCornerShape(8.dp)
                                        )
                                        .padding(horizontal = 12.dp, vertical = 8.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Column {
                                        Text(
                                            text = "${cidrGroups.sumOf { it.rangeCount }} ranges",
                                            style = MaterialTheme.typography.labelMedium,
                                            fontWeight = FontWeight.SemiBold
                                        )
                                        Text(
                                            text = "%,d total IPs".format(countryTotalIps),
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                    Column(horizontalAlignment = Alignment.End) {
                                        Text(
                                            text = "${selectedOctets.size}/${cidrGroups.size} groups",
                                            style = MaterialTheme.typography.labelMedium,
                                            fontWeight = FontWeight.SemiBold
                                        )
                                        Text(
                                            text = "%,d selected IPs".format(selectedTotalIps),
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.primary
                                        )
                                    }
                                }
                            }

                            // Sample count selector
                            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text(
                                    text = "Sample Size",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                FlowRow(
                                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                                    verticalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    listOf(1000, 2000, 5000, 10000).forEach { count ->
                                        OptionChip(
                                            selected = !useCustomSampleCount && sampleCount == count,
                                            onClick = { onSelectSampleCount(count) },
                                            label = count.toString()
                                        )
                                    }
                                    OptionChip(
                                        selected = useCustomSampleCount,
                                        onClick = { onUseCustomSampleCount(true) },
                                        label = "Custom"
                                    )
                                }
                                AnimatedVisibility(visible = useCustomSampleCount) {
                                    OutlinedTextField(
                                        value = customSampleCountText,
                                        onValueChange = onCustomSampleCountChange,
                                        label = { Text("Count") },
                                        placeholder = { Text("e.g. 3000") },
                                        singleLine = true,
                                        modifier = Modifier.fillMaxWidth(),
                                        shape = RoundedCornerShape(12.dp),
                                        supportingText = { Text("1 - %,d".format(DnsScannerUiState.MAX_SAMPLE_COUNT)) },
                                        trailingIcon = if (selectedTotalIps > 0) {
                                            {
                                                Text(
                                                    text = "Max",
                                                    style = MaterialTheme.typography.labelMedium,
                                                    color = MaterialTheme.colorScheme.primary,
                                                    modifier = Modifier
                                                        .clickable {
                                                            onCustomSampleCountChange(
                                                                selectedTotalIps.coerceAtMost(DnsScannerUiState.MAX_SAMPLE_COUNT.toLong()).toString()
                                                            )
                                                        }
                                                        .padding(end = 12.dp)
                                                )
                                            }
                                        } else null
                                    )
                                }
                            }

                            // Range browser (collapsed by default)
                            if (cidrGroups.isNotEmpty()) {
                                var showRangeGroups by remember { mutableStateOf(false) }
                                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clip(RoundedCornerShape(8.dp))
                                            .clickable { showRangeGroups = !showRangeGroups }
                                            .padding(vertical = 4.dp),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Row(
                                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Icon(
                                                if (showRangeGroups) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                                                contentDescription = null,
                                                modifier = Modifier.size(18.dp),
                                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                            Text(
                                                text = "IP Range Groups (${selectedOctets.size}/${cidrGroups.size} selected)",
                                                style = MaterialTheme.typography.labelMedium,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        }
                                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                            Text(
                                                text = "All",
                                                style = MaterialTheme.typography.labelSmall,
                                                color = MaterialTheme.colorScheme.primary,
                                                modifier = Modifier.clickable { onSelectAllOctets() }
                                            )
                                            Text(
                                                text = "None",
                                                style = MaterialTheme.typography.labelSmall,
                                                color = MaterialTheme.colorScheme.primary,
                                                modifier = Modifier.clickable { onDeselectAllOctets() }
                                            )
                                        }
                                    }

                                    AnimatedVisibility(visible = showRangeGroups) {
                                        Box(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .height(200.dp)
                                                .border(
                                                    1.dp,
                                                    MaterialTheme.colorScheme.outline.copy(alpha = 0.3f),
                                                    RoundedCornerShape(12.dp)
                                                )
                                                .clip(RoundedCornerShape(12.dp))
                                        ) {
                                            LazyColumn(
                                                modifier = Modifier.fillMaxSize(),
                                                contentPadding = PaddingValues(4.dp)
                                            ) {
                                                items(cidrGroups.size) { index ->
                                                    val group = cidrGroups[index]
                                                    val isSelected = group.firstOctet in selectedOctets
                                                    Row(
                                                        modifier = Modifier
                                                            .fillMaxWidth()
                                                            .clickable { onToggleOctet(group.firstOctet) }
                                                            .padding(horizontal = 8.dp, vertical = 4.dp),
                                                        verticalAlignment = Alignment.CenterVertically,
                                                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                                                    ) {
                                                        Checkbox(
                                                            checked = isSelected,
                                                            onCheckedChange = { onToggleOctet(group.firstOctet) },
                                                            modifier = Modifier.size(20.dp)
                                                        )
                                                        Text(
                                                            text = group.label,
                                                            style = MaterialTheme.typography.bodyMedium,
                                                            fontWeight = FontWeight.Medium,
                                                            modifier = Modifier.width(80.dp)
                                                        )
                                                        Text(
                                                            text = "${group.rangeCount} ranges",
                                                            style = MaterialTheme.typography.bodySmall,
                                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                            modifier = Modifier.weight(1f)
                                                        )
                                                        Text(
                                                            text = "%,d".format(group.totalIps),
                                                            style = MaterialTheme.typography.bodySmall,
                                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                                        )
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // Generate button
                            FilledTonalButton(
                                onClick = onGenerateCountryList,
                                enabled = !isLoading && selectedOctets.isNotEmpty(),
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp)
                            ) {
                                if (isLoading) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(18.dp),
                                        strokeWidth = 2.dp
                                    )
                                } else {
                                    Icon(
                                        Icons.Default.PlayArrow,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp)
                                    )
                                }
                                Spacer(Modifier.width(8.dp))
                                Text("Generate $effectiveSampleCount ${selectedCountry.displayName} IPs")
                            }

                            // Start Scan button after generation
                            AnimatedVisibility(
                                visible = listSource == ListSource.COUNTRY_RANGE && !isLoading && resolverCount > 0
                            ) {
                                Button(
                                    onClick = onStartScan,
                                    enabled = canStartScan,
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(12.dp),
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = MaterialTheme.colorScheme.primary
                                    )
                                ) {
                                    Icon(
                                        Icons.Default.PlayArrow,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp)
                                    )
                                    Spacer(Modifier.width(8.dp))
                                    Text("Start Scan", fontWeight = FontWeight.SemiBold)
                                }
                            }
                        }
                    }

                    ResolverPanel.NONE -> {
                        // Empty — no extra panel shown
                    }
                }
            }
        }
    }
}

@Composable
private fun RecentDnsSection(
    recentResolvers: List<String>,
    selectedResolvers: Set<String>,
    isLimitReached: Boolean,
    maxCount: Int,
    canSelect: Boolean,
    onToggleSelection: (String) -> Unit,
    onApply: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerLow
        ),
        shape = RoundedCornerShape(16.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                SectionHeader(
                    icon = Icons.Default.History,
                    title = "Recent DNS"
                )
                if (canSelect && selectedResolvers.isNotEmpty()) {
                    Text(
                        text = "${selectedResolvers.size} / $maxCount",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = if (isLimitReached) Color(0xFFFF9800)
                                else MaterialTheme.colorScheme.primary
                    )
                }
            }

            recentResolvers.forEach { ip ->
                val isSelected = canSelect && selectedResolvers.contains(ip)
                val isDisabled = isLimitReached && !isSelected
                val backgroundColor by animateColorAsState(
                    targetValue = if (isSelected) MaterialTheme.colorScheme.primaryContainer
                    else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                    label = "recentBg_$ip"
                )

                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .then(
                            if (canSelect && !isDisabled) Modifier.clickable { onToggleSelection(ip) }
                            else Modifier
                        ),
                    colors = CardDefaults.cardColors(containerColor = backgroundColor),
                    shape = RoundedCornerShape(12.dp),
                    elevation = CardDefaults.cardElevation(
                        defaultElevation = if (isSelected) 1.dp else 0.dp
                    )
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 14.dp, vertical = 10.dp),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(34.dp)
                                .clip(RoundedCornerShape(8.dp))
                                .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                Icons.Default.Dns,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(18.dp)
                            )
                        }

                        Text(
                            text = ip,
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.bodyMedium.copy(
                                fontFamily = FontFamily.Monospace,
                                letterSpacing = 0.5.sp
                            ),
                            fontWeight = FontWeight.Medium
                        )

                        if (canSelect) {
                            Checkbox(
                                checked = isSelected,
                                onCheckedChange = { if (!isDisabled) onToggleSelection(ip) },
                                enabled = !isDisabled
                            )
                        }
                    }
                }
            }

            if (canSelect && selectedResolvers.any { it in recentResolvers }) {
                Button(
                    onClick = onApply,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Icon(
                        Icons.Default.Check,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text("Apply Selected")
                }
            }
        }
    }
}

@Composable
private fun OptionChip(
    selected: Boolean,
    onClick: () -> Unit,
    label: String
) {
    val backgroundColor by animateColorAsState(
        targetValue = if (selected) MaterialTheme.colorScheme.primaryContainer
        else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        label = "optionChipBg"
    )
    val borderColor by animateColorAsState(
        targetValue = if (selected) MaterialTheme.colorScheme.primary
        else MaterialTheme.colorScheme.outline.copy(alpha = 0.3f),
        label = "optionChipBorder"
    )

    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(10.dp))
            .border(
                width = if (selected) 1.5.dp else 1.dp,
                color = borderColor,
                shape = RoundedCornerShape(10.dp)
            )
            .background(backgroundColor)
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 8.dp)
    ) {
        Row(
            horizontalArrangement = Arrangement.spacedBy(4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (selected) {
                Icon(
                    Icons.Default.Check,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(14.dp)
                )
            }
            Text(
                text = label,
                style = MaterialTheme.typography.labelLarge,
                fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium,
                color = if (selected) MaterialTheme.colorScheme.primary
                else MaterialTheme.colorScheme.onSurface
            )
        }
    }
}

@Composable
private fun SectionHeader(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Icon(
            icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(18.dp)
        )
        Text(
            text = title,
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.primary
        )
    }
}
