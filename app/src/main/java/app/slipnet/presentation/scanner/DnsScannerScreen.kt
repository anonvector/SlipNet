package app.slipnet.presentation.scanner

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.SearchOff
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.CloudOff
import androidx.compose.material.icons.outlined.Error
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.hilt.navigation.compose.hiltViewModel
import app.slipnet.domain.model.ResolverScanResult
import app.slipnet.domain.model.ResolverStatus

// Custom colors for status
private val WorkingGreen = Color(0xFF4CAF50)
private val CensoredOrange = Color(0xFFFF9800)
private val TimeoutGray = Color(0xFF9E9E9E)
private val ErrorRed = Color(0xFFE53935)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DnsScannerScreen(
    profileId: Long? = null,
    onNavigateBack: () -> Unit,
    onResolversSelected: (String) -> Unit,
    viewModel: DnsScannerViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    // Always enable selection - Apply will work when navigating back to profile
    val canApply = true
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current
    var showScanDialog by remember { mutableStateOf(false) }

    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            try {
                context.contentResolver.openInputStream(it)?.use { inputStream ->
                    val content = inputStream.bufferedReader().readText()
                    viewModel.importList(content)
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
            showScanDialog = true
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Default.Dns,
                            contentDescription = null,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(Modifier.width(12.dp))
                        Text("DNS Scanner")
                    }
                },
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
        snackbarHost = { SnackbarHost(snackbarHostState) }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp)
        ) {
            // Hero Section
            HeroCard()

            // Configuration Section
            ConfigurationSection(
                testDomain = uiState.testDomain,
                timeoutMs = uiState.timeoutMs,
                concurrency = uiState.concurrency,
                onTestDomainChange = { viewModel.updateTestDomain(it) },
                onTimeoutChange = { viewModel.updateTimeout(it) },
                onConcurrencyChange = { viewModel.updateConcurrency(it) }
            )

            // Resolver List Section
            ResolverListSection(
                resolverCount = uiState.resolverList.size,
                listSource = uiState.listSource,
                isLoading = uiState.isLoadingList,
                onLoadDefault = { viewModel.loadDefaultList() },
                onImportFile = { filePickerLauncher.launch("text/*") }
            )

            // Action Buttons
            ActionSection(
                canStartScan = uiState.resolverList.isNotEmpty() && !uiState.scannerState.isScanning,
                hasResults = uiState.scannerState.results.isNotEmpty(),
                workingCount = uiState.scannerState.workingCount,
                onStartScan = {
                    viewModel.startScan()
                    showScanDialog = true
                },
                onViewResults = { showScanDialog = true }
            )

            Spacer(modifier = Modifier.height(16.dp))
        }
    }

    // Full-screen scan results dialog
    if (showScanDialog) {
        ScanResultsDialog(
            uiState = uiState,
            canApply = canApply,
            onDismiss = { showScanDialog = false },
            onStopScan = { viewModel.stopScan() },
            onToggleSelection = { viewModel.toggleResolverSelection(it) },
            onClearSelection = { viewModel.clearSelection() },
            onApplySelection = {
                onResolversSelected(viewModel.getSelectedResolversString())
                onNavigateBack()
            },
            onClearError = { viewModel.clearError() }
        )
    }
}

@Composable
private fun HeroCard() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer
        ),
        shape = RoundedCornerShape(20.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            horizontalArrangement = Arrangement.spacedBy(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(56.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.primary),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    Icons.Default.NetworkCheck,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onPrimary,
                    modifier = Modifier.size(32.dp)
                )
            }

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Find Working Resolvers",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onPrimaryContainer
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Scan DNS servers to find ones that respond correctly without censorship or hijacking.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.8f)
                )
            }
        }
    }
}

@Composable
private fun ConfigurationSection(
    testDomain: String,
    timeoutMs: String,
    concurrency: String,
    onTestDomainChange: (String) -> Unit,
    onTimeoutChange: (String) -> Unit,
    onConcurrencyChange: (String) -> Unit
) {
    OutlinedCard(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(
                    Icons.Default.Settings,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
                Text(
                    text = "Configuration",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.primary
                )
            }

            OutlinedTextField(
                value = testDomain,
                onValueChange = onTestDomainChange,
                label = { Text("Test Domain") },
                placeholder = { Text("google.com") },
                leadingIcon = {
                    Icon(
                        Icons.Default.Search,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                },
                supportingText = { Text("Domain used to test if resolvers work") },
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
        }
    }
}

@Composable
private fun ResolverListSection(
    resolverCount: Int,
    listSource: ListSource,
    isLoading: Boolean,
    onLoadDefault: () -> Unit,
    onImportFile: () -> Unit
) {
    OutlinedCard(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(
                    Icons.Default.Storage,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
                Text(
                    text = "Resolver List",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.primary
                )
            }

            // Status Card
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
                ),
                shape = RoundedCornerShape(12.dp)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .clip(RoundedCornerShape(10.dp))
                                .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)),
                            contentAlignment = Alignment.Center
                        ) {
                            if (isLoading) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(20.dp),
                                    strokeWidth = 2.dp
                                )
                            } else {
                                Icon(
                                    Icons.Default.Dns,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(20.dp)
                                )
                            }
                        }

                        Column {
                            Text(
                                text = "$resolverCount resolvers",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = when (listSource) {
                                    ListSource.DEFAULT -> "Built-in list"
                                    ListSource.IMPORTED -> "Imported from file"
                                },
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }

            // Action Buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedButton(
                    onClick = onLoadDefault,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(12.dp),
                    contentPadding = PaddingValues(vertical = 12.dp)
                ) {
                    Icon(
                        Icons.Default.Refresh,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text("Default")
                }

                OutlinedButton(
                    onClick = onImportFile,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(12.dp),
                    contentPadding = PaddingValues(vertical = 12.dp)
                ) {
                    Icon(
                        Icons.Default.FileUpload,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text("Import")
                }
            }
        }
    }
}

@Composable
private fun ActionSection(
    canStartScan: Boolean,
    hasResults: Boolean,
    workingCount: Int,
    onStartScan: () -> Unit,
    onViewResults: () -> Unit
) {
    Column(
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Button(
            onClick = onStartScan,
            enabled = canStartScan,
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            shape = RoundedCornerShape(16.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.primary
            )
        ) {
            Icon(
                Icons.Default.PlayArrow,
                contentDescription = null,
                modifier = Modifier.size(24.dp)
            )
            Spacer(Modifier.width(12.dp))
            Text(
                "Start Scan",
                style = MaterialTheme.typography.titleMedium,
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
                    modifier = Modifier.size(20.dp)
                )
                Spacer(Modifier.width(8.dp))
                Text("View Results ($workingCount working)")
            }
        }
    }
}

// ============================================
// SCAN RESULTS DIALOG
// ============================================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ScanResultsDialog(
    uiState: DnsScannerUiState,
    canApply: Boolean,
    onDismiss: () -> Unit,
    onStopScan: () -> Unit,
    onToggleSelection: (String) -> Unit,
    onClearSelection: () -> Unit,
    onApplySelection: () -> Unit,
    onClearError: () -> Unit = {}
) {
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(uiState.error) {
        uiState.error?.let { error ->
            snackbarHostState.showSnackbar(error)
            onClearError()
        }
    }

    Dialog(
        onDismissRequest = {
            if (!uiState.scannerState.isScanning) onDismiss()
        },
        properties = DialogProperties(
            usePlatformDefaultWidth = false,
            dismissOnBackPress = !uiState.scannerState.isScanning,
            dismissOnClickOutside = false
        )
    ) {
        Box(
            modifier = Modifier.fillMaxSize()
        ) {
            Scaffold(
                snackbarHost = { SnackbarHost(snackbarHostState) },
                topBar = {
                    ScanResultsTopBar(
                        isScanning = uiState.scannerState.isScanning,
                        scannedCount = uiState.scannerState.scannedCount,
                        totalCount = uiState.scannerState.totalCount,
                        hasSelection = canApply && uiState.selectedResolvers.isNotEmpty(),
                        onDismiss = onDismiss,
                        onApplySelection = onApplySelection
                    )
                }
            ) { paddingValues ->
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(paddingValues)
                ) {
                    // Progress Section
                    if (uiState.scannerState.isScanning || uiState.scannerState.scannedCount > 0) {
                        ProgressSection(
                            isScanning = uiState.scannerState.isScanning,
                            progress = uiState.scannerState.progress,
                            totalCount = uiState.scannerState.totalCount,
                            scannedCount = uiState.scannerState.scannedCount,
                            workingCount = uiState.scannerState.workingCount,
                            onStopScan = onStopScan
                        )
                    }

                    // Selection Controls (only when can apply to profile)
                    if (canApply) {
                        SelectionControls(
                            selectedCount = uiState.selectedResolvers.size,
                            onClearSelection = onClearSelection
                        )
                    }

                    // Results List - always show working only
                    val filteredResults = uiState.scannerState.results.filter {
                        it.status == ResolverStatus.WORKING
                    }

                    if (filteredResults.isEmpty() && !uiState.scannerState.isScanning) {
                        EmptyResultsState()
                    } else {
                        LazyColumn(
                            modifier = Modifier.fillMaxSize(),
                            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            items(filteredResults, key = { it.host }) { result ->
                                val isSelected = uiState.selectedResolvers.contains(result.host)
                                ResolverResultItem(
                                    result = result,
                                    isSelected = isSelected,
                                    showSelection = canApply,
                                    onToggleSelection = if (canApply) {{ onToggleSelection(result.host) }} else null
                                )
                            }
                        }
                    }
                }
            }

        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ScanResultsTopBar(
    isScanning: Boolean,
    scannedCount: Int,
    totalCount: Int,
    hasSelection: Boolean,
    onDismiss: () -> Unit,
    onApplySelection: () -> Unit
) {
    TopAppBar(
        title = {
            Column {
                Text(
                    "Scan Results",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.SemiBold
                )
                if (isScanning) {
                    Text(
                        text = "Scanning $scannedCount of $totalCount...",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
            }
        },
        navigationIcon = {
            IconButton(
                onClick = onDismiss,
                enabled = !isScanning
            ) {
                Icon(Icons.Default.Close, contentDescription = "Close")
            }
        },
        actions = {
            if (hasSelection) {
                TextButton(onClick = onApplySelection) {
                    Text("Apply", fontWeight = FontWeight.SemiBold)
                }
            }
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = MaterialTheme.colorScheme.surface
        )
    )
}

@Composable
private fun ProgressSection(
    isScanning: Boolean,
    progress: Float,
    totalCount: Int,
    scannedCount: Int,
    workingCount: Int,
    onStopScan: () -> Unit
) {
    val animatedProgress by animateFloatAsState(
        targetValue = progress,
        label = "progress"
    )

    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Stats
                Row(
                    horizontalArrangement = Arrangement.spacedBy(24.dp)
                ) {
                    StatChip(
                        icon = Icons.Default.Dns,
                        label = "Total",
                        value = totalCount.toString(),
                        color = MaterialTheme.colorScheme.primary
                    )
                    StatChip(
                        icon = Icons.Default.Search,
                        label = "Scanned",
                        value = scannedCount.toString(),
                        color = MaterialTheme.colorScheme.secondary
                    )
                    StatChip(
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
                        shape = RoundedCornerShape(12.dp),
                        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp)
                    ) {
                        Icon(
                            Icons.Default.Stop,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(Modifier.width(6.dp))
                        Text("Stop")
                    }
                }
            }

            LinearProgressIndicator(
                progress = { animatedProgress },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(6.dp)
                    .clip(RoundedCornerShape(3.dp)),
                strokeCap = StrokeCap.Round
            )
        }
    }
}

@Composable
private fun StatChip(
    icon: ImageVector,
    label: String,
    value: String,
    color: Color
) {
    Row(
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            icon,
            contentDescription = null,
            tint = color,
            modifier = Modifier.size(16.dp)
        )
        Column {
            Text(
                text = value,
                style = MaterialTheme.typography.titleMedium,
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
private fun SelectionControls(
    selectedCount: Int,
    onClearSelection: () -> Unit
) {
    if (selectedCount > 0) {
        Surface(
            color = MaterialTheme.colorScheme.surface,
            tonalElevation = 1.dp,
            modifier = Modifier.fillMaxWidth()
        ) {
            Column {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(8.dp))
                            .background(MaterialTheme.colorScheme.primaryContainer)
                            .padding(horizontal = 10.dp, vertical = 4.dp)
                    ) {
                        Text(
                            text = "1 selected",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.primary
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
private fun EmptyResultsState() {
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
            Box(
                modifier = Modifier
                    .size(72.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.surfaceVariant),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    Icons.Default.SearchOff,
                    contentDescription = null,
                    modifier = Modifier.size(36.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Text(
                text = "No working resolvers found",
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

@Composable
private fun ResolverResultItem(
    result: ResolverScanResult,
    isSelected: Boolean,
    showSelection: Boolean = true,
    onToggleSelection: (() -> Unit)? = null
) {
    val canInteract = showSelection && result.status == ResolverStatus.WORKING && onToggleSelection != null

    val backgroundColor by animateColorAsState(
        targetValue = when {
            isSelected && showSelection -> MaterialTheme.colorScheme.primaryContainer
            else -> MaterialTheme.colorScheme.surface
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
            defaultElevation = if (isSelected && showSelection) 2.dp else 0.dp
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Status Icon
            StatusIcon(status = result.status)

            // Content
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = result.host,
                    style = MaterialTheme.typography.bodyLarge.copy(
                        fontFamily = FontFamily.Monospace,
                        letterSpacing = 0.5.sp
                    ),
                    fontWeight = FontWeight.Medium
                )
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    StatusLabel(status = result.status)

                    result.responseTimeMs?.let { ms ->
                        Text(
                            text = "${ms}ms",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                result.errorMessage?.let { error ->
                    Text(
                        text = error,
                        style = MaterialTheme.typography.labelSmall,
                        color = ErrorRed,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            // Checkbox (only for working resolvers when selection is enabled)
            if (showSelection && result.status == ResolverStatus.WORKING && onToggleSelection != null) {
                Checkbox(
                    checked = isSelected,
                    onCheckedChange = { onToggleSelection() }
                )
            }
        }
    }
}

@Composable
private fun StatusIcon(status: ResolverStatus) {
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
            .size(40.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(bgColor),
        contentAlignment = Alignment.Center
    ) {
        if (status == ResolverStatus.SCANNING) {
            CircularProgressIndicator(
                modifier = Modifier.size(20.dp),
                strokeWidth = 2.dp,
                color = color
            )
        } else {
            Icon(
                icon,
                contentDescription = null,
                tint = color,
                modifier = Modifier.size(22.dp)
            )
        }
    }
}

@Composable
private fun StatusLabel(status: ResolverStatus) {
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
