package app.slipnet.presentation.scanner

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.SearchOff
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Stop
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
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.draw.clip
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
import app.slipnet.domain.model.ResolverScanResult
import app.slipnet.domain.model.ResolverStatus

private val WorkingGreen = Color(0xFF4CAF50)
private val CensoredOrange = Color(0xFFFF9800)
private val TimeoutGray = Color(0xFF9E9E9E)
private val ErrorRed = Color(0xFFE53935)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanResultsScreen(
    profileId: Long? = null,
    parentBackStackEntry: NavBackStackEntry,
    onNavigateBack: () -> Unit,
    onResolversSelected: (String) -> Unit,
    viewModel: DnsScannerViewModel = hiltViewModel(parentBackStackEntry)
) {
    val uiState by viewModel.uiState.collectAsState()
    val canApply = profileId != null
    val snackbarHostState = remember { SnackbarHostState() }
    val navBarPadding = WindowInsets.navigationBars.asPaddingValues()
    var sortOption by remember { mutableStateOf(SortOption.NONE) }

    LaunchedEffect(uiState.error) {
        uiState.error?.let { error ->
            snackbarHostState.showSnackbar(error)
            viewModel.clearError()
        }
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
                        if (uiState.scannerState.isScanning) {
                            Text(
                                text = "Scanning ${uiState.scannerState.scannedCount} of ${uiState.scannerState.totalCount}...",
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
                    if (canApply && uiState.selectedResolvers.isNotEmpty()) {
                        TextButton(
                            onClick = {
                                onResolversSelected(viewModel.getSelectedResolversString())
                                onNavigateBack()
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
        snackbarHost = { SnackbarHost(snackbarHostState) },
        contentWindowInsets = WindowInsets(0, 0, 0, 0)
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
        ) {
            // Progress Section
            if (uiState.scannerState.isScanning || uiState.scannerState.scannedCount > 0) {
                ResultsProgressSection(
                    isScanning = uiState.scannerState.isScanning,
                    progress = uiState.scannerState.progress,
                    totalCount = uiState.scannerState.totalCount,
                    scannedCount = uiState.scannerState.scannedCount,
                    workingCount = uiState.scannerState.workingCount,
                    onStopScan = { viewModel.stopScan() }
                )
            }

            // Selection Controls (only when can apply to profile)
            if (canApply) {
                ResultsSelectionControls(
                    selectedCount = uiState.selectedResolvers.size,
                    onClearSelection = { viewModel.clearSelection() }
                )
            }

            // Results List - always show working only
            val filteredResults = uiState.scannerState.results.filter {
                it.status == ResolverStatus.WORKING
            }

            // Apply sorting based on selected option
            val displayResults = when (sortOption) {
                SortOption.SPEED -> filteredResults.sortedBy { it.responseTimeMs ?: Long.MAX_VALUE }
                SortOption.IP -> filteredResults.sortedWith(compareBy {
                    // Parse IP for proper numeric sorting
                    it.host.split(".").map { part -> part.toIntOrNull() ?: 0 }
                        .fold(0L) { acc, i -> acc * 256 + i }
                })
                SortOption.NONE -> filteredResults
            }

            if (displayResults.isEmpty() && !uiState.scannerState.isScanning) {
                ResultsEmptyState()
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
                    items(displayResults, key = { it.host }) { result ->
                        val isSelected = uiState.selectedResolvers.contains(result.host)
                        ResultsResolverItem(
                            result = result,
                            isSelected = isSelected,
                            showSelection = canApply,
                            onToggleSelection = if (canApply) {
                                { viewModel.toggleResolverSelection(result.host) }
                            } else null
                        )
                    }
                }

                // Sort controls at bottom
                if (displayResults.isNotEmpty()) {
                    SortControlBar(
                        sortOption = sortOption,
                        onSortOptionChange = { sortOption = it },
                        modifier = Modifier.padding(bottom = navBarPadding.calculateBottomPadding())
                    )
                }
            }
        }
    }
}

private enum class SortOption {
    NONE, SPEED, IP
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SortControlBar(
    sortOption: SortOption,
    onSortOptionChange: (SortOption) -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        modifier = modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp),
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
                        modifier = Modifier.size(18.dp)
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
                        modifier = Modifier.size(18.dp)
                    )
                },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                    selectedLabelColor = MaterialTheme.colorScheme.primary,
                    selectedLeadingIconColor = MaterialTheme.colorScheme.primary
                )
            )
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
                Row(
                    horizontalArrangement = Arrangement.spacedBy(24.dp)
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
private fun ResultsStatChip(
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
private fun ResultsSelectionControls(
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
private fun ResultsEmptyState() {
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
private fun ResultsResolverItem(
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
            ResultsStatusIcon(status = result.status)

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
                            color = if (tunnelResult.isCompatible) WorkingGreen else CensoredOrange
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
            }

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
