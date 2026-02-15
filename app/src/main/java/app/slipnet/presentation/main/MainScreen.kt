package app.slipnet.presentation.main

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
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
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.DriveFileMove
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Waves
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.draw.scale
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.TransformOrigin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.zIndex
import androidx.core.content.FileProvider
import androidx.hilt.navigation.compose.hiltViewModel
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.ServerProfile
import app.slipnet.presentation.common.components.ProfileListItem
import app.slipnet.presentation.common.components.QrCodeDialog
import app.slipnet.presentation.common.icons.TorIcon
import app.slipnet.presentation.home.DebugLogSheet
import app.slipnet.presentation.theme.ConnectedGreen
import app.slipnet.presentation.theme.ConnectingOrange
import app.slipnet.presentation.theme.DisconnectedRed
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.launch
import sh.calvin.reorderable.ReorderableItem
import sh.calvin.reorderable.rememberReorderableLazyListState

private fun Context.findActivity(): Activity? {
    var context = this
    while (context is ContextWrapper) {
        if (context is Activity) return context
        context = context.baseContext
    }
    return null
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    onNavigateToAddProfile: (tunnelType: String) -> Unit,
    onNavigateToEditProfile: (Long) -> Unit,
    onNavigateToSettings: () -> Unit,
    viewModel: MainViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val activity = context.findActivity()

    // VPN permission flow
    var pendingConnect by remember { mutableStateOf(false) }
    var pendingProfile by remember { mutableStateOf<ServerProfile?>(null) }

    // Dialog/sheet state
    var showShareDialog by remember { mutableStateOf(false) }
    var showLogSheet by remember { mutableStateOf(false) }
    var showOverflowMenu by remember { mutableStateOf(false) }
    var showImportDialog by remember { mutableStateOf(false) }
    var importText by remember { mutableStateOf("") }
    var showAddMenu by remember { mutableStateOf(false) }
    var showDeleteAllDialog by remember { mutableStateOf(false) }
    var profileToDelete by remember { mutableStateOf<ServerProfile?>(null) }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK && pendingConnect) {
            if (pendingProfile != null) {
                viewModel.connect(pendingProfile)
            } else {
                viewModel.connect()
            }
        }
        pendingConnect = false
        pendingProfile = null
    }

    val importFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri?.let {
            try {
                context.contentResolver.openInputStream(it)?.use { inputStream ->
                    val json = inputStream.bufferedReader().readText()
                    viewModel.parseImportConfig(json)
                }
            } catch (_: Exception) {}
        }
    }

    val qrScanLauncher = rememberLauncherForActivityResult(
        contract = ScanContract()
    ) { result ->
        val contents = result.contents
        if (contents != null) {
            if (contents.startsWith("slipnet://")) {
                viewModel.parseImportConfig(contents)
            } else {
                scope.launch {
                    snackbarHostState.showSnackbar("Invalid QR code: not a SlipNet config")
                }
            }
        }
    }

    // Handle export
    LaunchedEffect(uiState.exportedJson) {
        uiState.exportedJson?.let { json ->
            val sendIntent = Intent().apply {
                action = Intent.ACTION_SEND
                putExtra(Intent.EXTRA_TEXT, json)
                type = "text/plain"
            }
            val shareIntent = Intent.createChooser(sendIntent, "Export Profile")
            context.startActivity(shareIntent)
            viewModel.clearExportedJson()
        }
    }

    LaunchedEffect(uiState.error) {
        uiState.error?.let { error ->
            snackbarHostState.showSnackbar(error)
            viewModel.clearError()
        }
    }

    val navBarPadding = WindowInsets.navigationBars.asPaddingValues()

    // Helper to request VPN permission and connect
    fun requestConnectOrToggle() {
        when (uiState.connectionState) {
            is ConnectionState.Connected,
            is ConnectionState.Connecting -> viewModel.disconnect()
            else -> {
                if (uiState.proxyOnlyMode) {
                    viewModel.connect()
                } else if (activity != null) {
                    val vpnIntent = VpnService.prepare(activity)
                    if (vpnIntent != null) {
                        pendingConnect = true
                        pendingProfile = null
                        vpnPermissionLauncher.launch(vpnIntent)
                    } else {
                        viewModel.connect()
                    }
                }
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "SlipNet",
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold
                    )
                },
                actions = {
                    if (uiState.debugLogging) {
                        IconButton(onClick = { showLogSheet = true }) {
                            Icon(Icons.Default.BugReport, contentDescription = "Debug Logs")
                        }
                    }
                    IconButton(onClick = { showShareDialog = true }) {
                        Icon(Icons.Default.Share, contentDescription = "Share App")
                    }
                    // Overflow menu
                    Box {
                        IconButton(onClick = { showOverflowMenu = true }) {
                            Icon(Icons.Default.DriveFileMove, contentDescription = "Import & Export")
                        }
                        DropdownMenu(
                            expanded = showOverflowMenu,
                            onDismissRequest = { showOverflowMenu = false }
                        ) {
                            DropdownMenuItem(
                                text = { Text("Export All Profiles") },
                                onClick = {
                                    showOverflowMenu = false
                                    viewModel.exportAllProfiles()
                                },
                                enabled = uiState.profiles.isNotEmpty()
                            )
                            DropdownMenuItem(
                                text = { Text("Import Profiles") },
                                onClick = {
                                    showOverflowMenu = false
                                    showImportDialog = true
                                }
                            )
                            DropdownMenuItem(
                                text = { Text("Delete All Profiles") },
                                onClick = {
                                    showOverflowMenu = false
                                    showDeleteAllDialog = true
                                },
                                enabled = uiState.profiles.isNotEmpty()
                            )
                        }
                    }
                    IconButton(onClick = onNavigateToSettings) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent
                )
            )
        },
        floatingActionButton = {
            Column(
                horizontalAlignment = Alignment.End
            ) {
                AnimatedVisibility(
                    visible = showAddMenu,
                    enter = scaleIn(transformOrigin = TransformOrigin(1f, 1f)) + fadeIn(),
                    exit = scaleOut(transformOrigin = TransformOrigin(1f, 1f)) + fadeOut()
                ) {
                    Surface(
                        shape = RoundedCornerShape(16.dp),
                        tonalElevation = 4.dp,
                        shadowElevation = 8.dp,
                        modifier = Modifier.padding(bottom = 12.dp, end = 8.dp)
                    ) {
                        Column(
                            modifier = Modifier
                                .width(220.dp)
                                .padding(vertical = 8.dp)
                        ) {
                            AddMenuOption(
                                icon = Icons.Default.Dns,
                                title = "DNSTT",
                                description = "DNS tunnel (KCP + Noise)",
                                onClick = {
                                    showAddMenu = false
                                    onNavigateToAddProfile("dnstt")
                                }
                            )
                            AddMenuOption(
                                icon = Icons.Default.Waves,
                                title = "Slipstream",
                                description = "DNS tunnel (QUIC)",
                                onClick = {
                                    showAddMenu = false
                                    onNavigateToAddProfile("slipstream")
                                }
                            )
                            AddMenuOption(
                                icon = Icons.Default.Lock,
                                title = "SSH",
                                description = "Direct SSH tunnel",
                                onClick = {
                                    showAddMenu = false
                                    onNavigateToAddProfile("ssh")
                                }
                            )
                            AddMenuOption(
                                icon = Icons.Default.Language,
                                title = "DOH",
                                description = "DNS over HTTPS",
                                onClick = {
                                    showAddMenu = false
                                    onNavigateToAddProfile("doh")
                                }
                            )
                            AddMenuOption(
                                icon = TorIcon,
                                title = "Tor",
                                description = "Connect via Tor network",
                                onClick = {
                                    showAddMenu = false
                                    onNavigateToAddProfile("snowflake")
                                }
                            )
                        }
                    }
                }
                FloatingActionButton(
                    onClick = { showAddMenu = !showAddMenu },
                    containerColor = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(end = 8.dp)
                ) {
                    Icon(Icons.Default.Add, contentDescription = "Add Profile")
                }

                Spacer(modifier = Modifier.height(12.dp))

                // Connect / Disconnect FAB
                ConnectFab(
                    connectionState = uiState.connectionState,
                    hasProfile = uiState.activeProfile != null || uiState.profiles.isNotEmpty(),
                    snowflakeBootstrapProgress = uiState.snowflakeBootstrapProgress,
                    onToggleConnection = { requestConnectOrToggle() },
                    modifier = Modifier.padding(
                        bottom = 24.dp + navBarPadding.calculateBottomPadding(),
                        end = 8.dp
                    )
                )
            }
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        containerColor = MaterialTheme.colorScheme.background,
        contentWindowInsets = WindowInsets(0, 0, 0, 0)
    ) { paddingValues ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
        ) {
            // ── Profile List ────────────────────────────────────────
            when {
                uiState.isLoading -> {
                    Box(
                        modifier = Modifier.fillMaxSize(),
                        contentAlignment = Alignment.Center
                    ) {
                        androidx.compose.material3.CircularProgressIndicator()
                    }
                }
                uiState.profiles.isEmpty() -> {
                    Box(
                        modifier = Modifier.fillMaxSize(),
                        contentAlignment = Alignment.Center
                    ) {
                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally,
                            modifier = Modifier.padding(32.dp)
                        ) {
                            Text(
                                text = "No profiles yet",
                                style = MaterialTheme.typography.bodyLarge,
                                fontWeight = FontWeight.Medium
                            )
                            Text(
                                text = "Tap + to add your first profile",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
                else -> {
                    val lazyListState = rememberLazyListState()
                    val reorderableLazyListState = rememberReorderableLazyListState(lazyListState) { from, to ->
                        viewModel.moveProfile(from.index, to.index)
                    }

                    LazyColumn(
                        state = lazyListState,
                        contentPadding = PaddingValues(
                            start = 16.dp, end = 16.dp,
                            top = 8.dp,
                            bottom = 200.dp + navBarPadding.calculateBottomPadding()
                        ),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                        modifier = Modifier.fillMaxSize()
                    ) {
                        items(
                            items = uiState.profiles,
                            key = { it.id }
                        ) { profile ->
                            val isConnected = uiState.connectedProfileId == profile.id

                            ReorderableItem(reorderableLazyListState, key = profile.id) { isDragging ->
                                val elevation = if (isDragging) 8.dp else 0.dp

                                ProfileListItem(
                                    profile = profile,
                                    isSelected = profile.isActive,
                                    isConnected = isConnected,
                                    onClick = { viewModel.setActiveProfile(profile) },
                                    onEditClick = { onNavigateToEditProfile(profile.id) },
                                    onDeleteClick = {
                                        if (isConnected) {
                                            scope.launch {
                                                snackbarHostState.showSnackbar(
                                                    "Disconnect VPN before deleting this profile"
                                                )
                                            }
                                        } else {
                                            profileToDelete = profile
                                        }
                                    },
                                    onExportClick = { viewModel.exportProfile(profile) },
                                    onShareQrClick = { viewModel.showQrCode(profile) },
                                    modifier = Modifier
                                        .longPressDraggableHandle()
                                        .shadow(elevation, RoundedCornerShape(12.dp))
                                        .zIndex(if (isDragging) 1f else 0f)
                                )
                            }
                        }
                    }
                }
            }

            // ── Connection Status Strip (bottom, behind FAB) ────────
            ConnectionStatusStrip(
                connectionState = uiState.connectionState,
                activeProfile = uiState.activeProfile,
                isProxyOnly = uiState.proxyOnlyMode,
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .padding(bottom = navBarPadding.calculateBottomPadding())
            )

            // Scrim to dismiss FAB menu
            if (showAddMenu) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .clickable(
                            indication = null,
                            interactionSource = remember { MutableInteractionSource() }
                        ) { showAddMenu = false }
                )
            }
        }
    }

    // ── Dialogs ─────────────────────────────────────────────────────────

    // Debug log sheet
    if (showLogSheet) {
        DebugLogSheet(onDismiss = { showLogSheet = false })
    }

    // Share dialog
    if (showShareDialog) {
        AlertDialog(
            onDismissRequest = { showShareDialog = false },
            title = { Text("Share SlipNet") },
            text = {
                Column(modifier = Modifier.fillMaxWidth()) {
                    Text(
                        "How would you like to share the app?",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.height(16.dp))
                    TextButton(
                        onClick = { showShareDialog = false; shareApk(context) },
                        modifier = Modifier.fillMaxWidth()
                    ) { Text("APK File") }
                    TextButton(
                        onClick = { showShareDialog = false; shareGithubLink(context) },
                        modifier = Modifier.fillMaxWidth()
                    ) { Text("GitHub Link") }
                    TextButton(
                        onClick = { showShareDialog = false; shareTelegramLink(context) },
                        modifier = Modifier.fillMaxWidth()
                    ) { Text("Telegram Channel") }
                }
            },
            confirmButton = {}
        )
    }

    // Delete confirmation dialog
    profileToDelete?.let { profile ->
        AlertDialog(
            onDismissRequest = { profileToDelete = null },
            title = { Text("Delete Profile") },
            text = { Text("Are you sure you want to delete \"${profile.name}\"?") },
            confirmButton = {
                TextButton(
                    onClick = {
                        viewModel.deleteProfile(profile)
                        profileToDelete = null
                    }
                ) { Text("Delete") }
            },
            dismissButton = {
                TextButton(onClick = { profileToDelete = null }) { Text("Cancel") }
            }
        )
    }

    // Delete all confirmation dialog
    if (showDeleteAllDialog) {
        val hasConnected = uiState.connectedProfileId != null
        AlertDialog(
            onDismissRequest = { showDeleteAllDialog = false },
            title = { Text("Delete All Profiles") },
            text = {
                Text(
                    if (hasConnected)
                        "Are you sure you want to delete all profiles? The currently connected profile will be kept."
                    else
                        "Are you sure you want to delete all profiles? This cannot be undone."
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        viewModel.deleteAllProfiles()
                        showDeleteAllDialog = false
                    }
                ) { Text("Delete All") }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteAllDialog = false }) { Text("Cancel") }
            }
        )
    }

    // Import preview dialog
    uiState.importPreview?.let { preview ->
        AlertDialog(
            onDismissRequest = { viewModel.cancelImport() },
            title = { Text("Import Profiles") },
            text = {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "${preview.profiles.size} profile(s) found:",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    preview.profiles.forEach { profile ->
                        Text(
                            text = "\u2022 ${profile.name}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    if (preview.warnings.isNotEmpty()) {
                        Text(
                            text = "Warnings:",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.padding(top = 8.dp)
                        )
                        preview.warnings.forEach { warning ->
                            Text(
                                text = "\u2022 $warning",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { viewModel.confirmImport() }) { Text("Import") }
            },
            dismissButton = {
                TextButton(onClick = { viewModel.cancelImport() }) { Text("Cancel") }
            }
        )
    }

    // QR code share dialog
    uiState.qrCodeData?.let { qrData ->
        QrCodeDialog(
            profileName = qrData.profileName,
            configUri = qrData.configUri,
            onDismiss = { viewModel.clearQrCode() }
        )
    }

    // Import input dialog
    if (showImportDialog) {
        AlertDialog(
            onDismissRequest = {
                showImportDialog = false
                importText = ""
            },
            title = { Text("Import Profiles") },
            text = {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = "Paste the config below:",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    OutlinedTextField(
                        value = importText,
                        onValueChange = { importText = it },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(120.dp),
                        placeholder = { Text("slipnet://...") },
                        singleLine = false,
                        maxLines = 5
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceEvenly
                    ) {
                        TextButton(
                            onClick = {
                                importFileLauncher.launch(arrayOf("text/plain", "*/*"))
                                showImportDialog = false
                                importText = ""
                            }
                        ) { Text("Import from File") }
                        TextButton(
                            onClick = {
                                showImportDialog = false
                                importText = ""
                                qrScanLauncher.launch(ScanOptions().apply {
                                    setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                    setPrompt("Scan a SlipNet QR code")
                                    setBeepEnabled(false)
                                })
                            }
                        ) { Text("Scan QR Code") }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        if (importText.isNotBlank()) {
                            viewModel.parseImportConfig(importText)
                            showImportDialog = false
                            importText = ""
                        }
                    },
                    enabled = importText.isNotBlank()
                ) { Text("Import") }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        showImportDialog = false
                        importText = ""
                    }
                ) { Text("Cancel") }
            }
        )
    }
}

// ── ConnectionStatusStrip ───────────────────────────────────────────────

@Composable
private fun ConnectionStatusStrip(
    connectionState: ConnectionState,
    activeProfile: ServerProfile?,
    isProxyOnly: Boolean,
    modifier: Modifier = Modifier
) {
    val isConnected = connectionState is ConnectionState.Connected
    val isConnecting = connectionState is ConnectionState.Connecting ||
            connectionState is ConnectionState.Disconnecting
    val isError = connectionState is ConnectionState.Error

    val statusColor by animateColorAsState(
        targetValue = when {
            isConnected -> ConnectedGreen
            isConnecting -> ConnectingOrange
            isError -> DisconnectedRed
            else -> MaterialTheme.colorScheme.outline
        },
        animationSpec = tween(300),
        label = "statusColor"
    )

    Surface(
        modifier = modifier.fillMaxWidth(),
        tonalElevation = 2.dp,
        shape = RoundedCornerShape(topStart = 16.dp, topEnd = 16.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Status indicator dot
            Box(
                modifier = Modifier
                    .size(10.dp)
                    .clip(CircleShape)
                    .background(statusColor)
            )

            Spacer(modifier = Modifier.width(12.dp))

            // Status text + profile name
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = when {
                        isConnected && isProxyOnly -> "Proxy Active"
                        isConnected -> "Connected"
                        connectionState is ConnectionState.Connecting -> "Connecting..."
                        connectionState is ConnectionState.Disconnecting -> "Disconnecting..."
                        isError -> "Connection Failed"
                        else -> "Not Connected"
                    },
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = if (isConnected || isConnecting) statusColor
                    else MaterialTheme.colorScheme.onBackground
                )
                Text(
                    text = when {
                        isConnected && connectionState is ConnectionState.Connected ->
                            connectionState.profile.name
                        isError && connectionState is ConnectionState.Error ->
                            connectionState.message
                        activeProfile != null -> activeProfile.name
                        else -> "No profile selected"
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = if (isError) DisconnectedRed
                    else MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

// ── Connect FAB ─────────────────────────────────────────────────────────

@Composable
private fun ConnectFab(
    connectionState: ConnectionState,
    hasProfile: Boolean,
    snowflakeBootstrapProgress: Int,
    onToggleConnection: () -> Unit,
    modifier: Modifier = Modifier
) {
    val isConnected = connectionState is ConnectionState.Connected
    val isConnecting = connectionState is ConnectionState.Connecting ||
            connectionState is ConnectionState.Disconnecting

    val statusColor by animateColorAsState(
        targetValue = when {
            isConnected -> ConnectedGreen
            isConnecting -> ConnectingOrange
            connectionState is ConnectionState.Error -> DisconnectedRed
            else -> MaterialTheme.colorScheme.primary
        },
        animationSpec = tween(300),
        label = "connectFabColor"
    )

    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 1.08f,
        animationSpec = infiniteRepeatable(
            animation = tween(1000, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseScale"
    )

    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = modifier
    ) {
        // Snowflake bootstrap progress above the FAB
        if (connectionState is ConnectionState.Connecting && snowflakeBootstrapProgress in 0..99) {
            Text(
                text = "Tor: $snowflakeBootstrapProgress%",
                style = MaterialTheme.typography.labelSmall,
                color = ConnectingOrange,
                modifier = Modifier.padding(bottom = 4.dp)
            )
        }

        FloatingActionButton(
            onClick = onToggleConnection,
            containerColor = statusColor,
            modifier = Modifier
                .size(56.dp)
                .then(if (isConnecting) Modifier.scale(pulseScale) else Modifier),
        ) {
            Icon(
                imageVector = Icons.Default.PowerSettingsNew,
                contentDescription = if (isConnected) "Disconnect" else "Connect",
                tint = when {
                    isConnected || isConnecting -> Color.White
                    hasProfile -> MaterialTheme.colorScheme.onPrimary
                    else -> MaterialTheme.colorScheme.onPrimary.copy(alpha = 0.5f)
                }
            )
        }
    }
}

// ── FAB menu option ─────────────────────────────────────────────────────

@Composable
private fun AddMenuOption(
    icon: ImageVector,
    title: String,
    description: String,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(28.dp)
        )
        Spacer(Modifier.width(16.dp))
        Column {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall
            )
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

// ── Share helpers ────────────────────────────────────────────────────────

private fun shareGithubLink(context: Context) {
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_SUBJECT, "SlipNet VPN")
        putExtra(Intent.EXTRA_TEXT, "Download SlipNet VPN:\nhttps://github.com/anonvector/SlipNet/releases/latest")
    }
    context.startActivity(Intent.createChooser(intent, "Share SlipNet"))
}

private fun shareTelegramLink(context: Context) {
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_SUBJECT, "SlipNet VPN")
        putExtra(Intent.EXTRA_TEXT, "Join SlipNet VPN on Telegram:\nhttps://t.me/SlipNet_app")
    }
    context.startActivity(Intent.createChooser(intent, "Share SlipNet"))
}

private fun shareApk(context: Context) {
    try {
        val appInfo = context.applicationInfo
        val sharedDir = java.io.File(context.cacheDir, "shared")
        sharedDir.mkdirs()

        val splits = appInfo.splitSourceDirs
        if (splits.isNullOrEmpty()) {
            val sourceApk = java.io.File(appInfo.sourceDir)
            val sharedApk = java.io.File(sharedDir, "SlipNet-v${app.slipnet.BuildConfig.VERSION_NAME}.apk")
            sourceApk.copyTo(sharedApk, overwrite = true)

            val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", sharedApk)
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "application/vnd.android.package-archive"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            context.startActivity(Intent.createChooser(intent, "Share SlipNet"))
        } else {
            val apksFile = java.io.File(sharedDir, "SlipNet-v${app.slipnet.BuildConfig.VERSION_NAME}.apks")
            java.util.zip.ZipOutputStream(apksFile.outputStream().buffered()).use { zip ->
                val allApks = listOf(appInfo.sourceDir) + splits
                for (path in allApks) {
                    val file = java.io.File(path)
                    zip.putNextEntry(java.util.zip.ZipEntry(file.name))
                    file.inputStream().buffered().use { it.copyTo(zip) }
                    zip.closeEntry()
                }
            }

            val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", apksFile)
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "application/zip"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            context.startActivity(Intent.createChooser(intent, "Share SlipNet"))
        }
    } catch (_: Exception) { }
}
