package app.slipnet.presentation.main

import app.slipnet.BuildConfig
import app.slipnet.domain.model.TunnelType
import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.PowerManager
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.Waves
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.zIndex
import androidx.core.content.FileProvider
import androidx.hilt.navigation.compose.hiltViewModel
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.ProfileChain
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TrafficStats
import app.slipnet.presentation.common.components.AboutDialogContent
import app.slipnet.presentation.common.components.ProfileListItem
import app.slipnet.presentation.common.components.QrCodeDialog
import app.slipnet.presentation.common.icons.TorIcon
import app.slipnet.presentation.home.DebugLogSheet
import app.slipnet.presentation.scanner.QrScannerActivity
import androidx.compose.material.icons.filled.Timer
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
    onNavigateToAddChain: () -> Unit = {},
    onNavigateToEditChain: (Long) -> Unit = {},
    viewModel: MainViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current
    val activity = context.findActivity()

    // Handle deep link (slipnet:// URI from external QR scanner or link)
    val mainActivity = activity as? app.slipnet.presentation.MainActivity
    val deepLinkUri by mainActivity?.deepLinkUri?.collectAsState() ?: remember { mutableStateOf(null) }
    LaunchedEffect(deepLinkUri) {
        deepLinkUri?.let { uri ->
            viewModel.parseImportConfig(uri)
            mainActivity?.consumeDeepLink()
        }
    }

    // VPN permission flow
    var pendingConnect by remember { mutableStateOf(false) }
    var pendingProfile by remember { mutableStateOf<ServerProfile?>(null) }
    var pendingChain by remember { mutableStateOf<ProfileChain?>(null) }

    // Battery optimization prompt (shown once on first connect)
    var showBatteryOptDialog by remember { mutableStateOf(false) }
    var pendingConnectAfterBatteryPrompt by remember { mutableStateOf(false) }
    var pendingProfileAfterBatteryPrompt by remember { mutableStateOf<ServerProfile?>(null) }
    var pendingChainAfterBatteryPrompt by remember { mutableStateOf<ProfileChain?>(null) }

    // Dialog/sheet state
    var showShareDialog by remember { mutableStateOf(false) }
    var showLogSheet by remember { mutableStateOf(false) }
    var showOverflowMenu by remember { mutableStateOf(false) }
    var showImportDialog by remember { mutableStateOf(false) }
    var importText by remember { mutableStateOf("") }
    var showAddMenu by remember { mutableStateOf(false) }
    var showDeleteAllDialog by remember { mutableStateOf(false) }
    var showDeleteDuplicatesDialog by remember { mutableStateOf(false) }
    var profileToDelete by remember { mutableStateOf<ServerProfile?>(null) }
    // Export lock dialog state
    var exportLockProfile by remember { mutableStateOf<ServerProfile?>(null) }
    var exportLockEnabled by remember { mutableStateOf(false) }
    var exportLockPassword by remember { mutableStateOf("") }
    var exportLockMode by remember { mutableStateOf("export") } // "export" or "qr"
    var exportLockExpiry by remember { mutableStateOf(false) }
    var exportLockExpiryDays by remember { mutableStateOf("30") }
    var exportLockAllowSharing by remember { mutableStateOf(false) }
    var exportLockDeviceId by remember { mutableStateOf("") }
    var exportLockPasswordVisible by remember { mutableStateOf(false) }
    var exportHideResolvers by remember { mutableStateOf(false) }

    // Tab state (hoisted so FAB and content can both access it)
    val hasChains = uiState.chains.isNotEmpty()
    var selectedTab by remember { mutableIntStateOf(0) }
    if (!hasChains && selectedTab == 1) selectedTab = 0
    var showLiteInfoDialog by remember { mutableStateOf(false) }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK && pendingConnect) {
            val chain = pendingChain
            val profile = pendingProfile
            if (chain != null) {
                viewModel.connectChain(chain)
            } else if (profile != null) {
                viewModel.connect(profile)
            } else {
                viewModel.connect()
            }
        }
        pendingConnect = false
        pendingProfile = null
        pendingChain = null
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
            if (contents.startsWith("slipnet://") || contents.startsWith("slipnet-enc://")) {
                viewModel.parseImportConfig(contents)
            } else {
                scope.launch {
                    snackbarHostState.showSnackbar("Invalid QR code: not a SlipNet config")
                }
            }
        }
    }

    // Handle export — show dialog with Copy and Share options
    uiState.exportedJson?.let { json ->
        AlertDialog(
            onDismissRequest = { viewModel.clearExportedJson() },
            title = { Text("Export") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Config is ready to share.", style = MaterialTheme.typography.bodyMedium)
                    OutlinedTextField(
                        value = json,
                        onValueChange = {},
                        readOnly = true,
                        modifier = Modifier.fillMaxWidth().height(100.dp),
                        maxLines = 4,
                        textStyle = MaterialTheme.typography.bodySmall
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val sendIntent = Intent().apply {
                        action = Intent.ACTION_SEND
                        putExtra(Intent.EXTRA_TEXT, json)
                        type = "text/plain"
                    }
                    context.startActivity(Intent.createChooser(sendIntent, "Export Profile"))
                    viewModel.clearExportedJson()
                }) { Text("Share") }
            },
            dismissButton = {
                Row {
                    TextButton(onClick = {
                        clipboardManager.setText(androidx.compose.ui.text.AnnotatedString(json))
                        viewModel.clearExportedJson()
                        scope.launch { snackbarHostState.showSnackbar("Copied to clipboard") }
                    }) { Text("Copy") }
                    TextButton(onClick = { viewModel.clearExportedJson() }) { Text("Cancel") }
                }
            }
        )
    }

    LaunchedEffect(uiState.error) {
        uiState.error?.let { error ->
            snackbarHostState.showSnackbar(error)
            viewModel.clearError()
        }
    }

    val navBarPadding = WindowInsets.navigationBars.asPaddingValues()

    val showTorProgressFab = uiState.connectionState is ConnectionState.Connecting &&
            uiState.snowflakeBootstrapProgress in 0..99

    val sleepTimerActive = uiState.connectionState is ConnectionState.Connected &&
            uiState.sleepTimerRemainingSeconds > 0

    val dnsWarningActive = uiState.connectionState is ConnectionState.Connected &&
            uiState.dnsWarning != null

    val fabExtraPadding by animateDpAsState(
        targetValue = when {
            uiState.connectionState is ConnectionState.Connected && sleepTimerActive && dnsWarningActive -> 72.dp
            uiState.connectionState is ConnectionState.Connected && sleepTimerActive -> 52.dp
            uiState.connectionState is ConnectionState.Connected && dnsWarningActive -> 48.dp
            uiState.connectionState is ConnectionState.Connected -> 28.dp
            showTorProgressFab -> 30.dp
            else -> 0.dp
        },
        animationSpec = tween(300),
        label = "fabPadding"
    )

    // Helper: proceed with VPN permission check and connect
    fun proceedWithConnect(profile: ServerProfile? = null) {
        if (activity != null) {
            // In proxy-only mode, skip VPN permission check — no TUN interface is created,
            // so VpnService.prepare() is unnecessary and would fail when another app
            // holds "Always-on VPN".
            if (uiState.proxyOnlyMode) {
                if (profile != null) viewModel.connect(profile) else viewModel.connect()
                return
            }
            val vpnIntent = VpnService.prepare(activity)
            if (vpnIntent != null) {
                pendingConnect = true
                pendingProfile = profile
                pendingChain = null
                vpnPermissionLauncher.launch(vpnIntent)
            } else {
                if (profile != null) viewModel.connect(profile) else viewModel.connect()
            }
        }
    }

    // Helper: proceed with VPN permission check and connect a chain
    fun proceedWithChainConnect(chain: ProfileChain) {
        if (activity != null) {
            if (uiState.proxyOnlyMode) {
                viewModel.connectChain(chain)
                return
            }
            val vpnIntent = VpnService.prepare(activity)
            if (vpnIntent != null) {
                pendingConnect = true
                pendingChain = chain
                pendingProfile = null
                vpnPermissionLauncher.launch(vpnIntent)
            } else {
                viewModel.connectChain(chain)
            }
        }
    }

    // Helper to request VPN permission and connect
    fun requestConnectOrToggle() {
        when (uiState.connectionState) {
            is ConnectionState.Connected,
            is ConnectionState.Connecting,
            is ConnectionState.Error -> viewModel.disconnect()
            else -> {
                if (activity != null) {
                    // Check battery optimization on first connect
                    val prefs = context.getSharedPreferences("vpn_service_state", Context.MODE_PRIVATE)
                    val prompted = prefs.getBoolean("battery_opt_prompted", false)
                    val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
                    if (!prompted && !pm.isIgnoringBatteryOptimizations(context.packageName)) {
                        pendingConnectAfterBatteryPrompt = true
                        pendingProfileAfterBatteryPrompt = null
                        // If on Chains tab, remember the active chain for after the battery dialog
                        pendingChainAfterBatteryPrompt = if (selectedTab == 1 && hasChains) uiState.activeChain else null
                        showBatteryOptDialog = true
                        return
                    }

                    // If on Chains tab, connect the active chain; otherwise connect active profile
                    if (selectedTab == 1 && hasChains) {
                        val chain = uiState.activeChain
                        if (chain != null) {
                            proceedWithChainConnect(chain)
                        }
                    } else {
                        proceedWithConnect()
                    }
                }
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text(
                            text = "SlipNet",
                            style = MaterialTheme.typography.headlineSmall,
                            fontWeight = FontWeight.Bold
                        )
                        if (BuildConfig.FLAVOR == "lite") {
                            Text(
                                text = "Lite",
                                style = MaterialTheme.typography.labelLarge,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        if (BuildConfig.FLAVOR == "lite") {
                            IconButton(onClick = { showLiteInfoDialog = true }) {
                                Icon(
                                    Icons.Default.Info,
                                    contentDescription = "Lite version info",
                                    modifier = Modifier.size(20.dp)
                                )
                            }
                        }
                    }
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
                    IconButton(onClick = onNavigateToSettings) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                    // Overflow menu (three-dot, rightmost)
                    Box {
                        IconButton(onClick = { showOverflowMenu = true }) {
                            Icon(Icons.Default.MoreVert, contentDescription = "More")
                        }
                        DropdownMenu(
                            expanded = showOverflowMenu,
                            onDismissRequest = { showOverflowMenu = false }
                        ) {
                            DropdownMenuItem(
                                text = {
                                    Text(if (uiState.isPingRunning) "Stop Reachability Test" else "Test Server Reachability")
                                },
                                onClick = {
                                    showOverflowMenu = false
                                    viewModel.pingAllProfiles()
                                },
                                enabled = uiState.profiles.isNotEmpty()
                            )
                            DropdownMenuItem(
                                text = {
                                    Text(if (uiState.isPingRunning) "Stop Ping" else "Ping Servers")
                                },
                                onClick = {
                                    showOverflowMenu = false
                                    viewModel.pingAllProfilesSimple()
                                },
                                enabled = uiState.profiles.isNotEmpty()
                            )
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
                                text = { Text("Delete Duplicate Profiles") },
                                onClick = {
                                    showOverflowMenu = false
                                    showDeleteDuplicatesDialog = true
                                },
                                enabled = uiState.profiles.size > 1
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
                    hasProfile = uiState.activeProfile != null || uiState.activeChain != null || uiState.profiles.isNotEmpty(),
                    snowflakeBootstrapProgress = uiState.snowflakeBootstrapProgress,
                    onToggleConnection = { requestConnectOrToggle() },
                    modifier = Modifier.padding(
                        bottom = 24.dp + navBarPadding.calculateBottomPadding() + fabExtraPadding,
                        end = 8.dp
                    )
                )
            }
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        containerColor = MaterialTheme.colorScheme.background,
        contentWindowInsets = WindowInsets(0, 0, 0, 0)
    ) { paddingValues ->
        // Auto-switch to chains tab when a chain is connected
        LaunchedEffect(uiState.connectedChainId) {
            if (uiState.connectedChainId != null && hasChains) selectedTab = 1
        }

        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
        ) {
            Column(modifier = Modifier.fillMaxSize()) {
                // ── Tab Row (only when chains exist) ────────────────────
                if (hasChains) {
                    SingleChoiceSegmentedButtonRow(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 8.dp)
                    ) {
                        SegmentedButton(
                            selected = selectedTab == 0,
                            onClick = { selectedTab = 0 },
                            shape = SegmentedButtonDefaults.itemShape(0, 2)
                        ) { Text("Profiles") }
                        SegmentedButton(
                            selected = selectedTab == 1,
                            onClick = { selectedTab = 1 },
                            shape = SegmentedButtonDefaults.itemShape(1, 2)
                        ) { Text("Chains") }
                    }
                }

                // ── Tab Content ─────────────────────────────────────────
                when {
                    selectedTab == 1 && hasChains -> {
                        // ── Chains Tab ──────────────────────────────────
                        val chainListState = rememberLazyListState()
                        val reorderableChainState = rememberReorderableLazyListState(chainListState) { from, to ->
                            viewModel.moveChain(from.index, to.index)
                        }

                        LazyColumn(
                            state = chainListState,
                            contentPadding = PaddingValues(
                                start = 16.dp, end = 16.dp,
                                top = 8.dp,
                                bottom = 200.dp + navBarPadding.calculateBottomPadding()
                            ),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                            modifier = Modifier.fillMaxSize()
                        ) {
                            items(
                                items = uiState.chains,
                                key = { "chain_${it.id}" }
                            ) { chain ->
                                ReorderableItem(reorderableChainState, key = "chain_${chain.id}") { isDragging ->
                                    val elevation = if (isDragging) 8.dp else 0.dp

                                    ChainListItem(
                                        chain = chain,
                                        profiles = uiState.profiles,
                                        isSelected = uiState.activeChain?.id == chain.id,
                                        isConnected = uiState.connectedChainId == chain.id,
                                        onClick = { viewModel.setActiveChain(chain) },
                                        onEditClick = { onNavigateToEditChain(chain.id) },
                                        onDeleteClick = {
                                            val isConnected = uiState.connectedChainId == chain.id
                                            if (isConnected) {
                                                scope.launch {
                                                    snackbarHostState.showSnackbar(
                                                        "Disconnect VPN before deleting this chain"
                                                    )
                                                }
                                            } else {
                                                viewModel.deleteChain(chain)
                                            }
                                        },
                                        modifier = Modifier
                                            .longPressDraggableHandle()
                                            .shadow(elevation, RoundedCornerShape(12.dp))
                                            .zIndex(if (isDragging) 1f else 0f)
                                    )
                                }
                            }
                        }
                    }
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
                        // ── Profiles Tab ────────────────────────────────
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
                                        pingResult = uiState.pingResults[profile.id],
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
                                        onExportClick = {
                                            exportLockProfile = profile
                                            exportLockEnabled = false
                                            exportLockPassword = ""
                                            exportLockMode = "export"
                                        },
                                        onShareQrClick = {
                                            exportLockProfile = profile
                                            exportLockEnabled = false
                                            exportLockPassword = ""
                                            exportLockMode = "qr"
                                        },
                                        onPinClick = { viewModel.togglePinProfile(profile) },
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
            }

            // ── Connection Status Strip (bottom, behind FAB) ────────
            ConnectionStatusStrip(
                connectionState = uiState.connectionState,
                activeProfile = uiState.activeProfile,
                activeChain = uiState.activeChain,
                isProxyOnly = uiState.proxyOnlyMode,
                snowflakeBootstrapProgress = uiState.snowflakeBootstrapProgress,
                uploadSpeed = uiState.uploadSpeed,
                downloadSpeed = uiState.downloadSpeed,
                totalUpload = uiState.trafficStats.bytesSent,
                totalDownload = uiState.trafficStats.bytesReceived,
                sleepTimerRemainingSeconds = uiState.sleepTimerRemainingSeconds,
                onCancelSleepTimer = { viewModel.userCancelSleepTimer() },
                dnsWarning = uiState.dnsWarning,
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .padding(bottom = navBarPadding.calculateBottomPadding())
            )

            // Bottom sheet for adding profiles
            if (showAddMenu) {
                val sheetState = rememberModalBottomSheetState()
                ModalBottomSheet(
                    onDismissRequest = { showAddMenu = false },
                    sheetState = sheetState,
                    dragHandle = null
                ) {
                    Text(
                        text = "New Profile",
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.padding(start = 24.dp, top = 20.dp, bottom = 8.dp)
                    )
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
                        icon = Icons.Default.VisibilityOff,
                        title = "NoizDNS",
                        description = "DPI-evasion DNS tunnel",
                        onClick = {
                            showAddMenu = false
                            onNavigateToAddProfile(TunnelType.NOIZDNS.value)
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
                        icon = Icons.Default.Share,
                        title = "SOCKS5",
                        description = "Remote SOCKS5 proxy",
                        onClick = {
                            showAddMenu = false
                            onNavigateToAddProfile("socks5")
                        }
                    )
                    if (BuildConfig.INCLUDE_NAIVE) {
                        AddMenuOption(
                            icon = Icons.Default.Shield,
                            title = "NaiveProxy",
                            description = "Chromium HTTPS tunnel",
                            onClick = {
                                showAddMenu = false
                                onNavigateToAddProfile("naive")
                            }
                        )
                    }
                    if (BuildConfig.INCLUDE_TOR) {
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
                    HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                    AddMenuOption(
                        icon = Icons.Default.Link,
                        title = "Chain",
                        description = "Chain multiple profiles",
                        onClick = {
                            showAddMenu = false
                            onNavigateToAddChain()
                        }
                    )
                    AddMenuOption(
                        icon = Icons.Default.FileDownload,
                        title = "Import",
                        description = "",
                        onClick = {
                            showAddMenu = false
                            showImportDialog = true
                        }
                    )
                    Spacer(Modifier.height(24.dp))
                }
            }
        }
    }

    // ── Dialogs ─────────────────────────────────────────────────────────

    // Debug log sheet
    if (showLogSheet) {
        DebugLogSheet(onDismiss = { showLogSheet = false })
    }

    // Lite version info dialog
    if (showLiteInfoDialog) {
        AlertDialog(
            onDismissRequest = { showLiteInfoDialog = false },
            title = { Text("SlipNet Lite") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("SlipNet Lite is a lightweight version with a smaller app size.")
                    Text("Included protocols:", fontWeight = FontWeight.Bold)
                    Text("• Slipstream / Slipstream + SSH")
                    Text("• DNSTT / DNSTT + SSH")
                    Text("• NoizDNS / NoizDNS + SSH")
                    Text("• SSH")
                    Text("• DOH (DNS over HTTPS)")
                    Text("Not included (full version only):", fontWeight = FontWeight.Bold)
                    Text("• Tor (Snowflake)")
                    Text("• NaïveProxy / NaïveProxy + SSH")
                }
            },
            confirmButton = {
                TextButton(onClick = { showLiteInfoDialog = false }) {
                    Text("OK")
                }
            }
        )
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
        AlertDialog(
            onDismissRequest = { showDeleteAllDialog = false },
            title = { Text("Delete All Profiles") },
            text = {
                Text("Are you sure you want to delete all profiles? This cannot be undone.")
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

    // Delete duplicate profiles confirmation dialog
    if (showDeleteDuplicatesDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteDuplicatesDialog = false },
            title = { Text("Delete Duplicate Profiles") },
            text = {
                Text("This will remove profiles with identical connection settings, keeping one copy of each.")
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        viewModel.deleteDuplicateProfiles()
                        showDeleteDuplicatesDialog = false
                    }
                ) { Text("Delete Duplicates") }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteDuplicatesDialog = false }) { Text("Cancel") }
            }
        )
    }

    // Battery optimization dialog (shown once on first connect)
    if (showBatteryOptDialog) {
        AlertDialog(
            onDismissRequest = {
                showBatteryOptDialog = false
                // Mark as prompted so we don't ask again
                context.getSharedPreferences("vpn_service_state", Context.MODE_PRIVATE)
                    .edit().putBoolean("battery_opt_prompted", true).apply()
                // Proceed with connect regardless
                if (pendingConnectAfterBatteryPrompt) {
                    pendingConnectAfterBatteryPrompt = false
                    val chain = pendingChainAfterBatteryPrompt
                    if (chain != null) {
                        pendingChainAfterBatteryPrompt = null
                        proceedWithChainConnect(chain)
                    } else {
                        proceedWithConnect(pendingProfileAfterBatteryPrompt)
                        pendingProfileAfterBatteryPrompt = null
                    }
                }
            },
            title = { Text("Disable Battery Optimization") },
            text = {
                Text("For reliable VPN operation, disable battery optimization for SlipNet. " +
                     "Without this, Android may suspend the VPN when the screen is off.")
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showBatteryOptDialog = false
                        context.getSharedPreferences("vpn_service_state", Context.MODE_PRIVATE)
                            .edit().putBoolean("battery_opt_prompted", true).apply()
                        // Open battery optimization settings
                        try {
                            val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                                data = Uri.parse("package:${context.packageName}")
                            }
                            context.startActivity(intent)
                        } catch (_: Exception) {
                            try {
                                context.startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                            } catch (_: Exception) { }
                        }
                        // Proceed with connect
                        if (pendingConnectAfterBatteryPrompt) {
                            pendingConnectAfterBatteryPrompt = false
                            val chain = pendingChainAfterBatteryPrompt
                            if (chain != null) {
                                pendingChainAfterBatteryPrompt = null
                                proceedWithChainConnect(chain)
                            } else {
                                proceedWithConnect(pendingProfileAfterBatteryPrompt)
                                pendingProfileAfterBatteryPrompt = null
                            }
                        }
                    }
                ) { Text("Disable") }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        showBatteryOptDialog = false
                        context.getSharedPreferences("vpn_service_state", Context.MODE_PRIVATE)
                            .edit().putBoolean("battery_opt_prompted", true).apply()
                        // Proceed with connect without disabling
                        if (pendingConnectAfterBatteryPrompt) {
                            pendingConnectAfterBatteryPrompt = false
                            val chain = pendingChainAfterBatteryPrompt
                            if (chain != null) {
                                pendingChainAfterBatteryPrompt = null
                                proceedWithChainConnect(chain)
                            } else {
                                proceedWithConnect(pendingProfileAfterBatteryPrompt)
                                pendingProfileAfterBatteryPrompt = null
                            }
                        }
                    }
                ) { Text("Skip") }
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
                            text = if (profile.isLocked) "\u2022 ${profile.name} (Locked)" else "\u2022 ${profile.name}",
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

    // Export lock dialog
    exportLockProfile?.let { profile ->
        // If profile is already locked+sharable, skip dialog and re-export directly
        if (profile.isLocked && profile.allowSharing) {
            LaunchedEffect(profile) {
                if (exportLockMode == "qr") {
                    viewModel.showQrCodeLockedReExport(profile)
                } else {
                    viewModel.reExportLockedProfile(profile)
                }
                exportLockProfile = null
            }
        } else if (!profile.isLocked) {
            AlertDialog(
                onDismissRequest = { exportLockProfile = null },
                title = { Text(if (exportLockMode == "qr") "Share QR Code" else "Export Profile") },
                text = {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        // SSH security warning when sharing with root credentials
                        if (profile.sshUsername.equals("root", ignoreCase = true) &&
                            profile.tunnelType in listOf(
                                TunnelType.SSH, TunnelType.DNSTT_SSH,
                                TunnelType.SLIPSTREAM_SSH, TunnelType.NOIZDNS_SSH,
                                TunnelType.NAIVE_SSH
                            )
                        ) {
                            Card(
                                colors = CardDefaults.cardColors(
                                    containerColor = MaterialTheme.colorScheme.errorContainer
                                )
                            ) {
                                Row(
                                    modifier = Modifier.padding(12.dp),
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    Icon(
                                        Icons.Default.Warning,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.error,
                                        modifier = Modifier.size(20.dp)
                                    )
                                    Text(
                                        text = "This profile contains SSH credentials. Avoid using a root account or password auth — anyone with this profile can access your server. Use a restricted user with key-based authentication instead.",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onErrorContainer
                                    )
                                }
                            }
                        }

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                text = "Lock for distribution",
                                style = MaterialTheme.typography.bodyMedium
                            )
                            Switch(
                                checked = exportLockEnabled,
                                onCheckedChange = {
                                    exportLockEnabled = it
                                    if (!it) exportHideResolvers = false
                                }
                            )
                        }
                        if (exportLockEnabled) {
                            OutlinedTextField(
                                value = exportLockPassword,
                                onValueChange = { exportLockPassword = it },
                                label = { Text("Lock Password") },
                                visualTransformation = if (exportLockPasswordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                                trailingIcon = {
                                    IconButton(onClick = { exportLockPasswordVisible = !exportLockPasswordVisible }) {
                                        Icon(
                                            imageVector = if (exportLockPasswordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                            contentDescription = if (exportLockPasswordVisible) "Hide password" else "Show password"
                                        )
                                    }
                                },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    text = "Hide DNS resolver",
                                    style = MaterialTheme.typography.bodyMedium
                                )
                                Switch(
                                    checked = exportHideResolvers,
                                    onCheckedChange = { exportHideResolvers = it }
                                )
                            }
                            if (exportHideResolvers) {
                                Text(
                                    text = "Resolver addresses will be hidden. Old app versions won't be able to import this profile.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }

                            // Expiration toggle + days
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    text = "Set expiration",
                                    style = MaterialTheme.typography.bodyMedium
                                )
                                Switch(
                                    checked = exportLockExpiry,
                                    onCheckedChange = { exportLockExpiry = it }
                                )
                            }
                            if (exportLockExpiry) {
                                OutlinedTextField(
                                    value = exportLockExpiryDays,
                                    onValueChange = { exportLockExpiryDays = it.filter { c -> c.isDigit() } },
                                    label = { Text("Expires in (days)") },
                                    singleLine = true,
                                    modifier = Modifier.fillMaxWidth()
                                )
                            }

                            // Allow re-sharing
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    text = "Allow re-sharing",
                                    style = MaterialTheme.typography.bodyMedium
                                )
                                Switch(
                                    checked = exportLockAllowSharing,
                                    onCheckedChange = { exportLockAllowSharing = it }
                                )
                            }

                            // Target device ID
                            OutlinedTextField(
                                value = exportLockDeviceId,
                                onValueChange = { exportLockDeviceId = it },
                                label = { Text("Target Device ID (optional)") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )
                            Text(
                                text = "Device ID can be found in Settings on the target device",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(start = 4.dp, top = 4.dp)
                            )
                        }
                    }
                },
                confirmButton = {
                    TextButton(
                        onClick = {
                            val p = exportLockProfile ?: return@TextButton
                            if (exportLockEnabled) {
                                val expiryMs = if (exportLockExpiry) {
                                    val days = exportLockExpiryDays.toLongOrNull() ?: 30
                                    System.currentTimeMillis() + days * 24 * 60 * 60 * 1000L
                                } else 0L
                                if (exportLockMode == "qr") {
                                    viewModel.showQrCodeLocked(p, exportLockPassword, expiryMs, exportLockAllowSharing, exportLockDeviceId, exportHideResolvers)
                                } else {
                                    viewModel.exportProfileLocked(p, exportLockPassword, expiryMs, exportLockAllowSharing, exportLockDeviceId, exportHideResolvers)
                                }
                            } else {
                                if (exportLockMode == "qr") {
                                    viewModel.showQrCode(p, exportHideResolvers)
                                } else {
                                    viewModel.exportProfile(p, exportHideResolvers)
                                }
                            }
                            exportHideResolvers = false
                            exportLockProfile = null
                        },
                        enabled = !exportLockEnabled || exportLockPassword.isNotBlank()
                    ) { Text(if (exportLockMode == "qr") "Share" else "Export") }
                },
                dismissButton = {
                    TextButton(onClick = { exportLockProfile = null }) { Text("Cancel") }
                }
            )
        }
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
                                clipboardManager.getText()?.text?.let { clip ->
                                    if (clip.isNotBlank()) importText = clip
                                }
                            }
                        ) { Text("Paste") }
                        TextButton(
                            onClick = {
                                importFileLauncher.launch(arrayOf("text/plain", "*/*"))
                                showImportDialog = false
                                importText = ""
                            }
                        ) { Text("File") }
                        TextButton(
                            onClick = {
                                showImportDialog = false
                                importText = ""
                                qrScanLauncher.launch(ScanOptions().apply {
                                    setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                    setPrompt("")
                                    setBeepEnabled(false)
                                    setCaptureActivity(QrScannerActivity::class.java)
                                })
                            }
                        ) { Text("QR Code") }
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

    // First launch About dialog
    if (uiState.showFirstLaunchAbout) {
        AlertDialog(
            onDismissRequest = { viewModel.dismissFirstLaunchAbout() },
            title = { Text("Welcome to SlipNet") },
            text = { AboutDialogContent() },
            confirmButton = {
                TextButton(onClick = { viewModel.dismissFirstLaunchAbout() }) {
                    Text("Get Started")
                }
            }
        )
    }

    // Update available dialog
    uiState.availableUpdate?.let { update ->
        val context = LocalContext.current
        AlertDialog(
            onDismissRequest = { viewModel.dismissUpdate() },
            title = { Text("Update Available") },
            text = {
                Text("Version ${update.versionName} is available. You are on ${BuildConfig.VERSION_NAME}.")
            },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.dismissUpdate()
                    val intent = android.content.Intent(
                        android.content.Intent.ACTION_VIEW,
                        android.net.Uri.parse(update.downloadUrl)
                    )
                    context.startActivity(intent)
                }) {
                    Text("Download")
                }
            },
            dismissButton = {
                Row {
                    TextButton(onClick = { viewModel.skipUpdate() }) {
                        Text("Skip")
                    }
                    TextButton(onClick = { viewModel.dismissUpdate() }) {
                        Text("Later")
                    }
                }
            }
        )
    }
}

// ── ChainListItem ───────────────────────────────────────────────────────

@Composable
private fun ChainListItem(
    chain: ProfileChain,
    profiles: List<ServerProfile>,
    isSelected: Boolean = false,
    isConnected: Boolean = false,
    onClick: () -> Unit,
    onEditClick: () -> Unit,
    onDeleteClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val layerNames = chain.profileIds.mapNotNull { id ->
        profiles.find { it.id == id }?.let { "${it.name} (${it.tunnelType.displayName})" }
    }

    val borderColor = when {
        isConnected -> ConnectedGreen
        isSelected -> MaterialTheme.colorScheme.primary
        else -> null
    }
    val cardShape = RoundedCornerShape(12.dp)

    val containerColor = when {
        isConnected -> ConnectedGreen.copy(alpha = 0.08f)
        isSelected -> MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f)
        else -> MaterialTheme.colorScheme.surface
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .then(
                if (borderColor != null) Modifier.border(2.dp, borderColor, cardShape)
                else Modifier
            )
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = containerColor),
        shape = cardShape,
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 16.dp, end = 4.dp, top = 12.dp, bottom = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(2.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = chain.name,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false)
                    )
                    if (isConnected) {
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Connected",
                            style = MaterialTheme.typography.labelSmall,
                            color = ConnectedGreen,
                            modifier = Modifier
                                .background(
                                    ConnectedGreen.copy(alpha = 0.15f),
                                    RoundedCornerShape(4.dp)
                                )
                                .padding(horizontal = 6.dp, vertical = 2.dp)
                        )
                    } else if (isSelected) {
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Selected",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier
                                .background(
                                    MaterialTheme.colorScheme.primaryContainer,
                                    RoundedCornerShape(4.dp)
                                )
                                .padding(horizontal = 6.dp, vertical = 2.dp)
                        )
                    }
                }
                Text(
                    text = layerNames.joinToString(" \u2192 "),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = "${chain.profileIds.size}-layer chain",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(
                    onClick = onEditClick,
                    modifier = Modifier.size(36.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Edit,
                        contentDescription = "Edit chain",
                        modifier = Modifier.size(18.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                IconButton(
                    onClick = onDeleteClick,
                    enabled = !isConnected,
                    modifier = Modifier.size(36.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Delete,
                        contentDescription = "Delete chain",
                        modifier = Modifier.size(18.dp),
                        tint = if (!isConnected)
                            MaterialTheme.colorScheme.onSurfaceVariant
                        else
                            MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.38f)
                    )
                }
            }
        }
    }
}

// ── ConnectionStatusStrip ───────────────────────────────────────────────

@Composable
private fun ConnectionStatusStrip(
    connectionState: ConnectionState,
    activeProfile: ServerProfile?,
    activeChain: ProfileChain? = null,
    isProxyOnly: Boolean,
    snowflakeBootstrapProgress: Int,
    uploadSpeed: Long = 0,
    downloadSpeed: Long = 0,
    totalUpload: Long = 0,
    totalDownload: Long = 0,
    sleepTimerRemainingSeconds: Int = 0,
    onCancelSleepTimer: () -> Unit = {},
    dnsWarning: String? = null,
    modifier: Modifier = Modifier
) {
    val isConnected = connectionState is ConnectionState.Connected
    val isConnecting = connectionState is ConnectionState.Connecting ||
            connectionState is ConnectionState.Disconnecting
    val isError = connectionState is ConnectionState.Error
    val showTorProgress = connectionState is ConnectionState.Connecting &&
            snowflakeBootstrapProgress in 0..99

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
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
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
                                connectionState.chainName ?: connectionState.profile.name
                            isError && connectionState is ConnectionState.Error ->
                                connectionState.message
                            activeChain != null -> activeChain.name
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

            // Traffic stats: live speed + totals when connected, session totals when disconnected
            AnimatedVisibility(
                visible = isConnected,
                enter = expandVertically(animationSpec = tween(300)) + fadeIn(animationSpec = tween(300)),
                exit = shrinkVertically(animationSpec = tween(200)) + fadeOut(animationSpec = tween(200))
            ) {
                Column {
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(start = 22.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        // Live speed
                        Text(
                            text = "\u2191 ${TrafficStats.formatBytes(uploadSpeed)}/s",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.width(16.dp))
                        Text(
                            text = "\u2193 ${TrafficStats.formatBytes(downloadSpeed)}/s",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.weight(1f))
                        // Session totals
                        Text(
                            text = "\u2191 ${TrafficStats.formatBytes(totalUpload)}  \u2193 ${TrafficStats.formatBytes(totalDownload)}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                        )
                    }
                }
            }

            // DNS warning
            AnimatedVisibility(
                visible = isConnected && dnsWarning != null,
                enter = expandVertically(animationSpec = tween(300)) + fadeIn(animationSpec = tween(300)),
                exit = shrinkVertically(animationSpec = tween(200)) + fadeOut(animationSpec = tween(200))
            ) {
                Text(
                    text = dnsWarning ?: "",
                    style = MaterialTheme.typography.labelSmall,
                    color = Color(0xFFFF9800),
                    modifier = Modifier.padding(start = 22.dp, top = 6.dp)
                )
            }

            // Sleep timer countdown
            AnimatedVisibility(
                visible = isConnected && sleepTimerRemainingSeconds > 0,
                enter = expandVertically(animationSpec = tween(300)) + fadeIn(animationSpec = tween(300)),
                exit = shrinkVertically(animationSpec = tween(200)) + fadeOut(animationSpec = tween(200))
            ) {
                Column {
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(start = 22.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.Timer,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Sleep: ${formatCountdown(sleepTimerRemainingSeconds)}",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.weight(1f))
                        TextButton(
                            onClick = onCancelSleepTimer,
                            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                            modifier = Modifier.height(28.dp)
                        ) {
                            Text(
                                text = "Cancel",
                                style = MaterialTheme.typography.labelSmall
                            )
                        }
                    }
                }
            }

            // Tor bootstrap progress
            AnimatedVisibility(
                visible = showTorProgress,
                enter = expandVertically(animationSpec = tween(300)) + fadeIn(animationSpec = tween(300)),
                exit = shrinkVertically(animationSpec = tween(200)) + fadeOut(animationSpec = tween(200))
            ) {
                Column {
                    Spacer(modifier = Modifier.height(12.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        LinearProgressIndicator(
                            progress = { snowflakeBootstrapProgress / 100f },
                            modifier = Modifier
                                .weight(1f)
                                .height(6.dp)
                                .clip(RoundedCornerShape(3.dp)),
                            color = ConnectingOrange,
                            trackColor = ConnectingOrange.copy(alpha = 0.2f),
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            text = "Tor: $snowflakeBootstrapProgress%",
                            style = MaterialTheme.typography.labelSmall,
                            color = ConnectingOrange
                        )
                    }
                }
            }
        }
    }
}

private fun formatCountdown(totalSeconds: Int): String {
    return "%d:%02d".format(totalSeconds / 60, totalSeconds % 60)
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
            if (description.isNotEmpty()) {
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
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
