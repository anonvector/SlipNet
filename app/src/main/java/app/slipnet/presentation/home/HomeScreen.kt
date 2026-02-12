package app.slipnet.presentation.home

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.net.VpnService
import androidx.core.content.FileProvider
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Power
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TunnelType
import app.slipnet.presentation.profiles.EditProfileViewModel
import app.slipnet.presentation.theme.ConnectedGreen
import app.slipnet.tunnel.DOH_SERVERS
import app.slipnet.presentation.theme.ConnectingOrange
import app.slipnet.presentation.theme.DisconnectedRed

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
fun HomeScreen(
    onNavigateToProfiles: () -> Unit,
    onNavigateToSettings: () -> Unit,
    viewModel: HomeViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current
    val activity = context.findActivity()

    var pendingConnect by remember { mutableStateOf(false) }
    var pendingProfile by remember { mutableStateOf<ServerProfile?>(null) }
    var showShareDialog by remember { mutableStateOf(false) }
    var showLogSheet by remember { mutableStateOf(false) }

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

    LaunchedEffect(uiState.error) {
        uiState.error?.let { error ->
            snackbarHostState.showSnackbar(error)
            viewModel.clearError()
        }
    }

    val navBarPadding = WindowInsets.navigationBars.asPaddingValues()

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
                    IconButton(onClick = onNavigateToSettings) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent
                )
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        containerColor = MaterialTheme.colorScheme.background,
        contentWindowInsets = WindowInsets(0, 0, 0, 0)
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
            contentPadding = PaddingValues(
                bottom = navBarPadding.calculateBottomPadding()
            ),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Hero Connection Section
            item {
                ConnectionHero(
                    connectionState = uiState.connectionState,
                    hasProfile = uiState.activeProfile != null || uiState.profiles.isNotEmpty(),
                    snowflakeBootstrapProgress = uiState.snowflakeBootstrapProgress,
                    isProxyOnly = uiState.proxyOnlyMode,
                    onConnectClick = {
                        when (uiState.connectionState) {
                            is ConnectionState.Connected,
                            is ConnectionState.Connecting -> {
                                viewModel.disconnect()
                            }
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
                )
            }

            // Profiles Section
            item {
                ProfilesSection(
                    profiles = uiState.profiles,
                    connectionState = uiState.connectionState,
                    onProfileClick = { profile ->
                        viewModel.setActiveProfile(profile)
                    },
                    onManageClick = onNavigateToProfiles,
                    modifier = Modifier.padding(horizontal = 20.dp)
                )
            }
        }
    }

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
}

@Composable
private fun ConnectionHero(
    connectionState: ConnectionState,
    hasProfile: Boolean,
    snowflakeBootstrapProgress: Int = -1,
    isProxyOnly: Boolean = false,
    onConnectClick: () -> Unit,
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

    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(top = 8.dp, bottom = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // Power Button
        PowerButton(
            isConnected = isConnected,
            isConnecting = isConnecting,
            statusColor = statusColor,
            enabled = hasProfile && connectionState !is ConnectionState.Disconnecting,
            onClick = onConnectClick
        )

        Spacer(modifier = Modifier.height(24.dp))

        // Status Text
        Text(
            text = when {
                isConnected && isProxyOnly -> "Proxy Active"
                isConnected -> "Connected"
                connectionState is ConnectionState.Connecting -> "Connecting..."
                connectionState is ConnectionState.Disconnecting -> "Disconnecting..."
                isError -> "Connection Failed"
                else -> "Not Connected"
            },
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.SemiBold,
            color = if (isConnected) statusColor else MaterialTheme.colorScheme.onBackground
        )

        // Snowflake bootstrap progress
        if (connectionState is ConnectionState.Connecting && snowflakeBootstrapProgress in 0..99) {
            Spacer(modifier = Modifier.height(12.dp))
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.padding(horizontal = 48.dp)
            ) {
                Text(
                    text = "Tor: $snowflakeBootstrapProgress%",
                    style = MaterialTheme.typography.bodySmall,
                    color = ConnectingOrange
                )
                Spacer(modifier = Modifier.height(6.dp))
                LinearProgressIndicator(
                    progress = { snowflakeBootstrapProgress / 100f },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(4.dp),
                    color = ConnectingOrange,
                    trackColor = MaterialTheme.colorScheme.surfaceVariant,
                )
            }
        }

        Spacer(modifier = Modifier.height(4.dp))

        // Subtitle
        Text(
            text = when {
                isConnected && connectionState is ConnectionState.Connected ->
                    connectionState.profile.name
                isError && connectionState is ConnectionState.Error ->
                    connectionState.message
                !hasProfile -> "Add a profile to connect"
                else -> "Tap to connect"
            },
            style = MaterialTheme.typography.bodyMedium,
            color = if (isError) DisconnectedRed else MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(horizontal = 32.dp)
        )
    }
}

@Composable
private fun PowerButton(
    isConnected: Boolean,
    isConnecting: Boolean,
    statusColor: Color,
    enabled: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
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

    val buttonSize = 160.dp
    val outerRingSize = 180.dp

    Box(
        modifier = modifier,
        contentAlignment = Alignment.Center
    ) {
        // Outer pulsing ring (only when connecting)
        if (isConnecting) {
            Box(
                modifier = Modifier
                    .size(outerRingSize)
                    .scale(pulseScale)
                    .clip(CircleShape)
                    .border(
                        width = 3.dp,
                        color = statusColor.copy(alpha = 0.5f),
                        shape = CircleShape
                    )
            )
        }

        // Outer ring
        Box(
            modifier = Modifier
                .size(outerRingSize)
                .clip(CircleShape)
                .border(
                    width = if (isConnected || isConnecting) 3.dp else 2.dp,
                    color = if (isConnected || isConnecting) statusColor else MaterialTheme.colorScheme.outlineVariant,
                    shape = CircleShape
                )
        )

        // Main button
        Surface(
            modifier = Modifier
                .size(buttonSize)
                .clip(CircleShape)
                .clickable(enabled = enabled) { onClick() },
            shape = CircleShape,
            color = if (isConnected) {
                statusColor.copy(alpha = 0.15f)
            } else {
                MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
            },
            tonalElevation = if (isConnected) 0.dp else 2.dp
        ) {
            Box(
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Default.PowerSettingsNew,
                    contentDescription = if (isConnected) "Disconnect" else "Connect",
                    modifier = Modifier.size(64.dp),
                    tint = when {
                        isConnected -> statusColor
                        isConnecting -> statusColor
                        enabled -> MaterialTheme.colorScheme.onSurfaceVariant
                        else -> MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)
                    }
                )
            }
        }
    }
}

@Composable
private fun ProfilesSection(
    profiles: List<ServerProfile>,
    connectionState: ConnectionState,
    onProfileClick: (ServerProfile) -> Unit,
    onManageClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(modifier = modifier.fillMaxWidth()) {
        // Header
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Profiles",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            Surface(
                onClick = onManageClick,
                shape = RoundedCornerShape(8.dp),
                color = Color.Transparent
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Manage",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Icon(
                        imageVector = Icons.Default.ChevronRight,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                        tint = MaterialTheme.colorScheme.primary
                    )
                }
            }
        }

        if (profiles.isEmpty()) {
            // Empty State
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onManageClick() }
                        .padding(32.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Box(
                        modifier = Modifier
                            .size(56.dp)
                            .clip(CircleShape)
                            .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.Add,
                            contentDescription = null,
                            modifier = Modifier.size(28.dp),
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "Add your first profile",
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Medium
                    )
                    Text(
                        text = "Configure a server to get started",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } else {
            // Profile List — recently connected first
            Column(
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                val sortedProfiles = profiles.sortedWith(
                    compareByDescending<ServerProfile> { it.isActive }
                        .thenByDescending { it.lastConnectedAt }
                )
                sortedProfiles.take(3).forEach { profile ->
                    val isConnected = connectionState is ConnectionState.Connected &&
                            connectionState.profile.id == profile.id

                    ProfileCard(
                        profile = profile,
                        isSelected = profile.isActive,
                        isConnected = isConnected,
                        onClick = { onProfileClick(profile) }
                    )
                }

                if (profiles.size > 3) {
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        onClick = onManageClick,
                        shape = RoundedCornerShape(12.dp),
                        color = Color.Transparent
                    ) {
                        Text(
                            text = "View all ${profiles.size} profiles",
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 12.dp),
                            textAlign = TextAlign.Center
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ProfileCard(
    profile: ServerProfile,
    isSelected: Boolean,
    isConnected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val borderStroke = when {
        isConnected -> androidx.compose.foundation.BorderStroke(1.5.dp, ConnectedGreen.copy(alpha = 0.5f))
        isSelected -> androidx.compose.foundation.BorderStroke(1.5.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.5f))
        else -> null
    }

    val cardColor = when {
        isConnected -> ConnectedGreen.copy(alpha = 0.1f)
        isSelected -> MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f)
        else -> MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
    }

    val iconBackground = when {
        isConnected -> ConnectedGreen.copy(alpha = 0.15f)
        isSelected -> MaterialTheme.colorScheme.primaryContainer
        else -> MaterialTheme.colorScheme.surface
    }

    val iconTint = when {
        isConnected -> ConnectedGreen
        isSelected -> MaterialTheme.colorScheme.primary
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }

    Surface(
        modifier = modifier.fillMaxWidth(),
        onClick = onClick,
        shape = RoundedCornerShape(12.dp),
        color = cardColor,
        border = borderStroke
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Icon
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(CircleShape)
                    .background(iconBackground),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = if (isConnected || isSelected) Icons.Default.Check else Icons.Outlined.Shield,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp),
                    tint = iconTint
                )
            }

            Spacer(modifier = Modifier.width(12.dp))

            // Info
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = profile.name,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = when (profile.tunnelType) {
                        TunnelType.DOH -> DOH_SERVERS.firstOrNull { it.url == profile.dohUrl }?.name
                            ?: profile.dohUrl
                        TunnelType.SSH -> "${profile.domain}:${profile.sshPort}"
                        TunnelType.DNSTT_SSH -> "${profile.domain} via SSH"
                        TunnelType.SNOWFLAKE -> "Tor Network"
                        else -> profile.domain
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = when (profile.tunnelType) {
                        TunnelType.SNOWFLAKE -> EditProfileViewModel.detectBridgeType(profile.torBridgeLines).displayName
                        else -> profile.tunnelType.displayName
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            // Status indicator
            if (isConnected) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(ConnectedGreen)
                )
            }
        }
    }
}

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
            // Single APK — share directly
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
            // Split APKs (Android Studio install) — bundle into .apks zip
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
