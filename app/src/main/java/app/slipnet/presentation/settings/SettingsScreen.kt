package app.slipnet.presentation.settings

import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import androidx.compose.material3.CircularProgressIndicator
import android.provider.Settings
import app.slipnet.BuildConfig
import app.slipnet.presentation.common.components.AboutDialogContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
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
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.BatteryAlert
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.CallSplit
import androidx.compose.material.icons.filled.Compress
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Remove
import androidx.compose.material.icons.filled.Timer
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.Favorite
import androidx.compose.material.icons.filled.Help
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.TravelExplore
import androidx.compose.material.icons.filled.SettingsEthernet
import androidx.compose.material.icons.filled.RestartAlt
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import app.slipnet.data.local.datastore.DarkMode
import app.slipnet.data.local.datastore.DomainRoutingMode
import app.slipnet.data.local.datastore.SplitTunnelingMode
import app.slipnet.data.local.datastore.SshCipher
import app.slipnet.tunnel.GeoBypassCountry
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.filled.Lan
import androidx.compose.material.icons.filled.Numbers
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.input.KeyboardType
import java.net.Inet4Address
import java.net.NetworkInterface
import kotlin.math.roundToInt

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onNavigateBack: () -> Unit,
    onNavigateToScanner: (() -> Unit)? = null,
    onNavigateToAppSelector: () -> Unit = {},
    viewModel: SettingsViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    val scrollState = rememberScrollState()

    var showDarkModeDialog by remember { mutableStateOf(false) }
    var showSshCipherDialog by remember { mutableStateOf(false) }
    var showSplitModeDialog by remember { mutableStateOf(false) }
    var showDomainRoutingModeDialog by remember { mutableStateOf(false) }
    var showDomainManagementDialog by remember { mutableStateOf(false) }
    var showGeoBypassCountryDialog by remember { mutableStateOf(false) }
    var showAboutDialog by remember { mutableStateOf(false) }
    var showRemoteDnsDialog by remember { mutableStateOf(false) }
    var showGlobalResolverDialog by remember { mutableStateOf(false) }
    var showMtuDialog by remember { mutableStateOf(false) }
    var showResetSettingsDialog by remember { mutableStateOf(false) }

    // Proxy settings - local state for port text fields to avoid cursor jumps from async DataStore round-trip
    var proxyPort by remember { mutableStateOf(uiState.proxyListenPort.toString()) }
    var httpProxyPort by remember { mutableStateOf(uiState.httpProxyPort.toString()) }

    // Sync local state when DataStore values load (initial default → actual saved value)
    LaunchedEffect(uiState.proxyListenPort) {
        proxyPort = uiState.proxyListenPort.toString()
    }
    LaunchedEffect(uiState.httpProxyPort) {
        httpProxyPort = uiState.httpProxyPort.toString()
    }

    val addressOptions = getAddressOptions()

    // Battery optimization state
    val context = LocalContext.current
    var isBatteryOptimized by remember { mutableStateOf(true) }
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                val pm = context.getSystemService(android.content.Context.POWER_SERVICE) as PowerManager
                isBatteryOptimized = !pm.isIgnoringBatteryOptimizations(context.packageName)
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    val navBarPadding = WindowInsets.navigationBars.asPaddingValues()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = { showAboutDialog = true }) {
                        Icon(Icons.Default.Help, contentDescription = "About")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent
                )
            )
        },
        containerColor = MaterialTheme.colorScheme.background,
        contentWindowInsets = WindowInsets(0, 0, 0, 0)
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .verticalScroll(scrollState)
                .padding(
                    start = 16.dp,
                    end = 16.dp,
                    top = 12.dp,
                    bottom = 12.dp + navBarPadding.calculateBottomPadding()
                ),
            verticalArrangement = Arrangement.spacedBy(20.dp)
        ) {
            // Donate Card
            DonateCard()

            // Connection Settings
            SettingsSection(title = "Connection") {
                SwitchSettingItem(
                    icon = Icons.Default.PowerSettingsNew,
                    title = "Auto-connect on boot",
                    description = "Automatically connect when device starts",
                    checked = uiState.autoConnectOnBoot,
                    onCheckedChange = { viewModel.setAutoConnectOnBoot(it) }
                )

                SettingsDivider()

                SwitchSettingItem(
                    icon = Icons.Default.SettingsEthernet,
                    title = "Proxy-only mode",
                    description = "Expose SOCKS5 proxy without creating VPN tunnel",
                    checked = uiState.proxyOnlyMode,
                    onCheckedChange = { viewModel.setProxyOnlyMode(it) }
                )

                SettingsDivider()

                SwitchSettingItem(
                    icon = Icons.Default.Shield,
                    title = "Kill switch",
                    description = "Block all traffic if VPN connection drops",
                    checked = uiState.killSwitch,
                    onCheckedChange = { viewModel.setKillSwitch(it) }
                )

                SettingsDivider()

                SwitchSettingItem(
                    icon = Icons.Default.Sync,
                    title = "Auto-reconnect",
                    description = "Automatically reconnect if VPN drops unexpectedly",
                    checked = uiState.autoReconnect,
                    onCheckedChange = { viewModel.setAutoReconnect(it) }
                )

                SettingsDivider()

                StepperSettingItem(
                    icon = Icons.Default.Timer,
                    title = "Sleep timer",
                    description = "Auto-disconnect after a set time",
                    value = uiState.sleepTimerMinutes,
                    step = 5,
                    range = 0..120,
                    valueFormatter = { if (it == 0) "Off" else "$it min" },
                    onValueChange = { viewModel.setSleepTimerMinutes(it) }
                )

                SettingsDivider()

                ClickableSettingItem(
                    icon = Icons.Default.BatteryAlert,
                    title = "Battery optimization",
                    description = if (isBatteryOptimized) "Not exempted — VPN may disconnect in background"
                                  else "Exempted — VPN will run reliably in background",
                    onClick = {
                        if (isBatteryOptimized) {
                            try {
                                val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                                    data = Uri.parse("package:${context.packageName}")
                                }
                                context.startActivity(intent)
                            } catch (_: Exception) {
                                val intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                                context.startActivity(intent)
                            }
                        } else {
                            // Already exempted — open system battery settings so user can change it
                            val intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                            context.startActivity(intent)
                        }
                    }
                )
            }

            // Tools Section
            if (onNavigateToScanner != null) {
                SettingsSection(title = "Tools") {
                    ClickableSettingItem(
                        icon = Icons.Default.Search,
                        title = "DNS Resolver Scanner",
                        description = "Find working DNS resolvers for your profiles",
                        onClick = onNavigateToScanner
                    )
                }
            }

            // Proxy Settings
            SettingsSection(
                title = "Proxy Settings",
                subtitle = "Changes apply on next connection"
            ) {
                AddressSettingItem(
                    value = uiState.proxyListenAddress,
                    options = addressOptions,
                    onValueChange = { viewModel.setProxyListenAddress(it) }
                )

                SettingsDivider()

                TextFieldSettingItem(
                    icon = Icons.Default.Numbers,
                    title = "Listen Port",
                    value = proxyPort,
                    placeholder = "1080",
                    supportingText = "Local SOCKS5 proxy port",
                    keyboardType = KeyboardType.Number,
                    onValueChange = { text ->
                        proxyPort = text
                        text.toIntOrNull()?.let { viewModel.setProxyListenPort(it) }
                    }
                )

                SettingsDivider()

                SwitchSettingItem(
                    icon = Icons.Default.Lan,
                    title = "HTTP proxy",
                    description = "Enable HTTP proxy for devices that don't support SOCKS5",
                    checked = uiState.httpProxyEnabled,
                    onCheckedChange = { viewModel.setHttpProxyEnabled(it) }
                )

                if (uiState.httpProxyEnabled) {
                    SettingsDivider()

                    TextFieldSettingItem(
                        icon = Icons.Default.Numbers,
                        title = "HTTP Proxy Port",
                        value = httpProxyPort,
                        placeholder = "8080",
                        supportingText = "Local HTTP proxy port",
                        keyboardType = KeyboardType.Number,
                        onValueChange = { text ->
                            httpProxyPort = text
                            text.toIntOrNull()?.let { viewModel.setHttpProxyPort(it) }
                        }
                    )
                }

                if (uiState.proxyListenAddress == "0.0.0.0") {
                    HotspotInfoCard(
                        socksPort = uiState.proxyListenPort,
                        httpProxyEnabled = uiState.httpProxyEnabled,
                        httpProxyPort = uiState.httpProxyPort
                    )
                } else {
                    LocalProxyInfoCard(
                        listenAddress = uiState.proxyListenAddress,
                        socksPort = uiState.proxyListenPort,
                        httpProxyEnabled = uiState.httpProxyEnabled,
                        httpProxyPort = uiState.httpProxyPort
                    )
                }
            }

            // Network Settings
            SettingsSection(
                title = "Network",
                subtitle = "Changes apply on next connection"
            ) {
                SwitchSettingItem(
                    icon = Icons.Default.Block,
                    title = "Disable QUIC",
                    description = "Block QUIC protocol to force TCP (faster page loads over tunnels)",
                    checked = uiState.disableQuic,
                    onCheckedChange = { viewModel.setDisableQuic(it) }
                )

                SettingsDivider()

                ClickableSettingItem(
                    icon = Icons.Default.SettingsEthernet,
                    title = "VPN MTU",
                    description = "VPN packet size: ${uiState.vpnMtu}. Lower values improve compatibility on mobile networks.",
                    onClick = { showMtuDialog = true }
                )

                SettingsDivider()

                SwitchSettingItem(
                    icon = Icons.Default.Lan,
                    title = "Append HTTP Proxy to VPN",
                    description = "Route app traffic through HTTP proxy directly, bypassing TUN for better speeds (Android 10+)",
                    checked = uiState.appendHttpProxyToVpn,
                    onCheckedChange = { viewModel.setAppendHttpProxyToVpn(it) }
                )

                if (uiState.appendHttpProxyToVpn && !uiState.httpProxyEnabled) {
                    Text(
                        text = "To also share the HTTP proxy with other devices, enable \"HTTP proxy\" in Proxy Settings above.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(start = 56.dp, end = 16.dp, bottom = 8.dp)
                    )
                }
            }

            // DNS Settings
            SettingsSection(
                title = "DNS",
                subtitle = "Changes apply on next connection"
            ) {
                SwitchSettingItem(
                    icon = Icons.Default.Language,
                    title = "Global DNS resolver override",
                    description = if (uiState.globalResolverEnabled) {
                        val list = uiState.globalResolverList.ifBlank { "Not set" }
                        "Active: $list"
                    } else {
                        "Use profile resolvers (default)"
                    },
                    checked = uiState.globalResolverEnabled,
                    onCheckedChange = { viewModel.setGlobalResolverEnabled(it) }
                )
                if (uiState.globalResolverEnabled) {
                    ClickableSettingItem(
                        icon = Icons.Default.Language,
                        title = "Global resolver IPs",
                        description = uiState.globalResolverList.ifBlank { "Tap to set resolver IPs" },
                        onClick = { showGlobalResolverDialog = true }
                    )
                }
                ClickableSettingItem(
                    icon = Icons.Default.Language,
                    title = "Remote DNS server",
                    description = if (uiState.remoteDnsMode == "custom") {
                        val primary = uiState.customRemoteDns.ifBlank { "8.8.8.8" }
                        val fallback = uiState.customRemoteDnsFallback.ifBlank { "1.1.1.1" }
                        "Custom ($primary, $fallback)"
                    } else {
                        "Default (8.8.8.8, 1.1.1.1)"
                    },
                    onClick = { showRemoteDnsDialog = true }
                )
            }

            // Domain Routing Settings
            SettingsSection(
                title = "Domain Routing",
                subtitle = "Changes apply on next connection"
            ) {
                SwitchSettingItem(
                    icon = Icons.Default.Language,
                    title = "Enable domain routing",
                    description = "Route specific domains through or around the VPN",
                    checked = uiState.domainRoutingEnabled,
                    onCheckedChange = { viewModel.setDomainRoutingEnabled(it) }
                )

                if (uiState.domainRoutingEnabled) {
                    SettingsDivider()

                    ClickableSettingItem(
                        icon = Icons.Default.FilterList,
                        title = "Routing mode",
                        description = when (uiState.domainRoutingMode) {
                            DomainRoutingMode.BYPASS -> "Listed domains bypass VPN"
                            DomainRoutingMode.ONLY_VPN -> "Only listed domains use VPN"
                        },
                        onClick = { showDomainRoutingModeDialog = true }
                    )

                    SettingsDivider()

                    ClickableSettingItem(
                        icon = Icons.Default.TravelExplore,
                        title = "Manage domains",
                        description = "${uiState.domainRoutingDomains.size} domains configured",
                        onClick = { showDomainManagementDialog = true }
                    )
                }
            }

            // Geo-Bypass Settings
            SettingsSection(
                title = "Geo-Bypass",
                subtitle = "Changes apply on next connection"
            ) {
                SwitchSettingItem(
                    icon = Icons.Default.Public,
                    title = "Enable geo-bypass",
                    description = "Route domestic traffic directly, bypass VPN for local sites",
                    checked = uiState.geoBypassEnabled,
                    onCheckedChange = { viewModel.setGeoBypassEnabled(it) }
                )

                if (uiState.geoBypassEnabled) {
                    SettingsDivider()

                    ClickableSettingItem(
                        icon = Icons.Default.Language,
                        title = "Country",
                        description = uiState.geoBypassCountry.displayName,
                        onClick = { showGeoBypassCountryDialog = true }
                    )
                }
            }

            // Split Tunneling Settings
            SettingsSection(
                title = "Split Tunneling",
                subtitle = "Changes apply on next connection"
            ) {
                SwitchSettingItem(
                    icon = Icons.Default.CallSplit,
                    title = "Enable split tunneling",
                    description = "Choose which apps use the VPN",
                    checked = uiState.splitTunnelingEnabled,
                    onCheckedChange = { viewModel.setSplitTunnelingEnabled(it) }
                )

                if (uiState.splitTunnelingEnabled) {
                    SettingsDivider()

                    ClickableSettingItem(
                        icon = Icons.Default.FilterList,
                        title = "Mode",
                        description = when (uiState.splitTunnelingMode) {
                            SplitTunnelingMode.DISALLOW -> "Selected apps bypass VPN"
                            SplitTunnelingMode.ALLOW -> "Only selected apps use VPN"
                        },
                        onClick = { showSplitModeDialog = true }
                    )

                    SettingsDivider()

                    ClickableSettingItem(
                        icon = Icons.Default.Apps,
                        title = "Select apps",
                        description = "${uiState.splitTunnelingApps.size} apps selected",
                        onClick = onNavigateToAppSelector
                    )
                }
            }

            // SSH Tunnel Settings
            SettingsSection(
                title = "SSH Tunnel",
                subtitle = "Changes apply on next connection"
            ) {
                ClickableSettingItem(
                    icon = Icons.Default.Lock,
                    title = "Cipher",
                    description = when (uiState.sshCipher) {
                        SshCipher.AUTO -> "Auto (Fastest)"
                        SshCipher.AES_128_GCM -> "AES-128-GCM"
                        SshCipher.CHACHA20 -> "ChaCha20-Poly1305"
                        SshCipher.AES_128_CTR -> "AES-128-CTR (Legacy)"
                    },
                    onClick = { showSshCipherDialog = true }
                )

                SettingsDivider()

                SwitchSettingItem(
                    icon = Icons.Default.Compress,
                    title = "Compression",
                    description = "Compress data through SSH (helps on slow links, hurts with HTTPS)",
                    checked = uiState.sshCompression,
                    onCheckedChange = { viewModel.setSshCompression(it) }
                )

                SettingsDivider()

                SliderSettingItem(
                    icon = Icons.Default.Hub,
                    title = "Max Channels",
                    subtitle = if (!uiState.sshMaxChannelsIsCustom) "Auto (adapts per tunnel type)" else null,
                    value = uiState.sshMaxChannels,
                    valueRange = 1f..64f,
                    steps = 63,
                    valueFormatter = { "${it.roundToInt()}" },
                    onValueChange = { viewModel.setSshMaxChannels(it.roundToInt()) },
                    onReset = if (uiState.sshMaxChannelsIsCustom) {{ viewModel.resetSshMaxChannelsToAuto() }} else null
                )
            }

            // Appearance Settings
            SettingsSection(title = "Appearance") {
                ClickableSettingItem(
                    icon = Icons.Default.DarkMode,
                    title = "Dark mode",
                    description = when (uiState.darkMode) {
                        DarkMode.LIGHT -> "Light"
                        DarkMode.DARK -> "Dark"
                        DarkMode.AMOLED -> "AMOLED Dark"
                        DarkMode.SYSTEM -> "Follow system"
                    },
                    onClick = { showDarkModeDialog = true }
                )
            }

            // Debug Settings
            SettingsSection(title = "Debug") {
                SwitchSettingItem(
                    icon = Icons.Default.BugReport,
                    title = "Debug logging",
                    description = "Enable verbose logging for troubleshooting",
                    checked = uiState.debugLogging,
                    onCheckedChange = { viewModel.setDebugLogging(it) }
                )
            }

            // Reset Settings
            SettingsSection(title = "Reset") {
                ClickableSettingItem(
                    icon = Icons.Default.RestartAlt,
                    title = "Reset all settings",
                    description = "Restore all settings to their default values",
                    onClick = { showResetSettingsDialog = true }
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Device ID
            val deviceId = remember {
                app.slipnet.util.DeviceIdUtil.getScrambledDeviceId(context)
            }
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Center
            ) {
                Text(
                    text = "Device ID: $deviceId",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                IconButton(
                    onClick = {
                        val clipboardManager = context.getSystemService(android.content.ClipboardManager::class.java)
                        clipboardManager?.setPrimaryClip(android.content.ClipData.newPlainText("Device ID", deviceId))
                    },
                    modifier = Modifier.size(32.dp)
                ) {
                    Icon(
                        Icons.Default.ContentCopy,
                        contentDescription = "Copy device ID",
                        modifier = Modifier.size(14.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            // App Info + Check for updates
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = "SlipNet VPN v${BuildConfig.VERSION_NAME}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(4.dp))
                when (uiState.updateCheckResult) {
                    UpdateCheckResult.CHECKING -> {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(14.dp),
                                strokeWidth = 2.dp
                            )
                            Text(
                                text = "Checking...",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                    UpdateCheckResult.UP_TO_DATE -> {
                        Text(
                            text = "You're up to date",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                    else -> {
                        TextButton(onClick = { viewModel.checkForUpdate() }) {
                            Text(
                                text = "Check for updates",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))
        }
    }

    // Dark Mode Dialog
    if (showMtuDialog) {
        val mtuPresets = listOf(
            1500 to "Best throughput on clean networks",
            1400 to "Recommended for most mobile networks",
            1350 to "Conservative, for double-NAT or PPPoE",
            1280 to "Maximum compatibility"
        )
        val isCustom = mtuPresets.none { it.first == uiState.vpnMtu }
        var customMtuText by remember { mutableStateOf(if (isCustom) uiState.vpnMtu.toString() else "") }
        var useCustom by remember { mutableStateOf(isCustom) }
        AlertDialog(
            onDismissRequest = { showMtuDialog = false },
            title = { Text("VPN MTU") },
            text = {
                Column {
                    mtuPresets.forEach { (mtu, desc) ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .clickable {
                                    useCustom = false
                                    viewModel.setVpnMtu(mtu)
                                    showMtuDialog = false
                                }
                                .padding(vertical = 12.dp, horizontal = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = !useCustom && uiState.vpnMtu == mtu,
                                onClick = {
                                    useCustom = false
                                    viewModel.setVpnMtu(mtu)
                                    showMtuDialog = false
                                }
                            )
                            Column(modifier = Modifier.padding(start = 8.dp)) {
                                Text(text = "$mtu")
                                Text(
                                    text = desc,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .clickable { useCustom = true }
                            .padding(vertical = 12.dp, horizontal = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = useCustom,
                            onClick = { useCustom = true }
                        )
                        OutlinedTextField(
                            value = customMtuText,
                            onValueChange = { customMtuText = it.filter { c -> c.isDigit() }.take(5) },
                            enabled = useCustom,
                            label = { Text("Custom") },
                            placeholder = { Text("512–1500") },
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            singleLine = true,
                            modifier = Modifier
                                .padding(start = 8.dp)
                                .fillMaxWidth()
                        )
                    }
                }
            },
            confirmButton = {
                if (useCustom) {
                    TextButton(
                        onClick = {
                            val value = customMtuText.toIntOrNull()
                            if (value != null && value in 512..1500) {
                                viewModel.setVpnMtu(value)
                                showMtuDialog = false
                            }
                        }
                    ) {
                        Text("Apply")
                    }
                }
            },
            dismissButton = {
                TextButton(onClick = { showMtuDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    if (showDarkModeDialog) {
        AlertDialog(
            onDismissRequest = { showDarkModeDialog = false },
            title = { Text("Dark Mode") },
            text = {
                Column {
                    DarkMode.entries.forEach { mode ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .clickable {
                                    viewModel.setDarkMode(mode)
                                    showDarkModeDialog = false
                                }
                                .padding(vertical = 12.dp, horizontal = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = uiState.darkMode == mode,
                                onClick = {
                                    viewModel.setDarkMode(mode)
                                    showDarkModeDialog = false
                                }
                            )
                            Text(
                                text = when (mode) {
                                    DarkMode.LIGHT -> "Light"
                                    DarkMode.DARK -> "Dark"
                                    DarkMode.AMOLED -> "AMOLED Dark"
                                    DarkMode.SYSTEM -> "Follow system"
                                },
                                modifier = Modifier.padding(start = 8.dp)
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showDarkModeDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    // Split Tunneling Mode Dialog
    if (showSplitModeDialog) {
        AlertDialog(
            onDismissRequest = { showSplitModeDialog = false },
            title = { Text("Split Tunneling Mode") },
            text = {
                Column {
                    SplitTunnelingMode.entries.forEach { mode ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .clickable {
                                    viewModel.setSplitTunnelingMode(mode)
                                    showSplitModeDialog = false
                                }
                                .padding(vertical = 12.dp, horizontal = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = uiState.splitTunnelingMode == mode,
                                onClick = {
                                    viewModel.setSplitTunnelingMode(mode)
                                    showSplitModeDialog = false
                                }
                            )
                            Column(modifier = Modifier.padding(start = 8.dp)) {
                                Text(
                                    text = when (mode) {
                                        SplitTunnelingMode.DISALLOW -> "Bypass"
                                        SplitTunnelingMode.ALLOW -> "Only"
                                    }
                                )
                                Text(
                                    text = when (mode) {
                                        SplitTunnelingMode.DISALLOW -> "Selected apps bypass VPN"
                                        SplitTunnelingMode.ALLOW -> "Only selected apps use VPN"
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showSplitModeDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    // Domain Routing Mode Dialog
    if (showDomainRoutingModeDialog) {
        AlertDialog(
            onDismissRequest = { showDomainRoutingModeDialog = false },
            title = { Text("Domain Routing Mode") },
            text = {
                Column {
                    DomainRoutingMode.entries.forEach { mode ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .clickable {
                                    viewModel.setDomainRoutingMode(mode)
                                    showDomainRoutingModeDialog = false
                                }
                                .padding(vertical = 12.dp, horizontal = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = uiState.domainRoutingMode == mode,
                                onClick = {
                                    viewModel.setDomainRoutingMode(mode)
                                    showDomainRoutingModeDialog = false
                                }
                            )
                            Column(modifier = Modifier.padding(start = 8.dp)) {
                                Text(
                                    text = when (mode) {
                                        DomainRoutingMode.BYPASS -> "Bypass VPN"
                                        DomainRoutingMode.ONLY_VPN -> "Only VPN"
                                    }
                                )
                                Text(
                                    text = when (mode) {
                                        DomainRoutingMode.BYPASS -> "Listed domains connect directly"
                                        DomainRoutingMode.ONLY_VPN -> "Only listed domains use the VPN"
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showDomainRoutingModeDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    // Domain Management Dialog
    if (showDomainManagementDialog) {
        DomainManagementDialog(
            domains = uiState.domainRoutingDomains,
            onAddDomain = { viewModel.addDomainRoutingDomain(it) },
            onRemoveDomain = { viewModel.removeDomainRoutingDomain(it) },
            onDismiss = { showDomainManagementDialog = false }
        )
    }

    // Geo-Bypass Country Dialog
    if (showGeoBypassCountryDialog) {
        AlertDialog(
            onDismissRequest = { showGeoBypassCountryDialog = false },
            title = { Text("Select Country") },
            text = {
                Column {
                    GeoBypassCountry.entries.forEach { country ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .clickable {
                                    viewModel.setGeoBypassCountry(country)
                                    showGeoBypassCountryDialog = false
                                }
                                .padding(vertical = 12.dp, horizontal = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = uiState.geoBypassCountry == country,
                                onClick = {
                                    viewModel.setGeoBypassCountry(country)
                                    showGeoBypassCountryDialog = false
                                }
                            )
                            Text(
                                text = country.displayName,
                                modifier = Modifier.padding(start = 8.dp)
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showGeoBypassCountryDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    // Global Resolver Override Dialog
    if (showGlobalResolverDialog) {
        var resolverText by remember { mutableStateOf(uiState.globalResolverList) }
        AlertDialog(
            onDismissRequest = { showGlobalResolverDialog = false },
            title = { Text("Global DNS Resolvers") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        "Enter DNS resolver IPs, one per line or comma-separated. These will override the resolvers in all DNS tunnel profiles (DNSTT, NoizDNS, Slipstream).",
                        style = MaterialTheme.typography.bodySmall
                    )
                    OutlinedTextField(
                        value = resolverText,
                        onValueChange = { resolverText = it },
                        modifier = Modifier.fillMaxWidth().height(120.dp),
                        placeholder = { Text("e.g. 8.8.8.8, 1.1.1.1") },
                        singleLine = false,
                        maxLines = 5
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.setGlobalResolverList(resolverText.trim())
                    showGlobalResolverDialog = false
                }) { Text("Save") }
            },
            dismissButton = {
                TextButton(onClick = { showGlobalResolverDialog = false }) { Text("Cancel") }
            }
        )
    }

    // Remote DNS Dialog
    if (showRemoteDnsDialog) {
        RemoteDnsDialog(
            currentMode = uiState.remoteDnsMode,
            currentCustomDns = uiState.customRemoteDns,
            currentCustomDnsFallback = uiState.customRemoteDnsFallback,
            onSelectDefault = {
                viewModel.setRemoteDnsMode("default")
                showRemoteDnsDialog = false
            },
            onSelectCustom = { dns, fallback ->
                viewModel.setRemoteDnsMode("custom")
                viewModel.setCustomRemoteDns(dns)
                viewModel.setCustomRemoteDnsFallback(fallback)
                showRemoteDnsDialog = false
            },
            onDismiss = { showRemoteDnsDialog = false }
        )
    }

    // SSH Cipher Dialog
    if (showSshCipherDialog) {
        AlertDialog(
            onDismissRequest = { showSshCipherDialog = false },
            title = { Text("SSH Cipher") },
            text = {
                Column {
                    SshCipher.entries.forEach { cipher ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .clickable {
                                    viewModel.setSshCipher(cipher)
                                    showSshCipherDialog = false
                                }
                                .padding(vertical = 12.dp, horizontal = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = uiState.sshCipher == cipher,
                                onClick = {
                                    viewModel.setSshCipher(cipher)
                                    showSshCipherDialog = false
                                }
                            )
                            Text(
                                text = cipher.displayName,
                                modifier = Modifier.padding(start = 8.dp)
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showSshCipherDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    // Reset Settings Confirmation Dialog
    if (showResetSettingsDialog) {
        AlertDialog(
            onDismissRequest = { showResetSettingsDialog = false },
            title = { Text("Reset all settings?") },
            text = {
                Text("This will restore all settings to their default values. Your profiles and connection stats will not be affected.")
            },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.resetAllSettings()
                    showResetSettingsDialog = false
                }) {
                    Text("Reset", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { showResetSettingsDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    // About Dialog
    if (showAboutDialog) {
        AlertDialog(
            onDismissRequest = { showAboutDialog = false },
            title = { Text("About SlipNet") },
            text = { AboutDialogContent() },
            confirmButton = {
                TextButton(onClick = { showAboutDialog = false }) {
                    Text("Close")
                }
            }
        )
    }

    // Update available dialog
    if (uiState.updateCheckResult == UpdateCheckResult.UPDATE_AVAILABLE) {
        val update = viewModel.availableUpdate
        if (update != null) {
            val context = LocalContext.current
            AlertDialog(
                onDismissRequest = { viewModel.clearUpdateCheck() },
                title = { Text("Update Available") },
                text = {
                    Text("Version ${update.versionName} is available. You are on ${BuildConfig.VERSION_NAME}.")
                },
                confirmButton = {
                    TextButton(onClick = {
                        viewModel.clearUpdateCheck()
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
                    TextButton(onClick = { viewModel.clearUpdateCheck() }) {
                        Text("Later")
                    }
                }
            )
        }
    }
}

@Composable
private fun DomainManagementDialog(
    domains: Set<String>,
    onAddDomain: (String) -> Unit,
    onRemoveDomain: (String) -> Unit,
    onDismiss: () -> Unit
) {
    var newDomain by remember { mutableStateOf("") }
    val sortedDomains = remember(domains) { domains.sorted() }

    val addDomain = {
        val trimmed = newDomain.trim().lowercase()
        if (trimmed.isNotEmpty()) {
            onAddDomain(trimmed)
            newDomain = ""
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Manage Domains") },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth()
            ) {
                // Add domain input
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = newDomain,
                        onValueChange = { newDomain = it },
                        placeholder = { Text("e.g., google.com") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions.Default,
                        keyboardActions = KeyboardActions(onDone = { addDomain() }),
                        modifier = Modifier.weight(1f)
                    )
                    IconButton(onClick = { addDomain() }) {
                        Icon(Icons.Default.Add, contentDescription = "Add domain")
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                if (sortedDomains.isEmpty()) {
                    Text(
                        text = "No domains configured",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(vertical = 8.dp)
                    )
                } else {
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(240.dp)
                    ) {
                        items(sortedDomains) { domain ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = domain,
                                    style = MaterialTheme.typography.bodyMedium,
                                    modifier = Modifier.weight(1f)
                                )
                                IconButton(
                                    onClick = { onRemoveDomain(domain) },
                                    modifier = Modifier.size(32.dp)
                                ) {
                                    Icon(
                                        Icons.Default.Delete,
                                        contentDescription = "Remove $domain",
                                        tint = MaterialTheme.colorScheme.error,
                                        modifier = Modifier.size(18.dp)
                                    )
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { addDomain(); onDismiss() }) {
                Text("Done")
            }
        }
    )
}

@Composable
private fun RemoteDnsDialog(
    currentMode: String,
    currentCustomDns: String,
    currentCustomDnsFallback: String,
    onSelectDefault: () -> Unit,
    onSelectCustom: (String, String) -> Unit,
    onDismiss: () -> Unit
) {
    var selectedMode by remember { mutableStateOf(currentMode) }
    var customDns by remember { mutableStateOf(currentCustomDns) }
    var customDnsFallback by remember { mutableStateOf(currentCustomDnsFallback) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Remote DNS Server") },
        text = {
            Column {
                Text(
                    text = "DNS servers used on the remote side of the tunnel for resolving domain names.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = 12.dp)
                )

                // Default option
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .clickable { selectedMode = "default" }
                        .padding(vertical = 12.dp, horizontal = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RadioButton(
                        selected = selectedMode == "default",
                        onClick = { selectedMode = "default" }
                    )
                    Column(modifier = Modifier.padding(start = 8.dp)) {
                        Text("Default (8.8.8.8, 1.1.1.1)")
                        Text(
                            text = "Google primary, Cloudflare fallback",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                // Custom option
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .clickable { selectedMode = "custom" }
                        .padding(vertical = 12.dp, horizontal = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RadioButton(
                        selected = selectedMode == "custom",
                        onClick = { selectedMode = "custom" }
                    )
                    Text(
                        text = "Custom",
                        modifier = Modifier.padding(start = 8.dp)
                    )
                }

                if (selectedMode == "custom") {
                    OutlinedTextField(
                        value = customDns,
                        onValueChange = { customDns = it },
                        placeholder = { Text("e.g., 9.9.9.9") },
                        supportingText = { Text("Primary DNS server") },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(start = 40.dp, top = 4.dp)
                    )

                    OutlinedTextField(
                        value = customDnsFallback,
                        onValueChange = { customDnsFallback = it },
                        placeholder = { Text("e.g., 8.8.8.8") },
                        supportingText = { Text("Fallback DNS server") },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(start = 40.dp, top = 4.dp)
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    if (selectedMode == "default") {
                        onSelectDefault()
                    } else {
                        onSelectCustom(customDns.trim(), customDnsFallback.trim())
                    }
                }
            ) {
                Text("OK")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

@Composable
private fun SettingsSection(
    title: String,
    subtitle: String? = null,
    content: @Composable () -> Unit
) {
    Column {
        Row(
            modifier = Modifier.padding(start = 4.dp, bottom = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary
            )
            if (subtitle != null) {
                Text(
                    text = " · $subtitle",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainerLow
            ),
            elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
        ) {
            Column(
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)
            ) {
                content()
            }
        }
    }
}

@Composable
private fun SettingsDivider() {
    HorizontalDivider(
        modifier = Modifier.padding(vertical = 12.dp),
        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
    )
}

@Composable
private fun SwitchSettingItem(
    icon: ImageVector,
    title: String,
    description: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(24.dp)
        )
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(horizontal = 16.dp)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.bodyLarge
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange
        )
    }
}

@Composable
private fun ClickableSettingItem(
    icon: ImageVector,
    title: String,
    description: String,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .clickable { onClick() }
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(24.dp)
        )
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(horizontal = 16.dp)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.bodyLarge
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun SliderSettingItem(
    icon: ImageVector,
    title: String,
    subtitle: String? = null,
    value: Int,
    valueRange: ClosedFloatingPointRange<Float>,
    steps: Int,
    valueFormatter: (Float) -> String,
    onValueChange: (Float) -> Unit,
    onReset: (() -> Unit)? = null
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(24.dp)
            )
            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(horizontal = 16.dp)
            ) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.bodyLarge
                )
                if (subtitle != null) {
                    Text(
                        text = subtitle,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            if (onReset != null) {
                TextButton(onClick = onReset) {
                    Text("Auto", style = MaterialTheme.typography.labelSmall)
                }
            }
            Text(
                text = valueFormatter(value.toFloat()),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.primary
            )
        }
        Spacer(modifier = Modifier.height(4.dp))
        Slider(
            value = value.toFloat(),
            onValueChange = onValueChange,
            valueRange = valueRange,
            steps = steps,
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 40.dp, top = 4.dp)
        )
    }
}

@Composable
private fun StepperSettingItem(
    icon: ImageVector,
    title: String,
    description: String,
    value: Int,
    step: Int,
    range: IntRange,
    valueFormatter: (Int) -> String,
    onValueChange: (Int) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(24.dp)
        )
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(horizontal = 16.dp)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.bodyLarge
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Row(
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(
                onClick = { onValueChange((value - step).coerceIn(range)) },
                enabled = value > range.first,
                modifier = Modifier.size(36.dp)
            ) {
                Icon(
                    Icons.Default.Remove,
                    contentDescription = "Decrease",
                    modifier = Modifier.size(20.dp)
                )
            }
            Text(
                text = valueFormatter(value),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.primary,
                textAlign = TextAlign.Center,
                modifier = Modifier.widthIn(min = 48.dp)
            )
            IconButton(
                onClick = { onValueChange((value + step).coerceIn(range)) },
                enabled = value < range.last,
                modifier = Modifier.size(36.dp)
            ) {
                Icon(
                    Icons.Default.Add,
                    contentDescription = "Increase",
                    modifier = Modifier.size(20.dp)
                )
            }
        }
    }
}

@Composable
/**
 * Detect available network addresses for the listen address picker.
 * Returns list of (label, ip) pairs.
 */
private fun getAddressOptions(): List<Pair<String, String>> {
    return listOf(
        "All interfaces" to "0.0.0.0",
        "Localhost" to "127.0.0.1"
    )
}

/**
 * Detect the device's shareable IP address.
 * Priority: hotspot interface > Wi-Fi > any non-loopback IPv4 interface.
 * Returns a pair of (ip, isHotspot) or null if no suitable interface is found.
 */
private fun detectShareableIp(): Pair<String, Boolean>? {
    try {
        val interfaces = NetworkInterface.getNetworkInterfaces()?.toList() ?: return null
        val hotspotPrefixes = listOf("wlan1", "ap0", "swlan0", "softap", "wlan-ap", "rndis")

        // First try hotspot interfaces
        for (iface in interfaces) {
            if (!iface.isUp) continue
            if (hotspotPrefixes.any { iface.name.startsWith(it) }) {
                val ip = iface.inetAddresses.toList()
                    .firstOrNull { it is Inet4Address && !it.isLoopbackAddress }
                    ?.hostAddress
                if (ip != null) return ip to true
            }
        }

        // Fall back to Wi-Fi (wlan0)
        for (iface in interfaces) {
            if (!iface.isUp) continue
            if (iface.name.startsWith("wlan0") || iface.name.startsWith("wlan")) {
                val ip = iface.inetAddresses.toList()
                    .firstOrNull { it is Inet4Address && !it.isLoopbackAddress }
                    ?.hostAddress
                if (ip != null) return ip to false
            }
        }

        // Fall back to any non-loopback IPv4 interface (mobile data, USB, ethernet, etc.)
        for (iface in interfaces) {
            if (!iface.isUp || iface.isLoopback) continue
            val ip = iface.inetAddresses.toList()
                .firstOrNull { it is Inet4Address && !it.isLoopbackAddress }
                ?.hostAddress
            if (ip != null) return ip to false
        }
    } catch (_: Exception) { }
    return null
}

@Composable
private fun HotspotInfoCard(
    socksPort: Int,
    httpProxyEnabled: Boolean = false,
    httpProxyPort: Int = 8080
) {
    val shareableIp = remember { detectShareableIp() }
    if (shareableIp == null) return

    val (ip, isHotspot) = shareableIp
    val socksAddress = "$ip:$socksPort"
    val httpAddress = "$ip:$httpProxyPort"
    val copyText = if (httpProxyEnabled) "SOCKS5: $socksAddress | HTTP: $httpAddress" else socksAddress
    val clipboardManager = LocalClipboardManager.current

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isHotspot)
                MaterialTheme.colorScheme.primaryContainer
            else
                MaterialTheme.colorScheme.surfaceContainerHigh
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Default.Wifi,
                contentDescription = null,
                tint = if (isHotspot)
                    MaterialTheme.colorScheme.onPrimaryContainer
                else
                    MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(20.dp)
            )
            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(horizontal = 12.dp)
            ) {
                Text(
                    text = if (isHotspot) "Hotspot proxy address" else "Device IP",
                    style = MaterialTheme.typography.labelMedium,
                    color = if (isHotspot)
                        MaterialTheme.colorScheme.onPrimaryContainer
                    else
                        MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = "SOCKS5: $socksAddress",
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (isHotspot)
                        MaterialTheme.colorScheme.onPrimaryContainer
                    else
                        MaterialTheme.colorScheme.onSurface
                )
                if (httpProxyEnabled) {
                    Text(
                        text = "HTTP: $httpAddress",
                        style = MaterialTheme.typography.bodyMedium,
                        color = if (isHotspot)
                            MaterialTheme.colorScheme.onPrimaryContainer
                        else
                            MaterialTheme.colorScheme.onSurface
                    )
                }
                if (isHotspot) {
                    Text(
                        text = "Use as proxy on connected devices",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
                    )
                } else {
                    Text(
                        text = "Enable hotspot to share with other devices",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            IconButton(
                onClick = { clipboardManager.setText(AnnotatedString(copyText)) },
                modifier = Modifier.size(32.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.ContentCopy,
                    contentDescription = "Copy address",
                    tint = if (isHotspot)
                        MaterialTheme.colorScheme.onPrimaryContainer
                    else
                        MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(18.dp)
                )
            }
        }
    }
}

@Composable
private fun LocalProxyInfoCard(
    listenAddress: String,
    socksPort: Int,
    httpProxyEnabled: Boolean = false,
    httpProxyPort: Int = 8080
) {
    val socksAddress = "$listenAddress:$socksPort"
    val httpAddress = "$listenAddress:$httpProxyPort"
    val copyText = if (httpProxyEnabled) "SOCKS5: $socksAddress | HTTP: $httpAddress" else socksAddress
    val clipboardManager = LocalClipboardManager.current

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Default.SettingsEthernet,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(20.dp)
            )
            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(horizontal = 12.dp)
            ) {
                Text(
                    text = "Proxy address",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = "SOCKS5: $socksAddress",
                    style = MaterialTheme.typography.bodyMedium
                )
                if (httpProxyEnabled) {
                    Text(
                        text = "HTTP: $httpAddress",
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
                Text(
                    text = "Configure this in your app's proxy settings",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            IconButton(
                onClick = { clipboardManager.setText(AnnotatedString(copyText)) },
                modifier = Modifier.size(32.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.ContentCopy,
                    contentDescription = "Copy address",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(18.dp)
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AddressSettingItem(
    value: String,
    options: List<Pair<String, String>>,
    onValueChange: (String) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }

    // Find the label for the current value, if it matches a known option
    val displayText = options.find { it.second == value }?.let { (label, ip) ->
        if (label == "All interfaces" || label == "Localhost") "$label ($ip)" else "$label: $ip"
    } ?: value

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Default.Lan,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(24.dp)
            )
            Text(
                text = "Listen Address",
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.padding(start = 16.dp)
            )
        }
        Spacer(modifier = Modifier.height(8.dp))
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = it },
            modifier = Modifier.padding(start = 40.dp)
        ) {
            OutlinedTextField(
                value = displayText,
                onValueChange = { },
                readOnly = true,
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .menuAnchor()
            )

            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false }
            ) {
                options.forEach { (label, ip) ->
                    DropdownMenuItem(
                        text = {
                            Text(
                                text = "$label ($ip)",
                                style = MaterialTheme.typography.bodyMedium
                            )
                        },
                        onClick = {
                            onValueChange(ip)
                            expanded = false
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun TextFieldSettingItem(
    icon: ImageVector,
    title: String,
    value: String,
    placeholder: String,
    supportingText: String,
    keyboardType: KeyboardType = KeyboardType.Text,
    onValueChange: (String) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(24.dp)
            )
            Text(
                text = title,
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.padding(start = 16.dp)
            )
        }
        Spacer(modifier = Modifier.height(8.dp))
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            placeholder = { Text(placeholder) },
            supportingText = { Text(supportingText) },
            keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
            singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 40.dp)
        )
    }
}

@Composable
private fun DonateCard() {
    val clipboardManager = LocalClipboardManager.current
    val donationAddress = ""
    var showDonateDialog by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { showDonateDialog = true },
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.4f)
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Default.Favorite,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(20.dp)
            )
            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(horizontal = 12.dp)
            ) {
                Text(
                    text = "Support SlipNet",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = "Help keep this project free and maintained",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Icon(
                imageVector = Icons.Default.Favorite,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.5f),
                modifier = Modifier.size(16.dp)
            )
        }
    }

    if (showDonateDialog) {
        AlertDialog(
            onDismissRequest = { showDonateDialog = false },
            title = { Text("Support SlipNet") },
            text = {
                Column(
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = "SlipNet is free, source-available, and built to fight internet censorship. No ads, no data collection, no subscriptions. Your donation helps keep this tool free and improving for everyone who needs it.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
                    Text(
                        text = "USDT (BEP20 / ERC20 / Arbitrum)",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = donationAddress,
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.weight(1f),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        IconButton(
                            onClick = {
                                clipboardManager.setText(AnnotatedString(donationAddress))
                            },
                            modifier = Modifier.size(32.dp)
                        ) {
                            Icon(
                                Icons.Default.ContentCopy,
                                contentDescription = "Copy address",
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }
                    Text(
                        text = "Even a small amount makes a difference. Thank you.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = { showDonateDialog = false }) {
                    Text("Close")
                }
            }
        )
    }
}
