package app.slipnet.presentation.settings

import app.slipnet.BuildConfig
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.CallSplit
import androidx.compose.material.icons.filled.Compress
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.SettingsEthernet
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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import app.slipnet.data.local.datastore.DarkMode
import app.slipnet.data.local.datastore.SplitTunnelingMode
import app.slipnet.data.local.datastore.SshCipher
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.filled.Lan
import androidx.compose.material.icons.filled.Numbers
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.ui.text.input.KeyboardType
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

    // Proxy settings - local state for port text field to avoid cursor jumps from async DataStore round-trip
    var proxyPort by remember { mutableStateOf(uiState.proxyListenPort.toString()) }
    val addressOptions = getAddressOptions()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .verticalScroll(scrollState)
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp)
        ) {
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
                    value = uiState.sshMaxChannels,
                    valueRange = 4f..64f,
                    steps = 14,
                    valueFormatter = { "${it.roundToInt()}" },
                    onValueChange = { viewModel.setSshMaxChannels(it.roundToInt()) }
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

            Spacer(modifier = Modifier.height(8.dp))

            // App Info
            Text(
                text = "SlipNet VPN v${BuildConfig.VERSION_NAME}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.align(Alignment.CenterHorizontally)
            )

            Spacer(modifier = Modifier.height(8.dp))
        }
    }

    // Dark Mode Dialog
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
    value: Int,
    valueRange: ClosedFloatingPointRange<Float>,
    steps: Int,
    valueFormatter: (Float) -> String,
    onValueChange: (Float) -> Unit
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
                modifier = Modifier
                    .weight(1f)
                    .padding(horizontal = 16.dp)
            )
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
