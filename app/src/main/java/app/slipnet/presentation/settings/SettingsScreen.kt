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
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Timer
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
import app.slipnet.data.local.datastore.BufferSize
import app.slipnet.data.local.datastore.DarkMode
import kotlin.math.roundToInt

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onNavigateBack: () -> Unit,
    onNavigateToScanner: (() -> Unit)? = null,
    viewModel: SettingsViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    val scrollState = rememberScrollState()

    var showDarkModeDialog by remember { mutableStateOf(false) }
    var showBufferSizeDialog by remember { mutableStateOf(false) }

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
            }

            // Network Optimization Settings
            SettingsSection(
                title = "Network Optimization",
                subtitle = "Changes apply on next connection"
            ) {
                SliderSettingItem(
                    icon = Icons.Default.Timer,
                    title = "DNS Timeout",
                    value = uiState.dnsTimeout,
                    valueRange = 1000f..15000f,
                    steps = 13,
                    valueFormatter = { "${(it / 1000f).roundToInt()}s" },
                    onValueChange = { viewModel.setDnsTimeout(it.roundToInt()) }
                )

                SettingsDivider()

                SliderSettingItem(
                    icon = Icons.Default.NetworkCheck,
                    title = "Connection Timeout",
                    value = uiState.connectionTimeout,
                    valueRange = 10000f..60000f,
                    steps = 9,
                    valueFormatter = { "${(it / 1000f).roundToInt()}s" },
                    onValueChange = { viewModel.setConnectionTimeout(it.roundToInt()) }
                )

                SettingsDivider()

                ClickableSettingItem(
                    icon = Icons.Default.Memory,
                    title = "Buffer Size",
                    description = when (uiState.bufferSize) {
                        BufferSize.SMALL -> "Small (64KB)"
                        BufferSize.MEDIUM -> "Medium (256KB)"
                        BufferSize.LARGE -> "Large (512KB)"
                    },
                    onClick = { showBufferSizeDialog = true }
                )

                SettingsDivider()

                SliderSettingItem(
                    icon = Icons.Default.Hub,
                    title = "Connection Pool Size",
                    value = uiState.connectionPoolSize,
                    valueRange = 1f..20f,
                    steps = 18,
                    valueFormatter = { "${it.roundToInt()}" },
                    onValueChange = { viewModel.setConnectionPoolSize(it.roundToInt()) }
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

    // Buffer Size Dialog
    if (showBufferSizeDialog) {
        AlertDialog(
            onDismissRequest = { showBufferSizeDialog = false },
            title = { Text("Buffer Size") },
            text = {
                Column {
                    BufferSize.entries.forEach { size ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .clickable {
                                    viewModel.setBufferSize(size)
                                    showBufferSizeDialog = false
                                }
                                .padding(vertical = 12.dp, horizontal = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = uiState.bufferSize == size,
                                onClick = {
                                    viewModel.setBufferSize(size)
                                    showBufferSizeDialog = false
                                }
                            )
                            Text(
                                text = when (size) {
                                    BufferSize.SMALL -> "Small (64KB)"
                                    BufferSize.MEDIUM -> "Medium (256KB)"
                                    BufferSize.LARGE -> "Large (512KB)"
                                },
                                modifier = Modifier.padding(start = 8.dp)
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showBufferSizeDialog = false }) {
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
