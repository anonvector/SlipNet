package app.slipnet.presentation.profiles

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import app.slipnet.domain.model.CongestionControl
import app.slipnet.domain.model.DnsTransport
import app.slipnet.tunnel.DOH_SERVERS
import app.slipnet.tunnel.DohServer

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditProfileScreen(
    profileId: Long?,
    onNavigateBack: () -> Unit,
    onNavigateToScanner: (() -> Unit)? = null,
    selectedResolvers: String? = null,
    viewModel: EditProfileViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }
    val scrollState = rememberScrollState()

    // Apply selected resolvers from scanner
    LaunchedEffect(selectedResolvers) {
        selectedResolvers?.let { resolvers ->
            if (resolvers.isNotBlank()) {
                viewModel.updateResolvers(resolvers)
            }
        }
    }

    LaunchedEffect(uiState.saveSuccess) {
        if (uiState.saveSuccess) {
            onNavigateBack()
        }
    }

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
                    Text(if (profileId != null) "Edit Profile" else "Add Profile")
                },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    if (uiState.isSaving) {
                        CircularProgressIndicator(
                            modifier = Modifier.padding(16.dp),
                            strokeWidth = 2.dp
                        )
                    } else {
                        IconButton(onClick = { viewModel.save() }) {
                            Icon(Icons.Default.Check, contentDescription = "Save")
                        }
                    }
                }
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) }
    ) { paddingValues ->
        if (uiState.isLoading) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues),
                contentAlignment = Alignment.Center
            ) {
                CircularProgressIndicator()
            }
        } else {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues)
                    .imePadding()
                    .verticalScroll(scrollState)
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Name
                OutlinedTextField(
                    value = uiState.name,
                    onValueChange = { viewModel.updateName(it) },
                    label = { Text("Profile Name") },
                    placeholder = { Text("My VPN Server") },
                    isError = uiState.nameError != null,
                    supportingText = uiState.nameError?.let { { Text(it) } },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                // Domain / SSH Server (hidden for DOH profiles)
                if (!uiState.isDoh) {
                    OutlinedTextField(
                        value = uiState.domain,
                        onValueChange = { viewModel.updateDomain(it) },
                        label = { Text(if (uiState.isSshOnly) "SSH Server" else "Domain") },
                        placeholder = {
                            Text(
                                when {
                                    uiState.isDnsttBased -> "t.example.com"
                                    uiState.isSshOnly -> "ssh.example.com"
                                    else -> "vpn.example.com"
                                }
                            )
                        },
                        isError = uiState.domainError != null,
                        supportingText = {
                            Text(
                                uiState.domainError ?: when {
                                    uiState.isDnsttBased -> "DNSTT tunnel domain"
                                    uiState.isSlipstreamBased -> "Slipstream tunnel domain"
                                    else -> "SSH server hostname or IP"
                                }
                            )
                        },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                }

                // DoH Server URL (shown for DOH profiles)
                if (uiState.isDoh) {
                    DohServerSelector(
                        dohUrl = uiState.dohUrl,
                        dohUrlError = uiState.dohUrlError,
                        onUrlChange = { viewModel.updateDohUrl(it) },
                        onPresetSelected = { viewModel.selectDohPreset(it) },
                        onTestServers = { viewModel.testDohServers() }
                    )

                    // DoH warning
                    Surface(
                        shape = MaterialTheme.shapes.small,
                        color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.5f),
                        modifier = Modifier.fillMaxWidth()
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
                            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(
                                    text = "DNS-only encryption",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.SemiBold,
                                    color = MaterialTheme.colorScheme.onErrorContainer
                                )
                                Text(
                                    text = "DoH encrypts DNS queries only. Your IP address remains visible to websites. For bypassing censorship, it may not work on all websites.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onErrorContainer
                                )
                            }
                        }
                    }
                }

                // SSH Port (shown only for SSH-only, near domain)
                if (uiState.isSshOnly) {
                    OutlinedTextField(
                        value = uiState.sshPort,
                        onValueChange = { viewModel.updateSshPort(it) },
                        label = { Text("SSH Port") },
                        placeholder = { Text("22") },
                        isError = uiState.sshPortError != null,
                        supportingText = uiState.sshPortError?.let { { Text(it) } },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                }

                // DNSTT Public Key
                if (uiState.isDnsttBased) {
                    OutlinedTextField(
                        value = uiState.dnsttPublicKey,
                        onValueChange = { viewModel.updateDnsttPublicKey(it) },
                        label = { Text("Public Key") },
                        placeholder = { Text("Server's Noise public key (hex)") },
                        isError = uiState.dnsttPublicKeyError != null,
                        supportingText = {
                            Text(uiState.dnsttPublicKeyError ?: "Server's Noise protocol public key in hex format")
                        },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                }

                // DNS Transport selector (DNSTT-based profiles only)
                if (uiState.isDnsttBased) {
                    Text(
                        text = "DNS Transport",
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.padding(top = 8.dp)
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        DnsTransport.entries.forEach { transport ->
                            if (uiState.dnsTransport == transport) {
                                Button(
                                    onClick = { },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text(transport.displayName)
                                }
                            } else {
                                OutlinedButton(
                                    onClick = { viewModel.updateDnsTransport(transport) },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text(transport.displayName)
                                }
                            }
                        }
                    }
                }

                // DoH URL for DNSTT with DoH transport
                if (uiState.isDnsttBased && uiState.dnsTransport == DnsTransport.DOH) {
                    DohServerSelector(
                        dohUrl = uiState.dohUrl,
                        dohUrlError = uiState.dohUrlError,
                        onUrlChange = { viewModel.updateDohUrl(it) },
                        onPresetSelected = { viewModel.selectDohPreset(it) },
                        onTestServers = { viewModel.testDohServers() }
                    )
                }

                // Resolvers (not shown for SSH-only, DOH, or DNSTT with DoH transport)
                val showResolvers = !uiState.isSshOnly && !uiState.isDoh &&
                        !(uiState.isDnsttBased && uiState.dnsTransport == DnsTransport.DOH)
                if (showResolvers) {
                    val isDoT = uiState.isDnsttBased && uiState.dnsTransport == DnsTransport.DOT
                    OutlinedTextField(
                        value = uiState.resolvers,
                        onValueChange = { viewModel.updateResolvers(it) },
                        label = { Text("DNS Resolver") },
                        placeholder = { Text(if (isDoT) "8.8.8.8:853" else "1.1.1.1:53") },
                        isError = uiState.resolversError != null,
                        supportingText = {
                            Text(uiState.resolversError ?: if (isDoT) "DNS-over-TLS server (IP:853)" else "DNS server address (IP:port)")
                        },
                        trailingIcon = {
                            IconButton(
                                onClick = { viewModel.autoDetectResolver() },
                                enabled = !uiState.isAutoDetecting
                            ) {
                                if (uiState.isAutoDetecting) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(18.dp),
                                        strokeWidth = 2.dp
                                    )
                                } else {
                                    Text(
                                        text = "Local",
                                        style = MaterialTheme.typography.labelMedium,
                                        color = MaterialTheme.colorScheme.primary
                                    )
                                }
                            }
                        },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )

                    // Scan Resolvers button
                    if (onNavigateToScanner != null) {
                        OutlinedButton(
                            onClick = onNavigateToScanner,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Default.Search, contentDescription = null)
                            Spacer(Modifier.width(8.dp))
                            Text("Scan for Working Resolvers")
                        }
                    }
                }

                // Slipstream-specific settings
                if (uiState.isSlipstreamBased) {
                    // Keep-Alive Interval
                    OutlinedTextField(
                        value = uiState.keepAliveInterval,
                        onValueChange = { viewModel.updateKeepAliveInterval(it) },
                        label = { Text("Keep-Alive Interval (ms)") },
                        placeholder = { Text("200") },
                        supportingText = { Text("QUIC keep-alive interval in milliseconds") },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )

                    // Congestion Control
                    CongestionControlDropdown(
                        selected = uiState.congestionControl,
                        onSelect = { viewModel.updateCongestionControl(it) }
                    )

                    // Authoritative Mode
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Authoritative Mode",
                                style = MaterialTheme.typography.bodyLarge
                            )
                            Text(
                                text = "Use authoritative DNS resolution (--authoritative)",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = uiState.authoritativeMode,
                            onCheckedChange = { viewModel.updateAuthoritativeMode(it) }
                        )
                    }

                    // GSO Mode
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "GSO (Generic Segmentation Offload)",
                                style = MaterialTheme.typography.bodyLarge
                            )
                            Text(
                                text = "Enable GSO for better performance (--gso)",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = uiState.gsoEnabled,
                            onCheckedChange = { viewModel.updateGsoEnabled(it) }
                        )
                    }
                }

                // Connection Method section (DNSTT & Slipstream only, not SSH-only)
                if (uiState.showConnectionMethod) {
                    Text(
                        text = "Connection Method",
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.padding(top = 8.dp)
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        if (uiState.useSsh) {
                            OutlinedButton(
                                onClick = { viewModel.setUseSsh(false) },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("SOCKS")
                            }
                            Button(
                                onClick = { },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("SSH")
                            }
                        } else {
                            Button(
                                onClick = { },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("SOCKS")
                            }
                            OutlinedButton(
                                onClick = { viewModel.setUseSsh(true) },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("SSH")
                            }
                        }
                    }
                }

                // SOCKS5 Credentials (optional, when SOCKS selected for DNSTT/Slipstream)
                if (uiState.showConnectionMethod && !uiState.useSsh) {
                    Text(
                        text = "SOCKS5 Credentials (Optional)",
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.padding(top = 8.dp)
                    )

                    OutlinedTextField(
                        value = uiState.socksUsername,
                        onValueChange = { viewModel.updateSocksUsername(it) },
                        label = { Text("Username") },
                        placeholder = { Text("Enter SOCKS username") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )

                    var passwordVisible by remember { mutableStateOf(false) }
                    OutlinedTextField(
                        value = uiState.socksPassword,
                        onValueChange = { viewModel.updateSocksPassword(it) },
                        label = { Text("Password") },
                        placeholder = { Text("Enter SOCKS password") },
                        singleLine = true,
                        visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        trailingIcon = {
                            IconButton(onClick = { passwordVisible = !passwordVisible }) {
                                Text(
                                    text = if (passwordVisible) "Hide" else "Show",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = MaterialTheme.colorScheme.primary
                                )
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    )
                }

                // SSH Credentials (SSH-only, or when SSH selected for DNSTT/Slipstream)
                if (uiState.useSsh) {
                    Text(
                        text = "SSH Credentials",
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.padding(top = 8.dp)
                    )

                    // SSH Port (only for DNSTT+SSH / Slipstream+SSH, not SSH-only which has it near domain)
                    if (uiState.showConnectionMethod) {
                        OutlinedTextField(
                            value = uiState.sshPort,
                            onValueChange = { viewModel.updateSshPort(it) },
                            label = { Text("SSH Port") },
                            placeholder = { Text("22") },
                            isError = uiState.sshPortError != null,
                            supportingText = uiState.sshPortError?.let { { Text(it) } },
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }

                    OutlinedTextField(
                        value = uiState.sshUsername,
                        onValueChange = { viewModel.updateSshUsername(it) },
                        label = { Text("SSH Username") },
                        placeholder = { Text("Enter SSH username") },
                        isError = uiState.sshUsernameError != null,
                        supportingText = uiState.sshUsernameError?.let { { Text(it) } },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )

                    var sshPasswordVisible by remember { mutableStateOf(false) }
                    OutlinedTextField(
                        value = uiState.sshPassword,
                        onValueChange = { viewModel.updateSshPassword(it) },
                        label = { Text("SSH Password") },
                        placeholder = { Text("Enter SSH password") },
                        isError = uiState.sshPasswordError != null,
                        supportingText = uiState.sshPasswordError?.let { { Text(it) } },
                        singleLine = true,
                        visualTransformation = if (sshPasswordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        trailingIcon = {
                            IconButton(onClick = { sshPasswordVisible = !sshPasswordVisible }) {
                                Text(
                                    text = if (sshPasswordVisible) "Hide" else "Show",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = MaterialTheme.colorScheme.primary
                                )
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    )
                }

                Spacer(modifier = Modifier.height(32.dp))
            }
        }
    }

    // DoH test results dialog
    if (uiState.showDohTestDialog) {
        DohTestDialog(
            isTestingDoh = uiState.isTestingDoh,
            results = uiState.dohTestResults,
            onDismiss = { viewModel.dismissDohTestDialog() },
            onSelectResult = { viewModel.selectDohTestResult(it) }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun CongestionControlDropdown(
    selected: CongestionControl,
    onSelect: (CongestionControl) -> Unit,
    modifier: Modifier = Modifier
) {
    var expanded by remember { mutableStateOf(false) }

    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
        modifier = modifier.fillMaxWidth()
    ) {
        OutlinedTextField(
            value = selected.value.uppercase(),
            onValueChange = { },
            readOnly = true,
            label = { Text("Congestion Control") },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor()
        )

        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false }
        ) {
            CongestionControl.entries.forEach { option ->
                DropdownMenuItem(
                    text = { Text(option.value.uppercase()) },
                    onClick = {
                        onSelect(option)
                        expanded = false
                    }
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DohServerSelector(
    dohUrl: String,
    dohUrlError: String?,
    onUrlChange: (String) -> Unit,
    onPresetSelected: (DohServer) -> Unit,
    onTestServers: () -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    val matchingPreset = DOH_SERVERS.find { it.url == dohUrl }

    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
        modifier = Modifier.fillMaxWidth()
    ) {
        OutlinedTextField(
            value = matchingPreset?.name ?: if (dohUrl.isNotBlank()) "Custom" else "",
            onValueChange = { },
            readOnly = true,
            label = { Text("DoH Server") },
            placeholder = { Text("Select a server") },
            isError = dohUrlError != null,
            supportingText = {
                Text(dohUrlError ?: (matchingPreset?.url ?: "Select a preset or enter custom URL"))
            },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor()
        )

        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false }
        ) {
            DOH_SERVERS.forEach { preset ->
                DropdownMenuItem(
                    text = {
                        Column {
                            Text(preset.name, style = MaterialTheme.typography.bodyLarge)
                            Text(
                                preset.url,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    },
                    onClick = {
                        onPresetSelected(preset)
                        expanded = false
                    }
                )
            }
            DropdownMenuItem(
                text = {
                    Text("Custom URL...", style = MaterialTheme.typography.bodyLarge)
                },
                onClick = {
                    onUrlChange("")
                    expanded = false
                }
            )
        }
    }

    // Show custom URL field when no preset matches (and not empty)
    if (matchingPreset == null) {
        OutlinedTextField(
            value = dohUrl,
            onValueChange = onUrlChange,
            label = { Text("Custom DoH URL") },
            placeholder = { Text("https://example.com/dns-query") },
            isError = dohUrlError != null,
            supportingText = if (dohUrl.isNotBlank()) {
                { Text(dohUrlError ?: "Custom DNS-over-HTTPS endpoint") }
            } else null,
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
    }

    // Test Servers button
    OutlinedButton(
        onClick = onTestServers,
        modifier = Modifier.fillMaxWidth()
    ) {
        Icon(Icons.Default.Speed, contentDescription = null, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text("Test Servers")
    }
}

@Composable
private fun DohTestDialog(
    isTestingDoh: Boolean,
    results: List<DohTestResult>,
    onDismiss: () -> Unit,
    onSelectResult: (DohTestResult) -> Unit
) {
    val total = results.size
    val completed = results.count { it.latencyMs != null || it.error != null }
    val reachable = results.count { it.isSuccess }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("DoH Server Test")
                if (isTestingDoh) {
                    Spacer(Modifier.width(12.dp))
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                }
            }
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text(
                    text = if (isTestingDoh) {
                        "Testing $completed/$total servers..."
                    } else {
                        "$reachable/$total reachable — tap to select"
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(8.dp))
                LazyColumn(
                    modifier = Modifier.height(400.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    items(results, key = { it.url }) { result ->
                        Surface(
                            onClick = { if (result.isSuccess) onSelectResult(result) },
                            enabled = result.isSuccess,
                            shape = MaterialTheme.shapes.small,
                            tonalElevation = if (result.isSuccess) 2.dp else 0.dp,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 12.dp, vertical = 8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = result.name,
                                        style = MaterialTheme.typography.bodyMedium
                                    )
                                    Text(
                                        text = if (result.error != null) result.error else result.url,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = if (result.error != null)
                                            MaterialTheme.colorScheme.error
                                        else
                                            MaterialTheme.colorScheme.onSurfaceVariant,
                                        maxLines = 1
                                    )
                                }
                                Spacer(Modifier.width(8.dp))
                                when {
                                    result.latencyMs == null && result.error == null -> {
                                        CircularProgressIndicator(
                                            modifier = Modifier.size(16.dp),
                                            strokeWidth = 2.dp
                                        )
                                    }
                                    result.isSuccess -> {
                                        Text(
                                            text = "${result.latencyMs}ms",
                                            style = MaterialTheme.typography.labelMedium,
                                            color = MaterialTheme.colorScheme.primary
                                        )
                                    }
                                    result.error != null -> {
                                        Text(
                                            text = "Failed",
                                            style = MaterialTheme.typography.labelMedium,
                                            color = MaterialTheme.colorScheme.error
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Close")
            }
        }
    )
}

