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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Search
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
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
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
import app.slipnet.domain.model.TunnelType

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

                // Tunnel Type
                TunnelTypeDropdown(
                    selected = uiState.tunnelType,
                    onSelect = { viewModel.updateTunnelType(it) }
                )

                // Domain
                OutlinedTextField(
                    value = uiState.domain,
                    onValueChange = { viewModel.updateDomain(it) },
                    label = { Text("Domain") },
                    placeholder = { Text(if (uiState.tunnelType == TunnelType.DNSTT) "t.example.com" else "vpn.example.com") },
                    isError = uiState.domainError != null,
                    supportingText = {
                        Text(
                            uiState.domainError ?: when (uiState.tunnelType) {
                                TunnelType.DNSTT -> "DNSTT tunnel domain"
                                TunnelType.SLIPSTREAM -> "Slipstream tunnel domain"
                            }
                        )
                    },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                // DNSTT Public Key (only shown for DNSTT)
                if (uiState.tunnelType == TunnelType.DNSTT) {
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

                // Resolvers
                OutlinedTextField(
                    value = uiState.resolvers,
                    onValueChange = { viewModel.updateResolvers(it) },
                    label = { Text("DNS Resolver") },
                    placeholder = { Text("1.1.1.1:53") },
                    isError = uiState.resolversError != null,
                    supportingText = {
                        Text(uiState.resolversError ?: "DNS server address (IP:port)")
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
                                    text = "Auto",
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

                // Slipstream-specific settings (only shown for Slipstream tunnel type)
                if (uiState.tunnelType == TunnelType.SLIPSTREAM) {
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

                // SOCKS5 Authentication Section
                Text(
                    text = "SOCKS5 Authentication",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp)
                )

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 8.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Enable Authentication",
                            style = MaterialTheme.typography.bodyLarge
                        )
                        Text(
                            text = "Use username/password for SOCKS5 proxy",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(
                        checked = uiState.socksAuthEnabled,
                        onCheckedChange = { viewModel.updateSocksAuthEnabled(it) }
                    )
                }

                // Username and Password fields (shown when auth is enabled)
                if (uiState.socksAuthEnabled) {
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

                // SSH Tunnel Section (DNSTT only)
                if (uiState.tunnelType == TunnelType.DNSTT) {
                    Text(
                        text = "SSH Tunnel",
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.padding(top = 8.dp)
                    )

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Enable SSH Tunnel",
                                style = MaterialTheme.typography.bodyLarge
                            )
                            Text(
                                text = "Route traffic through SSH over the DNS tunnel",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = uiState.sshEnabled,
                            onCheckedChange = { viewModel.updateSshEnabled(it) }
                        )
                    }

                    if (uiState.sshEnabled) {
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
                }

                Spacer(modifier = Modifier.height(32.dp))
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TunnelTypeDropdown(
    selected: TunnelType,
    onSelect: (TunnelType) -> Unit,
    modifier: Modifier = Modifier
) {
    var expanded by remember { mutableStateOf(false) }

    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
        modifier = modifier.fillMaxWidth()
    ) {
        OutlinedTextField(
            value = selected.displayName,
            onValueChange = { },
            readOnly = true,
            label = { Text("Tunnel Type") },
            supportingText = {
                Text(
                    when (selected) {
                        TunnelType.SLIPSTREAM -> "DNS tunnel using QUIC protocol"
                        TunnelType.DNSTT -> "DNS tunnel using KCP + Noise protocol"
                    }
                )
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
            // Show DNSTT first since it's recommended
            listOf(TunnelType.DNSTT, TunnelType.SLIPSTREAM).forEach { option ->
                DropdownMenuItem(
                    text = { Text(option.displayName) },
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

