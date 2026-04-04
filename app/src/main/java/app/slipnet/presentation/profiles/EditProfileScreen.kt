package app.slipnet.presentation.profiles

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.SmartToy
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.ui.draw.rotate
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.KeyboardArrowRight
import androidx.compose.ui.draw.clip
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import app.slipnet.domain.model.CongestionControl
import app.slipnet.domain.model.DnsTransport
import app.slipnet.domain.model.SshAuthType
import app.slipnet.tunnel.DOH_SERVERS
import app.slipnet.tunnel.DohServer

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditProfileScreen(
    profileId: Long?,
    onNavigateBack: () -> Unit,
    onNavigateToScanner: ((Long?) -> Unit)? = null,
    selectedResolvers: String? = null,
    viewModel: EditProfileViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    val context = LocalContext.current
    val globalResolverEnabled by viewModel.globalResolverEnabled.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }
    val scrollState = rememberScrollState()
    var showUnlockDialog by remember { mutableStateOf(false) }
    var unlockPassword by remember { mutableStateOf("") }
    var unlockError by remember { mutableStateOf(false) }

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
            if (uiState.showRestartVpnMessage) {
                android.widget.Toast.makeText(
                    context,
                    "Profile saved. Turn VPN off and on to apply changes.",
                    android.widget.Toast.LENGTH_LONG
                ).show()
            }
            onNavigateBack()
        }
    }

    // Navigate to scanner after profile is saved
    LaunchedEffect(uiState.savedProfileIdForScanner) {
        uiState.savedProfileIdForScanner?.let { savedId ->
            viewModel.clearScannerNavigation()
            onNavigateToScanner?.invoke(savedId)
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
                    Text(
                        if (uiState.isLocked) "Locked Profile"
                        else if (profileId != null) "Edit Profile"
                        else "Add Profile"
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    val lockedCanEditDns = uiState.isLocked &&
                            (uiState.isDnsttOrNoizOrVaydnsBased || uiState.isSlipstreamBased)
                    if (!uiState.isLocked || lockedCanEditDns) {
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
        } else if (uiState.isLocked) {
            // Locked profile view
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues)
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // Profile info card
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceContainerLow
                    ),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Column(
                        modifier = Modifier.padding(20.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Surface(
                                shape = CircleShape,
                                color = MaterialTheme.colorScheme.primaryContainer,
                                modifier = Modifier.size(44.dp)
                            ) {
                                Box(contentAlignment = Alignment.Center) {
                                    Icon(
                                        imageVector = Icons.Default.Lock,
                                        contentDescription = null,
                                        modifier = Modifier.size(22.dp),
                                        tint = MaterialTheme.colorScheme.primary
                                    )
                                }
                            }
                            Column {
                                Text(
                                    text = uiState.name,
                                    style = MaterialTheme.typography.titleLarge,
                                    fontWeight = FontWeight.SemiBold
                                )
                                Text(
                                    text = uiState.tunnelType.displayName,
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }

                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))

                        // Info rows
                        if (uiState.expirationDate > 0) {
                            val isExpired = System.currentTimeMillis() > uiState.expirationDate
                            val dateStr = java.text.SimpleDateFormat("MMM dd, yyyy HH:mm", java.util.Locale.getDefault())
                                .format(java.util.Date(uiState.expirationDate))
                            LockedInfoRow(
                                icon = if (isExpired) Icons.Default.Warning else Icons.Default.Schedule,
                                label = if (isExpired) "Expired" else "Expires",
                                value = dateStr,
                                valueColor = if (isExpired) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface
                            )
                        }
                        if (uiState.boundDeviceId.isNotEmpty()) {
                            LockedInfoRow(
                                icon = Icons.Default.PhoneAndroid,
                                label = "Device",
                                value = "Bound"
                            )
                        }
                        LockedInfoRow(
                            icon = Icons.Default.Share,
                            label = "Re-sharing",
                            value = if (uiState.allowSharing) "Allowed" else "Disabled"
                        )
                    }
                }

                // DNS settings card
                if (uiState.isDnsttOrNoizOrVaydnsBased || uiState.isSlipstreamBased) {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceContainerLow
                        ),
                        shape = RoundedCornerShape(16.dp)
                    ) {
                        Column(
                            modifier = Modifier.padding(20.dp),
                            verticalArrangement = Arrangement.spacedBy(14.dp)
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Icon(
                                    Icons.Default.Dns,
                                    contentDescription = null,
                                    modifier = Modifier.size(20.dp),
                                    tint = MaterialTheme.colorScheme.primary
                                )
                                Text(
                                    text = "DNS Settings",
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }

                            Text(
                                text = "You can change DNS settings. Other profile details are locked.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )

                            // DNS Transport selector (DNSTT-based profiles only)
                            if (uiState.isDnsttOrNoizOrVaydnsBased) {
                                Text(
                                    text = "Transport",
                                    style = MaterialTheme.typography.labelLarge,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )

                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    DnsTransport.entries.forEach { transport ->
                                        if (uiState.dnsTransport == transport) {
                                            Button(
                                                onClick = { },
                                                modifier = Modifier.weight(1f),
                                                shape = RoundedCornerShape(10.dp),
                                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp)
                                            ) {
                                                Text(transport.displayName, style = MaterialTheme.typography.labelMedium)
                                            }
                                        } else {
                                            OutlinedButton(
                                                onClick = { viewModel.updateDnsTransport(transport) },
                                                modifier = Modifier.weight(1f),
                                                shape = RoundedCornerShape(10.dp),
                                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp)
                                            ) {
                                                Text(transport.displayName, style = MaterialTheme.typography.labelMedium)
                                            }
                                        }
                                    }
                                }
                            }

                            // DoH URL for DNSTT with DoH transport
                            if (uiState.isDnsttOrNoizOrVaydnsBased && uiState.dnsTransport == DnsTransport.DOH) {
                                DohServerSelector(
                                    dohUrl = uiState.dohUrl,
                                    dohUrlError = uiState.dohUrlError,
                                    onUrlChange = { viewModel.updateDohUrl(it) },
                                    onPresetSelected = { viewModel.selectDohPreset(it) },
                                    onTestServers = { scope -> viewModel.testDohServers(scope) },
                                    customDohUrls = uiState.customDohUrls,
                                    onCustomDohUrlsChange = { viewModel.updateCustomDohUrls(it) }
                                )
                            }

                            // Resolver field (not shown when DNSTT with DoH transport)
                            if (!(uiState.isDnsttOrNoizOrVaydnsBased && uiState.dnsTransport == DnsTransport.DOH)) {
                                if (globalResolverEnabled) {
                                    Card(
                                        colors = CardDefaults.cardColors(
                                            containerColor = MaterialTheme.colorScheme.primaryContainer
                                        ),
                                        modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp)
                                    ) {
                                        Text(
                                            text = "Global DNS resolver override is active in Settings. Profile resolvers will be ignored at connection time.",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                                            modifier = Modifier.padding(12.dp)
                                        )
                                    }
                                }
                                if (uiState.resolversHidden) {
                                    // Hidden resolver: show toggle for custom override
                                    Text(
                                        text = "DNS Resolver: Default (hidden)",
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Text(
                                            text = "Use custom resolver",
                                            style = MaterialTheme.typography.bodyMedium
                                        )
                                        Switch(
                                            checked = uiState.useCustomResolver,
                                            onCheckedChange = { viewModel.updateUseCustomResolver(it) }
                                        )
                                    }
                                    if (uiState.useCustomResolver) {
                                        val isDoT = uiState.isDnsttOrNoizOrVaydnsBased && uiState.dnsTransport == DnsTransport.DOT
                                        OutlinedTextField(
                                            value = uiState.resolvers,
                                            onValueChange = { viewModel.updateResolvers(it) },
                                            label = { Text("DNS Resolver") },
                                            placeholder = { Text(if (isDoT) "e.g. dns.google:853" else "e.g. 8.8.8.8:53") },
                                            isError = uiState.resolversError != null,
                                            supportingText = {
                                                Text(uiState.resolversError ?: if (isDoT) "IP or domain (host:853)" else "IP or domain (host:port)")
                                            },
                                            singleLine = true,
                                            modifier = Modifier.fillMaxWidth(),
                                            shape = RoundedCornerShape(12.dp)
                                        )
                                        if (onNavigateToScanner != null) {
                                            Button(
                                                onClick = { viewModel.saveForScanner() },
                                                modifier = Modifier.fillMaxWidth(),
                                                shape = RoundedCornerShape(10.dp)
                                            ) {
                                                Icon(Icons.Default.Search, contentDescription = null, modifier = Modifier.size(18.dp))
                                                Spacer(Modifier.width(8.dp))
                                                Text("Scan for Working Resolvers")
                                            }
                                        }
                                    }
                                } else {
                                    val isDoT = uiState.isDnsttOrNoizOrVaydnsBased && uiState.dnsTransport == DnsTransport.DOT
                                    OutlinedTextField(
                                        value = uiState.resolvers,
                                        onValueChange = { viewModel.updateResolvers(it) },
                                        label = { Text("DNS Resolver") },
                                        placeholder = { Text(if (isDoT) "e.g. dns.google:853" else "e.g. 8.8.8.8:53") },
                                        isError = uiState.resolversError != null,
                                        supportingText = {
                                            Text(uiState.resolversError ?: if (isDoT) "IP or domain (host:853)" else "IP or domain (host:port)")
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
                                        modifier = Modifier.fillMaxWidth(),
                                        shape = RoundedCornerShape(12.dp)
                                    )

                                    if (onNavigateToScanner != null) {
                                        Button(
                                            onClick = { viewModel.saveForScanner() },
                                            modifier = Modifier.fillMaxWidth(),
                                            shape = RoundedCornerShape(10.dp)
                                        ) {
                                            Icon(Icons.Default.Search, contentDescription = null, modifier = Modifier.size(18.dp))
                                            Spacer(Modifier.width(8.dp))
                                            Text("Scan for Working Resolvers")
                                        }
                                    }
                                }
                            }

                            // DNS Query Size (locked profiles)
                            if (uiState.isDnsttOrNoizOrVaydnsBased) {
                                var showMtuDialogLocked by remember { mutableStateOf(false) }
                                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clip(RoundedCornerShape(8.dp))
                                        .clickable { showMtuDialogLocked = true }
                                        .padding(vertical = 12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = "DNS Query Size",
                                            style = MaterialTheme.typography.bodyLarge
                                        )
                                        Text(
                                            text = if (uiState.dnsPayloadSize == 0) "Full capacity (fastest)"
                                                   else "${uiState.dnsPayloadSize} bytes per query",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                    Icon(
                                        Icons.AutoMirrored.Filled.KeyboardArrowRight,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }

                                if (showMtuDialogLocked) {
                                    val mtuPresetsLocked = listOf(
                                        0 to "Full capacity — fastest, largest queries",
                                        100 to "Large — good balance",
                                        80 to "Medium — less conspicuous",
                                        60 to "Small — stealthier, slower",
                                        50 to "Minimum — most stealthy, slowest"
                                    )
                                    val isCustomLocked = mtuPresetsLocked.none { it.first == uiState.dnsPayloadSize }
                                    var customMtuTextLocked by remember { mutableStateOf(if (isCustomLocked) uiState.dnsPayloadSize.toString() else "") }
                                    var useCustomLocked by remember { mutableStateOf(isCustomLocked) }
                                    AlertDialog(
                                        onDismissRequest = { showMtuDialogLocked = false },
                                        title = { Text("DNS Query Size") },
                                        text = {
                                            Column {
                                                Text(
                                                    text = "Bytes of data per DNS query. Smaller values produce shorter, less suspicious queries at the cost of speed.",
                                                    style = MaterialTheme.typography.bodySmall,
                                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                    modifier = Modifier.padding(bottom = 12.dp)
                                                )
                                                mtuPresetsLocked.forEach { (size, desc) ->
                                                    Row(
                                                        modifier = Modifier
                                                            .fillMaxWidth()
                                                            .clip(RoundedCornerShape(8.dp))
                                                            .clickable {
                                                                useCustomLocked = false
                                                                viewModel.updateDnsPayloadSize(size)
                                                                showMtuDialogLocked = false
                                                            }
                                                            .padding(vertical = 10.dp, horizontal = 8.dp),
                                                        verticalAlignment = Alignment.CenterVertically
                                                    ) {
                                                        RadioButton(
                                                            selected = !useCustomLocked && uiState.dnsPayloadSize == size,
                                                            onClick = {
                                                                useCustomLocked = false
                                                                viewModel.updateDnsPayloadSize(size)
                                                                showMtuDialogLocked = false
                                                            }
                                                        )
                                                        Column(modifier = Modifier.padding(start = 8.dp)) {
                                                            Text(text = if (size == 0) "Full" else "$size")
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
                                                        .clickable { useCustomLocked = true }
                                                        .padding(vertical = 10.dp, horizontal = 8.dp),
                                                    verticalAlignment = Alignment.CenterVertically
                                                ) {
                                                    RadioButton(
                                                        selected = useCustomLocked,
                                                        onClick = { useCustomLocked = true }
                                                    )
                                                    OutlinedTextField(
                                                        value = customMtuTextLocked,
                                                        onValueChange = { customMtuTextLocked = it.filter { c -> c.isDigit() }.take(3) },
                                                        enabled = useCustomLocked,
                                                        label = { Text("Custom") },
                                                        placeholder = { Text("50–120") },
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
                                            if (useCustomLocked) {
                                                TextButton(
                                                    onClick = {
                                                        val value = customMtuTextLocked.toIntOrNull()
                                                        if (value != null && value in 50..120) {
                                                            viewModel.updateDnsPayloadSize(value)
                                                            showMtuDialogLocked = false
                                                        }
                                                    }
                                                ) {
                                                    Text("Apply")
                                                }
                                            }
                                        },
                                        dismissButton = {
                                            TextButton(onClick = { showMtuDialogLocked = false }) {
                                                Text("Cancel")
                                            }
                                        }
                                    )
                                }
                            }

                            // Stealth mode (locked profiles, NoizDNS only)
                            if (uiState.isNoizdnsBased) {
                                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 4.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = "Stealth mode",
                                            style = MaterialTheme.typography.bodyLarge
                                        )
                                        Text(
                                            text = "Slower speed, harder to detect by DPI",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                    Switch(
                                        checked = uiState.noizdnsStealth,
                                        onCheckedChange = { viewModel.updateNoizdnsStealth(it) }
                                    )
                                }
                                if (uiState.noizdnsStealth && !uiState.dnsttAuthoritative) {
                                    Text(
                                        text = "Internet speed will be reduced.",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.error
                                    )
                                }
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                // Unlock button
                OutlinedButton(
                    onClick = {
                        unlockPassword = ""
                        unlockError = false
                        showUnlockDialog = true
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 8.dp),
                    shape = RoundedCornerShape(12.dp),
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
                ) {
                    Icon(
                        imageVector = Icons.Default.LockOpen,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Unlock Profile")
                }
            }

            // Unlock dialog
            if (showUnlockDialog) {
                AlertDialog(
                    onDismissRequest = { showUnlockDialog = false },
                    title = { Text("Unlock Profile") },
                    text = {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text("Enter the admin password to permanently unlock this profile.")
                            OutlinedTextField(
                                value = unlockPassword,
                                onValueChange = {
                                    unlockPassword = it
                                    unlockError = false
                                },
                                label = { Text("Password") },
                                visualTransformation = PasswordVisualTransformation(),
                                isError = unlockError,
                                supportingText = if (unlockError) {
                                    { Text("Incorrect password") }
                                } else null,
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )
                        }
                    },
                    confirmButton = {
                        TextButton(
                            onClick = {
                                viewModel.unlockProfile(unlockPassword) { success ->
                                    if (success) {
                                        showUnlockDialog = false
                                    } else {
                                        unlockError = true
                                    }
                                }
                            },
                            enabled = unlockPassword.isNotBlank()
                        ) { Text("Unlock") }
                    },
                    dismissButton = {
                        TextButton(onClick = { showUnlockDialog = false }) { Text("Cancel") }
                    }
                )
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

                // Domain / SSH Server (hidden for DOH, Snowflake, and SOCKS5 profiles)
                if (!uiState.isDoh && !uiState.isSnowflake && !uiState.isSocks5) {
                    OutlinedTextField(
                        value = uiState.domain,
                        onValueChange = { viewModel.updateDomain(it) },
                        label = {
                            Text(
                                when {
                                    uiState.isSshOnly -> "SSH Server"
                                    uiState.isNaiveBased -> "Server"
                                    else -> "Domain"
                                }
                            )
                        },
                        placeholder = {
                            Text(
                                when {
                                    uiState.isDnsttOrNoizOrVaydnsBased -> "t.example.com"
                                    uiState.isSshOnly -> "ssh.example.com"
                                    uiState.isNaiveBased -> "proxy.example.com"
                                    else -> "vpn.example.com"
                                }
                            )
                        },
                        isError = uiState.domainError != null,
                        supportingText = {
                            Text(
                                uiState.domainError ?: when {
                                    uiState.isNoizdnsBased -> "NoizDNS tunnel domain"
                                    uiState.isVaydnsBased -> "VayDNS tunnel domain"
                                    uiState.isDnsttBased -> "DNSTT tunnel domain"
                                    uiState.isSlipstreamBased -> "Slipstream tunnel domain"
                                    uiState.isNaiveBased -> "Caddy server hostname"
                                    else -> "SSH server hostname or IP"
                                }
                            )
                        },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                }

                // SOCKS5 Proxy fields
                if (uiState.isSocks5) {
                    OutlinedTextField(
                        value = uiState.domain,
                        onValueChange = { viewModel.updateDomain(it) },
                        label = { Text("SOCKS5 Server") },
                        placeholder = { Text("proxy.example.com") },
                        isError = uiState.domainError != null,
                        supportingText = { Text(uiState.domainError ?: "Remote SOCKS5 proxy hostname or IP") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = uiState.socks5ServerPort,
                        onValueChange = { viewModel.updateSocks5ServerPort(it) },
                        label = { Text("Port") },
                        placeholder = { Text("1080") },
                        isError = uiState.socks5ServerPortError != null,
                        supportingText = { Text(uiState.socks5ServerPortError ?: "SOCKS5 proxy port") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = uiState.socksUsername,
                        onValueChange = { viewModel.updateSocksUsername(it) },
                        label = { Text("Username (optional)") },
                        placeholder = { Text("") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = uiState.socksPassword,
                        onValueChange = { viewModel.updateSocksPassword(it) },
                        label = { Text("Password (optional)") },
                        placeholder = { Text("") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
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
                        onTestServers = { scope -> viewModel.testDohServers(scope) },
                        customDohUrls = uiState.customDohUrls,
                        onCustomDohUrlsChange = { viewModel.updateCustomDohUrls(it) }
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

                // NaiveProxy fields (shown for NAIVE and NAIVE_SSH)
                if (uiState.isNaiveBased) {
                    OutlinedTextField(
                        value = uiState.naivePort,
                        onValueChange = { viewModel.updateNaivePort(it) },
                        label = { Text("Server Port") },
                        placeholder = { Text("443") },
                        isError = uiState.naivePortError != null,
                        supportingText = uiState.naivePortError?.let { { Text(it) } },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = uiState.naiveUsername,
                        onValueChange = { viewModel.updateNaiveUsername(it) },
                        label = { Text("Proxy Username") },
                        placeholder = { Text("HTTP proxy auth username") },
                        isError = uiState.naiveUsernameError != null,
                        supportingText = uiState.naiveUsernameError?.let { { Text(it) } },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = uiState.naivePassword,
                        onValueChange = { viewModel.updateNaivePassword(it) },
                        label = { Text("Proxy Password") },
                        placeholder = { Text("HTTP proxy auth password") },
                        isError = uiState.naivePasswordError != null,
                        supportingText = uiState.naivePasswordError?.let { { Text(it) } },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth()
                    )
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
                if (uiState.isDnsttOrNoizOrVaydnsBased) {
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
                if (uiState.isDnsttOrNoizOrVaydnsBased) {
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
                if (uiState.isDnsttOrNoizOrVaydnsBased && uiState.dnsTransport == DnsTransport.DOH) {
                    DohServerSelector(
                        dohUrl = uiState.dohUrl,
                        dohUrlError = uiState.dohUrlError,
                        onUrlChange = { viewModel.updateDohUrl(it) },
                        onPresetSelected = { viewModel.selectDohPreset(it) },
                        onTestServers = { scope -> viewModel.testDohServers(scope) },
                        customDohUrls = uiState.customDohUrls,
                        onCustomDohUrlsChange = { viewModel.updateCustomDohUrls(it) }
                    )
                }

                // DNS Resolver
                val showResolvers = !uiState.isSshOnly && !uiState.isDoh && !uiState.isSnowflake && !uiState.isNaiveBased &&
                        !uiState.isSocks5 && !(uiState.isDnsttOrNoizOrVaydnsBased && uiState.dnsTransport == DnsTransport.DOH)
                if (showResolvers) {
                    if (globalResolverEnabled) {
                        Card(
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.primaryContainer
                            ),
                            modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp)
                        ) {
                            Text(
                                text = "Global DNS resolver override is active in Settings. Profile resolvers will be ignored at connection time.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onPrimaryContainer,
                                modifier = Modifier.padding(12.dp)
                            )
                        }
                    }
                    if (uiState.resolversHidden) {
                        Text(
                            text = "DNS Resolver: Default (hidden)",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                text = "Use custom resolver",
                                style = MaterialTheme.typography.bodyMedium
                            )
                            Switch(
                                checked = uiState.useCustomResolver,
                                onCheckedChange = { viewModel.updateUseCustomResolver(it) }
                            )
                        }
                        if (uiState.useCustomResolver) {
                            val isDoT = uiState.isDnsttOrNoizOrVaydnsBased && uiState.dnsTransport == DnsTransport.DOT
                            OutlinedTextField(
                                value = uiState.resolvers,
                                onValueChange = { viewModel.updateResolvers(it) },
                                label = { Text("DNS Resolver") },
                                placeholder = { Text(if (isDoT) "e.g. dns.google:853" else "e.g. 8.8.8.8:53") },
                                isError = uiState.resolversError != null,
                                supportingText = {
                                    Text(uiState.resolversError ?: if (isDoT) "IP or domain (host:853)" else "IP or domain (host:port)")
                                },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )
                            if (onNavigateToScanner != null) {
                                Button(
                                    onClick = { viewModel.saveForScanner() },
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(10.dp)
                                ) {
                                    Icon(Icons.Default.Search, contentDescription = null)
                                    Spacer(Modifier.width(8.dp))
                                    Text("Scan for Working Resolvers")
                                }
                            }
                        }
                    } else {
                        val isDoT = uiState.isDnsttOrNoizOrVaydnsBased && uiState.dnsTransport == DnsTransport.DOT
                        OutlinedTextField(
                            value = uiState.resolvers,
                            onValueChange = { viewModel.updateResolvers(it) },
                            label = { Text("DNS Resolver") },
                            placeholder = { Text(if (isDoT) "e.g. dns.google:853" else "e.g. 8.8.8.8:53") },
                            isError = uiState.resolversError != null,
                            supportingText = {
                                Text(uiState.resolversError ?: if (isDoT) "IP or domain (host:853)" else "IP or domain (host:port)")
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

                        if (onNavigateToScanner != null) {
                            Button(
                                onClick = { viewModel.saveForScanner() },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(10.dp)
                            ) {
                                Icon(Icons.Default.Search, contentDescription = null)
                                Spacer(Modifier.width(8.dp))
                                Text("Scan for Working Resolvers")
                            }
                        }
                    }
                }

                // Authoritative Mode toggle (DNSTT/NoizDNS only — VayDNS has no authoritative mode)
                if (uiState.isDnsttOrNoizBased) {
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
                                text = "Aggressive query rate for faster speeds",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = uiState.dnsttAuthoritative,
                            onCheckedChange = { viewModel.updateDnsttAuthoritative(it) }
                        )
                    }
                    if (uiState.dnsttAuthoritative) {
                        Text(
                            text = "Only use when the DNS resolver is your own server. Public resolvers (Google, Cloudflare) will rate-limit and block your connection.",
                            style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Bold),
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.padding(bottom = 8.dp)
                        )
                    }
                }

                // VayDNS-specific settings
                if (uiState.isVaydnsBased) {
                    // Response Record Type selector
                    Text(
                        text = "Response Record Type",
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.padding(top = 8.dp)
                    )
                    Text(
                        text = "Must match the server configuration. Try CNAME or A if TXT is blocked.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(bottom = 4.dp)
                    )
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        listOf("txt", "cname", "a", "aaaa", "mx", "ns", "srv").forEach { type ->
                            if (uiState.vaydnsRecordType == type) {
                                Button(onClick = { }) {
                                    Text(type.uppercase())
                                }
                            } else {
                                OutlinedButton(onClick = { viewModel.updateVaydnsRecordType(type) }) {
                                    Text(type.uppercase())
                                }
                            }
                        }
                    }
                }

                // VayDNS: QNAME length slider (controls query size on the wire)
                if (uiState.isVaydnsBased) {
                    var showQnameDialog by remember { mutableStateOf(false) }
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .clickable { showQnameDialog = true }
                            .padding(vertical = 12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Query Length",
                                style = MaterialTheme.typography.bodyLarge
                            )
                            Text(
                                text = "${uiState.vaydnsMaxQnameLen} bytes" + when {
                                    uiState.vaydnsMaxQnameLen <= 80 -> " — stealthy"
                                    uiState.vaydnsMaxQnameLen <= 120 -> " — balanced"
                                    uiState.vaydnsMaxQnameLen <= 180 -> " — fast"
                                    else -> " — maximum"
                                },
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Icon(
                            Icons.Default.KeyboardArrowRight,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }

                    if (showQnameDialog) {
                        val minQname = 60
                        val maxQname = 253
                        var sliderValue by remember {
                            mutableStateOf(uiState.vaydnsMaxQnameLen.toFloat().coerceIn(minQname.toFloat(), maxQname.toFloat()))
                        }
                        AlertDialog(
                            onDismissRequest = { showQnameDialog = false },
                            title = { Text("Query Length") },
                            text = {
                                Column {
                                    Text(
                                        text = "Controls the size of each DNS query on the wire. Shorter queries blend in with normal traffic but carry less data.",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        modifier = Modifier.padding(bottom = 12.dp)
                                    )
                                    Text(
                                        text = "${sliderValue.toInt()} bytes",
                                        style = MaterialTheme.typography.titleMedium,
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(top = 4.dp),
                                        textAlign = TextAlign.Center
                                    )
                                    Slider(
                                        value = sliderValue,
                                        onValueChange = { sliderValue = it },
                                        valueRange = minQname.toFloat()..maxQname.toFloat(),
                                        steps = (maxQname - minQname) / 10 - 1,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Text("60\nStealthy", style = MaterialTheme.typography.labelSmall, textAlign = TextAlign.Center)
                                        Text("101\nDefault", style = MaterialTheme.typography.labelSmall, textAlign = TextAlign.Center)
                                        Text("253\nFastest", style = MaterialTheme.typography.labelSmall, textAlign = TextAlign.Center)
                                    }
                                }
                            },
                            confirmButton = {
                                TextButton(
                                    onClick = {
                                        viewModel.updateVaydnsMaxQnameLen(sliderValue.toInt())
                                        showQnameDialog = false
                                    }
                                ) {
                                    Text("Apply")
                                }
                            },
                            dismissButton = {
                                Row {
                                    if (sliderValue.toInt() != 101) {
                                        TextButton(onClick = {
                                            sliderValue = 101f
                                            viewModel.updateVaydnsMaxQnameLen(101)
                                            showQnameDialog = false
                                        }) {
                                            Text("Reset")
                                        }
                                    }
                                    TextButton(onClick = { showQnameDialog = false }) {
                                        Text("Cancel")
                                    }
                                }
                            }
                        )
                    }
                }

                // VayDNS: Query rate limit
                if (uiState.isVaydnsBased) {
                    OutlinedTextField(
                        value = uiState.vaydnsRps,
                        onValueChange = { viewModel.updateVaydnsRps(it.filter { c -> c.isDigit() || c == '.' }.take(6)) },
                        label = { Text("Query Rate Limit (q/s)") },
                        supportingText = { Text("Max DNS queries per second. 0 = unlimited.") },
                        modifier = Modifier.fillMaxWidth(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                        singleLine = true
                    )
                }

                // VayDNS: Advanced settings (hidden by default)
                if (uiState.isVaydnsBased) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .clickable { viewModel.toggleVaydnsAdvanced() }
                            .padding(vertical = 12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Advanced",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Icon(
                            Icons.Default.KeyboardArrowRight,
                            contentDescription = if (uiState.vaydnsAdvancedExpanded) "Collapse" else "Expand",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.rotate(if (uiState.vaydnsAdvancedExpanded) 90f else 0f)
                        )
                    }

                    AnimatedVisibility(visible = uiState.vaydnsAdvancedExpanded) {
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text(
                                text = "Only change these if you know what you're doing. 0 = use default.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(bottom = 4.dp)
                            )
                            OutlinedTextField(
                                value = uiState.vaydnsIdleTimeout,
                                onValueChange = { viewModel.updateVaydnsIdleTimeout(it.filter { c -> c.isDigit() }.take(4)) },
                                label = { Text("Idle Timeout (seconds)") },
                                supportingText = { Text("Session idle timeout. Default: 10s (120s with DNSTT compat).") },
                                modifier = Modifier.fillMaxWidth(),
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                singleLine = true
                            )
                            OutlinedTextField(
                                value = uiState.vaydnsKeepalive,
                                onValueChange = { viewModel.updateVaydnsKeepalive(it.filter { c -> c.isDigit() }.take(4)) },
                                label = { Text("Keepalive (seconds)") },
                                supportingText = { Text("Keepalive interval. Default: 2s (10s with DNSTT compat).") },
                                modifier = Modifier.fillMaxWidth(),
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                singleLine = true
                            )
                            OutlinedTextField(
                                value = uiState.vaydnsUdpTimeout,
                                onValueChange = { viewModel.updateVaydnsUdpTimeout(it.filter { c -> c.isDigit() }.take(5)) },
                                label = { Text("UDP Timeout (ms)") },
                                supportingText = { Text("Per-query UDP response timeout. Default: ~500ms.") },
                                modifier = Modifier.fillMaxWidth(),
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                singleLine = true
                            )
                            OutlinedTextField(
                                value = uiState.vaydnsMaxNumLabels,
                                onValueChange = { viewModel.updateVaydnsMaxNumLabels(it.filter { c -> c.isDigit() }.take(2)) },
                                label = { Text("Max Labels") },
                                supportingText = { Text("Max data labels in query name. 0 = unlimited.") },
                                modifier = Modifier.fillMaxWidth(),
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                singleLine = true
                            )
                            OutlinedTextField(
                                value = uiState.vaydnsClientIdSize,
                                onValueChange = { viewModel.updateVaydnsClientIdSize(it.filter { c -> c.isDigit() }.take(1)) },
                                label = { Text("Client ID Size (bytes)") },
                                supportingText = { Text("Client ID size in bytes. Default: 2.") },
                                modifier = Modifier.fillMaxWidth(),
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                singleLine = true
                            )
                        }
                    }
                }

                // DNS MTU selector (DNSTT/NoizDNS only)
                if (uiState.isDnsttOrNoizBased) {
                    var showMtuDialog by remember { mutableStateOf(false) }
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .clickable { showMtuDialog = true }
                            .padding(vertical = 12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "DNS Query Size",
                                style = MaterialTheme.typography.bodyLarge
                            )
                            Text(
                                text = if (uiState.dnsPayloadSize == 0) "Full capacity (fastest)"
                                       else "${uiState.dnsPayloadSize} bytes per query",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Icon(
                            Icons.Default.KeyboardArrowRight,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }

                    if (showMtuDialog) {
                            // DNSTT/NoizDNS: preset list
                            val mtuPresets = listOf(
                                0 to "Full capacity — fastest, largest queries",
                                100 to "Large — good balance",
                                80 to "Medium — less conspicuous",
                                60 to "Small — stealthier, slower",
                                50 to "Minimum — most stealthy, slowest"
                            )
                            val isCustom = mtuPresets.none { it.first == uiState.dnsPayloadSize }
                            var customMtuText by remember { mutableStateOf(if (isCustom) uiState.dnsPayloadSize.toString() else "") }
                            var useCustom by remember { mutableStateOf(isCustom) }
                            AlertDialog(
                                onDismissRequest = { showMtuDialog = false },
                                title = { Text("DNS Query Size") },
                                text = {
                                    Column {
                                        Text(
                                            text = "Bytes of data per DNS query. Smaller values produce shorter, less suspicious queries at the cost of speed.",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                            modifier = Modifier.padding(bottom = 12.dp)
                                        )
                                        mtuPresets.forEach { (size, desc) ->
                                            Row(
                                                modifier = Modifier
                                                    .fillMaxWidth()
                                                    .clip(RoundedCornerShape(8.dp))
                                                    .clickable {
                                                        useCustom = false
                                                        viewModel.updateDnsPayloadSize(size)
                                                        showMtuDialog = false
                                                    }
                                                    .padding(vertical = 10.dp, horizontal = 8.dp),
                                                verticalAlignment = Alignment.CenterVertically
                                            ) {
                                                RadioButton(
                                                    selected = !useCustom && uiState.dnsPayloadSize == size,
                                                    onClick = {
                                                        useCustom = false
                                                        viewModel.updateDnsPayloadSize(size)
                                                        showMtuDialog = false
                                                    }
                                                )
                                                Column(modifier = Modifier.padding(start = 8.dp)) {
                                                    Text(text = if (size == 0) "Full" else "$size")
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
                                                .padding(vertical = 10.dp, horizontal = 8.dp),
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            RadioButton(
                                                selected = useCustom,
                                                onClick = { useCustom = true }
                                            )
                                            OutlinedTextField(
                                                value = customMtuText,
                                                onValueChange = { customMtuText = it.filter { c -> c.isDigit() }.take(3) },
                                                enabled = useCustom,
                                                label = { Text("Custom") },
                                                placeholder = { Text("50–120") },
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
                                                if (value != null && value in 50..120) {
                                                    viewModel.updateDnsPayloadSize(value)
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
                }

                // NoizDNS stealth mode toggle
                if (uiState.isNoizdnsBased) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Stealth mode",
                                style = MaterialTheme.typography.bodyLarge
                            )
                            Text(
                                text = "Slower speed, harder to detect by DPI",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = uiState.noizdnsStealth,
                            onCheckedChange = { viewModel.updateNoizdnsStealth(it) }
                        )
                    }
                    if (uiState.noizdnsStealth && !uiState.dnsttAuthoritative) {
                        Text(
                            text = "Internet speed will be reduced. Use split tunneling to limit which apps use the tunnel for better performance.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.padding(bottom = 8.dp)
                        )
                    }

                }

                // Snowflake / Tor bridge config
                if (uiState.isSnowflake) {
                    Text(
                        text = "Your bridges",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(top = 8.dp)
                    )

                    // "Not sure? Ask Tor" auto-detect button
                    OutlinedButton(
                        onClick = { viewModel.askTor() },
                        enabled = !uiState.isAskingTor,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        if (uiState.isAskingTor) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(18.dp),
                                strokeWidth = 2.dp
                            )
                            Spacer(Modifier.width(8.dp))
                            Text("Detecting...")
                        } else {
                            Text("Auto-detect Best Bridge")
                        }
                    }
                    Text(
                        text = "Auto-detect the best transport for your network",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    // Bridge type selector — vertical radio list
                    val bridgeOptions = listOf(
                        TorBridgeType.SNOWFLAKE to Pair("Snowflake (built-in)", "Disguises your traffic as a video call"),
                        TorBridgeType.SNOWFLAKE_AMP to Pair("Snowflake (AMP)", "Uses Google AMP cache for rendezvous"),
                        TorBridgeType.DIRECT to Pair("Direct", "Connect directly without bridges (easiest to block)"),
                        TorBridgeType.OBFS4 to Pair("obfs4 (built-in)", "Disguises your traffic as random data"),
                        TorBridgeType.MEEK_AZURE to Pair("Meek (Azure)", "Disguises your traffic as cloud service requests"),
                        TorBridgeType.SMART to Pair("Smart Connect", "Automatically tries transports until one works"),
                        TorBridgeType.CUSTOM to Pair(
                            "Manual selection",
                            if (uiState.torBridgeLines.isNotBlank() && uiState.torBridgeType == TorBridgeType.CUSTOM) {
                                val count = uiState.torBridgeLines.lines().count { it.isNotBlank() }
                                "$count bridge${if (count != 1) "s" else ""} added"
                            } else {
                                "Enter your own bridge lines"
                            }
                        )
                    )

                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(0.dp)
                    ) {
                        bridgeOptions.forEach { (type, labels) ->
                            val (title, description) = labels
                            Surface(
                                onClick = { viewModel.selectTorBridgeType(type) },
                                shape = MaterialTheme.shapes.small,
                                color = if (uiState.torBridgeType == type)
                                    MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
                                else
                                    MaterialTheme.colorScheme.surface,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 12.dp, horizontal = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    RadioButton(
                                        selected = uiState.torBridgeType == type,
                                        onClick = { viewModel.selectTorBridgeType(type) }
                                    )
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = title,
                                            style = MaterialTheme.typography.bodyLarge
                                        )
                                        Text(
                                            text = description,
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                            }
                        }
                    }

                    // Bridge lines text field (Custom mode only)
                    if (uiState.torBridgeType == TorBridgeType.CUSTOM) {
                        OutlinedTextField(
                            value = uiState.torBridgeLines,
                            onValueChange = { viewModel.updateTorBridgeLines(it) },
                            label = { Text("Bridge Lines") },
                            placeholder = {
                                Text("obfs4 IP:PORT FINGERPRINT cert=... iat-mode=0")
                            },
                            isError = uiState.torBridgeLinesError != null,
                            supportingText = {
                                Text(
                                    uiState.torBridgeLinesError
                                        ?: "Supported: obfs4, webtunnel, meek, snowflake (one per line)"
                                )
                            },
                            minLines = 3,
                            maxLines = 6,
                            textStyle = MaterialTheme.typography.bodySmall.copy(
                                fontFamily = FontFamily.Monospace
                            ),
                            modifier = Modifier.fillMaxWidth()
                        )
                    }

                    // Find more bridges section
                    Text(
                        text = "Find more bridges",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(top = 16.dp)
                    )

                    Text(
                        text = "Since bridge addresses aren't public, you'll need to request one from the Tor Project.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(bottom = 4.dp)
                    )

                    // Request bridges button (Moat API)
                    Surface(
                        onClick = { if (!uiState.isRequestingBridges) viewModel.requestBridges() },
                        shape = MaterialTheme.shapes.small,
                        color = MaterialTheme.colorScheme.surface,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 12.dp, horizontal = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Spacer(Modifier.width(4.dp))
                            Icon(
                                Icons.Default.SmartToy,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(Modifier.width(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "Bridge Bot",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Text(
                                    text = "Request bridges",
                                    style = MaterialTheme.typography.bodyLarge
                                )
                            }
                            if (uiState.isRequestingBridges) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(20.dp),
                                    strokeWidth = 2.dp
                                )
                            }
                            Spacer(Modifier.width(8.dp))
                        }
                    }

                    val context = LocalContext.current
                    data class BridgeLink(val label: String, val description: String, val url: String, val icon: androidx.compose.ui.graphics.vector.ImageVector)
                    val bridgeLinks = listOf(
                        BridgeLink("Telegram", "Message @GetBridgesBot", "https://t.me/GetBridgesBot", Icons.Default.Send),
                        BridgeLink("Web", "bridges.torproject.org", "https://bridges.torproject.org", Icons.Default.Language),
                        BridgeLink("Gmail or Riseup", "bridges@torproject.org", "mailto:bridges@torproject.org", Icons.Default.Email)
                    )
                    bridgeLinks.forEach { link ->
                        Surface(
                            onClick = {
                                val intent = android.content.Intent(
                                    android.content.Intent.ACTION_VIEW,
                                    android.net.Uri.parse(link.url)
                                )
                                context.startActivity(intent)
                            },
                            shape = MaterialTheme.shapes.small,
                            color = MaterialTheme.colorScheme.surface,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 12.dp, horizontal = 4.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Spacer(Modifier.width(4.dp))
                                Icon(
                                    link.icon,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.size(20.dp)
                                )
                                Spacer(Modifier.width(12.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = link.label,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                    Text(
                                        text = link.description,
                                        style = MaterialTheme.typography.bodyLarge
                                    )
                                }
                                Icon(
                                    Icons.Default.OpenInNew,
                                    contentDescription = "Open",
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.size(20.dp)
                                )
                                Spacer(Modifier.width(8.dp))
                            }
                        }
                    }
                }

                // Slipstream-specific settings
                if (uiState.isSlipstreamBased) {
                    // Keep-Alive Interval (hidden in authoritative mode — polling subsumes keep-alive)
                    if (!uiState.authoritativeMode) {
                        OutlinedTextField(
                            value = uiState.keepAliveInterval,
                            onValueChange = { viewModel.updateKeepAliveInterval(it) },
                            label = { Text("Keep-Alive Interval (ms)") },
                            placeholder = { Text("5000") },
                            supportingText = { Text("QUIC keep-alive interval in milliseconds") },
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }

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
                    if (uiState.authoritativeMode) {
                        Text(
                            text = "Only use when the DNS resolver is your own server. Public resolvers (Google, Cloudflare) will rate-limit and block your connection.",
                            style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Bold),
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.padding(bottom = 8.dp)
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
                        val directLabel = if (uiState.isNaiveBased) "Direct" else "SOCKS"
                        val sshLabel = if (uiState.isNaiveBased) "+ SSH" else "SSH"

                        if (uiState.useSsh) {
                            OutlinedButton(
                                onClick = { viewModel.setUseSsh(false) },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text(directLabel)
                            }
                            Button(
                                onClick = { },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text(sshLabel)
                            }
                        } else {
                            Button(
                                onClick = { },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text(directLabel)
                            }
                            OutlinedButton(
                                onClick = { viewModel.setUseSsh(true) },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text(sshLabel)
                            }
                        }
                    }
                }

                // SOCKS5 Credentials (optional, when SOCKS selected for DNSTT/Slipstream)
                if (uiState.showConnectionMethod && !uiState.useSsh && !uiState.isNaiveBased) {
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

                    // SSH Port (only for DNSTT+SSH / Slipstream+SSH / NAIVE_SSH, not SSH-only which has it near domain)
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

                    // SSH Auth Type Toggle
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        if (uiState.sshAuthType == SshAuthType.PASSWORD) {
                            Button(
                                onClick = { },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("Password")
                            }
                            OutlinedButton(
                                onClick = { viewModel.updateSshAuthType(SshAuthType.KEY) },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("Key")
                            }
                        } else {
                            OutlinedButton(
                                onClick = { viewModel.updateSshAuthType(SshAuthType.PASSWORD) },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("Password")
                            }
                            Button(
                                onClick = { },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("Key")
                            }
                        }
                    }

                    if (uiState.sshAuthType == SshAuthType.PASSWORD) {
                        // Password auth
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
                    } else {
                        // Key auth
                        val context = LocalContext.current
                        val keyFileLauncher = rememberLauncherForActivityResult(
                            ActivityResultContracts.OpenDocument()
                        ) { uri: Uri? ->
                            uri?.let {
                                try {
                                    val content = context.contentResolver.openInputStream(it)
                                        ?.bufferedReader()?.readText() ?: ""
                                    viewModel.updateSshPrivateKey(content)
                                } catch (_: Exception) {}
                            }
                        }

                        OutlinedTextField(
                            value = uiState.sshPrivateKey,
                            onValueChange = { viewModel.updateSshPrivateKey(it) },
                            label = { Text("SSH Private Key") },
                            placeholder = { Text("-----BEGIN OPENSSH PRIVATE KEY-----") },
                            isError = uiState.sshPrivateKeyError != null,
                            supportingText = uiState.sshPrivateKeyError?.let { { Text(it) } },
                            minLines = 3,
                            maxLines = 8,
                            textStyle = MaterialTheme.typography.bodySmall.copy(
                                fontFamily = FontFamily.Monospace
                            ),
                            modifier = Modifier.fillMaxWidth()
                        )

                        OutlinedButton(
                            onClick = { keyFileLauncher.launch(arrayOf("*/*")) },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Import Key File")
                        }

                        var passphraseVisible by remember { mutableStateOf(false) }
                        OutlinedTextField(
                            value = uiState.sshKeyPassphrase,
                            onValueChange = { viewModel.updateSshKeyPassphrase(it) },
                            label = { Text("Key Passphrase (optional)") },
                            placeholder = { Text("Enter passphrase if key is encrypted") },
                            singleLine = true,
                            visualTransformation = if (passphraseVisible) VisualTransformation.None else PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                            trailingIcon = {
                                IconButton(onClick = { passphraseVisible = !passphraseVisible }) {
                                    Text(
                                        text = if (passphraseVisible) "Hide" else "Show",
                                        style = MaterialTheme.typography.labelMedium,
                                        color = MaterialTheme.colorScheme.primary
                                    )
                                }
                            },
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                }

                // Server setup guide
                Spacer(modifier = Modifier.height(8.dp))
                HorizontalDivider()
                Spacer(modifier = Modifier.height(12.dp))

                Surface(
                    onClick = {
                        val intent = android.content.Intent(
                            android.content.Intent.ACTION_VIEW,
                            android.net.Uri.parse("https://github.com/anonvector/slipgate")
                        )
                        context.startActivity(intent)
                    },
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.4f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 14.dp, horizontal = 16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.OpenInNew,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp),
                            tint = MaterialTheme.colorScheme.primary
                        )
                        Spacer(Modifier.width(12.dp))
                        Text(
                            "Server Setup Guide",
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
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
    onTestServers: (DohTestScope) -> Unit,
    customDohUrls: String = "",
    onCustomDohUrlsChange: (String) -> Unit = {}
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

    // Multi-line custom URLs for batch testing
    OutlinedTextField(
        value = customDohUrls,
        onValueChange = onCustomDohUrlsChange,
        label = { Text("Custom DoH URLs to Test") },
        placeholder = { Text("https://example.com/dns-query\nhttps://other.com/dns-query") },
        supportingText = { Text("One URL per line — tested alongside presets") },
        singleLine = false,
        minLines = 2,
        maxLines = 5,
        modifier = Modifier.fillMaxWidth()
    )

    // Import + Test buttons
    val context = LocalContext.current
    val importLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            try {
                context.contentResolver.openInputStream(it)?.use { stream ->
                    val content = stream.bufferedReader().readText()
                    // Extract lines that look like DoH URLs
                    val urls = content.lines()
                        .map { line -> line.trim() }
                        .filter { line -> line.startsWith("https://", ignoreCase = true) }
                    if (urls.isNotEmpty()) {
                        val existing = customDohUrls.trim()
                        val merged = if (existing.isNotEmpty()) {
                            existing + "\n" + urls.joinToString("\n")
                        } else {
                            urls.joinToString("\n")
                        }
                        onCustomDohUrlsChange(merged)
                    }
                }
            } catch (_: Exception) { }
        }
    }

    OutlinedButton(
        onClick = { importLauncher.launch("text/*") },
        modifier = Modifier.fillMaxWidth()
    ) {
        Icon(Icons.Default.FileUpload, contentDescription = null, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text("Import List")
    }

    val presetUrls = remember { DOH_SERVERS.map { it.url }.toSet() }
    val hasCustom = customDohUrls.lines().any { it.trim().startsWith("https://") }
            || (dohUrl.startsWith("https://") && dohUrl !in presetUrls)
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        OutlinedButton(
            onClick = { onTestServers(DohTestScope.PRESETS) },
            modifier = Modifier.weight(1f)
        ) {
            Icon(Icons.Default.Speed, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text("Presets")
        }

        OutlinedButton(
            onClick = { onTestServers(DohTestScope.CUSTOM) },
            enabled = hasCustom,
            modifier = Modifier.weight(1f)
        ) {
            Icon(Icons.Default.Speed, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text("Custom")
        }
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

@Composable
private fun LockedInfoRow(
    icon: ImageVector,
    label: String,
    value: String,
    valueColor: Color = MaterialTheme.colorScheme.onSurface
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            modifier = Modifier.size(18.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.weight(1f))
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
            color = valueColor
        )
    }
}

