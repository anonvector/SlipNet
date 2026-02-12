package app.slipnet.presentation.profiles

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import app.slipnet.presentation.common.icons.TorIcon
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Waves
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
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
import androidx.compose.ui.graphics.TransformOrigin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import app.slipnet.domain.model.ServerProfile
import kotlinx.coroutines.launch

import app.slipnet.presentation.common.components.ProfileListItem
import app.slipnet.presentation.common.components.QrCodeDialog
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfileListScreen(
    onNavigateBack: () -> Unit,
    onNavigateToAddProfile: (tunnelType: String) -> Unit,
    onNavigateToEditProfile: (Long) -> Unit,
    viewModel: ProfileListViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    var profileToDelete by remember { mutableStateOf<ServerProfile?>(null) }
    var showOverflowMenu by remember { mutableStateOf(false) }
    var showImportDialog by remember { mutableStateOf(false) }
    var importText by remember { mutableStateOf("") }
    var showAddMenu by remember { mutableStateOf(false) }

    val importFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri?.let {
            try {
                context.contentResolver.openInputStream(it)?.use { inputStream ->
                    val json = inputStream.bufferedReader().readText()
                    viewModel.parseImportConfig(json)
                }
            } catch (e: Exception) {
                viewModel.clearError()
            }
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

    // Handle export - launch share sheet
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

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Profiles") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    Box {
                        IconButton(onClick = { showOverflowMenu = true }) {
                            Icon(Icons.Default.MoreVert, contentDescription = "More options")
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
                        }
                    }
                }
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
                    modifier = Modifier.padding(bottom = 16.dp, end = 8.dp)
                ) {
                    Icon(Icons.Default.Add, contentDescription = "Add Profile")
                }
            }
        },
        snackbarHost = { SnackbarHost(snackbarHostState) }
    ) { paddingValues ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
        ) {
            when {
                uiState.isLoading -> {
                    CircularProgressIndicator(
                        modifier = Modifier.align(Alignment.Center)
                    )
                }
                uiState.profiles.isEmpty() -> {
                    Text(
                        text = "No profiles yet.\nTap + to add your first profile.",
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                        modifier = Modifier
                            .align(Alignment.Center)
                            .padding(32.dp)
                    )
                }
                else -> {
                    LazyColumn(
                        contentPadding = PaddingValues(
                            start = 16.dp, end = 16.dp,
                            top = 16.dp, bottom = 88.dp
                        ),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        items(
                            items = uiState.profiles,
                            key = { it.id }
                        ) { profile ->
                            val isConnected = uiState.connectedProfileId == profile.id

                            ProfileListItem(
                                profile = profile,
                                isSelected = profile.isActive,
                                isConnected = isConnected,
                                onClick = { viewModel.setActiveProfile(profile) },
                                onEditClick = {
                                    onNavigateToEditProfile(profile.id)
                                },
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
                                onShareQrClick = { viewModel.showQrCode(profile) }
                            )
                        }
                    }
                }
            }

            // Scrim to dismiss the FAB menu
            if (showAddMenu) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .clickable(
                            indication = null,
                            interactionSource = remember { androidx.compose.foundation.interaction.MutableInteractionSource() }
                        ) { showAddMenu = false }
                )
            }
        }
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
                ) {
                    Text("Delete")
                }
            },
            dismissButton = {
                TextButton(onClick = { profileToDelete = null }) {
                    Text("Cancel")
                }
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
                            text = "• ${profile.name}",
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
                                text = "• $warning",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { viewModel.confirmImport() }) {
                    Text("Import")
                }
            },
            dismissButton = {
                TextButton(onClick = { viewModel.cancelImport() }) {
                    Text("Cancel")
                }
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
                        ) {
                            Text("Import from File")
                        }
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
                        ) {
                            Text("Scan QR Code")
                        }
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
                ) {
                    Text("Import")
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        showImportDialog = false
                        importText = ""
                    }
                ) {
                    Text("Cancel")
                }
            }
        )
    }
}

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
