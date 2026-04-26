package app.slipnet.presentation.chain

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditChainScreen(
    onNavigateBack: () -> Unit,
    viewModel: EditChainViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()

    LaunchedEffect(uiState.isSaved) {
        if (uiState.isSaved) onNavigateBack()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (uiState.isEditing) "Edit Chain" else "New Chain") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
        ) {
            OutlinedTextField(
                value = uiState.name,
                onValueChange = viewModel::setName,
                label = { Text("Chain Name") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                "Layers",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold
            )
            Text(
                "Top layer reaches the Internet. Bottom layer receives your apps.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(8.dp))

            // Selected profiles in chain order
            LazyColumn(
                modifier = Modifier.weight(1f),
                contentPadding = PaddingValues(vertical = 4.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                itemsIndexed(uiState.selectedProfileIds) { index, profileId ->
                    val profile = uiState.allProfiles.find { it.id == profileId }
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant
                        )
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 12.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            // Layer number badge
                            Text(
                                text = "${index + 1}",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier
                                    .size(28.dp)
                                    .clip(RoundedCornerShape(14.dp))
                                    .background(MaterialTheme.colorScheme.primary)
                                    .padding(4.dp),
                                color = MaterialTheme.colorScheme.onPrimary,
                                textAlign = androidx.compose.ui.text.style.TextAlign.Center
                            )

                            Spacer(modifier = Modifier.width(12.dp))

                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = profile?.name ?: "Deleted profile",
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.Medium
                                )
                                Text(
                                    text = profile?.tunnelType?.displayName ?: "Unknown",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }

                            // Move up/down
                            if (index > 0) {
                                IconButton(
                                    onClick = { viewModel.moveProfile(index, index - 1) },
                                    modifier = Modifier.size(32.dp)
                                ) {
                                    Icon(Icons.Default.KeyboardArrowUp, "Move up", modifier = Modifier.size(20.dp))
                                }
                            }
                            if (index < uiState.selectedProfileIds.size - 1) {
                                IconButton(
                                    onClick = { viewModel.moveProfile(index, index + 1) },
                                    modifier = Modifier.size(32.dp)
                                ) {
                                    Icon(Icons.Default.KeyboardArrowDown, "Move down", modifier = Modifier.size(20.dp))
                                }
                            }
                            IconButton(
                                onClick = { viewModel.removeProfile(index) },
                                modifier = Modifier.size(32.dp)
                            ) {
                                Icon(Icons.Default.Delete, "Remove", modifier = Modifier.size(20.dp))
                            }
                        }
                    }
                }

                // Add profile button
                item {
                    var showDropdown by remember { mutableStateOf(false) }
                    val availableProfiles = uiState.allProfiles.filter {
                        it.id !in uiState.selectedProfileIds
                    }

                    OutlinedButton(
                        onClick = { showDropdown = true },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = availableProfiles.isNotEmpty()
                    ) {
                        Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Add Layer")
                    }

                    DropdownMenu(
                        expanded = showDropdown,
                        onDismissRequest = { showDropdown = false }
                    ) {
                        availableProfiles.forEach { profile ->
                            DropdownMenuItem(
                                text = {
                                    Column {
                                        Text(profile.name)
                                        Text(
                                            profile.tunnelType.displayName,
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                },
                                onClick = {
                                    viewModel.addProfile(profile.id)
                                    showDropdown = false
                                }
                            )
                        }
                    }
                }
            }

            // Validation error
            uiState.validationError?.let { error ->
                Text(
                    text = error,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(vertical = 8.dp)
                )
            }

            // Save button
            androidx.compose.material3.Button(
                onClick = viewModel::save,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 16.dp),
                enabled = uiState.selectedProfileIds.size >= 2 && uiState.name.isNotBlank() && uiState.validationError == null
            ) {
                Text(if (uiState.isEditing) "Save Chain" else "Create Chain")
            }
        }
    }
}
