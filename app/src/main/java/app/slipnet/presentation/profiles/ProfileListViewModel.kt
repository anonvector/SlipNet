package app.slipnet.presentation.profiles

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.slipnet.data.export.ConfigExporter
import app.slipnet.data.export.ConfigImporter
import app.slipnet.data.export.ImportResult
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.repository.ProfileRepository
import app.slipnet.domain.usecase.DeleteProfileUseCase
import app.slipnet.domain.usecase.GetProfilesUseCase
import app.slipnet.domain.usecase.SaveProfileUseCase
import app.slipnet.domain.usecase.SetActiveProfileUseCase
import app.slipnet.service.VpnConnectionManager
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import javax.inject.Inject

data class ImportPreview(
    val profiles: List<ServerProfile>,
    val warnings: List<String>
)

data class QrCodeData(
    val profileName: String,
    val configUri: String
)

data class ProfileListUiState(
    val profiles: List<ServerProfile> = emptyList(),
    val connectedProfileId: Long? = null,
    val isLoading: Boolean = false,
    val error: String? = null,
    val exportedJson: String? = null,
    val importPreview: ImportPreview? = null,
    val qrCodeData: QrCodeData? = null
)

@HiltViewModel
class ProfileListViewModel @Inject constructor(
    private val getProfilesUseCase: GetProfilesUseCase,
    private val deleteProfileUseCase: DeleteProfileUseCase,
    private val setActiveProfileUseCase: SetActiveProfileUseCase,
    private val saveProfileUseCase: SaveProfileUseCase,
    private val profileRepository: ProfileRepository,
    private val configExporter: ConfigExporter,
    private val configImporter: ConfigImporter,
    private val connectionManager: VpnConnectionManager
) : ViewModel() {

    private val _uiState = MutableStateFlow(ProfileListUiState())
    val uiState: StateFlow<ProfileListUiState> = _uiState.asStateFlow()

    init {
        loadProfiles()
    }

    private fun loadProfiles() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true)

            combine(
                getProfilesUseCase(),
                connectionManager.connectionState
            ) { profiles, connectionState ->
                val connectedId = when (connectionState) {
                    is ConnectionState.Connected -> connectionState.profile.id
                    else -> null
                }
                Pair(profiles, connectedId)
            }.collect { (profiles, connectedId) ->
                _uiState.value = _uiState.value.copy(
                    profiles = profiles,
                    connectedProfileId = connectedId,
                    isLoading = false
                )
            }
        }
    }

    fun moveProfile(fromIndex: Int, toIndex: Int) {
        val currentList = _uiState.value.profiles.toMutableList()
        if (fromIndex < 0 || fromIndex >= currentList.size ||
            toIndex < 0 || toIndex >= currentList.size) return

        val item = currentList.removeAt(fromIndex)
        currentList.add(toIndex, item)

        // Instant UI update
        _uiState.value = _uiState.value.copy(profiles = currentList)

        // Persist in background
        viewModelScope.launch {
            profileRepository.updateProfileOrder(currentList.map { it.id })
        }
    }

    fun deleteProfile(profile: ServerProfile) {
        viewModelScope.launch {
            val result = deleteProfileUseCase(profile.id)
            if (result.isFailure) {
                _uiState.value = _uiState.value.copy(
                    error = result.exceptionOrNull()?.message ?: "Failed to delete profile"
                )
            }
        }
    }

    fun deleteAllProfiles() {
        viewModelScope.launch {
            val connectedId = _uiState.value.connectedProfileId
            val profilesToDelete = _uiState.value.profiles.filter { it.id != connectedId }
            for (profile in profilesToDelete) {
                deleteProfileUseCase(profile.id)
            }
        }
    }

    fun setActiveProfile(profile: ServerProfile) {
        viewModelScope.launch {
            setActiveProfileUseCase(profile.id)
        }
    }

    fun connectToProfile(profile: ServerProfile) {
        connectionManager.connect(profile)
    }

    fun clearError() {
        _uiState.value = _uiState.value.copy(error = null)
    }

    fun exportProfile(profile: ServerProfile) {
        val json = configExporter.exportSingleProfile(profile)
        _uiState.value = _uiState.value.copy(exportedJson = json)
    }

    fun exportAllProfiles() {
        val profiles = _uiState.value.profiles
        if (profiles.isEmpty()) {
            _uiState.value = _uiState.value.copy(error = "No profiles to export")
            return
        }
        val json = configExporter.exportAllProfiles(profiles)
        _uiState.value = _uiState.value.copy(exportedJson = json)
    }

    fun clearExportedJson() {
        _uiState.value = _uiState.value.copy(exportedJson = null)
    }

    fun parseImportConfig(json: String) {
        when (val result = configImporter.parseAndImport(json)) {
            is ImportResult.Success -> {
                _uiState.value = _uiState.value.copy(
                    importPreview = ImportPreview(result.profiles, result.warnings)
                )
            }
            is ImportResult.Error -> {
                _uiState.value = _uiState.value.copy(error = result.message)
            }
        }
    }

    fun confirmImport() {
        val preview = _uiState.value.importPreview ?: return
        viewModelScope.launch {
            try {
                var importedCount = 0
                for (profile in preview.profiles) {
                    saveProfileUseCase(profile)
                    importedCount++
                }
                _uiState.value = _uiState.value.copy(
                    importPreview = null,
                    error = null
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    error = "Failed to import profiles: ${e.message}",
                    importPreview = null
                )
            }
        }
    }

    fun cancelImport() {
        _uiState.value = _uiState.value.copy(importPreview = null)
    }

    fun showQrCode(profile: ServerProfile) {
        val configUri = configExporter.exportSingleProfile(profile)
        _uiState.value = _uiState.value.copy(
            qrCodeData = QrCodeData(profile.name, configUri)
        )
    }

    fun clearQrCode() {
        _uiState.value = _uiState.value.copy(qrCodeData = null)
    }
}
