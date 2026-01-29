package app.slipnet.presentation.profiles

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.usecase.DeleteProfileUseCase
import app.slipnet.domain.usecase.GetProfilesUseCase
import app.slipnet.domain.usecase.SetActiveProfileUseCase
import app.slipnet.service.VpnConnectionManager
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import javax.inject.Inject

data class ProfileListUiState(
    val profiles: List<ServerProfile> = emptyList(),
    val connectedProfileId: Long? = null,
    val isLoading: Boolean = false,
    val error: String? = null
)

@HiltViewModel
class ProfileListViewModel @Inject constructor(
    private val getProfilesUseCase: GetProfilesUseCase,
    private val deleteProfileUseCase: DeleteProfileUseCase,
    private val setActiveProfileUseCase: SetActiveProfileUseCase,
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
}
