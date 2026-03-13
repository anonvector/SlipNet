package app.slipnet.presentation.chain

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.slipnet.domain.model.ChainValidation
import app.slipnet.domain.model.ProfileChain
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.repository.ChainRepository
import app.slipnet.domain.repository.ProfileRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import javax.inject.Inject

data class EditChainUiState(
    val name: String = "",
    val selectedProfileIds: List<Long> = emptyList(),
    val allProfiles: List<ServerProfile> = emptyList(),
    val validationError: String? = null,
    val isSaved: Boolean = false,
    val isEditing: Boolean = false
)

@HiltViewModel
class EditChainViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val chainRepository: ChainRepository,
    private val profileRepository: ProfileRepository
) : ViewModel() {

    private val chainId: Long = savedStateHandle.get<Long>("chainId") ?: 0L

    private val _uiState = MutableStateFlow(EditChainUiState(isEditing = chainId > 0))
    val uiState: StateFlow<EditChainUiState> = _uiState.asStateFlow()

    init {
        loadProfiles()
        if (chainId > 0) loadChain()
    }

    private fun loadProfiles() {
        viewModelScope.launch {
            profileRepository.getAllProfiles().first().let { profiles ->
                // Only show single-layer chainable types
                val chainable = profiles.filter { it.tunnelType in ChainValidation.CHAINABLE_TYPES }
                _uiState.value = _uiState.value.copy(allProfiles = chainable)
            }
        }
    }

    private fun loadChain() {
        viewModelScope.launch {
            val chain = chainRepository.getChainById(chainId) ?: return@launch
            _uiState.value = _uiState.value.copy(
                name = chain.name,
                selectedProfileIds = chain.profileIds
            )
            validate()
        }
    }

    fun setName(name: String) {
        _uiState.value = _uiState.value.copy(name = name)
    }

    fun addProfile(profileId: Long) {
        val current = _uiState.value.selectedProfileIds
        if (profileId !in current) {
            _uiState.value = _uiState.value.copy(selectedProfileIds = current + profileId)
            validate()
        }
    }

    fun removeProfile(index: Int) {
        val current = _uiState.value.selectedProfileIds.toMutableList()
        if (index in current.indices) {
            current.removeAt(index)
            _uiState.value = _uiState.value.copy(selectedProfileIds = current)
            validate()
        }
    }

    fun moveProfile(fromIndex: Int, toIndex: Int) {
        val current = _uiState.value.selectedProfileIds.toMutableList()
        if (fromIndex in current.indices && toIndex in current.indices) {
            val item = current.removeAt(fromIndex)
            current.add(toIndex, item)
            _uiState.value = _uiState.value.copy(selectedProfileIds = current)
            validate()
        }
    }

    private fun validate() {
        val state = _uiState.value
        val profiles = state.selectedProfileIds.mapNotNull { id ->
            state.allProfiles.find { it.id == id }
        }
        val error = if (profiles.size < 2) null else ChainValidation.validate(profiles)
        _uiState.value = _uiState.value.copy(validationError = error)
    }

    fun save() {
        viewModelScope.launch {
            val state = _uiState.value
            if (state.name.isBlank()) {
                _uiState.value = state.copy(validationError = "Chain name is required")
                return@launch
            }
            if (state.selectedProfileIds.size < 2) {
                _uiState.value = state.copy(validationError = "Chain must have at least 2 profiles")
                return@launch
            }

            // Final validation
            val profiles = state.selectedProfileIds.mapNotNull { id ->
                state.allProfiles.find { it.id == id }
            }
            val error = ChainValidation.validate(profiles)
            if (error != null) {
                _uiState.value = state.copy(validationError = error)
                return@launch
            }

            val chain = ProfileChain(
                id = chainId,
                name = state.name,
                profileIds = state.selectedProfileIds
            )
            chainRepository.saveChain(chain)
            _uiState.value = state.copy(isSaved = true)
        }
    }
}
