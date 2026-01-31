package app.slipnet.presentation.profiles

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.slipnet.domain.model.CongestionControl
import app.slipnet.domain.model.DnsResolver
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.usecase.GetProfileByIdUseCase
import app.slipnet.domain.usecase.SaveProfileUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

data class EditProfileUiState(
    val profileId: Long? = null,
    val name: String = "",
    val domain: String = "",
    val resolvers: String = "", // Format: "host:port,host:port"
    val authoritativeMode: Boolean = false,
    val keepAliveInterval: String = "200",
    val congestionControl: CongestionControl = CongestionControl.BBR,
    val tcpListenPort: String = "10800",
    val tcpListenHost: String = "127.0.0.1",
    val gsoEnabled: Boolean = false,
    val isLoading: Boolean = false,
    val isSaving: Boolean = false,
    val saveSuccess: Boolean = false,
    val error: String? = null,
    val nameError: String? = null,
    val domainError: String? = null,
    val resolversError: String? = null
)

@HiltViewModel
class EditProfileViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val getProfileByIdUseCase: GetProfileByIdUseCase,
    private val saveProfileUseCase: SaveProfileUseCase
) : ViewModel() {

    private val profileId: Long? = savedStateHandle.get<Long>("profileId")

    private val _uiState = MutableStateFlow(EditProfileUiState(profileId = profileId))
    val uiState: StateFlow<EditProfileUiState> = _uiState.asStateFlow()

    init {
        if (profileId != null && profileId != 0L) {
            loadProfile(profileId)
        }
    }

    private fun loadProfile(id: Long) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true)

            val profile = getProfileByIdUseCase(id)
            if (profile != null) {
                _uiState.value = _uiState.value.copy(
                    profileId = profile.id,
                    name = profile.name,
                    domain = profile.domain,
                    resolvers = profile.resolvers.joinToString(",") { "${it.host}:${it.port}" },
                    authoritativeMode = profile.authoritativeMode,
                    keepAliveInterval = profile.keepAliveInterval.toString(),
                    congestionControl = profile.congestionControl,
                    tcpListenPort = profile.tcpListenPort.toString(),
                    tcpListenHost = profile.tcpListenHost,
                    gsoEnabled = profile.gsoEnabled,
                    isLoading = false
                )
            } else {
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    error = "Profile not found"
                )
            }
        }
    }

    fun updateName(name: String) {
        _uiState.value = _uiState.value.copy(name = name, nameError = null)
    }

    fun updateDomain(domain: String) {
        _uiState.value = _uiState.value.copy(domain = domain, domainError = null)
    }

    fun updateResolvers(resolvers: String) {
        _uiState.value = _uiState.value.copy(resolvers = resolvers, resolversError = null)
    }

    fun updateAuthoritativeMode(enabled: Boolean) {
        _uiState.value = _uiState.value.copy(authoritativeMode = enabled)
    }

    fun updateKeepAliveInterval(interval: String) {
        _uiState.value = _uiState.value.copy(keepAliveInterval = interval)
    }

    fun updateCongestionControl(cc: CongestionControl) {
        _uiState.value = _uiState.value.copy(congestionControl = cc)
    }

    fun updateTcpListenPort(port: String) {
        _uiState.value = _uiState.value.copy(tcpListenPort = port)
    }

    fun updateTcpListenHost(host: String) {
        _uiState.value = _uiState.value.copy(tcpListenHost = host)
    }

    fun updateGsoEnabled(enabled: Boolean) {
        _uiState.value = _uiState.value.copy(gsoEnabled = enabled)
    }

    fun save() {
        val state = _uiState.value

        // Validation
        var hasError = false

        if (state.name.isBlank()) {
            _uiState.value = _uiState.value.copy(nameError = "Name is required")
            hasError = true
        }

        if (state.domain.isBlank()) {
            _uiState.value = _uiState.value.copy(domainError = "Domain is required")
            hasError = true
        }

        if (state.resolvers.isBlank()) {
            _uiState.value = _uiState.value.copy(resolversError = "At least one resolver is required")
            hasError = true
        }

        if (hasError) return

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isSaving = true)

            try {
                val resolversList = parseResolvers(state.resolvers, state.authoritativeMode)
                val keepAlive = state.keepAliveInterval.toIntOrNull() ?: 200
                val listenPort = state.tcpListenPort.toIntOrNull() ?: 10800

                val profile = ServerProfile(
                    id = state.profileId ?: 0,
                    name = state.name.trim(),
                    domain = state.domain.trim(),
                    resolvers = resolversList,
                    authoritativeMode = state.authoritativeMode,
                    keepAliveInterval = keepAlive,
                    congestionControl = state.congestionControl,
                    tcpListenPort = listenPort,
                    tcpListenHost = state.tcpListenHost.ifBlank { "127.0.0.1" },
                    gsoEnabled = state.gsoEnabled
                )

                saveProfileUseCase(profile)
                _uiState.value = _uiState.value.copy(
                    isSaving = false,
                    saveSuccess = true
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isSaving = false,
                    error = e.message ?: "Failed to save profile"
                )
            }
        }
    }

    private fun parseResolvers(input: String, authoritativeMode: Boolean): List<DnsResolver> {
        return input.split(",")
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .map { resolver ->
                val parts = resolver.split(":")
                DnsResolver(
                    host = parts[0].trim(),
                    port = parts.getOrNull(1)?.trim()?.toIntOrNull() ?: 53,
                    authoritative = authoritativeMode
                )
            }
    }

    fun clearError() {
        _uiState.value = _uiState.value.copy(error = null)
    }
}
