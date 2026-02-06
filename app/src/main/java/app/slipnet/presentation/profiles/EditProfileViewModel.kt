package app.slipnet.presentation.profiles

import android.content.Context
import android.net.ConnectivityManager
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.slipnet.domain.model.CongestionControl
import app.slipnet.domain.model.DnsResolver
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TunnelType
import app.slipnet.domain.usecase.GetProfileByIdUseCase
import app.slipnet.domain.usecase.SaveProfileUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

data class EditProfileUiState(
    val profileId: Long? = null,
    val name: String = "",
    val domain: String = "",
    val resolvers: String = "1.1.1.1:53", // Format: "host:port,host:port"
    val authoritativeMode: Boolean = false,
    val keepAliveInterval: String = "200",
    val congestionControl: CongestionControl = CongestionControl.BBR,
    val gsoEnabled: Boolean = false,
    val tcpListenPort: String = "10800",
    val tcpListenHost: String = "127.0.0.1",
    val socksAuthEnabled: Boolean = false,
    val socksUsername: String = "",
    val socksPassword: String = "",
    // Tunnel type selection (DNSTT is recommended)
    val tunnelType: TunnelType = TunnelType.DNSTT,
    // DNSTT-specific fields
    val dnsttPublicKey: String = "",
    val dnsttPublicKeyError: String? = null,
    // SSH tunnel fields
    val sshEnabled: Boolean = false,
    val sshUsername: String = "",
    val sshPassword: String = "",
    val sshUsernameError: String? = null,
    val sshPasswordError: String? = null,
    val isLoading: Boolean = false,
    val isSaving: Boolean = false,
    val isAutoDetecting: Boolean = false,
    val saveSuccess: Boolean = false,
    val error: String? = null,
    val nameError: String? = null,
    val domainError: String? = null,
    val resolversError: String? = null
)

@HiltViewModel
class EditProfileViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
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
                    gsoEnabled = profile.gsoEnabled,
                    tcpListenPort = profile.tcpListenPort.toString(),
                    tcpListenHost = profile.tcpListenHost,
                    socksAuthEnabled = !profile.socksUsername.isNullOrBlank(),
                    socksUsername = profile.socksUsername ?: "",
                    socksPassword = profile.socksPassword ?: "",
                    tunnelType = profile.tunnelType,
                    dnsttPublicKey = profile.dnsttPublicKey,
                    sshEnabled = profile.sshEnabled,
                    sshUsername = profile.sshUsername,
                    sshPassword = profile.sshPassword,
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
        // Validate in real-time but only show error if user has typed something
        val error = if (resolvers.isNotBlank()) {
            validateResolvers(resolvers)
        } else {
            null
        }
        _uiState.value = _uiState.value.copy(resolvers = resolvers, resolversError = error)
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

    fun updateSocksAuthEnabled(enabled: Boolean) {
        val isDnstt = _uiState.value.tunnelType == TunnelType.DNSTT
        _uiState.value = _uiState.value.copy(
            socksAuthEnabled = enabled,
            // Clear credentials when disabled
            socksUsername = if (enabled) _uiState.value.socksUsername else "",
            socksPassword = if (enabled) _uiState.value.socksPassword else "",
            // Mutually exclusive with SSH (DNSTT only)
            sshEnabled = if (enabled && isDnstt) false else _uiState.value.sshEnabled,
            sshUsername = if (enabled && isDnstt) "" else _uiState.value.sshUsername,
            sshPassword = if (enabled && isDnstt) "" else _uiState.value.sshPassword,
            sshUsernameError = null,
            sshPasswordError = null
        )
    }

    fun updateSocksUsername(username: String) {
        _uiState.value = _uiState.value.copy(socksUsername = username)
    }

    fun updateSocksPassword(password: String) {
        _uiState.value = _uiState.value.copy(socksPassword = password)
    }

    fun updateTunnelType(tunnelType: TunnelType) {
        _uiState.value = _uiState.value.copy(
            tunnelType = tunnelType,
            // SSH is only supported for DNSTT - disable when switching to Slipstream
            sshEnabled = if (tunnelType == TunnelType.SLIPSTREAM) false else _uiState.value.sshEnabled,
            sshUsername = if (tunnelType == TunnelType.SLIPSTREAM) "" else _uiState.value.sshUsername,
            sshPassword = if (tunnelType == TunnelType.SLIPSTREAM) "" else _uiState.value.sshPassword,
            sshUsernameError = null,
            sshPasswordError = null
        )
    }

    fun updateDnsttPublicKey(publicKey: String) {
        // Validate in real-time but only show error if user has typed something
        val error = if (publicKey.isNotBlank()) {
            validateDnsttPublicKey(publicKey)
        } else {
            null
        }
        _uiState.value = _uiState.value.copy(dnsttPublicKey = publicKey, dnsttPublicKeyError = error)
    }

    fun updateSshEnabled(enabled: Boolean) {
        _uiState.value = _uiState.value.copy(
            sshEnabled = enabled,
            sshUsername = if (enabled) _uiState.value.sshUsername else "",
            sshPassword = if (enabled) _uiState.value.sshPassword else "",
            sshUsernameError = null,
            sshPasswordError = null,
            // Mutually exclusive with SOCKS5 auth
            socksAuthEnabled = if (enabled) false else _uiState.value.socksAuthEnabled,
            socksUsername = if (enabled) "" else _uiState.value.socksUsername,
            socksPassword = if (enabled) "" else _uiState.value.socksPassword
        )
    }

    fun updateSshUsername(username: String) {
        _uiState.value = _uiState.value.copy(sshUsername = username, sshUsernameError = null)
    }

    fun updateSshPassword(password: String) {
        _uiState.value = _uiState.value.copy(sshPassword = password, sshPasswordError = null)
    }

    fun autoDetectResolver() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isAutoDetecting = true)
            try {
                val state = _uiState.value
                val resolverIp = withContext(Dispatchers.IO) {
                    // Both tunnel types need the ISP DNS server as resolver
                    // to forward tunneled DNS queries to the authoritative server
                    getSystemDnsServer()
                }

                if (resolverIp != null) {
                    updateResolvers("$resolverIp:53")
                } else {
                    _uiState.value = _uiState.value.copy(
                        error = "Could not detect DNS server"
                    )
                }
                _uiState.value = _uiState.value.copy(isAutoDetecting = false)
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isAutoDetecting = false,
                    error = "Auto-detect failed: ${e.message}"
                )
            }
        }
    }

    private fun getSystemDnsServer(): String? {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = connectivityManager.activeNetwork ?: return null
        val linkProperties = connectivityManager.getLinkProperties(network) ?: return null
        return linkProperties.dnsServers.firstOrNull()?.hostAddress
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

        // Resolver validation
        if (state.resolvers.isBlank()) {
            _uiState.value = _uiState.value.copy(resolversError = "At least one resolver is required")
            hasError = true
        } else {
            val resolversError = validateResolvers(state.resolvers)
            if (resolversError != null) {
                _uiState.value = _uiState.value.copy(resolversError = resolversError)
                hasError = true
            }
        }

        // DNSTT-specific validation
        if (state.tunnelType == TunnelType.DNSTT) {
            val publicKeyError = validateDnsttPublicKey(state.dnsttPublicKey)
            if (publicKeyError != null) {
                _uiState.value = _uiState.value.copy(dnsttPublicKeyError = publicKeyError)
                hasError = true
            }
        }

        // SSH validation (DNSTT only)
        if (state.sshEnabled && state.tunnelType == TunnelType.DNSTT) {
            if (state.sshUsername.isBlank()) {
                _uiState.value = _uiState.value.copy(sshUsernameError = "SSH username is required")
                hasError = true
            }
            if (state.sshPassword.isBlank()) {
                _uiState.value = _uiState.value.copy(sshPasswordError = "SSH password is required")
                hasError = true
            }
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
                    gsoEnabled = state.gsoEnabled,
                    tcpListenPort = listenPort,
                    tcpListenHost = state.tcpListenHost.ifBlank { "127.0.0.1" },
                    socksUsername = if (state.socksAuthEnabled && state.socksUsername.isNotBlank()) state.socksUsername else null,
                    socksPassword = if (state.socksAuthEnabled && state.socksPassword.isNotBlank()) state.socksPassword else null,
                    tunnelType = state.tunnelType,
                    dnsttPublicKey = state.dnsttPublicKey.trim(),
                    sshEnabled = state.sshEnabled && state.tunnelType == TunnelType.DNSTT,
                    sshUsername = if (state.sshEnabled && state.tunnelType == TunnelType.DNSTT) state.sshUsername.trim() else "",
                    sshPassword = if (state.sshEnabled && state.tunnelType == TunnelType.DNSTT) state.sshPassword else ""
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

    /**
     * Validates DNSTT public key format.
     * Noise protocol uses Curve25519 keys which are 32 bytes (64 hex characters).
     * @return error message if invalid, null if valid
     */
    private fun validateDnsttPublicKey(publicKey: String): String? {
        val trimmed = publicKey.trim()

        if (trimmed.isBlank()) {
            return "Public key is required for DNSTT"
        }

        // Check length: 32 bytes = 64 hex characters
        if (trimmed.length != 64) {
            return "Public key must be 64 hex characters (32 bytes), got ${trimmed.length}"
        }

        // Check if all characters are valid hex
        if (!trimmed.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
            return "Public key must contain only hex characters (0-9, a-f)"
        }

        return null
    }

    /**
     * Validates DNS resolver format.
     * Expected format: "host:port" or "host" (port defaults to 53)
     * Multiple resolvers can be comma-separated.
     * Supports IPv4, IPv6, and domain names.
     * @return error message if invalid, null if valid
     */
    private fun validateResolvers(input: String): String? {
        val resolvers = input.split(",").map { it.trim() }.filter { it.isNotBlank() }

        if (resolvers.isEmpty()) {
            return "At least one resolver is required"
        }

        for (resolver in resolvers) {
            val error = validateSingleResolver(resolver)
            if (error != null) {
                return error
            }
        }

        return null
    }

    private fun validateSingleResolver(resolver: String): String? {
        val trimmed = resolver.trim()

        if (trimmed.isBlank()) {
            return "Resolver cannot be empty"
        }

        // Handle IPv6 with port: [2001:db8::1]:53
        if (trimmed.startsWith("[")) {
            val closeBracket = trimmed.indexOf("]")
            if (closeBracket == -1) {
                return "Invalid IPv6 format: missing closing bracket in '$trimmed'"
            }

            val ipv6 = trimmed.substring(1, closeBracket)
            if (!isValidIPv6(ipv6)) {
                return "Invalid IPv6 address: '$ipv6'"
            }

            // Check for port after ]
            if (closeBracket < trimmed.length - 1) {
                if (trimmed[closeBracket + 1] != ':') {
                    return "Invalid format: expected ':' after ']' in '$trimmed'"
                }
                val portStr = trimmed.substring(closeBracket + 2)
                val portError = validatePort(portStr, trimmed)
                if (portError != null) return portError
            }

            return null
        }

        // Count colons to distinguish IPv4:port from IPv6
        val colonCount = trimmed.count { it == ':' }

        when {
            // IPv6 without port (multiple colons)
            colonCount > 1 -> {
                if (!isValidIPv6(trimmed)) {
                    return "Invalid IPv6 address: '$trimmed'"
                }
            }
            // IPv4:port or host:port (single colon)
            colonCount == 1 -> {
                val parts = trimmed.split(":")
                val host = parts[0]
                val portStr = parts[1]

                val hostError = validateHost(host)
                if (hostError != null) return hostError

                val portError = validatePort(portStr, trimmed)
                if (portError != null) return portError
            }
            // No colon - just host/IP (port defaults to 53)
            else -> {
                val hostError = validateHost(trimmed)
                if (hostError != null) return hostError
            }
        }

        return null
    }

    private fun validateHost(host: String): String? {
        if (host.isBlank()) {
            return "Host cannot be empty"
        }

        // Check if it's an IPv4 address
        if (host.all { it.isDigit() || it == '.' }) {
            if (!isValidIPv4(host)) {
                return "Invalid IPv4 address: '$host'"
            }
            return null
        }

        // Otherwise treat as domain name - basic validation
        if (!isValidDomainName(host)) {
            return "Invalid host: '$host'"
        }

        return null
    }

    private fun validatePort(portStr: String, context: String): String? {
        val port = portStr.toIntOrNull()
        if (port == null) {
            return "Invalid port number in '$context'"
        }
        if (port !in 1..65535) {
            return "Port must be between 1 and 65535 in '$context'"
        }
        return null
    }

    private fun isValidIPv4(ip: String): Boolean {
        val parts = ip.split(".")
        if (parts.size != 4) return false

        return parts.all { part ->
            val num = part.toIntOrNull() ?: return false
            num in 0..255 && (part == "0" || !part.startsWith("0"))
        }
    }

    private fun isValidIPv6(ip: String): Boolean {
        // Basic IPv6 validation
        val trimmed = ip.trim()

        // Handle :: shorthand
        if (trimmed.contains("::")) {
            val parts = trimmed.split("::")
            if (parts.size > 2) return false // Only one :: allowed

            val left = if (parts[0].isEmpty()) emptyList() else parts[0].split(":")
            val right = if (parts.size < 2 || parts[1].isEmpty()) emptyList() else parts[1].split(":")

            if (left.size + right.size > 7) return false

            return (left + right).all { isValidIPv6Segment(it) }
        }

        // Full IPv6 address
        val segments = trimmed.split(":")
        if (segments.size != 8) return false

        return segments.all { isValidIPv6Segment(it) }
    }

    private fun isValidIPv6Segment(segment: String): Boolean {
        if (segment.isEmpty() || segment.length > 4) return false
        return segment.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
    }

    private fun isValidDomainName(domain: String): Boolean {
        // Basic domain name validation
        if (domain.isEmpty() || domain.length > 253) return false

        val labels = domain.split(".")
        if (labels.isEmpty()) return false

        return labels.all { label ->
            label.isNotEmpty() &&
                    label.length <= 63 &&
                    label.first().isLetterOrDigit() &&
                    label.last().isLetterOrDigit() &&
                    label.all { it.isLetterOrDigit() || it == '-' }
        }
    }

    fun clearError() {
        _uiState.value = _uiState.value.copy(error = null)
    }
}
