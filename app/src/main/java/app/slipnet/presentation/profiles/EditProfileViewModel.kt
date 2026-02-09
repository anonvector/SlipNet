package app.slipnet.presentation.profiles

import android.content.Context
import android.net.ConnectivityManager
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.slipnet.domain.model.CongestionControl
import app.slipnet.domain.model.DnsResolver
import app.slipnet.domain.model.DnsTransport
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TunnelType
import app.slipnet.domain.usecase.GetProfileByIdUseCase
import app.slipnet.domain.usecase.SaveProfileUseCase
import app.slipnet.domain.usecase.SetActiveProfileUseCase
import app.slipnet.tunnel.DOH_SERVERS
import app.slipnet.tunnel.DohBridge
import app.slipnet.tunnel.DohServer
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.inject.Inject
import javax.net.ssl.SSLException
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

data class DohTestResult(
    val name: String,
    val url: String,
    val latencyMs: Long? = null,
    val error: String? = null
) {
    val isSuccess: Boolean get() = latencyMs != null && error == null
}

data class EditProfileUiState(
    val profileId: Long? = null,
    val name: String = "",
    val domain: String = "",
    val resolvers: String = "", // Format: "host:port,host:port" — auto-filled from system DNS
    val authoritativeMode: Boolean = false,
    val keepAliveInterval: String = "200",
    val congestionControl: CongestionControl = CongestionControl.BBR,
    val gsoEnabled: Boolean = false,
    val socksUsername: String = "",
    val socksPassword: String = "",
    // Tunnel type selection (DNSTT is recommended)
    val tunnelType: TunnelType = TunnelType.DNSTT,
    // DNSTT-specific fields
    val dnsttPublicKey: String = "",
    val dnsttPublicKeyError: String? = null,
    // SSH tunnel fields (SSH-only tunnel type)
    val sshUsername: String = "",
    val sshPassword: String = "",
    val sshPort: String = "22",
    val sshUsernameError: String? = null,
    val sshPasswordError: String? = null,
    val sshPortError: String? = null,
    val isLoading: Boolean = false,
    val isSaving: Boolean = false,
    val isAutoDetecting: Boolean = false,
    val saveSuccess: Boolean = false,
    val error: String? = null,
    val nameError: String? = null,
    val domainError: String? = null,
    val resolversError: String? = null,
    // DoH fields
    val dohUrl: String = "",
    val dohUrlError: String? = null,
    val isTestingDoh: Boolean = false,
    val showDohTestDialog: Boolean = false,
    val dohTestResults: List<DohTestResult> = emptyList(),
    // DNS transport for DNSTT tunnel types
    val dnsTransport: DnsTransport = DnsTransport.UDP
) {
    val useSsh: Boolean
        get() = tunnelType == TunnelType.SSH || tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.SLIPSTREAM_SSH

    val isDnsttBased: Boolean
        get() = tunnelType == TunnelType.DNSTT || tunnelType == TunnelType.DNSTT_SSH

    val isSlipstreamBased: Boolean
        get() = tunnelType == TunnelType.SLIPSTREAM || tunnelType == TunnelType.SLIPSTREAM_SSH

    val isSshOnly: Boolean
        get() = tunnelType == TunnelType.SSH

    val isDoh: Boolean
        get() = tunnelType == TunnelType.DOH

    val showConnectionMethod: Boolean
        get() = !isSshOnly && !isDoh
}

@HiltViewModel
class EditProfileViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    savedStateHandle: SavedStateHandle,
    private val getProfileByIdUseCase: GetProfileByIdUseCase,
    private val saveProfileUseCase: SaveProfileUseCase,
    private val setActiveProfileUseCase: SetActiveProfileUseCase
) : ViewModel() {

    private val profileId: Long? = savedStateHandle.get<Long>("profileId")
    private val initialTunnelType: TunnelType = savedStateHandle.get<String>("tunnelType")
        ?.let { TunnelType.fromValue(it) } ?: TunnelType.DNSTT

    private val _uiState = MutableStateFlow(
        EditProfileUiState(profileId = profileId, tunnelType = initialTunnelType)
    )
    val uiState: StateFlow<EditProfileUiState> = _uiState.asStateFlow()

    init {
        if (profileId != null && profileId != 0L) {
            loadProfile(profileId)
        } else {
            // New profile: auto-fill resolver with device's current DNS server
            autoFillResolver()
        }
    }

    private fun autoFillResolver() {
        viewModelScope.launch {
            val dns = withContext(Dispatchers.IO) { getSystemDnsServer() }
            if (dns != null) {
                _uiState.value = _uiState.value.copy(resolvers = "$dns:53")
            }
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
                    socksUsername = profile.socksUsername ?: "",
                    socksPassword = profile.socksPassword ?: "",
                    tunnelType = profile.tunnelType,
                    dnsttPublicKey = profile.dnsttPublicKey,
                    sshUsername = profile.sshUsername,
                    sshPassword = profile.sshPassword,
                    sshPort = profile.sshPort.toString(),
                    dohUrl = profile.dohUrl,
                    dnsTransport = profile.dnsTransport,
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
        val error = if (domain.isNotBlank()) {
            validateDomain(domain.trim(), _uiState.value.tunnelType)
        } else {
            null
        }
        _uiState.value = _uiState.value.copy(domain = domain, domainError = error)
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

    fun updateGsoEnabled(enabled: Boolean) {
        _uiState.value = _uiState.value.copy(gsoEnabled = enabled)
    }

    fun updateSocksUsername(username: String) {
        _uiState.value = _uiState.value.copy(socksUsername = username)
    }

    fun updateSocksPassword(password: String) {
        _uiState.value = _uiState.value.copy(socksPassword = password)
    }

    fun setUseSsh(useSsh: Boolean) {
        val currentType = _uiState.value.tunnelType
        val newType = when {
            useSsh && (currentType == TunnelType.DNSTT || currentType == TunnelType.DNSTT_SSH) -> TunnelType.DNSTT_SSH
            useSsh && (currentType == TunnelType.SLIPSTREAM || currentType == TunnelType.SLIPSTREAM_SSH) -> TunnelType.SLIPSTREAM_SSH
            !useSsh && (currentType == TunnelType.DNSTT || currentType == TunnelType.DNSTT_SSH) -> TunnelType.DNSTT
            !useSsh && (currentType == TunnelType.SLIPSTREAM || currentType == TunnelType.SLIPSTREAM_SSH) -> TunnelType.SLIPSTREAM
            else -> currentType
        }
        _uiState.value = _uiState.value.copy(
            tunnelType = newType,
            sshUsernameError = null,
            sshPasswordError = null,
            sshPortError = null
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

    fun updateSshUsername(username: String) {
        _uiState.value = _uiState.value.copy(sshUsername = username, sshUsernameError = null)
    }

    fun updateSshPassword(password: String) {
        _uiState.value = _uiState.value.copy(sshPassword = password, sshPasswordError = null)
    }

    fun updateSshPort(port: String) {
        _uiState.value = _uiState.value.copy(sshPort = port, sshPortError = null)
    }

    fun updateDnsTransport(transport: DnsTransport) {
        _uiState.value = _uiState.value.copy(dnsTransport = transport)
    }

    fun updateDohUrl(url: String) {
        _uiState.value = _uiState.value.copy(dohUrl = url, dohUrlError = null)
    }

    fun selectDohPreset(preset: DohServer) {
        _uiState.value = _uiState.value.copy(
            dohUrl = preset.url,
            dohUrlError = null
        )
    }

    fun testDohServers() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isTestingDoh = true,
                showDohTestDialog = true,
                dohTestResults = DOH_SERVERS.map { DohTestResult(it.name, it.url) }
            )

            val client = DohBridge.createHttpClient()
            val completed = java.util.concurrent.ConcurrentHashMap<String, DohTestResult>()

            // Launch all tests in parallel — results stream in as each completes
            val jobs = DOH_SERVERS.map { preset ->
                launch(Dispatchers.IO) {
                    val result = testSingleDohServer(preset, client)
                    completed[result.url] = result

                    // Update UI immediately with this result
                    val snapshot = completed.values.toList()
                    val pending = DOH_SERVERS
                        .filter { p -> !completed.containsKey(p.url) }
                        .map { DohTestResult(it.name, it.url) }
                    _uiState.value = _uiState.value.copy(
                        dohTestResults = sortTestResults(snapshot + pending)
                    )
                }
            }

            jobs.joinAll()

            // Clean up OkHttp on IO thread to avoid NetworkOnMainThreadException
            withContext(Dispatchers.IO) {
                client.connectionPool.evictAll()
            }

            _uiState.value = _uiState.value.copy(
                isTestingDoh = false,
                dohTestResults = sortTestResults(completed.values.toList())
            )
        }
    }

    private fun sortTestResults(results: List<DohTestResult>): List<DohTestResult> {
        return results.sortedWith(
            compareBy<DohTestResult> {
                when {
                    it.isSuccess -> 0   // Successful first
                    it.error != null -> 1 // Failed second
                    else -> 2            // Pending last
                }
            }.thenBy { it.latencyMs ?: Long.MAX_VALUE }
        )
    }

    fun dismissDohTestDialog() {
        _uiState.value = _uiState.value.copy(showDohTestDialog = false)
    }

    fun selectDohTestResult(result: DohTestResult) {
        _uiState.value = _uiState.value.copy(
            dohUrl = result.url,
            dohUrlError = null,
            showDohTestDialog = false
        )
    }

    private fun testSingleDohServer(preset: DohServer, client: okhttp3.OkHttpClient): DohTestResult {
        return try {
            val dnsQuery = buildDnsQuery("example.com")
            val startTime = System.currentTimeMillis()

            val body = dnsQuery.toRequestBody("application/dns-message".toMediaType())
            val request = Request.Builder()
                .url(preset.url)
                .post(body)
                .header("Accept", "application/dns-message")
                .build()

            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    response.body?.bytes()
                    val latency = System.currentTimeMillis() - startTime
                    DohTestResult(preset.name, preset.url, latencyMs = latency)
                } else {
                    DohTestResult(preset.name, preset.url, error = "HTTP ${response.code}")
                }
            }
        } catch (e: Exception) {
            val error = when (e) {
                is SocketTimeoutException -> "Timeout"
                is ConnectException -> "Connection refused"
                is UnknownHostException -> "DNS lookup failed"
                is SSLException -> "TLS error"
                else -> {
                    // Clean up raw Java messages like "Failed to connect to /1.2.3.4:443"
                    val msg = e.message ?: "Connection failed"
                    if (msg.contains("/")) msg.substringAfterLast("/").let {
                        if (it.isBlank()) "Unreachable" else it
                    } else msg
                }
            }
            DohTestResult(preset.name, preset.url, error = error)
        }
    }

    /**
     * Build a minimal DNS query for an A record lookup.
     * Wire format per RFC 1035.
     */
    private fun buildDnsQuery(domain: String): ByteArray {
        val out = ByteArrayOutputStream()
        // Transaction ID
        out.write(0x00); out.write(0x01)
        // Flags: standard query, recursion desired
        out.write(0x01); out.write(0x00)
        // Questions: 1
        out.write(0x00); out.write(0x01)
        // Answer/Authority/Additional RRs: 0
        out.write(0x00); out.write(0x00)
        out.write(0x00); out.write(0x00)
        out.write(0x00); out.write(0x00)
        // QNAME
        for (label in domain.split(".")) {
            out.write(label.length)
            out.write(label.toByteArray(Charsets.US_ASCII))
        }
        out.write(0x00) // root label
        // QTYPE: A (1)
        out.write(0x00); out.write(0x01)
        // QCLASS: IN (1)
        out.write(0x00); out.write(0x01)
        return out.toByteArray()
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

        if (state.tunnelType != TunnelType.DOH && state.domain.isBlank()) {
            _uiState.value = _uiState.value.copy(domainError = "Domain is required")
            hasError = true
        } else if (state.tunnelType != TunnelType.DOH && state.domain.isNotBlank()) {
            val domainError = validateDomain(state.domain.trim(), state.tunnelType)
            if (domainError != null) {
                _uiState.value = _uiState.value.copy(domainError = domainError)
                hasError = true
            }
        }

        // DoH URL validation (DOH tunnel type or DNSTT with DoH transport)
        val needsDohUrl = state.tunnelType == TunnelType.DOH ||
                (state.isDnsttBased && state.dnsTransport == DnsTransport.DOH)
        if (needsDohUrl) {
            if (state.dohUrl.isBlank()) {
                _uiState.value = _uiState.value.copy(dohUrlError = "DoH server URL is required")
                hasError = true
            } else if (!state.dohUrl.startsWith("https://")) {
                _uiState.value = _uiState.value.copy(dohUrlError = "URL must start with https://")
                hasError = true
            }
        }

        // Resolver validation (SSH-only, DOH profiles, and DNSTT with DoH transport don't need resolvers)
        val skipResolvers = state.tunnelType == TunnelType.SSH || state.tunnelType == TunnelType.DOH ||
                (state.isDnsttBased && state.dnsTransport == DnsTransport.DOH)
        if (!skipResolvers) {
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
        }

        // DNSTT-specific validation (DNSTT and DNSTT+SSH)
        if (state.tunnelType == TunnelType.DNSTT || state.tunnelType == TunnelType.DNSTT_SSH) {
            val publicKeyError = validateDnsttPublicKey(state.dnsttPublicKey)
            if (publicKeyError != null) {
                _uiState.value = _uiState.value.copy(dnsttPublicKeyError = publicKeyError)
                hasError = true
            }
        }

        // SSH validation (SSH-only, DNSTT+SSH, and Slipstream+SSH tunnel types)
        if (state.tunnelType == TunnelType.SSH || state.tunnelType == TunnelType.DNSTT_SSH || state.tunnelType == TunnelType.SLIPSTREAM_SSH) {
            if (state.sshUsername.isBlank()) {
                _uiState.value = _uiState.value.copy(sshUsernameError = "SSH username is required")
                hasError = true
            }
            if (state.sshPassword.isBlank()) {
                _uiState.value = _uiState.value.copy(sshPasswordError = "SSH password is required")
                hasError = true
            }
        }

        // SSH port validation (SSH-only, DNSTT+SSH, and Slipstream+SSH)
        if (state.tunnelType == TunnelType.SSH || state.tunnelType == TunnelType.DNSTT_SSH || state.tunnelType == TunnelType.SLIPSTREAM_SSH) {
            val sshPort = state.sshPort.toIntOrNull()
            if (sshPort == null || sshPort !in 1..65535) {
                _uiState.value = _uiState.value.copy(sshPortError = "Port must be between 1 and 65535")
                hasError = true
            }
        }

        if (hasError) return

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isSaving = true)

            try {
                val resolversList = parseResolvers(state.resolvers, state.authoritativeMode)
                val keepAlive = state.keepAliveInterval.toIntOrNull() ?: 200

                val profile = ServerProfile(
                    id = state.profileId ?: 0,
                    name = state.name.trim(),
                    domain = state.domain.trim(),
                    resolvers = resolversList,
                    authoritativeMode = state.authoritativeMode,
                    keepAliveInterval = keepAlive,
                    congestionControl = state.congestionControl,
                    gsoEnabled = state.gsoEnabled,
                    socksUsername = state.socksUsername.takeIf { it.isNotBlank() },
                    socksPassword = state.socksPassword.takeIf { it.isNotBlank() },
                    tunnelType = state.tunnelType,
                    dnsttPublicKey = state.dnsttPublicKey.trim(),
                    sshUsername = if (state.useSsh) state.sshUsername.trim() else "",
                    sshPassword = if (state.useSsh) state.sshPassword else "",
                    sshPort = state.sshPort.toIntOrNull() ?: 22,
                    sshHost = "127.0.0.1",
                    useServerDns = false,
                    dohUrl = if (state.isDoh || (state.isDnsttBased && state.dnsTransport == DnsTransport.DOH)) state.dohUrl.trim() else "",
                    dnsTransport = if (state.isDnsttBased) state.dnsTransport else DnsTransport.UDP
                )

                val savedId = saveProfileUseCase(profile)
                setActiveProfileUseCase(savedId)
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
     * Validates domain format for DNSTT and Slipstream tunnel types.
     * These require a proper DNS domain name (e.g., "t.example.com").
     * SSH tunnel type allows IP addresses as the domain field is the SSH host.
     * @return error message if invalid, null if valid
     */
    private fun validateDomain(domain: String, tunnelType: TunnelType): String? {
        val isDnsTunnel = tunnelType == TunnelType.DNSTT || tunnelType == TunnelType.DNSTT_SSH ||
                tunnelType == TunnelType.SLIPSTREAM || tunnelType == TunnelType.SLIPSTREAM_SSH

        if (!isDnsTunnel) return null

        // Must not be an IP address
        if (domain.all { it.isDigit() || it == '.' } && isValidIPv4(domain)) {
            return "Domain must be a hostname, not an IP address"
        }

        // Must be a valid domain with at least 2 labels (e.g., "example.com")
        if (!isValidDomainName(domain)) {
            return "Invalid domain format"
        }

        val labels = domain.split(".")
        if (labels.size < 2) {
            return "Domain must have at least two parts (e.g., t.example.com)"
        }

        return null
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

        if (resolvers.size > MAX_RESOLVERS) {
            return "Maximum $MAX_RESOLVERS resolvers allowed"
        }

        for (resolver in resolvers) {
            val error = validateSingleResolver(resolver)
            if (error != null) {
                return error
            }
        }

        return null
    }

    companion object {
        const val MAX_RESOLVERS = 3
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

        // Check if it's an IPv4 address (all digits and dots)
        if (host.all { it.isDigit() || it == '.' }) {
            if (!isValidIPv4(host)) {
                return "Invalid IPv4 address: '$host'"
            }
            return null
        }

        // Starts with digit + has 3 dots = IPv4 attempt with trailing garbage (e.g. "1.1.1.1abc")
        if (host.first().isDigit() && host.count { it == '.' } == 3) {
            return "Invalid IPv4 address: '$host'"
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
