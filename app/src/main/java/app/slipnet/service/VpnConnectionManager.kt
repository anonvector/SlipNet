package app.slipnet.service

import android.content.Context
import android.content.Intent
import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.data.repository.VpnRepositoryImpl
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.ProfileChain
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TrafficStats
import app.slipnet.domain.repository.ChainRepository
import app.slipnet.domain.repository.ProfileRepository
import app.slipnet.widget.VpnWidgetCompactProvider
import app.slipnet.widget.VpnWidgetProvider
import app.slipnet.util.DeviceIdUtil
import androidx.core.content.ContextCompat
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class VpnConnectionManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val vpnRepository: VpnRepositoryImpl,
    private val profileRepository: ProfileRepository,
    private val chainRepository: ChainRepository,
    private val preferencesDataStore: PreferencesDataStore
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    private val _connectionState = MutableStateFlow<ConnectionState>(ConnectionState.Disconnected)
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    private val _dnsWarning = MutableStateFlow<String?>(null)
    val dnsWarning: StateFlow<String?> = _dnsWarning.asStateFlow()

    val trafficStats: StateFlow<TrafficStats> = vpnRepository.trafficStats

    private var pendingProfile: ServerProfile? = null
    private var pendingChain: ProfileChain? = null

    init {
        // Observe VPN repository state
        scope.launch {
            vpnRepository.connectionState.collect { state ->
                _connectionState.value = state
            }
        }

        // Push state changes to home screen widget
        scope.launch {
            _connectionState.collect { state ->
                VpnWidgetProvider.notifyStateChanged(context, state)
                VpnWidgetCompactProvider.notifyStateChanged(context, state)
            }
        }
    }

    fun getDeviceId(): String {
        return DeviceIdUtil.getScrambledDeviceId(context)
    }

    fun connect(profile: ServerProfile) {
        if (_connectionState.value is ConnectionState.Connected ||
            _connectionState.value is ConnectionState.Connecting) {
            return
        }

        if (profile.isExpired) {
            _connectionState.value = ConnectionState.Error("This profile has expired")
            return
        }
        if (profile.boundDeviceId.isNotEmpty() && profile.boundDeviceId != getDeviceId()) {
            _connectionState.value = ConnectionState.Error("This profile is bound to a different device")
            return
        }

        pendingProfile = profile
        _connectionState.value = ConnectionState.Connecting
        _dnsWarning.value = null

        // Set active profile immediately so it shows on the main screen
        scope.launch {
            profileRepository.setActiveProfile(profile.id)
        }

        // Start VPN service
        val intent = Intent(context, SlipNetVpnService::class.java).apply {
            action = SlipNetVpnService.ACTION_CONNECT
            putExtra(SlipNetVpnService.EXTRA_PROFILE_ID, profile.id)
        }
        ContextCompat.startForegroundService(context, intent)
    }

    fun reconnect(profile: ServerProfile) {
        if (profile.isExpired) {
            _connectionState.value = ConnectionState.Error("This profile has expired")
            return
        }
        if (profile.boundDeviceId.isNotEmpty() && profile.boundDeviceId != getDeviceId()) {
            _connectionState.value = ConnectionState.Error("This profile is bound to a different device")
            return
        }

        pendingProfile = profile
        _connectionState.value = ConnectionState.Connecting
        _dnsWarning.value = null

        scope.launch {
            profileRepository.setActiveProfile(profile.id)
        }

        // Send CONNECT directly — the service handles stopping the old connection
        // (disconnectJob?.join()) before starting the new one.
        val intent = Intent(context, SlipNetVpnService::class.java).apply {
            action = SlipNetVpnService.ACTION_CONNECT
            putExtra(SlipNetVpnService.EXTRA_PROFILE_ID, profile.id)
        }
        ContextCompat.startForegroundService(context, intent)
    }

    fun connectChain(chain: ProfileChain, firstProfile: ServerProfile) {
        if (_connectionState.value is ConnectionState.Connected ||
            _connectionState.value is ConnectionState.Connecting) {
            return
        }

        pendingProfile = firstProfile
        pendingChain = chain
        _connectionState.value = ConnectionState.Connecting
        _dnsWarning.value = null

        val intent = Intent(context, SlipNetVpnService::class.java).apply {
            action = SlipNetVpnService.ACTION_CONNECT
            putExtra(SlipNetVpnService.EXTRA_CHAIN_ID, chain.id)
        }
        ContextCompat.startForegroundService(context, intent)
    }

    fun disconnect() {
        if (_connectionState.value is ConnectionState.Disconnected) {
            return
        }

        _connectionState.value = ConnectionState.Disconnecting

        val intent = Intent(context, SlipNetVpnService::class.java).apply {
            action = SlipNetVpnService.ACTION_DISCONNECT
        }
        context.startService(intent)
    }

    fun onVpnEstablished() {
        val profile = pendingProfile ?: return

        // Tunnels are already started by SlipNetVpnService before calling this method.
        // Just do bookkeeping here - save the profile as last connected.
        scope.launch {
            preferencesDataStore.setLastConnectedProfileId(profile.id)
            profileRepository.updateLastConnectedAt(profile.id)
        }
    }

    fun onVpnDisconnected() {
        // Reset repository state without going through the full disconnect flow
        // (which would redundantly stop tunnels and emit Disconnecting state that
        // can race with a new Connecting state if the user reconnects quickly).
        vpnRepository.updateConnectionState(ConnectionState.Disconnected)
        _connectionState.value = ConnectionState.Disconnected
        _dnsWarning.value = null
        pendingProfile = null
    }

    fun onVpnError(error: String) {
        scope.launch {
            _connectionState.value = ConnectionState.Error(friendlyError(error))
        }
    }

    private fun friendlyError(raw: String): String {
        // Map raw Java/Go exception messages to user-friendly text
        val lower = raw.lowercase()
        return when {
            // Timeouts (Java + Go)
            lower.contains("i/o timeout") || lower.contains("dial tcp") && lower.contains("timeout") ->
                "DNS tunnel timed out — server may be unreachable or blocked"
            lower.contains("context deadline exceeded") ->
                "Connection timed out — server took too long to respond"
            lower.contains("sockettimeoutexception") || lower.contains("read timed out") || lower.contains("connect timed out") ->
                "Connection timed out — server may be unreachable or blocked"
            // Connection errors
            lower.contains("connectionexception") || lower.contains("connection refused") ->
                "Connection refused — server may be down"
            lower.contains("unknownhostexception") || lower.contains("unable to resolve host") || lower.contains("no such host") ->
                "DNS lookup failed — check your internet connection"
            lower.contains("network is unreachable") || lower.contains("networkunreachable") || lower.contains("no route to host") ->
                "Network unreachable — check your internet connection"
            // TLS/SSL
            lower.contains("sslexception") || lower.contains("ssl handshake") || lower.contains("tls handshake") ->
                "Secure connection failed — TLS handshake error"
            // Resets & broken pipes
            lower.contains("econnreset") || lower.contains("connection reset") ->
                "Connection was reset — the server closed the connection"
            lower.contains("broken pipe") || lower.contains("eof") && lower.contains("unexpected") ->
                "Connection lost — the tunnel was interrupted"
            // Permission
            lower.contains("permission denied") ->
                "Permission denied — check VPN permissions"
            else -> raw
        }
    }

    fun setDnsWarning(message: String?) {
        _dnsWarning.value = message
    }

    fun refreshTrafficStats() {
        vpnRepository.refreshTrafficStats()
    }

    suspend fun getProfileById(id: Long): ServerProfile? {
        return profileRepository.getProfileById(id)
    }

    suspend fun getActiveProfile(): ServerProfile? {
        return profileRepository.getActiveProfile().first()
    }

    suspend fun shouldAutoConnect(): Boolean {
        return preferencesDataStore.autoConnectOnBoot.first()
    }

    suspend fun getLastConnectedProfile(): ServerProfile? {
        val lastProfileId = preferencesDataStore.lastConnectedProfileId.first() ?: return null
        return profileRepository.getProfileById(lastProfileId)
    }
}
