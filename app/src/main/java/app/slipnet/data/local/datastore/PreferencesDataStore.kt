package app.slipnet.data.local.datastore

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "slipstream_preferences")

@Singleton
class PreferencesDataStore @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val dataStore = context.dataStore

    // Preference Keys
    private object Keys {
        val AUTO_CONNECT_ON_BOOT = booleanPreferencesKey("auto_connect_on_boot")
        val ACTIVE_PROFILE_ID = longPreferencesKey("active_profile_id")
        val DARK_MODE = stringPreferencesKey("dark_mode")
        val DEBUG_LOGGING = booleanPreferencesKey("debug_logging")
        val TOTAL_BYTES_SENT = longPreferencesKey("total_bytes_sent")
        val TOTAL_BYTES_RECEIVED = longPreferencesKey("total_bytes_received")
        val TOTAL_CONNECTION_TIME = longPreferencesKey("total_connection_time")
        val LAST_CONNECTED_PROFILE_ID = longPreferencesKey("last_connected_profile_id")
        // Proxy Settings Keys
        val PROXY_LISTEN_ADDRESS = stringPreferencesKey("proxy_listen_address")
        val PROXY_LISTEN_PORT = intPreferencesKey("proxy_listen_port")
        // Network Settings Keys
        val DISABLE_QUIC = booleanPreferencesKey("disable_quic")
        // Network Optimization Keys
        val DNS_TIMEOUT = intPreferencesKey("dns_timeout")
        val CONNECTION_TIMEOUT = intPreferencesKey("connection_timeout")
        val BUFFER_SIZE = stringPreferencesKey("buffer_size")
        val CONNECTION_POOL_SIZE = intPreferencesKey("connection_pool_size")
        // SSH Tunnel Keys
        val SSH_CIPHER = stringPreferencesKey("ssh_cipher")
        val SSH_COMPRESSION = booleanPreferencesKey("ssh_compression")
        val SSH_MAX_CHANNELS = intPreferencesKey("ssh_max_channels")
        // Split Tunneling Keys
        val SPLIT_TUNNELING_ENABLED = booleanPreferencesKey("split_tunneling_enabled")
        val SPLIT_TUNNELING_MODE = stringPreferencesKey("split_tunneling_mode")
        val SPLIT_TUNNELING_APPS = stringPreferencesKey("split_tunneling_apps")
        // HTTP Proxy Keys
        val HTTP_PROXY_ENABLED = booleanPreferencesKey("http_proxy_enabled")
        val HTTP_PROXY_PORT = intPreferencesKey("http_proxy_port")
        val APPEND_HTTP_PROXY_TO_VPN = booleanPreferencesKey("append_http_proxy_to_vpn")
        // Proxy-Only Mode
        val PROXY_ONLY_MODE = booleanPreferencesKey("proxy_only_mode")
        // Kill Switch
        val KILL_SWITCH = booleanPreferencesKey("kill_switch")
        // Sleep Timer
        val SLEEP_TIMER_MINUTES = intPreferencesKey("sleep_timer_minutes")
        // Recent DNS Resolvers
        val RECENT_DNS_RESOLVERS = stringPreferencesKey("recent_dns_resolvers")
        // First Launch
        val FIRST_LAUNCH_DONE = booleanPreferencesKey("first_launch_done")
        // Domain Routing Keys
        val DOMAIN_ROUTING_ENABLED = booleanPreferencesKey("domain_routing_enabled")
        val DOMAIN_ROUTING_MODE = stringPreferencesKey("domain_routing_mode")
        val DOMAIN_ROUTING_DOMAINS = stringPreferencesKey("domain_routing_domains")
        // Geo-Bypass Keys
        val GEO_BYPASS_ENABLED = booleanPreferencesKey("geo_bypass_enabled")
        val GEO_BYPASS_COUNTRY = stringPreferencesKey("geo_bypass_country")
        // Remote DNS Keys
        val REMOTE_DNS_MODE = stringPreferencesKey("remote_dns_mode")
        val CUSTOM_REMOTE_DNS = stringPreferencesKey("custom_remote_dns")
        val CUSTOM_REMOTE_DNS_FALLBACK = stringPreferencesKey("custom_remote_dns_fallback")
    }

    // Auto-connect on boot
    val autoConnectOnBoot: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.AUTO_CONNECT_ON_BOOT] ?: false
    }

    suspend fun setAutoConnectOnBoot(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[Keys.AUTO_CONNECT_ON_BOOT] = enabled
        }
    }

    // Active profile ID
    val activeProfileId: Flow<Long?> = dataStore.data.map { prefs ->
        prefs[Keys.ACTIVE_PROFILE_ID]
    }

    suspend fun setActiveProfileId(id: Long?) {
        dataStore.edit { prefs ->
            if (id != null) {
                prefs[Keys.ACTIVE_PROFILE_ID] = id
            } else {
                prefs.remove(Keys.ACTIVE_PROFILE_ID)
            }
        }
    }

    // Dark mode
    val darkMode: Flow<DarkMode> = dataStore.data.map { prefs ->
        DarkMode.fromValue(prefs[Keys.DARK_MODE] ?: DarkMode.SYSTEM.value)
    }

    suspend fun setDarkMode(mode: DarkMode) {
        dataStore.edit { prefs ->
            prefs[Keys.DARK_MODE] = mode.value
        }
    }

    // Debug logging
    val debugLogging: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.DEBUG_LOGGING] ?: false
    }

    suspend fun setDebugLogging(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[Keys.DEBUG_LOGGING] = enabled
        }
    }

    // Total statistics
    val totalBytesSent: Flow<Long> = dataStore.data.map { prefs ->
        prefs[Keys.TOTAL_BYTES_SENT] ?: 0L
    }

    val totalBytesReceived: Flow<Long> = dataStore.data.map { prefs ->
        prefs[Keys.TOTAL_BYTES_RECEIVED] ?: 0L
    }

    val totalConnectionTime: Flow<Long> = dataStore.data.map { prefs ->
        prefs[Keys.TOTAL_CONNECTION_TIME] ?: 0L
    }

    suspend fun updateTotalStats(bytesSent: Long, bytesReceived: Long, connectionTime: Long) {
        dataStore.edit { prefs ->
            prefs[Keys.TOTAL_BYTES_SENT] = (prefs[Keys.TOTAL_BYTES_SENT] ?: 0L) + bytesSent
            prefs[Keys.TOTAL_BYTES_RECEIVED] = (prefs[Keys.TOTAL_BYTES_RECEIVED] ?: 0L) + bytesReceived
            prefs[Keys.TOTAL_CONNECTION_TIME] = (prefs[Keys.TOTAL_CONNECTION_TIME] ?: 0L) + connectionTime
        }
    }

    suspend fun resetTotalStats() {
        dataStore.edit { prefs ->
            prefs[Keys.TOTAL_BYTES_SENT] = 0L
            prefs[Keys.TOTAL_BYTES_RECEIVED] = 0L
            prefs[Keys.TOTAL_CONNECTION_TIME] = 0L
        }
    }

    // Last connected profile
    val lastConnectedProfileId: Flow<Long?> = dataStore.data.map { prefs ->
        prefs[Keys.LAST_CONNECTED_PROFILE_ID]
    }

    suspend fun setLastConnectedProfileId(id: Long?) {
        dataStore.edit { prefs ->
            if (id != null) {
                prefs[Keys.LAST_CONNECTED_PROFILE_ID] = id
            } else {
                prefs.remove(Keys.LAST_CONNECTED_PROFILE_ID)
            }
        }
    }

    // Proxy Settings
    val proxyListenAddress: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.PROXY_LISTEN_ADDRESS] ?: "0.0.0.0"
    }

    suspend fun setProxyListenAddress(address: String) {
        dataStore.edit { prefs ->
            prefs[Keys.PROXY_LISTEN_ADDRESS] = address
        }
    }

    val proxyListenPort: Flow<Int> = dataStore.data.map { prefs ->
        prefs[Keys.PROXY_LISTEN_PORT] ?: 1080
    }

    suspend fun setProxyListenPort(port: Int) {
        dataStore.edit { prefs ->
            prefs[Keys.PROXY_LISTEN_PORT] = port.coerceIn(1, 65535)
        }
    }

    // Network Settings
    val disableQuic: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.DISABLE_QUIC] ?: true
    }

    suspend fun setDisableQuic(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[Keys.DISABLE_QUIC] = enabled
        }
    }

    // Network Optimization Settings
    val dnsTimeout: Flow<Int> = dataStore.data.map { prefs ->
        prefs[Keys.DNS_TIMEOUT] ?: 5000
    }

    suspend fun setDnsTimeout(timeout: Int) {
        dataStore.edit { prefs ->
            prefs[Keys.DNS_TIMEOUT] = timeout.coerceIn(1000, 15000)
        }
    }

    val connectionTimeout: Flow<Int> = dataStore.data.map { prefs ->
        prefs[Keys.CONNECTION_TIMEOUT] ?: 30000
    }

    suspend fun setConnectionTimeout(timeout: Int) {
        dataStore.edit { prefs ->
            prefs[Keys.CONNECTION_TIMEOUT] = timeout.coerceIn(10000, 60000)
        }
    }

    val bufferSize: Flow<BufferSize> = dataStore.data.map { prefs ->
        BufferSize.fromValue(prefs[Keys.BUFFER_SIZE] ?: BufferSize.MEDIUM.value)
    }

    suspend fun setBufferSize(size: BufferSize) {
        dataStore.edit { prefs ->
            prefs[Keys.BUFFER_SIZE] = size.value
        }
    }

    val connectionPoolSize: Flow<Int> = dataStore.data.map { prefs ->
        prefs[Keys.CONNECTION_POOL_SIZE] ?: 10
    }

    suspend fun setConnectionPoolSize(size: Int) {
        dataStore.edit { prefs ->
            prefs[Keys.CONNECTION_POOL_SIZE] = size.coerceIn(1, 20)
        }
    }

    // SSH Tunnel Settings
    val sshCipher: Flow<SshCipher> = dataStore.data.map { prefs ->
        SshCipher.fromValue(prefs[Keys.SSH_CIPHER] ?: SshCipher.AUTO.value)
    }

    suspend fun setSshCipher(cipher: SshCipher) {
        dataStore.edit { prefs ->
            prefs[Keys.SSH_CIPHER] = cipher.value
        }
    }

    val sshCompression: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.SSH_COMPRESSION] ?: false
    }

    suspend fun setSshCompression(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[Keys.SSH_COMPRESSION] = enabled
        }
    }

    val sshMaxChannels: Flow<Int> = dataStore.data.map { prefs ->
        prefs[Keys.SSH_MAX_CHANNELS] ?: 16
    }

    suspend fun setSshMaxChannels(count: Int) {
        dataStore.edit { prefs ->
            prefs[Keys.SSH_MAX_CHANNELS] = count.coerceIn(4, 64)
        }
    }

    // Split Tunneling Settings
    val splitTunnelingEnabled: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.SPLIT_TUNNELING_ENABLED] ?: false
    }

    suspend fun setSplitTunnelingEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[Keys.SPLIT_TUNNELING_ENABLED] = enabled
        }
    }

    val splitTunnelingMode: Flow<SplitTunnelingMode> = dataStore.data.map { prefs ->
        SplitTunnelingMode.fromValue(prefs[Keys.SPLIT_TUNNELING_MODE] ?: SplitTunnelingMode.DISALLOW.value)
    }

    suspend fun setSplitTunnelingMode(mode: SplitTunnelingMode) {
        dataStore.edit { prefs ->
            prefs[Keys.SPLIT_TUNNELING_MODE] = mode.value
        }
    }

    val splitTunnelingApps: Flow<Set<String>> = dataStore.data.map { prefs ->
        val json = prefs[Keys.SPLIT_TUNNELING_APPS] ?: "[]"
        try {
            org.json.JSONArray(json).let { arr ->
                (0 until arr.length()).map { arr.getString(it) }.toSet()
            }
        } catch (_: Exception) {
            emptySet()
        }
    }

    suspend fun setSplitTunnelingApps(apps: Set<String>) {
        dataStore.edit { prefs ->
            prefs[Keys.SPLIT_TUNNELING_APPS] = org.json.JSONArray(apps.toList()).toString()
        }
    }

    // Recent DNS Resolvers
    val recentDnsResolvers: Flow<List<String>> = dataStore.data.map { prefs ->
        val json = prefs[Keys.RECENT_DNS_RESOLVERS] ?: "[]"
        try {
            org.json.JSONArray(json).let { arr ->
                (0 until arr.length()).map { arr.getString(it) }
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    suspend fun addRecentDnsResolvers(newResolvers: List<String>) {
        dataStore.edit { prefs ->
            val existing = try {
                val json = prefs[Keys.RECENT_DNS_RESOLVERS] ?: "[]"
                org.json.JSONArray(json).let { arr ->
                    (0 until arr.length()).map { arr.getString(it) }
                }
            } catch (_: Exception) {
                emptyList()
            }
            val updated = (newResolvers + existing).distinct().take(5)
            prefs[Keys.RECENT_DNS_RESOLVERS] = org.json.JSONArray(updated).toString()
        }
    }

    // HTTP Proxy Settings
    val httpProxyEnabled: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.HTTP_PROXY_ENABLED] ?: false
    }

    suspend fun setHttpProxyEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[Keys.HTTP_PROXY_ENABLED] = enabled
        }
    }

    val httpProxyPort: Flow<Int> = dataStore.data.map { prefs ->
        prefs[Keys.HTTP_PROXY_PORT] ?: 8080
    }

    suspend fun setHttpProxyPort(port: Int) {
        dataStore.edit { prefs ->
            prefs[Keys.HTTP_PROXY_PORT] = port.coerceIn(1, 65535)
        }
    }

    val appendHttpProxyToVpn: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.APPEND_HTTP_PROXY_TO_VPN] ?: false
    }

    suspend fun setAppendHttpProxyToVpn(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[Keys.APPEND_HTTP_PROXY_TO_VPN] = enabled
        }
    }

    // Proxy-Only Mode
    val proxyOnlyMode: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.PROXY_ONLY_MODE] ?: false
    }

    suspend fun setProxyOnlyMode(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[Keys.PROXY_ONLY_MODE] = enabled
        }
    }

    // Kill Switch
    val killSwitch: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.KILL_SWITCH] ?: false
    }

    suspend fun setKillSwitch(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[Keys.KILL_SWITCH] = enabled
        }
    }

    // Sleep Timer
    val sleepTimerMinutes: Flow<Int> = dataStore.data.map { prefs ->
        prefs[Keys.SLEEP_TIMER_MINUTES] ?: 0
    }

    suspend fun setSleepTimerMinutes(minutes: Int) {
        dataStore.edit { prefs ->
            prefs[Keys.SLEEP_TIMER_MINUTES] = minutes.coerceIn(0, 120)
        }
    }

    // First Launch
    val firstLaunchDone: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.FIRST_LAUNCH_DONE] ?: false
    }

    suspend fun setFirstLaunchDone() {
        dataStore.edit { prefs ->
            prefs[Keys.FIRST_LAUNCH_DONE] = true
        }
    }

    // Domain Routing Settings
    val domainRoutingEnabled: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.DOMAIN_ROUTING_ENABLED] ?: false
    }

    suspend fun setDomainRoutingEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[Keys.DOMAIN_ROUTING_ENABLED] = enabled
        }
    }

    val domainRoutingMode: Flow<DomainRoutingMode> = dataStore.data.map { prefs ->
        DomainRoutingMode.fromValue(prefs[Keys.DOMAIN_ROUTING_MODE] ?: DomainRoutingMode.BYPASS.value)
    }

    suspend fun setDomainRoutingMode(mode: DomainRoutingMode) {
        dataStore.edit { prefs ->
            prefs[Keys.DOMAIN_ROUTING_MODE] = mode.value
        }
    }

    val domainRoutingDomains: Flow<Set<String>> = dataStore.data.map { prefs ->
        val json = prefs[Keys.DOMAIN_ROUTING_DOMAINS] ?: "[]"
        try {
            org.json.JSONArray(json).let { arr ->
                (0 until arr.length()).map { arr.getString(it) }.toSet()
            }
        } catch (_: Exception) {
            emptySet()
        }
    }

    suspend fun setDomainRoutingDomains(domains: Set<String>) {
        dataStore.edit { prefs ->
            prefs[Keys.DOMAIN_ROUTING_DOMAINS] = org.json.JSONArray(domains.toList()).toString()
        }
    }

    // Geo-Bypass Settings
    val geoBypassEnabled: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.GEO_BYPASS_ENABLED] ?: false
    }

    suspend fun setGeoBypassEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[Keys.GEO_BYPASS_ENABLED] = enabled
        }
    }

    val geoBypassCountry: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.GEO_BYPASS_COUNTRY] ?: "ir"
    }

    suspend fun setGeoBypassCountry(country: String) {
        dataStore.edit { prefs ->
            prefs[Keys.GEO_BYPASS_COUNTRY] = country
        }
    }

    // Remote DNS Settings
    val remoteDnsMode: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.REMOTE_DNS_MODE] ?: "default"
    }

    suspend fun setRemoteDnsMode(mode: String) {
        dataStore.edit { prefs ->
            prefs[Keys.REMOTE_DNS_MODE] = mode
        }
    }

    val customRemoteDns: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.CUSTOM_REMOTE_DNS] ?: ""
    }

    suspend fun setCustomRemoteDns(dns: String) {
        dataStore.edit { prefs ->
            prefs[Keys.CUSTOM_REMOTE_DNS] = dns
        }
    }

    val customRemoteDnsFallback: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.CUSTOM_REMOTE_DNS_FALLBACK] ?: ""
    }

    suspend fun setCustomRemoteDnsFallback(dns: String) {
        dataStore.edit { prefs ->
            prefs[Keys.CUSTOM_REMOTE_DNS_FALLBACK] = dns
        }
    }

    companion object {
        const val DEFAULT_REMOTE_DNS = "8.8.8.8"
        const val DEFAULT_REMOTE_DNS_FALLBACK = "1.1.1.1"
    }

    /**
     * Returns the effective primary remote DNS server IP.
     * "8.8.8.8" for default mode, or the custom IP when custom mode is selected.
     */
    fun getEffectiveRemoteDns(): Flow<String> = dataStore.data.map { prefs ->
        val mode = prefs[Keys.REMOTE_DNS_MODE] ?: "default"
        if (mode == "custom") {
            val custom = prefs[Keys.CUSTOM_REMOTE_DNS] ?: ""
            custom.ifBlank { DEFAULT_REMOTE_DNS }
        } else {
            DEFAULT_REMOTE_DNS
        }
    }

    /**
     * Returns the effective fallback remote DNS server IP.
     * "1.1.1.1" for default mode, or the custom fallback when custom mode is selected.
     */
    fun getEffectiveRemoteDnsFallback(): Flow<String> = dataStore.data.map { prefs ->
        val mode = prefs[Keys.REMOTE_DNS_MODE] ?: "default"
        if (mode == "custom") {
            val custom = prefs[Keys.CUSTOM_REMOTE_DNS_FALLBACK] ?: ""
            custom.ifBlank { DEFAULT_REMOTE_DNS_FALLBACK }
        } else {
            DEFAULT_REMOTE_DNS_FALLBACK
        }
    }

    // Scan Session (file-based — can be large with 10K+ resolvers)
    private val scanSessionFile: File
        get() = File(context.cacheDir, "scan_session.json")

    suspend fun saveScanSession(json: String) = withContext(Dispatchers.IO) {
        scanSessionFile.writeText(json)
    }

    suspend fun getSavedScanSession(): String? = withContext(Dispatchers.IO) {
        val file = scanSessionFile
        if (file.exists()) file.readText() else null
    }

    suspend fun clearScanSession() = withContext(Dispatchers.IO) {
        scanSessionFile.delete()
    }
}

enum class DarkMode(val value: String) {
    LIGHT("light"),
    DARK("dark"),
    SYSTEM("system");

    companion object {
        fun fromValue(value: String): DarkMode {
            return entries.find { it.value == value } ?: SYSTEM
        }
    }
}

enum class BufferSize(val value: String, val bytes: Int) {
    SMALL("small", 65536),       // 64KB
    MEDIUM("medium", 262144),    // 256KB
    LARGE("large", 524288);      // 512KB

    companion object {
        fun fromValue(value: String): BufferSize {
            return entries.find { it.value == value } ?: MEDIUM
        }
    }
}

enum class SshCipher(val value: String, val displayName: String, val jschConfig: String?) {
    AUTO("auto", "Auto (Fastest)", null),
    AES_128_GCM("aes128-gcm", "AES-128-GCM", "aes128-gcm@openssh.com"),
    CHACHA20("chacha20", "ChaCha20-Poly1305", "chacha20-poly1305@openssh.com"),
    AES_128_CTR("aes128-ctr", "AES-128-CTR (Legacy)", "aes128-ctr");

    companion object {
        fun fromValue(value: String): SshCipher {
            return entries.find { it.value == value } ?: AUTO
        }
    }
}

enum class SplitTunnelingMode(val value: String) {
    DISALLOW("disallow"),
    ALLOW("allow");

    companion object {
        fun fromValue(value: String): SplitTunnelingMode {
            return entries.find { it.value == value } ?: DISALLOW
        }
    }
}

enum class DomainRoutingMode(val value: String) {
    BYPASS("bypass"),
    ONLY_VPN("only_vpn");

    companion object {
        fun fromValue(value: String): DomainRoutingMode {
            return entries.find { it.value == value } ?: BYPASS
        }
    }
}

