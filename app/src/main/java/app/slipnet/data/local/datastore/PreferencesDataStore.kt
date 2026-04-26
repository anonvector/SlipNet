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
import app.slipnet.domain.model.DnsResolver
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
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
        // Proxy Auth Keys
        val PROXY_AUTH_ENABLED = booleanPreferencesKey("proxy_auth_enabled")
        val PROXY_AUTH_USERNAME = stringPreferencesKey("proxy_auth_username")
        val PROXY_AUTH_PASSWORD = stringPreferencesKey("proxy_auth_password")
        // Network Settings Keys
        val DISABLE_QUIC = booleanPreferencesKey("disable_quic")
        val BLOCK_IPV6 = booleanPreferencesKey("block_ipv6")
        val VPN_MTU = intPreferencesKey("vpn_mtu")
        // Network Optimization Keys
        val DNS_TIMEOUT = intPreferencesKey("dns_timeout")
        val CONNECTION_TIMEOUT = intPreferencesKey("connection_timeout")
        val BUFFER_SIZE = stringPreferencesKey("buffer_size")
        val CONNECTION_POOL_SIZE = intPreferencesKey("connection_pool_size")
        // SSH Tunnel Keys
        val SSH_CIPHER = stringPreferencesKey("ssh_cipher")
        val SSH_COMPRESSION = booleanPreferencesKey("ssh_compression")
        val SSH_MAX_CHANNELS = intPreferencesKey("ssh_max_channels")
        val SSH_MAX_CHANNELS_CUSTOM = booleanPreferencesKey("ssh_max_channels_custom")
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
        // Auto-Reconnect
        val AUTO_RECONNECT = booleanPreferencesKey("auto_reconnect")
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
        // Global DNS Resolver Override
        val GLOBAL_RESOLVER_ENABLED = booleanPreferencesKey("global_resolver_enabled")
        val GLOBAL_RESOLVER_LIST = stringPreferencesKey("global_resolver_list")
        // DNS Leak Prevention
        val PREVENT_DNS_FALLBACK = booleanPreferencesKey("prevent_dns_fallback")
        // Notification Traffic Counter
        val SHOW_NOTIFICATION_TRAFFIC = booleanPreferencesKey("show_notification_traffic")
        // DNS Worker Mode
        val DNS_WORKER_MODE = stringPreferencesKey("dns_worker_mode")
        // Remote DNS Keys
        val REMOTE_DNS_MODE = stringPreferencesKey("remote_dns_mode")
        val CUSTOM_REMOTE_DNS = stringPreferencesKey("custom_remote_dns")
        val CUSTOM_REMOTE_DNS_FALLBACK = stringPreferencesKey("custom_remote_dns_fallback")
        // Bandwidth Limiting Keys
        val UPLOAD_LIMIT_KBPS = intPreferencesKey("upload_limit_kbps")
        val DOWNLOAD_LIMIT_KBPS = intPreferencesKey("download_limit_kbps")
        // DNS Scanner Settings Keys
        val SCANNER_TIMEOUT_MS = stringPreferencesKey("scanner_timeout_ms")
        val SCANNER_CONCURRENCY = stringPreferencesKey("scanner_concurrency")
        val SCANNER_E2E_TIMEOUT_MS = stringPreferencesKey("scanner_e2e_timeout_ms")
        val SCANNER_E2E_CONCURRENCY = stringPreferencesKey("scanner_e2e_concurrency")
        val SCANNER_TEST_URL = stringPreferencesKey("scanner_test_url")
        val SCANNER_PRISM_TIMEOUT_MS = stringPreferencesKey("scanner_prism_timeout_ms")
        val SCANNER_PRISM_PROBE_COUNT = stringPreferencesKey("scanner_prism_probe_count")
        val SCANNER_PRISM_PASS_THRESHOLD = stringPreferencesKey("scanner_prism_pass_threshold")
        val SCANNER_PRISM_RESPONSE_SIZE = stringPreferencesKey("scanner_prism_response_size")
        val SCANNER_PRISM_PREFILTER = booleanPreferencesKey("scanner_prism_prefilter")
        val SCANNER_PRISM_PREFILTER_TIMEOUT_MS = stringPreferencesKey("scanner_prism_prefilter_timeout_ms")
        val SCANNER_TRANSPORT = stringPreferencesKey("scanner_transport")
        // DNS Scanner Resolver List Selection Keys
        val SCANNER_LIST_SOURCE = stringPreferencesKey("scanner_list_source")
        val SCANNER_COUNTRY = stringPreferencesKey("scanner_country")
        val SCANNER_SAMPLE_COUNT = intPreferencesKey("scanner_sample_count")
        val SCANNER_CUSTOM_RANGE = stringPreferencesKey("scanner_custom_range")
        // Update Checker Keys
        val SKIPPED_UPDATE_VERSION = stringPreferencesKey("skipped_update_version")
        val LAST_UPDATE_CHECK_TIME = longPreferencesKey("last_update_check_time")
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
        prefs[Keys.PROXY_LISTEN_ADDRESS] ?: "127.0.0.1"
    }

    suspend fun setProxyListenAddress(address: String) {
        dataStore.edit { prefs ->
            prefs[Keys.PROXY_LISTEN_ADDRESS] = address
        }
    }

    val proxyListenPort: Flow<Int> = dataStore.data.map { prefs ->
        prefs[Keys.PROXY_LISTEN_PORT] ?: DEFAULT_PROXY_PORT
    }

    suspend fun setProxyListenPort(port: Int) {
        dataStore.edit { prefs ->
            prefs[Keys.PROXY_LISTEN_PORT] = port.coerceIn(1, 65535)
        }
    }

    // Proxy Auth Settings
    val proxyAuthEnabled: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.PROXY_AUTH_ENABLED] ?: false
    }

    suspend fun setProxyAuthEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[Keys.PROXY_AUTH_ENABLED] = enabled
        }
    }

    val proxyAuthUsername: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.PROXY_AUTH_USERNAME] ?: ""
    }

    suspend fun setProxyAuthUsername(username: String) {
        dataStore.edit { prefs ->
            prefs[Keys.PROXY_AUTH_USERNAME] = username
        }
    }

    val proxyAuthPassword: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.PROXY_AUTH_PASSWORD] ?: ""
    }

    suspend fun setProxyAuthPassword(password: String) {
        dataStore.edit { prefs ->
            prefs[Keys.PROXY_AUTH_PASSWORD] = password
        }
    }

    /**
     * Initializes proxy settings on first launch:
     * - Assigns the default proxy listen port
     * - Generates random auth credentials and enables auth by default
     *
     * No-op for settings that have already been persisted (safe to call on every app start).
     */
    suspend fun ensureProxyPortInitialized() {
        dataStore.edit { prefs ->
            if (prefs[Keys.PROXY_LISTEN_PORT] == null) {
                prefs[Keys.PROXY_LISTEN_PORT] = DEFAULT_PROXY_PORT
            }
            if (prefs[Keys.PROXY_AUTH_USERNAME] == null) {
                val random = java.security.SecureRandom()
                val chars = "abcdefghijklmnopqrstuvwxyz0123456789"
                prefs[Keys.PROXY_AUTH_USERNAME] = (1..8).map { chars[random.nextInt(chars.length)] }.joinToString("")
                prefs[Keys.PROXY_AUTH_PASSWORD] = (1..12).map { chars[random.nextInt(chars.length)] }.joinToString("")
                prefs[Keys.PROXY_AUTH_ENABLED] = false
            }
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

    val blockIpv6: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.BLOCK_IPV6] ?: true
    }

    suspend fun setBlockIpv6(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[Keys.BLOCK_IPV6] = enabled
        }
    }

    // VPN MTU
    val vpnMtu: Flow<Int> = dataStore.data.map { prefs ->
        prefs[Keys.VPN_MTU] ?: DEFAULT_MTU
    }

    suspend fun setVpnMtu(mtu: Int) {
        dataStore.edit { prefs ->
            prefs[Keys.VPN_MTU] = mtu.coerceIn(512, 1500)
        }
    }

    // Bandwidth Limiting (0 = unlimited, value in KB/s)
    val uploadLimitKbps: Flow<Int> = dataStore.data.map { prefs ->
        prefs[Keys.UPLOAD_LIMIT_KBPS] ?: 0
    }

    val downloadLimitKbps: Flow<Int> = dataStore.data.map { prefs ->
        prefs[Keys.DOWNLOAD_LIMIT_KBPS] ?: 0
    }

    suspend fun setUploadLimitKbps(kbps: Int) {
        dataStore.edit { prefs ->
            prefs[Keys.UPLOAD_LIMIT_KBPS] = kbps.coerceAtLeast(0)
        }
    }

    suspend fun setDownloadLimitKbps(kbps: Int) {
        dataStore.edit { prefs ->
            prefs[Keys.DOWNLOAD_LIMIT_KBPS] = kbps.coerceAtLeast(0)
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

    // DNS Worker Mode
    val dnsWorkerMode: Flow<DnsWorkerMode> = dataStore.data.map { prefs ->
        DnsWorkerMode.fromValue(prefs[Keys.DNS_WORKER_MODE] ?: DnsWorkerMode.PER_QUERY.value)
    }

    suspend fun setDnsWorkerMode(mode: DnsWorkerMode) {
        dataStore.edit { prefs ->
            prefs[Keys.DNS_WORKER_MODE] = mode.value
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

    val sshMaxChannelsIsCustom: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.SSH_MAX_CHANNELS_CUSTOM] ?: false
    }

    suspend fun setSshMaxChannels(count: Int) {
        dataStore.edit { prefs ->
            prefs[Keys.SSH_MAX_CHANNELS] = count.coerceIn(1, 64)
            prefs[Keys.SSH_MAX_CHANNELS_CUSTOM] = true
        }
    }

    suspend fun resetSshMaxChannelsToAuto() {
        dataStore.edit { prefs ->
            prefs.remove(Keys.SSH_MAX_CHANNELS)
            prefs.remove(Keys.SSH_MAX_CHANNELS_CUSTOM)
        }
    }

    // DNS Leak Prevention
    val preventDnsFallback: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.PREVENT_DNS_FALLBACK] ?: true  // Default: on (safe)
    }

    suspend fun setPreventDnsFallback(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[Keys.PREVENT_DNS_FALLBACK] = enabled
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
        SplitTunnelingMode.fromValue(prefs[Keys.SPLIT_TUNNELING_MODE] ?: SplitTunnelingMode.ALLOW.value)
    }

    suspend fun setSplitTunnelingMode(mode: SplitTunnelingMode) {
        dataStore.edit { prefs ->
            prefs[Keys.SPLIT_TUNNELING_MODE] = mode.value
        }
    }

    val splitTunnelingApps: Flow<Set<String>> = dataStore.data.map { prefs ->
        val json = prefs[Keys.SPLIT_TUNNELING_APPS] ?: "[]"
        try {
            val saved = org.json.JSONArray(json).let { arr ->
                (0 until arr.length()).map { arr.getString(it) }.toSet()
            }
            if (saved.isEmpty()) return@map saved
            val installed = context.packageManager.getInstalledApplications(0)
                .map { it.packageName }.toSet()
            saved.intersect(installed)
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

    // Auto-Reconnect
    val autoReconnect: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.AUTO_RECONNECT] ?: true
    }

    suspend fun setAutoReconnect(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[Keys.AUTO_RECONNECT] = enabled
        }
    }

    // Notification Traffic Counter
    val showNotificationTraffic: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.SHOW_NOTIFICATION_TRAFFIC] ?: true
    }

    suspend fun setShowNotificationTraffic(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[Keys.SHOW_NOTIFICATION_TRAFFIC] = enabled
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
        const val DEFAULT_MTU = 1280
        /** Fallback only — [ensureProxyPortInitialized] assigns a random port on first launch. */
        const val DEFAULT_PROXY_PORT = 10880
    }

    // --- Global DNS Resolver Override ---

    val globalResolverEnabled: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.GLOBAL_RESOLVER_ENABLED] ?: false
    }

    val globalResolverList: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.GLOBAL_RESOLVER_LIST] ?: ""
    }

    suspend fun setGlobalResolverEnabled(enabled: Boolean) {
        dataStore.edit { it[Keys.GLOBAL_RESOLVER_ENABLED] = enabled }
    }

    suspend fun setGlobalResolverList(list: String) {
        dataStore.edit { it[Keys.GLOBAL_RESOLVER_LIST] = list }
    }

    /**
     * Parsed Global DNS override list. Empty when the override is disabled or
     * the list is blank. Single source of truth for the parsing — call sites
     * (Connect path, ping flow) should not duplicate this string-splitting
     * logic. Format: comma- or newline-separated `host[:port]`, port defaults
     * to 53.
     */
    suspend fun parsedGlobalResolvers(): List<DnsResolver> = parsedGlobalResolversFlow.first()

    /** Reactive variant of [parsedGlobalResolvers]; emits whenever the user toggles the override or edits the list. */
    val parsedGlobalResolversFlow: Flow<List<DnsResolver>> =
        combine(globalResolverEnabled, globalResolverList) { enabled, list ->
            if (!enabled) emptyList()
            else list.split(",", "\n").map { it.trim() }.filter { it.isNotBlank() }
                .map { entry ->
                    val parts = entry.split(":")
                    DnsResolver(host = parts[0], port = parts.getOrNull(1)?.toIntOrNull() ?: 53)
                }
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

    // DNS Scanner Settings (persisted across profiles)
    val scannerTimeoutMs: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.SCANNER_TIMEOUT_MS] ?: "3000"
    }

    val scannerConcurrency: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.SCANNER_CONCURRENCY] ?: "50"
    }

    val scannerE2eTimeoutMs: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.SCANNER_E2E_TIMEOUT_MS] ?: "15000"
    }

    val scannerE2eConcurrency: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.SCANNER_E2E_CONCURRENCY] ?: "6"
    }

    val scannerTestUrl: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.SCANNER_TEST_URL] ?: "http://www.gstatic.com/generate_204"
    }

    val scannerPrismTimeoutMs: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.SCANNER_PRISM_TIMEOUT_MS] ?: "2000"
    }

    val scannerPrismProbeCount: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.SCANNER_PRISM_PROBE_COUNT] ?: "5"
    }

    val scannerPrismPassThreshold: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.SCANNER_PRISM_PASS_THRESHOLD] ?: "2"
    }

    val scannerPrismResponseSize: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.SCANNER_PRISM_RESPONSE_SIZE] ?: "0"
    }

    val scannerPrismPrefilter: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.SCANNER_PRISM_PREFILTER] ?: false
    }

    val scannerPrismPrefilterTimeoutMs: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.SCANNER_PRISM_PREFILTER_TIMEOUT_MS] ?: "1500"
    }

    /** DNS transport used by the scanner. Valid values: "UDP", "TCP", "BOTH". */
    val scannerTransport: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.SCANNER_TRANSPORT] ?: "UDP"
    }

    suspend fun setScannerTransport(value: String) {
        dataStore.edit { prefs ->
            prefs[Keys.SCANNER_TRANSPORT] = when (value) {
                "TCP" -> "TCP"
                "BOTH" -> "BOTH"
                else -> "UDP"
            }
        }
    }

    suspend fun saveScannerSettings(
        timeoutMs: String,
        concurrency: String,
        e2eTimeoutMs: String,
        testUrl: String,
        e2eConcurrency: String = "6",
        prismTimeoutMs: String = "2000",
        prismProbeCount: String = "5",
        prismPassThreshold: String = "2",
        prismResponseSize: String = "1232",
        prismPrefilter: Boolean = false,
        prismPrefilterTimeoutMs: String = "1500"
    ) {
        dataStore.edit { prefs ->
            prefs[Keys.SCANNER_TIMEOUT_MS] = timeoutMs
            prefs[Keys.SCANNER_CONCURRENCY] = concurrency
            prefs[Keys.SCANNER_E2E_TIMEOUT_MS] = e2eTimeoutMs
            prefs[Keys.SCANNER_TEST_URL] = testUrl
            prefs[Keys.SCANNER_E2E_CONCURRENCY] = e2eConcurrency
            prefs[Keys.SCANNER_PRISM_TIMEOUT_MS] = prismTimeoutMs
            prefs[Keys.SCANNER_PRISM_PROBE_COUNT] = prismProbeCount
            prefs[Keys.SCANNER_PRISM_PASS_THRESHOLD] = prismPassThreshold
            prefs[Keys.SCANNER_PRISM_RESPONSE_SIZE] = prismResponseSize
            prefs[Keys.SCANNER_PRISM_PREFILTER] = prismPrefilter
            prefs[Keys.SCANNER_PRISM_PREFILTER_TIMEOUT_MS] = prismPrefilterTimeoutMs
        }
    }

    // DNS Scanner Resolver List Selection
    val scannerListSource: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.SCANNER_LIST_SOURCE] ?: "DEFAULT"
    }

    val scannerCountry: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.SCANNER_COUNTRY] ?: "IR"
    }

    val scannerSampleCount: Flow<Int> = dataStore.data.map { prefs ->
        prefs[Keys.SCANNER_SAMPLE_COUNT] ?: 2000
    }

    val scannerCustomRange: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.SCANNER_CUSTOM_RANGE] ?: ""
    }

    suspend fun saveScannerListSelection(
        listSource: String,
        country: String,
        sampleCount: Int,
        customRange: String
    ) {
        dataStore.edit { prefs ->
            prefs[Keys.SCANNER_LIST_SOURCE] = listSource
            prefs[Keys.SCANNER_COUNTRY] = country
            prefs[Keys.SCANNER_SAMPLE_COUNT] = sampleCount
            prefs[Keys.SCANNER_CUSTOM_RANGE] = customRange
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

    // ── Reset All Settings ─────────────────────────────────────────────

    /**
     * Clears all user-configurable settings back to defaults.
     * Preserves: active profile, last connected profile, first-launch flag,
     * cumulative stats, and update checker state.
     */
    suspend fun resetAllSettings() {
        dataStore.edit { prefs ->
            // Snapshot values we want to keep
            val activeProfile = prefs[Keys.ACTIVE_PROFILE_ID]
            val lastProfile = prefs[Keys.LAST_CONNECTED_PROFILE_ID]
            val firstLaunch = prefs[Keys.FIRST_LAUNCH_DONE]
            val bytesSent = prefs[Keys.TOTAL_BYTES_SENT]
            val bytesReceived = prefs[Keys.TOTAL_BYTES_RECEIVED]
            val connectionTime = prefs[Keys.TOTAL_CONNECTION_TIME]
            val skippedUpdate = prefs[Keys.SKIPPED_UPDATE_VERSION]
            val lastUpdateCheck = prefs[Keys.LAST_UPDATE_CHECK_TIME]
            val proxyAuthEnabled = prefs[Keys.PROXY_AUTH_ENABLED]
            val proxyAuthUsername = prefs[Keys.PROXY_AUTH_USERNAME]
            val proxyAuthPassword = prefs[Keys.PROXY_AUTH_PASSWORD]

            prefs.clear()

            // Restore preserved values
            activeProfile?.let { prefs[Keys.ACTIVE_PROFILE_ID] = it }
            lastProfile?.let { prefs[Keys.LAST_CONNECTED_PROFILE_ID] = it }
            firstLaunch?.let { prefs[Keys.FIRST_LAUNCH_DONE] = it }
            bytesSent?.let { prefs[Keys.TOTAL_BYTES_SENT] = it }
            bytesReceived?.let { prefs[Keys.TOTAL_BYTES_RECEIVED] = it }
            connectionTime?.let { prefs[Keys.TOTAL_CONNECTION_TIME] = it }
            skippedUpdate?.let { prefs[Keys.SKIPPED_UPDATE_VERSION] = it }
            lastUpdateCheck?.let { prefs[Keys.LAST_UPDATE_CHECK_TIME] = it }
            proxyAuthEnabled?.let { prefs[Keys.PROXY_AUTH_ENABLED] = it }
            proxyAuthUsername?.let { prefs[Keys.PROXY_AUTH_USERNAME] = it }
            proxyAuthPassword?.let { prefs[Keys.PROXY_AUTH_PASSWORD] = it }
        }
    }

    // ── Update Checker ──────────────────────────────────────────────────

    val skippedUpdateVersion: Flow<String> = dataStore.data.map { prefs ->
        prefs[Keys.SKIPPED_UPDATE_VERSION] ?: ""
    }

    val lastUpdateCheckTime: Flow<Long> = dataStore.data.map { prefs ->
        prefs[Keys.LAST_UPDATE_CHECK_TIME] ?: 0L
    }

    suspend fun setSkippedUpdateVersion(version: String) {
        dataStore.edit { it[Keys.SKIPPED_UPDATE_VERSION] = version }
    }

    suspend fun setLastUpdateCheckTime(time: Long) {
        dataStore.edit { it[Keys.LAST_UPDATE_CHECK_TIME] = time }
    }
}

enum class DarkMode(val value: String) {
    LIGHT("light"),
    DARK("dark"),
    AMOLED("amoled"),
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
    ALLOW("allow"),
    DISALLOW("disallow");

    companion object {
        fun fromValue(value: String): SplitTunnelingMode {
            return entries.find { it.value == value } ?: ALLOW
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

enum class DnsWorkerMode(val value: String, val displayName: String, val poolSize: Int) {
    PER_QUERY("per_query", "Per-query (default)", 0),
    TWO("two", "2 workers", 2),
    THREE("three", "3 workers", 3),
    FIVE("five", "5 workers (fastest)", 5);

    companion object {
        fun fromValue(value: String): DnsWorkerMode {
            return entries.find { it.value == value } ?: PER_QUERY
        }
    }
}

