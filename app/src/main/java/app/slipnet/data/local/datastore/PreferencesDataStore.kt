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
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
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
        // Proxy-Only Mode
        val PROXY_ONLY_MODE = booleanPreferencesKey("proxy_only_mode")
        // Recent DNS Resolvers
        val RECENT_DNS_RESOLVERS = stringPreferencesKey("recent_dns_resolvers")
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

    // Proxy-Only Mode
    val proxyOnlyMode: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[Keys.PROXY_ONLY_MODE] ?: false
    }

    suspend fun setProxyOnlyMode(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[Keys.PROXY_ONLY_MODE] = enabled
        }
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

