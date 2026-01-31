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
        // Network Optimization Keys
        val DNS_TIMEOUT = intPreferencesKey("dns_timeout")
        val CONNECTION_TIMEOUT = intPreferencesKey("connection_timeout")
        val BUFFER_SIZE = stringPreferencesKey("buffer_size")
        val CONNECTION_POOL_SIZE = intPreferencesKey("connection_pool_size")
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

