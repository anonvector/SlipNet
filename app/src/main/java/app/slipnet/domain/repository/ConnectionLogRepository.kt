package app.slipnet.domain.repository

import app.slipnet.domain.model.ConnectionLog
import app.slipnet.domain.model.LogEventType
import kotlinx.coroutines.flow.Flow

interface ConnectionLogRepository {
    fun getAllLogs(): Flow<List<ConnectionLog>>
    fun getLogsByProfileId(profileId: Long): Flow<List<ConnectionLog>>
    fun getRecentLogs(limit: Int): Flow<List<ConnectionLog>>
    suspend fun addLog(log: ConnectionLog): Long
    suspend fun addLog(
        profileId: Long,
        profileName: String,
        eventType: LogEventType,
        message: String,
        details: String? = null
    ): Long
    suspend fun clearLogs()
    suspend fun clearLogsForProfile(profileId: Long)
    suspend fun deleteOldLogs(olderThanTimestamp: Long)
}
