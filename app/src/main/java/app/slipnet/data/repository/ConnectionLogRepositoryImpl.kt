package app.slipnet.data.repository

import app.slipnet.data.local.database.ConnectionLogDao
import app.slipnet.data.local.database.ConnectionLogEntity
import app.slipnet.data.mapper.ConnectionLogMapper
import app.slipnet.domain.model.ConnectionLog
import app.slipnet.domain.model.LogEventType
import app.slipnet.domain.repository.ConnectionLogRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ConnectionLogRepositoryImpl @Inject constructor(
    private val logDao: ConnectionLogDao,
    private val logMapper: ConnectionLogMapper
) : ConnectionLogRepository {

    override fun getAllLogs(): Flow<List<ConnectionLog>> {
        return logDao.getAllLogs().map { entities ->
            logMapper.toDomainList(entities)
        }
    }

    override fun getLogsByProfileId(profileId: Long): Flow<List<ConnectionLog>> {
        return logDao.getLogsByProfileId(profileId).map { entities ->
            logMapper.toDomainList(entities)
        }
    }

    override fun getRecentLogs(limit: Int): Flow<List<ConnectionLog>> {
        return logDao.getRecentLogs(limit).map { entities ->
            logMapper.toDomainList(entities)
        }
    }

    override suspend fun addLog(log: ConnectionLog): Long {
        val entity = logMapper.toEntity(log)
        return logDao.insertLog(entity)
    }

    override suspend fun addLog(
        profileId: Long,
        profileName: String,
        eventType: LogEventType,
        message: String,
        details: String?
    ): Long {
        val entity = ConnectionLogEntity(
            profileId = profileId,
            profileName = profileName,
            timestamp = System.currentTimeMillis(),
            eventType = eventType.name,
            message = message,
            details = details
        )
        return logDao.insertLog(entity)
    }

    override suspend fun clearLogs() {
        logDao.clearAllLogs()
    }

    override suspend fun clearLogsForProfile(profileId: Long) {
        logDao.clearLogsForProfile(profileId)
    }

    override suspend fun deleteOldLogs(olderThanTimestamp: Long) {
        logDao.deleteOldLogs(olderThanTimestamp)
    }
}
