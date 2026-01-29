package app.slipnet.data.mapper

import app.slipnet.data.local.database.ConnectionLogEntity
import app.slipnet.domain.model.ConnectionLog
import app.slipnet.domain.model.LogEventType
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ConnectionLogMapper @Inject constructor() {
    fun toDomain(entity: ConnectionLogEntity): ConnectionLog {
        return ConnectionLog(
            id = entity.id,
            profileId = entity.profileId,
            profileName = entity.profileName,
            timestamp = entity.timestamp,
            eventType = try {
                LogEventType.valueOf(entity.eventType)
            } catch (e: Exception) {
                LogEventType.INFO
            },
            message = entity.message,
            details = entity.details
        )
    }

    fun toEntity(log: ConnectionLog): ConnectionLogEntity {
        return ConnectionLogEntity(
            id = log.id,
            profileId = log.profileId,
            profileName = log.profileName,
            timestamp = log.timestamp,
            eventType = log.eventType.name,
            message = log.message,
            details = log.details
        )
    }

    fun toDomainList(entities: List<ConnectionLogEntity>): List<ConnectionLog> {
        return entities.map { toDomain(it) }
    }
}
