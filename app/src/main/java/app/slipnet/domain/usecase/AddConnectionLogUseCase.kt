package app.slipnet.domain.usecase

import app.slipnet.domain.model.ConnectionLog
import app.slipnet.domain.model.LogEventType
import app.slipnet.domain.repository.ConnectionLogRepository
import javax.inject.Inject

class AddConnectionLogUseCase @Inject constructor(
    private val logRepository: ConnectionLogRepository
) {
    suspend operator fun invoke(log: ConnectionLog): Long {
        return logRepository.addLog(log)
    }

    suspend operator fun invoke(
        profileId: Long,
        profileName: String,
        eventType: LogEventType,
        message: String,
        details: String? = null
    ): Long {
        return logRepository.addLog(
            profileId = profileId,
            profileName = profileName,
            eventType = eventType,
            message = message,
            details = details
        )
    }
}
