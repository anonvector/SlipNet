package app.slipnet.domain.usecase

import app.slipnet.domain.repository.ConnectionLogRepository
import javax.inject.Inject

class ClearLogsUseCase @Inject constructor(
    private val logRepository: ConnectionLogRepository
) {
    suspend operator fun invoke() {
        logRepository.clearLogs()
    }

    suspend fun clearForProfile(profileId: Long) {
        logRepository.clearLogsForProfile(profileId)
    }

    suspend fun clearOldLogs(daysOld: Int = 7) {
        val cutoffTime = System.currentTimeMillis() - (daysOld * 24 * 60 * 60 * 1000L)
        logRepository.deleteOldLogs(cutoffTime)
    }
}
