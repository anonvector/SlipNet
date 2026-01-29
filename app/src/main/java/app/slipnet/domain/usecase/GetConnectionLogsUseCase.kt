package app.slipnet.domain.usecase

import app.slipnet.domain.model.ConnectionLog
import app.slipnet.domain.repository.ConnectionLogRepository
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class GetConnectionLogsUseCase @Inject constructor(
    private val logRepository: ConnectionLogRepository
) {
    operator fun invoke(): Flow<List<ConnectionLog>> {
        return logRepository.getAllLogs()
    }

    fun getRecentLogs(limit: Int = 100): Flow<List<ConnectionLog>> {
        return logRepository.getRecentLogs(limit)
    }

    fun getLogsForProfile(profileId: Long): Flow<List<ConnectionLog>> {
        return logRepository.getLogsByProfileId(profileId)
    }
}
