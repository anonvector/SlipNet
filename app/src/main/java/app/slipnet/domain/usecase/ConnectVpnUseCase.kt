package app.slipnet.domain.usecase

import app.slipnet.domain.model.LogEventType
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.repository.ConnectionLogRepository
import app.slipnet.domain.repository.VpnRepository
import javax.inject.Inject

class ConnectVpnUseCase @Inject constructor(
    private val vpnRepository: VpnRepository,
    private val logRepository: ConnectionLogRepository
) {
    suspend operator fun invoke(profile: ServerProfile): Result<Unit> {
        logRepository.addLog(
            profileId = profile.id,
            profileName = profile.name,
            eventType = LogEventType.CONNECT_START,
            message = "Connecting to ${profile.domain}"
        )

        return vpnRepository.connect(profile).also { result ->
            if (result.isSuccess) {
                logRepository.addLog(
                    profileId = profile.id,
                    profileName = profile.name,
                    eventType = LogEventType.CONNECT_SUCCESS,
                    message = "Connected to ${profile.domain}"
                )
            } else {
                logRepository.addLog(
                    profileId = profile.id,
                    profileName = profile.name,
                    eventType = LogEventType.CONNECT_FAILED,
                    message = "Failed to connect to ${profile.domain}",
                    details = result.exceptionOrNull()?.message
                )
            }
        }
    }
}
