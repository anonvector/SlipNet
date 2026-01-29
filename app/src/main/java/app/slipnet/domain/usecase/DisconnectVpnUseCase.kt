package app.slipnet.domain.usecase

import app.slipnet.domain.model.LogEventType
import app.slipnet.domain.repository.ConnectionLogRepository
import app.slipnet.domain.repository.VpnRepository
import javax.inject.Inject

class DisconnectVpnUseCase @Inject constructor(
    private val vpnRepository: VpnRepository,
    private val logRepository: ConnectionLogRepository
) {
    suspend operator fun invoke(): Result<Unit> {
        val connectedProfile = vpnRepository.getConnectedProfile()

        return vpnRepository.disconnect().also { result ->
            if (connectedProfile != null) {
                if (result.isSuccess) {
                    logRepository.addLog(
                        profileId = connectedProfile.id,
                        profileName = connectedProfile.name,
                        eventType = LogEventType.DISCONNECT,
                        message = "Disconnected from ${connectedProfile.domain}"
                    )
                } else {
                    logRepository.addLog(
                        profileId = connectedProfile.id,
                        profileName = connectedProfile.name,
                        eventType = LogEventType.DISCONNECT_ERROR,
                        message = "Error disconnecting from ${connectedProfile.domain}",
                        details = result.exceptionOrNull()?.message
                    )
                }
            }
        }
    }
}
