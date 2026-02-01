package app.slipnet.domain.usecase

import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.repository.VpnRepository
import javax.inject.Inject

class ConnectVpnUseCase @Inject constructor(
    private val vpnRepository: VpnRepository
) {
    suspend operator fun invoke(profile: ServerProfile): Result<Unit> {
        return vpnRepository.connect(profile)
    }
}
