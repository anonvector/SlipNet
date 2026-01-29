package app.slipnet.domain.usecase

import app.slipnet.domain.repository.ProfileRepository
import app.slipnet.domain.repository.VpnRepository
import javax.inject.Inject

class DeleteProfileUseCase @Inject constructor(
    private val profileRepository: ProfileRepository,
    private val vpnRepository: VpnRepository
) {
    suspend operator fun invoke(id: Long): Result<Unit> {
        // Check if this profile is currently connected
        val connectedProfile = vpnRepository.getConnectedProfile()
        if (connectedProfile?.id == id) {
            return Result.failure(IllegalStateException("Cannot delete profile while connected"))
        }

        profileRepository.deleteProfile(id)
        return Result.success(Unit)
    }
}
