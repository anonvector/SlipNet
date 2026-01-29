package app.slipnet.domain.usecase

import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.repository.ProfileRepository
import javax.inject.Inject

class GetProfileByIdUseCase @Inject constructor(
    private val profileRepository: ProfileRepository
) {
    suspend operator fun invoke(id: Long): ServerProfile? {
        return profileRepository.getProfileById(id)
    }
}
