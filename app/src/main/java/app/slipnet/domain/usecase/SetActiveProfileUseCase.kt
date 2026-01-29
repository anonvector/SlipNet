package app.slipnet.domain.usecase

import app.slipnet.domain.repository.ProfileRepository
import javax.inject.Inject

class SetActiveProfileUseCase @Inject constructor(
    private val profileRepository: ProfileRepository
) {
    suspend operator fun invoke(id: Long) {
        profileRepository.setActiveProfile(id)
    }
}
