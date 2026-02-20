package app.slipnet.domain.usecase

import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.repository.ProfileRepository
import javax.inject.Inject

class SaveProfileUseCase @Inject constructor(
    private val profileRepository: ProfileRepository
) {
    suspend operator fun invoke(profile: ServerProfile): Long {
        return if (profile.id == 0L) {
            profileRepository.prepareTopSortOrder()
            profileRepository.saveProfile(profile.copy(sortOrder = 0))
        } else {
            profileRepository.updateProfile(profile.copy(updatedAt = System.currentTimeMillis()))
            profile.id
        }
    }
}
