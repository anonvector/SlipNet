package app.slipnet.domain.usecase

import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.repository.ProfileRepository
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class GetProfilesUseCase @Inject constructor(
    private val profileRepository: ProfileRepository
) {
    operator fun invoke(): Flow<List<ServerProfile>> {
        return profileRepository.getAllProfiles()
    }
}
