package app.slipnet.data.repository

import app.slipnet.data.local.database.ProfileDao
import app.slipnet.data.mapper.ProfileMapper
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.repository.ProfileRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ProfileRepositoryImpl @Inject constructor(
    private val profileDao: ProfileDao,
    private val profileMapper: ProfileMapper
) : ProfileRepository {

    override fun getAllProfiles(): Flow<List<ServerProfile>> {
        return profileDao.getAllProfiles().map { entities ->
            profileMapper.toDomainList(entities)
        }
    }

    override fun getActiveProfile(): Flow<ServerProfile?> {
        return profileDao.getActiveProfile().map { entity ->
            entity?.let { profileMapper.toDomain(it) }
        }
    }

    override suspend fun getProfileById(id: Long): ServerProfile? {
        return profileDao.getProfileById(id)?.let { profileMapper.toDomain(it) }
    }

    override suspend fun saveProfile(profile: ServerProfile): Long {
        val entity = profileMapper.toEntity(profile)
        return profileDao.insertProfile(entity)
    }

    override suspend fun updateProfile(profile: ServerProfile) {
        val entity = profileMapper.toEntity(profile)
        profileDao.updateProfile(entity)
    }

    override suspend fun deleteProfile(id: Long) {
        profileDao.deleteProfile(id)
    }

    override suspend fun setActiveProfile(id: Long) {
        profileDao.clearActiveProfile()
        profileDao.setActiveProfile(id)
    }

    override suspend fun clearActiveProfile() {
        profileDao.clearActiveProfile()
    }

    override suspend fun updateLastConnectedAt(id: Long) {
        profileDao.updateLastConnectedAt(id, System.currentTimeMillis())
    }

    override suspend fun updateProfileOrder(orderedIds: List<Long>) {
        orderedIds.forEachIndexed { index, id ->
            profileDao.updateSortOrder(id, index)
        }
    }

    override suspend fun getMaxSortOrder(): Int {
        return profileDao.getMaxSortOrder() ?: -1
    }

    override suspend fun prepareTopSortOrder() {
        profileDao.incrementAllSortOrders()
    }
}
