package app.slipnet.domain.repository

import app.slipnet.domain.model.ServerProfile
import kotlinx.coroutines.flow.Flow

interface ProfileRepository {
    fun getAllProfiles(): Flow<List<ServerProfile>>
    fun getActiveProfile(): Flow<ServerProfile?>
    suspend fun getProfileById(id: Long): ServerProfile?
    suspend fun saveProfile(profile: ServerProfile): Long
    suspend fun updateProfile(profile: ServerProfile)
    suspend fun deleteProfile(id: Long)
    suspend fun setActiveProfile(id: Long)
    suspend fun clearActiveProfile()
    suspend fun updateLastConnectedAt(id: Long)
    suspend fun updateProfileOrder(orderedIds: List<Long>)
    suspend fun getMaxSortOrder(): Int
    suspend fun prepareTopSortOrder()
}
