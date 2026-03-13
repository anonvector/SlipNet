package app.slipnet.data.repository

import app.slipnet.data.local.database.ChainDao
import app.slipnet.data.mapper.ChainMapper
import app.slipnet.domain.model.ProfileChain
import app.slipnet.domain.repository.ChainRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ChainRepositoryImpl @Inject constructor(
    private val chainDao: ChainDao
) : ChainRepository {

    override fun getAllChains(): Flow<List<ProfileChain>> =
        chainDao.getAllChains().map { entities -> entities.map { ChainMapper.toDomain(it) } }

    override fun getActiveChain(): Flow<ProfileChain?> =
        chainDao.getActiveChain().map { it?.let { ChainMapper.toDomain(it) } }

    override suspend fun getChainById(id: Long): ProfileChain? =
        chainDao.getChainById(id)?.let { ChainMapper.toDomain(it) }

    override suspend fun saveChain(chain: ProfileChain): Long {
        val now = System.currentTimeMillis()
        val entity = ChainMapper.toEntity(chain.copy(updatedAt = now))
        return if (chain.id == 0L) {
            val maxSort = chainDao.getMaxSortOrder() ?: -1
            chainDao.insertChain(entity.copy(createdAt = now, sortOrder = maxSort + 1))
        } else {
            chainDao.updateChain(entity)
            chain.id
        }
    }

    override suspend fun deleteChain(id: Long) = chainDao.deleteChain(id)

    override suspend fun setActiveChain(id: Long) {
        chainDao.clearActiveChain()
        chainDao.setActiveChain(id)
    }

    override suspend fun clearActiveChain() = chainDao.clearActiveChain()

    override suspend fun updateChainOrder(orderedIds: List<Long>) {
        orderedIds.forEachIndexed { index, id ->
            chainDao.updateSortOrder(id, index)
        }
    }
}
