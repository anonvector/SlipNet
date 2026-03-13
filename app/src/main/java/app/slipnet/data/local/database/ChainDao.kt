package app.slipnet.data.local.database

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import kotlinx.coroutines.flow.Flow

@Dao
interface ChainDao {
    @Query("SELECT * FROM profile_chains ORDER BY sort_order ASC")
    fun getAllChains(): Flow<List<ChainEntity>>

    @Query("SELECT * FROM profile_chains WHERE is_active = 1 LIMIT 1")
    fun getActiveChain(): Flow<ChainEntity?>

    @Query("SELECT * FROM profile_chains WHERE id = :id")
    suspend fun getChainById(id: Long): ChainEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertChain(chain: ChainEntity): Long

    @Update
    suspend fun updateChain(chain: ChainEntity)

    @Query("DELETE FROM profile_chains WHERE id = :id")
    suspend fun deleteChain(id: Long)

    @Query("UPDATE profile_chains SET is_active = 0")
    suspend fun clearActiveChain()

    @Query("UPDATE profile_chains SET is_active = 1 WHERE id = :id")
    suspend fun setActiveChain(id: Long)

    @Query("SELECT MAX(sort_order) FROM profile_chains")
    suspend fun getMaxSortOrder(): Int?

    @Query("UPDATE profile_chains SET sort_order = :sortOrder WHERE id = :id")
    suspend fun updateSortOrder(id: Long, sortOrder: Int)
}
