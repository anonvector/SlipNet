package app.slipnet.data.local.database

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface ConnectionLogDao {
    @Query("SELECT * FROM connection_logs ORDER BY timestamp DESC")
    fun getAllLogs(): Flow<List<ConnectionLogEntity>>

    @Query("SELECT * FROM connection_logs WHERE profile_id = :profileId ORDER BY timestamp DESC")
    fun getLogsByProfileId(profileId: Long): Flow<List<ConnectionLogEntity>>

    @Query("SELECT * FROM connection_logs ORDER BY timestamp DESC LIMIT :limit")
    fun getRecentLogs(limit: Int): Flow<List<ConnectionLogEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertLog(log: ConnectionLogEntity): Long

    @Query("DELETE FROM connection_logs")
    suspend fun clearAllLogs()

    @Query("DELETE FROM connection_logs WHERE profile_id = :profileId")
    suspend fun clearLogsForProfile(profileId: Long)

    @Query("DELETE FROM connection_logs WHERE timestamp < :timestamp")
    suspend fun deleteOldLogs(timestamp: Long)

    @Query("SELECT COUNT(*) FROM connection_logs")
    suspend fun getLogCount(): Int
}
