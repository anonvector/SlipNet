package app.slipnet.data.local.database

import androidx.room.Database
import androidx.room.RoomDatabase

@Database(
    entities = [ProfileEntity::class, ConnectionLogEntity::class],
    version = 1,
    exportSchema = true
)
abstract class SlipNetDatabase : RoomDatabase() {
    abstract fun profileDao(): ProfileDao
    abstract fun connectionLogDao(): ConnectionLogDao

    companion object {
        const val DATABASE_NAME = "slipstream_database"
    }
}
