package app.slipnet.di

import android.content.Context
import androidx.room.Room
import app.slipnet.data.local.database.ProfileDao
import app.slipnet.data.local.database.SlipNetDatabase
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    @Provides
    @Singleton
    fun provideDatabase(
        @ApplicationContext context: Context
    ): SlipNetDatabase {
        return Room.databaseBuilder(
            context,
            SlipNetDatabase::class.java,
            SlipNetDatabase.DATABASE_NAME
        )
            .addMigrations(
                SlipNetDatabase.MIGRATION_5_6,
                SlipNetDatabase.MIGRATION_6_7,
                SlipNetDatabase.MIGRATION_7_8,
                SlipNetDatabase.MIGRATION_8_9,
                SlipNetDatabase.MIGRATION_9_10,
                SlipNetDatabase.MIGRATION_10_11,
                SlipNetDatabase.MIGRATION_11_12,
                SlipNetDatabase.MIGRATION_12_13,
                SlipNetDatabase.MIGRATION_13_14,
                SlipNetDatabase.MIGRATION_14_15
            )
            .fallbackToDestructiveMigrationFrom(1, 2, 3, 4)
            .build()
    }

    @Provides
    @Singleton
    fun provideProfileDao(database: SlipNetDatabase): ProfileDao {
        return database.profileDao()
    }
}
