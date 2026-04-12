package app.slipnet.di

import android.content.Context
import androidx.room.Room
import app.slipnet.data.local.database.ChainDao
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
                SlipNetDatabase.MIGRATION_14_15,
                SlipNetDatabase.MIGRATION_15_16,
                SlipNetDatabase.MIGRATION_16_17,
                SlipNetDatabase.MIGRATION_17_18,
                SlipNetDatabase.MIGRATION_18_19,
                SlipNetDatabase.MIGRATION_19_20,
                SlipNetDatabase.MIGRATION_20_21,
                SlipNetDatabase.MIGRATION_21_22,
                SlipNetDatabase.MIGRATION_22_23,
                SlipNetDatabase.MIGRATION_23_24,
                SlipNetDatabase.MIGRATION_24_25,
                SlipNetDatabase.MIGRATION_25_26,
                SlipNetDatabase.MIGRATION_26_27,
                SlipNetDatabase.MIGRATION_27_28,
                SlipNetDatabase.MIGRATION_28_29,
                SlipNetDatabase.MIGRATION_29_30,
                SlipNetDatabase.MIGRATION_30_31,
                SlipNetDatabase.MIGRATION_31_32
            )
            .fallbackToDestructiveMigrationFrom(1, 2, 3, 4)
            .fallbackToDestructiveMigrationOnDowngrade()
            .build()
    }

    @Provides
    @Singleton
    fun provideProfileDao(database: SlipNetDatabase): ProfileDao {
        return database.profileDao()
    }

    @Provides
    @Singleton
    fun provideChainDao(database: SlipNetDatabase): ChainDao {
        return database.chainDao()
    }
}
