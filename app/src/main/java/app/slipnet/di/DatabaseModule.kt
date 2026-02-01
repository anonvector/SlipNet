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
            .fallbackToDestructiveMigration()
            .build()
    }

    @Provides
    @Singleton
    fun provideProfileDao(database: SlipNetDatabase): ProfileDao {
        return database.profileDao()
    }
}
