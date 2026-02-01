package app.slipnet.di

import app.slipnet.data.repository.ProfileRepositoryImpl
import app.slipnet.data.repository.ResolverScannerRepositoryImpl
import app.slipnet.data.repository.VpnRepositoryImpl
import app.slipnet.domain.repository.ProfileRepository
import app.slipnet.domain.repository.ResolverScannerRepository
import app.slipnet.domain.repository.VpnRepository
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
abstract class RepositoryModule {

    @Binds
    @Singleton
    abstract fun bindProfileRepository(
        profileRepositoryImpl: ProfileRepositoryImpl
    ): ProfileRepository

    @Binds
    @Singleton
    abstract fun bindVpnRepository(
        vpnRepositoryImpl: VpnRepositoryImpl
    ): VpnRepository

    @Binds
    @Singleton
    abstract fun bindResolverScannerRepository(
        resolverScannerRepositoryImpl: ResolverScannerRepositoryImpl
    ): ResolverScannerRepository
}
