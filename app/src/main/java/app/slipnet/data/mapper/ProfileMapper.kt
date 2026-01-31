package app.slipnet.data.mapper

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import app.slipnet.data.local.database.ProfileEntity
import app.slipnet.domain.model.CongestionControl
import app.slipnet.domain.model.DnsResolver
import app.slipnet.domain.model.ServerProfile
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ProfileMapper @Inject constructor(
    private val gson: Gson
) {
    fun toDomain(entity: ProfileEntity): ServerProfile {
        val resolversType = object : TypeToken<List<DnsResolver>>() {}.type
        val resolvers: List<DnsResolver> = try {
            gson.fromJson(entity.resolversJson, resolversType) ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }

        return ServerProfile(
            id = entity.id,
            name = entity.name,
            domain = entity.domain,
            resolvers = resolvers,
            authoritativeMode = entity.authoritativeMode,
            keepAliveInterval = entity.keepAliveInterval,
            congestionControl = CongestionControl.fromValue(entity.congestionControl),
            tcpListenPort = entity.tcpListenPort,
            tcpListenHost = entity.tcpListenHost,
            gsoEnabled = entity.gsoEnabled,
            isActive = entity.isActive,
            createdAt = entity.createdAt,
            updatedAt = entity.updatedAt
        )
    }

    fun toEntity(profile: ServerProfile): ProfileEntity {
        val resolversJson = gson.toJson(profile.resolvers)

        return ProfileEntity(
            id = profile.id,
            name = profile.name,
            domain = profile.domain,
            resolversJson = resolversJson,
            authoritativeMode = profile.authoritativeMode,
            keepAliveInterval = profile.keepAliveInterval,
            congestionControl = profile.congestionControl.value,
            tcpListenPort = profile.tcpListenPort,
            tcpListenHost = profile.tcpListenHost,
            gsoEnabled = profile.gsoEnabled,
            isActive = profile.isActive,
            createdAt = profile.createdAt,
            updatedAt = profile.updatedAt
        )
    }

    fun toDomainList(entities: List<ProfileEntity>): List<ServerProfile> {
        return entities.map { toDomain(it) }
    }
}
