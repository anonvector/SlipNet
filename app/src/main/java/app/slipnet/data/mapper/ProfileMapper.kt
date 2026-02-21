package app.slipnet.data.mapper

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import app.slipnet.data.local.database.ProfileEntity
import app.slipnet.domain.model.CongestionControl
import app.slipnet.domain.model.DnsResolver
import app.slipnet.domain.model.DnsTransport
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.SshAuthType
import app.slipnet.domain.model.TunnelType
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
            gsoEnabled = entity.gsoEnabled,
            tcpListenPort = entity.tcpListenPort,
            tcpListenHost = entity.tcpListenHost,
            socksUsername = entity.socksUsername.ifBlank { null },
            socksPassword = entity.socksPassword.ifBlank { null },
            isActive = entity.isActive,
            createdAt = entity.createdAt,
            updatedAt = entity.updatedAt,
            tunnelType = TunnelType.fromValue(entity.tunnelType),
            dnsttPublicKey = entity.dnsttPublicKey,
            sshUsername = entity.sshUsername,
            sshPassword = entity.sshPassword,
            sshPort = entity.sshPort,
            sshHost = entity.sshHost,
            dohUrl = entity.dohUrl,
            lastConnectedAt = entity.lastConnectedAt,
            dnsTransport = DnsTransport.fromValue(entity.dnsTransport),
            sshAuthType = SshAuthType.fromValue(entity.sshAuthType),
            sshPrivateKey = entity.sshPrivateKey,
            sshKeyPassphrase = entity.sshKeyPassphrase,
            torBridgeLines = entity.torBridgeLines,
            sortOrder = entity.sortOrder,
            dnsttAuthoritative = entity.dnsttAuthoritative
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
            gsoEnabled = profile.gsoEnabled,
            tcpListenPort = profile.tcpListenPort,
            tcpListenHost = profile.tcpListenHost,
            socksUsername = profile.socksUsername ?: "",
            socksPassword = profile.socksPassword ?: "",
            isActive = profile.isActive,
            createdAt = profile.createdAt,
            updatedAt = profile.updatedAt,
            tunnelType = profile.tunnelType.value,
            dnsttPublicKey = profile.dnsttPublicKey,
            sshEnabled = profile.tunnelType == TunnelType.SSH || profile.tunnelType == TunnelType.DNSTT_SSH || profile.tunnelType == TunnelType.SLIPSTREAM_SSH,
            sshUsername = profile.sshUsername,
            sshPassword = profile.sshPassword,
            sshPort = profile.sshPort,
            forwardDnsThroughSsh = false,
            sshHost = profile.sshHost,
            dohUrl = profile.dohUrl,
            lastConnectedAt = profile.lastConnectedAt,
            dnsTransport = profile.dnsTransport.value,
            sshAuthType = profile.sshAuthType.value,
            sshPrivateKey = profile.sshPrivateKey,
            sshKeyPassphrase = profile.sshKeyPassphrase,
            torBridgeLines = profile.torBridgeLines,
            sortOrder = profile.sortOrder,
            dnsttAuthoritative = profile.dnsttAuthoritative
        )
    }

    fun toDomainList(entities: List<ProfileEntity>): List<ServerProfile> {
        return entities.map { toDomain(it) }
    }
}
