package app.slipnet.data.mapper

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import app.slipnet.data.local.database.ProfileEntity
import app.slipnet.domain.model.CongestionControl
import app.slipnet.domain.model.DnsResolver
import app.slipnet.domain.model.DnsTransport
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.ResolverMode
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
        val defaultResolvers: List<DnsResolver> = try {
            gson.fromJson(entity.defaultResolversJson, resolversType) ?: emptyList()
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
            dnsttAuthoritative = entity.dnsttAuthoritative,
            naivePort = entity.naivePort,
            naiveUsername = entity.naiveUsername,
            naivePassword = entity.naivePassword,
            isLocked = entity.isLocked,
            lockPasswordHash = entity.lockPasswordHash,
            expirationDate = entity.expirationDate,
            allowSharing = entity.allowSharing,
            boundDeviceId = entity.boundDeviceId,
            noizdnsStealth = entity.noizdnsStealth,
            dnsPayloadSize = entity.dnsPayloadSize,
            resolversHidden = entity.resolversHidden,
            defaultResolvers = defaultResolvers,
            socks5ServerPort = entity.socks5ServerPort,
            vaydnsDnsttCompat = entity.vaydnsDnsttCompat,
            vaydnsRecordType = entity.vaydnsRecordType,
            vaydnsMaxQnameLen = entity.vaydnsMaxQnameLen,
            vaydnsRps = entity.vaydnsRps,
            vaydnsIdleTimeout = entity.vaydnsIdleTimeout,
            vaydnsKeepalive = entity.vaydnsKeepalive,
            vaydnsUdpTimeout = entity.vaydnsUdpTimeout,
            vaydnsMaxNumLabels = entity.vaydnsMaxNumLabels,
            vaydnsClientIdSize = entity.vaydnsClientIdSize,
            isPinned = entity.isPinned,
            sshTlsEnabled = entity.sshTlsEnabled,
            sshTlsSni = entity.sshTlsSni,
            sshHttpProxyHost = entity.sshHttpProxyHost,
            sshHttpProxyPort = entity.sshHttpProxyPort,
            sshHttpProxyCustomHost = entity.sshHttpProxyCustomHost,
            sshWsEnabled = entity.sshWsEnabled,
            sshWsPath = entity.sshWsPath,
            sshWsUseTls = entity.sshWsUseTls,
            sshWsCustomHost = entity.sshWsCustomHost,
            sshPayload = entity.sshPayload,
            resolverMode = ResolverMode.fromValue(entity.resolverMode),
            rrSpreadCount = entity.rrSpreadCount,
            vlessUuid = entity.vlessUuid,
            vlessSecurity = entity.vlessSecurity,
            vlessTransport = entity.vlessTransport,
            vlessWsPath = entity.vlessWsPath,
            cdnIp = entity.cdnIp,
            cdnPort = entity.cdnPort,
            sniFragmentEnabled = entity.sniFragmentEnabled,
            sniFragmentStrategy = entity.sniFragmentStrategy,
            sniFragmentDelayMs = entity.sniFragmentDelayMs,
            sniSpoofTtl = entity.sniSpoofTtl,
            fakeDecoyHost = entity.fakeDecoyHost,
            tcpMaxSeg = entity.tcpMaxSeg,
            vlessSni = entity.vlessSni,
            chPaddingEnabled = entity.chPaddingEnabled,
            wsHeaderObfuscation = entity.wsHeaderObfuscation,
            wsPaddingEnabled = entity.wsPaddingEnabled
        )
    }

    fun toEntity(profile: ServerProfile): ProfileEntity {
        val resolversJson = gson.toJson(profile.resolvers)
        val defaultResolversJson = gson.toJson(profile.defaultResolvers)

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
            sshEnabled = profile.tunnelType == TunnelType.SSH || profile.tunnelType == TunnelType.DNSTT_SSH || profile.tunnelType == TunnelType.SLIPSTREAM_SSH || profile.tunnelType == TunnelType.NAIVE_SSH,
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
            dnsttAuthoritative = profile.dnsttAuthoritative,
            naivePort = profile.naivePort,
            naiveUsername = profile.naiveUsername,
            naivePassword = profile.naivePassword,
            isLocked = profile.isLocked,
            lockPasswordHash = profile.lockPasswordHash,
            expirationDate = profile.expirationDate,
            allowSharing = profile.allowSharing,
            boundDeviceId = profile.boundDeviceId,
            noizdnsStealth = profile.noizdnsStealth,
            dnsPayloadSize = profile.dnsPayloadSize,
            resolversHidden = profile.resolversHidden,
            defaultResolversJson = defaultResolversJson,
            socks5ServerPort = profile.socks5ServerPort,
            vaydnsDnsttCompat = profile.vaydnsDnsttCompat,
            vaydnsRecordType = profile.vaydnsRecordType,
            vaydnsMaxQnameLen = profile.vaydnsMaxQnameLen,
            vaydnsRps = profile.vaydnsRps,
            vaydnsIdleTimeout = profile.vaydnsIdleTimeout,
            vaydnsKeepalive = profile.vaydnsKeepalive,
            vaydnsUdpTimeout = profile.vaydnsUdpTimeout,
            vaydnsMaxNumLabels = profile.vaydnsMaxNumLabels,
            vaydnsClientIdSize = profile.vaydnsClientIdSize,
            isPinned = profile.isPinned,
            sshTlsEnabled = profile.sshTlsEnabled,
            sshTlsSni = profile.sshTlsSni,
            sshHttpProxyHost = profile.sshHttpProxyHost,
            sshHttpProxyPort = profile.sshHttpProxyPort,
            sshHttpProxyCustomHost = profile.sshHttpProxyCustomHost,
            sshWsEnabled = profile.sshWsEnabled,
            sshWsPath = profile.sshWsPath,
            sshWsUseTls = profile.sshWsUseTls,
            sshWsCustomHost = profile.sshWsCustomHost,
            sshPayload = profile.sshPayload,
            resolverMode = profile.resolverMode.value,
            rrSpreadCount = profile.rrSpreadCount,
            vlessUuid = profile.vlessUuid,
            vlessSecurity = profile.vlessSecurity,
            vlessTransport = profile.vlessTransport,
            vlessWsPath = profile.vlessWsPath,
            cdnIp = profile.cdnIp,
            cdnPort = profile.cdnPort,
            sniFragmentEnabled = profile.sniFragmentEnabled,
            sniFragmentStrategy = profile.sniFragmentStrategy,
            sniFragmentDelayMs = profile.sniFragmentDelayMs,
            sniSpoofTtl = profile.sniSpoofTtl,
            fakeDecoyHost = profile.fakeDecoyHost,
            tcpMaxSeg = profile.tcpMaxSeg,
            vlessSni = profile.vlessSni,
            fakeSni = "",
            chPaddingEnabled = profile.chPaddingEnabled,
            wsHeaderObfuscation = profile.wsHeaderObfuscation,
            wsPaddingEnabled = profile.wsPaddingEnabled
        )
    }

    fun toDomainList(entities: List<ProfileEntity>): List<ServerProfile> {
        return entities.map { toDomain(it) }
    }
}
