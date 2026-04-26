package app.slipnet.data.export

import android.util.Base64
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.SshAuthType
import app.slipnet.domain.model.TunnelType
import app.slipnet.util.BundleCrypto
import app.slipnet.util.LockPasswordUtil
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Exports profiles to compact encoded text format.
 *
 * Single profile format: slipnet://[base64-encoded-profile]
 * Multiple profiles: one URI per line
 *
 * Encoded profile format v24 (pipe-delimited):
 * v24|tunnelType|name|domain|resolvers|authMode|keepAlive|cc|port|host|gso|dnsttPublicKey|socksUsername|socksPassword|sshEnabled|sshUsername|sshPassword|sshPort|forwardDnsThroughSsh|sshHost|useServerDns|dohUrl|dnsTransport|sshAuthType|sshPrivateKey(b64)|sshKeyPassphrase(b64)|torBridgeLines(b64)|dnsttAuthoritative|naivePort|naiveUsername|naivePassword(b64)|isLocked|lockPasswordHash|expirationDate|allowSharing|boundDeviceId|resolversHidden|hiddenResolvers|noizdnsStealth|dnsPayloadSize|socks5ServerPort|vaydnsDnsttCompat|vaydnsRecordType|vaydnsMaxQnameLen|vaydnsRps|vaydnsIdleTimeout|vaydnsKeepalive|vaydnsUdpTimeout|vaydnsMaxNumLabels|vaydnsClientIdSize|sshTlsEnabled|sshTlsSni|sshHttpProxyHost|sshHttpProxyPort|sshHttpProxyCustomHost|sshWsEnabled|sshWsPath|sshWsUseTls|sshWsCustomHost|sshPayload(b64)|resolverMode|rrSpreadCount
 *
 * Resolvers format (comma-separated): host:port:auth,host:port:auth
 */
@Singleton
class ConfigExporter @Inject constructor() {

    companion object {
        const val SCHEME = "slipnet://"
        const val ENCRYPTED_SCHEME = "slipnet-enc://"
        /** Scheme for password-encrypted multi-profile bundles (see [exportAllProfilesEncrypted]). */
        const val BUNDLE_ENCRYPTED_SCHEME = "slipnet-bundle-enc://"
        const val VERSION = "28"
        const val MODE_SLIPSTREAM = "ss"
        const val MODE_SLIPSTREAM_SSH = "slipstream_ssh"
        const val MODE_DNSTT = "dnstt"
        const val MODE_DNSTT_SSH = "dnstt_ssh"
        const val MODE_NOIZDNS = "sayedns"
        const val MODE_NOIZDNS_SSH = "sayedns_ssh"
        const val MODE_SSH = "ssh"
        const val MODE_DOH = "doh"
        const val MODE_SNOWFLAKE = "snowflake"
        const val MODE_NAIVE_SSH = "naive_ssh"
        const val MODE_NAIVE = "naive"
        const val MODE_SOCKS5 = "socks5"
        const val MODE_VAYDNS = "vaydns"
        const val MODE_VAYDNS_SSH = "vaydns_ssh"
        const val MODE_VLESS = "vless"
        private const val FIELD_DELIMITER = "|"
        private const val RESOLVER_DELIMITER = ","
        private const val RESOLVER_PART_DELIMITER = ":"
    }

    fun exportSingleProfile(profile: ServerProfile, hideResolvers: Boolean = false): String {
        if (profile.isLocked) throw IllegalStateException("Cannot export a locked profile")
        return encodeProfile(profile, hideResolvers)
    }

    fun exportSingleProfileLocked(
        profile: ServerProfile,
        password: String,
        expirationDate: Long = 0,
        allowSharing: Boolean = false,
        boundDeviceId: String = "",
        hideResolvers: Boolean = false
    ): String {
        val hash = LockPasswordUtil.hashPassword(password)
        val lockedProfile = profile.copy(
            isLocked = true,
            lockPasswordHash = hash,
            expirationDate = expirationDate,
            allowSharing = allowSharing,
            boundDeviceId = boundDeviceId
        )
        val data = buildProfileData(lockedProfile, hideResolvers)
        val encrypted = LockPasswordUtil.encryptConfig(data)
        val encoded = Base64.encodeToString(encrypted, Base64.NO_WRAP)
        return "$ENCRYPTED_SCHEME$encoded"
    }

    fun reExportLockedProfile(profile: ServerProfile): String {
        if (!profile.isLocked) throw IllegalStateException("Profile is not locked")
        if (!profile.allowSharing) throw IllegalStateException("Profile does not allow re-sharing")
        val data = buildProfileData(profile)
        val encrypted = LockPasswordUtil.encryptConfig(data)
        val encoded = Base64.encodeToString(encrypted, Base64.NO_WRAP)
        return "$ENCRYPTED_SCHEME$encoded"
    }

    fun exportAllProfiles(profiles: List<ServerProfile>): String {
        val exportable = profiles.filter { !it.isLocked }
        return exportable.joinToString("\n") { encodeProfile(it) }
    }

    /**
     * Export all unlocked profiles into one password-encrypted bundle.
     *
     * When any of [expirationDate], [allowSharing], or [boundDeviceId] is set
     * (or when [hideResolvers] is true), each inner profile is also marked
     * locked with the same hashed password — giving per-profile enforcement
     * after the bundle is decrypted.
     */
    fun exportAllProfilesEncrypted(
        profiles: List<ServerProfile>,
        password: String,
        expirationDate: Long = 0,
        allowSharing: Boolean = false,
        boundDeviceId: String = "",
        hideResolvers: Boolean = false
    ): String {
        require(password.isNotEmpty()) { "Password must not be empty" }
        val exportable = profiles.filter { !it.isLocked }
        require(exportable.isNotEmpty()) { "No exportable profiles" }
        val lockForEnforcement =
            expirationDate > 0 || allowSharing || boundDeviceId.isNotEmpty() || hideResolvers
        val prepared = if (lockForEnforcement) {
            val hash = LockPasswordUtil.hashPassword(password)
            exportable.map { profile ->
                profile.copy(
                    isLocked = true,
                    lockPasswordHash = hash,
                    expirationDate = expirationDate,
                    allowSharing = allowSharing,
                    boundDeviceId = boundDeviceId
                )
            }
        } else {
            exportable
        }
        val bundle = prepared.joinToString("\n") { encodeProfile(it, hideResolvers) }
        val encrypted = BundleCrypto.encrypt(bundle, password)
        val encoded = Base64.encodeToString(encrypted, Base64.NO_WRAP)
        return "$BUNDLE_ENCRYPTED_SCHEME$encoded"
    }

    /** Strip the field delimiter so user-supplied strings can't shift field positions. */
    private fun sanitize(value: String): String = value.replace(FIELD_DELIMITER, "")

    private fun buildProfileData(profile: ServerProfile, hideResolvers: Boolean = false): String {
        val resolversStr = profile.resolvers.joinToString(RESOLVER_DELIMITER) { resolver ->
            "${resolver.host}${RESOLVER_PART_DELIMITER}${resolver.port}${RESOLVER_PART_DELIMITER}${if (resolver.authoritative) "1" else "0"}"
        }

        val tunnelTypeStr = when (profile.tunnelType) {
            TunnelType.SLIPSTREAM -> MODE_SLIPSTREAM
            TunnelType.SLIPSTREAM_SSH -> MODE_SLIPSTREAM_SSH
            TunnelType.DNSTT -> MODE_DNSTT
            TunnelType.DNSTT_SSH -> MODE_DNSTT_SSH
            TunnelType.NOIZDNS -> MODE_NOIZDNS
            TunnelType.NOIZDNS_SSH -> MODE_NOIZDNS_SSH
            TunnelType.SSH -> MODE_SSH
            TunnelType.DOH -> MODE_DOH
            TunnelType.SNOWFLAKE -> MODE_SNOWFLAKE
            TunnelType.NAIVE_SSH -> MODE_NAIVE_SSH
            TunnelType.NAIVE -> MODE_NAIVE
            TunnelType.SOCKS5 -> MODE_SOCKS5
            TunnelType.VAYDNS -> MODE_VAYDNS
            TunnelType.VAYDNS_SSH -> MODE_VAYDNS_SSH
            TunnelType.VLESS -> MODE_VLESS
        }

        // When hideResolvers is true, leave position 4 empty so old versions (v1-v16)
        // cannot see the resolver addresses. The actual resolvers go to a new trailing field.
        // Use defaultResolvers if available (these are the original config defaults).
        val defaultResolversStr = if (profile.defaultResolvers.isNotEmpty()) {
            profile.defaultResolvers.joinToString(RESOLVER_DELIMITER) { resolver ->
                "${resolver.host}${RESOLVER_PART_DELIMITER}${resolver.port}${RESOLVER_PART_DELIMITER}${if (resolver.authoritative) "1" else "0"}"
            }
        } else resolversStr
        val visibleResolvers = if (hideResolvers) "" else resolversStr
        val hiddenResolvers = if (hideResolvers) defaultResolversStr else ""

        return listOf(
            VERSION,
            tunnelTypeStr,
            sanitize(profile.name),
            sanitize(profile.domain),
            visibleResolvers,
            if (profile.authoritativeMode) "1" else "0",
            profile.keepAliveInterval.toString(),
            profile.congestionControl.value,
            profile.tcpListenPort.toString(),
            sanitize(profile.tcpListenHost),
            if (profile.gsoEnabled) "1" else "0",
            sanitize(profile.dnsttPublicKey),
            sanitize(profile.socksUsername ?: ""),
            sanitize(profile.socksPassword ?: ""),
            if (profile.tunnelType == TunnelType.SSH || profile.tunnelType == TunnelType.DNSTT_SSH || profile.tunnelType == TunnelType.SLIPSTREAM_SSH || profile.tunnelType == TunnelType.NAIVE_SSH || profile.tunnelType == TunnelType.VAYDNS_SSH) "1" else "0",
            sanitize(profile.sshUsername),
            sanitize(profile.sshPassword),
            profile.sshPort.toString(),
            "0",
            sanitize(profile.sshHost),
            "0", // position 20: was useServerDns (removed)
            sanitize(profile.dohUrl),
            profile.dnsTransport.value,
            profile.sshAuthType.value,
            Base64.encodeToString(profile.sshPrivateKey.toByteArray(Charsets.UTF_8), Base64.NO_WRAP),
            Base64.encodeToString(profile.sshKeyPassphrase.toByteArray(Charsets.UTF_8), Base64.NO_WRAP),
            Base64.encodeToString(profile.torBridgeLines.toByteArray(Charsets.UTF_8), Base64.NO_WRAP),
            if (profile.dnsttAuthoritative) "1" else "0",
            profile.naivePort.toString(),
            sanitize(profile.naiveUsername),
            Base64.encodeToString(profile.naivePassword.toByteArray(Charsets.UTF_8), Base64.NO_WRAP),
            if (profile.isLocked) "1" else "0",
            sanitize(profile.lockPasswordHash),
            profile.expirationDate.toString(),
            if (profile.allowSharing) "1" else "0",
            sanitize(profile.boundDeviceId),
            if (hideResolvers) "1" else "0",
            hiddenResolvers,
            if (profile.noizdnsStealth) "1" else "0",
            profile.dnsPayloadSize.toString(),
            profile.socks5ServerPort.toString(),
            if (profile.vaydnsDnsttCompat) "1" else "0",
            sanitize(profile.vaydnsRecordType),
            profile.vaydnsMaxQnameLen.toString(),
            profile.vaydnsRps.toString(),
            profile.vaydnsIdleTimeout.toString(),
            profile.vaydnsKeepalive.toString(),
            profile.vaydnsUdpTimeout.toString(),
            profile.vaydnsMaxNumLabels.toString(),
            profile.vaydnsClientIdSize.toString(),
            // v21: SSH over TLS + HTTP CONNECT proxy
            if (profile.sshTlsEnabled) "1" else "0",
            sanitize(profile.sshTlsSni),
            sanitize(profile.sshHttpProxyHost),
            profile.sshHttpProxyPort.toString(),
            sanitize(profile.sshHttpProxyCustomHost),
            // v21: SSH over WebSocket
            if (profile.sshWsEnabled) "1" else "0",
            sanitize(profile.sshWsPath),
            if (profile.sshWsUseTls) "1" else "0",
            sanitize(profile.sshWsCustomHost),
            // v22: SSH payload (raw prefix for DPI bypass)
            Base64.encodeToString(profile.sshPayload.toByteArray(Charsets.UTF_8), Base64.NO_WRAP),
            // v23: Multi-resolver mode
            profile.resolverMode.value,
            // v24: Round-robin spread count
            profile.rrSpreadCount.toString(),
            // v25: VLESS + SNI fragmentation
            sanitize(profile.vlessUuid),
            sanitize(profile.vlessSecurity),
            sanitize(profile.vlessTransport),
            sanitize(profile.vlessWsPath),
            sanitize(profile.cdnIp),
            profile.cdnPort.toString(),
            if (profile.sniFragmentEnabled) "1" else "0",
            sanitize(profile.sniFragmentStrategy),
            profile.sniFragmentDelayMs.toString(),
            // v25–v27 held the SNI here. v28 moves it to the trailing vlessSni
            // field so position 71 stays empty in all new exports. Kept in the
            // layout so v27 readers can still parse v28 output (they'd just
            // see SNI="", falling back to domain — usually fine).
            "",
            // v26: DPI evasion options
            if (profile.chPaddingEnabled) "1" else "0",
            if (profile.wsHeaderObfuscation) "1" else "0",
            if (profile.wsPaddingEnabled) "1" else "0",
            // v27: SNI spoof TTL for fake/disorder strategies
            profile.sniSpoofTtl.toString(),
            // v27: Decoy hostname for `fake` strategy (empty = use built-in default)
            sanitize(profile.fakeDecoyHost),
            // v27: TCP MSS override on CDN socket (0 = auto, 40..1400 = explicit, <0 = force-disable)
            profile.tcpMaxSeg.toString(),
            // v28: Single TLS SNI for VLESS. Empty = the bridge falls back to
            // profile.domain (the WS Host). Replaces the legacy position-71
            // field that v25–v27 used.
            sanitize(profile.vlessSni)
        ).joinToString(FIELD_DELIMITER)
    }

    private fun encodeProfile(profile: ServerProfile, hideResolvers: Boolean = false): String {
        val data = buildProfileData(profile, hideResolvers)
        val encoded = Base64.encodeToString(data.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
        return "$SCHEME$encoded"
    }
}
