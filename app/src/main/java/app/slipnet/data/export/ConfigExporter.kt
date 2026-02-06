package app.slipnet.data.export

import android.util.Base64
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TunnelType
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Exports profiles to compact encoded text format.
 *
 * Single profile format: slipnet://[base64-encoded-profile]
 * Multiple profiles: one URI per line
 *
 * Encoded profile format v3 (pipe-delimited):
 * v3|tunnelType|name|domain|resolvers|authMode|keepAlive|cc|port|host|gso|dnsttPublicKey|socksUsername|socksPassword|sshEnabled|sshUsername|sshPassword
 *
 * Resolvers format (comma-separated): host:port:auth,host:port:auth
 */
@Singleton
class ConfigExporter @Inject constructor() {

    companion object {
        const val SCHEME = "slipnet://"
        const val VERSION = "3"
        const val MODE_SLIPSTREAM = "ss"
        const val MODE_DNSTT = "dnstt"
        private const val FIELD_DELIMITER = "|"
        private const val RESOLVER_DELIMITER = ","
        private const val RESOLVER_PART_DELIMITER = ":"
    }

    fun exportSingleProfile(profile: ServerProfile): String {
        return encodeProfile(profile)
    }

    fun exportAllProfiles(profiles: List<ServerProfile>): String {
        return profiles.joinToString("\n") { encodeProfile(it) }
    }

    private fun encodeProfile(profile: ServerProfile): String {
        val resolversStr = profile.resolvers.joinToString(RESOLVER_DELIMITER) { resolver ->
            "${resolver.host}${RESOLVER_PART_DELIMITER}${resolver.port}${RESOLVER_PART_DELIMITER}${if (resolver.authoritative) "1" else "0"}"
        }

        val tunnelTypeStr = when (profile.tunnelType) {
            TunnelType.SLIPSTREAM -> MODE_SLIPSTREAM
            TunnelType.DNSTT -> MODE_DNSTT
        }

        val data = listOf(
            VERSION,
            tunnelTypeStr,
            profile.name,
            profile.domain,
            resolversStr,
            if (profile.authoritativeMode) "1" else "0",
            profile.keepAliveInterval.toString(),
            profile.congestionControl.value,
            profile.tcpListenPort.toString(),
            profile.tcpListenHost,
            if (profile.gsoEnabled) "1" else "0",
            profile.dnsttPublicKey,
            profile.socksUsername ?: "",
            profile.socksPassword ?: "",
            if (profile.sshEnabled) "1" else "0",
            profile.sshUsername,
            profile.sshPassword
        ).joinToString(FIELD_DELIMITER)

        val encoded = Base64.encodeToString(data.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
        return "$SCHEME$encoded"
    }
}
