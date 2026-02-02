package app.slipnet.data.export

import android.util.Base64
import app.slipnet.domain.model.ServerProfile
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Exports profiles to compact encoded text format.
 *
 * Single profile format: slipnet://[base64-encoded-profile]
 * Multiple profiles: one URI per line
 *
 * Encoded profile format (pipe-delimited):
 * v1|mode|name|domain|resolvers|authMode|keepAlive|cc|port|host|gso
 *
 * Resolvers format (comma-separated): host:port:auth,host:port:auth
 */
@Singleton
class ConfigExporter @Inject constructor() {

    companion object {
        const val SCHEME = "slipnet://"
        const val VERSION = "1"
        const val MODE_SLIPSTREAM = "ss"
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

        val data = listOf(
            VERSION,
            MODE_SLIPSTREAM,
            profile.name,
            profile.domain,
            resolversStr,
            if (profile.authoritativeMode) "1" else "0",
            profile.keepAliveInterval.toString(),
            profile.congestionControl.value,
            profile.tcpListenPort.toString(),
            profile.tcpListenHost,
            if (profile.gsoEnabled) "1" else "0"
        ).joinToString(FIELD_DELIMITER)

        val encoded = Base64.encodeToString(data.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
        return "$SCHEME$encoded"
    }
}
