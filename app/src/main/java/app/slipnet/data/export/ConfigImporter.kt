package app.slipnet.data.export

import android.util.Base64
import app.slipnet.domain.model.CongestionControl
import app.slipnet.domain.model.DnsResolver
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TunnelType
import javax.inject.Inject
import javax.inject.Singleton

sealed class ImportResult {
    data class Success(
        val profiles: List<ServerProfile>,
        val warnings: List<String> = emptyList()
    ) : ImportResult()

    data class Error(val message: String) : ImportResult()
}

/**
 * Imports profiles from compact encoded text format.
 *
 * Expected format: slipnet://[base64-encoded-profile]
 * Multiple profiles: one URI per line
 *
 * Decoded profile format v1 (pipe-delimited):
 * v1|mode|name|domain|resolvers|authMode|keepAlive|cc|port|host|gso
 *
 * Decoded profile format v2 (pipe-delimited):
 * v2|tunnelType|name|domain|resolvers|authMode|keepAlive|cc|port|host|gso|dnsttPublicKey|socksUsername|socksPassword
 */
@Singleton
class ConfigImporter @Inject constructor() {

    companion object {
        private const val SCHEME = "slipnet://"
        private const val MODE_SLIPSTREAM = "ss"
        private const val MODE_DNSTT = "dnstt"
        private const val FIELD_DELIMITER = "|"
        private const val RESOLVER_DELIMITER = ","
        private const val RESOLVER_PART_DELIMITER = ":"
        private const val V1_FIELD_COUNT = 11
        private const val V2_FIELD_COUNT = 14
    }

    fun parseAndImport(input: String): ImportResult {
        val lines = input.trim().lines().filter { it.isNotBlank() }

        if (lines.isEmpty()) {
            return ImportResult.Error("No profiles found in input")
        }

        val profiles = mutableListOf<ServerProfile>()
        val warnings = mutableListOf<String>()

        for ((index, line) in lines.withIndex()) {
            val trimmedLine = line.trim()
            if (!trimmedLine.startsWith(SCHEME, ignoreCase = true)) {
                warnings.add("Line ${index + 1}: Invalid format, skipping")
                continue
            }

            val encoded = trimmedLine.substring(SCHEME.length)
            val decoded = try {
                String(Base64.decode(encoded, Base64.NO_WRAP), Charsets.UTF_8)
            } catch (e: Exception) {
                warnings.add("Line ${index + 1}: Failed to decode, skipping")
                continue
            }

            val parseResult = parseProfile(decoded, index + 1)
            when (parseResult) {
                is ProfileParseResult.Success -> profiles.add(parseResult.profile)
                is ProfileParseResult.Warning -> warnings.add(parseResult.message)
                is ProfileParseResult.Error -> warnings.add(parseResult.message)
            }
        }

        if (profiles.isEmpty()) {
            return if (warnings.isNotEmpty()) {
                ImportResult.Error("No valid profiles found:\n${warnings.joinToString("\n")}")
            } else {
                ImportResult.Error("No valid profiles found")
            }
        }

        return ImportResult.Success(profiles, warnings)
    }

    private sealed class ProfileParseResult {
        data class Success(val profile: ServerProfile) : ProfileParseResult()
        data class Warning(val message: String) : ProfileParseResult()
        data class Error(val message: String) : ProfileParseResult()
    }

    private fun parseProfile(data: String, lineNum: Int): ProfileParseResult {
        val fields = data.split(FIELD_DELIMITER)

        if (fields.isEmpty()) {
            return ProfileParseResult.Error("Line $lineNum: Empty profile data")
        }

        val version = fields[0]
        return when (version) {
            "1" -> parseProfileV1(fields, lineNum)
            "2" -> parseProfileV2(fields, lineNum)
            else -> ProfileParseResult.Error("Line $lineNum: Unsupported version '$version'")
        }
    }

    private fun parseProfileV1(fields: List<String>, lineNum: Int): ProfileParseResult {
        if (fields.size < V1_FIELD_COUNT) {
            return ProfileParseResult.Error("Line $lineNum: Invalid v1 format (expected $V1_FIELD_COUNT fields, got ${fields.size})")
        }

        val mode = fields[1]
        if (mode != MODE_SLIPSTREAM) {
            return ProfileParseResult.Warning("Line $lineNum: Unsupported mode '$mode', skipping")
        }

        val name = fields[2]
        val domain = fields[3]
        val resolversStr = fields[4]
        val authMode = fields[5] == "1"
        val keepAlive = fields[6].toIntOrNull() ?: 200
        val cc = fields[7]
        val port = fields[8].toIntOrNull() ?: 10800
        val host = fields[9]
        val gso = fields[10] == "1"

        if (name.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Profile name is required")
        }
        if (domain.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Domain is required")
        }

        val resolvers = parseResolvers(resolversStr)
        if (resolvers.isEmpty()) {
            return ProfileParseResult.Error("Line $lineNum: At least one resolver is required")
        }

        if (port !in 1..65535) {
            return ProfileParseResult.Error("Line $lineNum: Invalid port $port")
        }

        // V1 profiles are always Slipstream
        val profile = ServerProfile(
            id = 0,
            name = name,
            domain = domain,
            resolvers = resolvers,
            authoritativeMode = authMode,
            keepAliveInterval = keepAlive,
            congestionControl = CongestionControl.fromValue(cc),
            tcpListenPort = port,
            tcpListenHost = host,
            gsoEnabled = gso,
            isActive = false,
            tunnelType = TunnelType.SLIPSTREAM,
            dnsttPublicKey = "",
            socksUsername = null,
            socksPassword = null
        )

        return ProfileParseResult.Success(profile)
    }

    private fun parseProfileV2(fields: List<String>, lineNum: Int): ProfileParseResult {
        if (fields.size < V2_FIELD_COUNT) {
            return ProfileParseResult.Error("Line $lineNum: Invalid v2 format (expected $V2_FIELD_COUNT fields, got ${fields.size})")
        }

        val tunnelTypeStr = fields[1]
        val tunnelType = when (tunnelTypeStr) {
            MODE_SLIPSTREAM -> TunnelType.SLIPSTREAM
            MODE_DNSTT -> TunnelType.DNSTT
            else -> {
                return ProfileParseResult.Warning("Line $lineNum: Unsupported tunnel type '$tunnelTypeStr', skipping")
            }
        }

        val name = fields[2]
        val domain = fields[3]
        val resolversStr = fields[4]
        val authMode = fields[5] == "1"
        val keepAlive = fields[6].toIntOrNull() ?: 200
        val cc = fields[7]
        val port = fields[8].toIntOrNull() ?: 10800
        val host = fields[9]
        val gso = fields[10] == "1"
        val dnsttPublicKey = fields[11]
        val socksUsername = fields[12].takeIf { it.isNotBlank() }
        val socksPassword = fields[13].takeIf { it.isNotBlank() }

        if (name.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Profile name is required")
        }
        if (domain.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Domain is required")
        }

        val resolvers = parseResolvers(resolversStr)
        if (resolvers.isEmpty()) {
            return ProfileParseResult.Error("Line $lineNum: At least one resolver is required")
        }

        if (port !in 1..65535) {
            return ProfileParseResult.Error("Line $lineNum: Invalid port $port")
        }

        // For DNSTT, validate public key
        if (tunnelType == TunnelType.DNSTT) {
            val keyError = validateDnsttPublicKey(dnsttPublicKey)
            if (keyError != null) {
                return ProfileParseResult.Error("Line $lineNum: $keyError")
            }
        }

        val profile = ServerProfile(
            id = 0,
            name = name,
            domain = domain,
            resolvers = resolvers,
            authoritativeMode = authMode,
            keepAliveInterval = keepAlive,
            congestionControl = CongestionControl.fromValue(cc),
            tcpListenPort = port,
            tcpListenHost = host,
            gsoEnabled = gso,
            isActive = false,
            tunnelType = tunnelType,
            dnsttPublicKey = dnsttPublicKey,
            socksUsername = socksUsername,
            socksPassword = socksPassword
        )

        return ProfileParseResult.Success(profile)
    }

    private fun parseResolvers(resolversStr: String): List<DnsResolver> {
        if (resolversStr.isBlank()) return emptyList()

        return resolversStr.split(RESOLVER_DELIMITER).mapNotNull { resolverStr ->
            val parts = resolverStr.split(RESOLVER_PART_DELIMITER)
            if (parts.size >= 2) {
                val host = parts[0]
                val port = parts[1].toIntOrNull() ?: 53
                val authoritative = parts.getOrNull(2) == "1"
                if (host.isNotBlank() && port in 1..65535) {
                    DnsResolver(host = host, port = port, authoritative = authoritative)
                } else null
            } else null
        }
    }

    /**
     * Validates DNSTT public key format.
     * Noise protocol uses Curve25519 keys which are 32 bytes (64 hex characters).
     * @return error message if invalid, null if valid
     */
    private fun validateDnsttPublicKey(publicKey: String): String? {
        val trimmed = publicKey.trim()

        if (trimmed.isBlank()) {
            return "DNSTT profiles require a public key"
        }

        if (trimmed.length != 64) {
            return "Public key must be 64 hex characters (32 bytes), got ${trimmed.length}"
        }

        if (!trimmed.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
            return "Public key must contain only hex characters (0-9, a-f)"
        }

        return null
    }
}
