package app.slipnet.data.export

import android.util.Base64
import app.slipnet.domain.model.CongestionControl
import app.slipnet.domain.model.DnsResolver
import app.slipnet.domain.model.ServerProfile
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
 * Decoded profile format (pipe-delimited):
 * v1|mode|name|domain|resolvers|authMode|keepAlive|cc|port|host|gso
 */
@Singleton
class ConfigImporter @Inject constructor() {

    companion object {
        private const val SCHEME = "slipnet://"
        private const val SUPPORTED_VERSION = "1"
        private const val MODE_SLIPSTREAM = "ss"
        private const val FIELD_DELIMITER = "|"
        private const val RESOLVER_DELIMITER = ","
        private const val RESOLVER_PART_DELIMITER = ":"
        private const val EXPECTED_FIELD_COUNT = 11
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

        if (fields.size < EXPECTED_FIELD_COUNT) {
            return ProfileParseResult.Error("Line $lineNum: Invalid format (expected $EXPECTED_FIELD_COUNT fields, got ${fields.size})")
        }

        val version = fields[0]
        if (version != SUPPORTED_VERSION) {
            return ProfileParseResult.Error("Line $lineNum: Unsupported version '$version'")
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
            isActive = false
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
}
