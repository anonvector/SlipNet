package app.slipnet.data.export

import android.util.Base64
import app.slipnet.domain.model.CongestionControl
import app.slipnet.domain.model.DnsResolver
import app.slipnet.domain.model.DnsTransport
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.SshAuthType
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
 *
 * Decoded profile format v3 (pipe-delimited):
 * v3|tunnelType|name|domain|resolvers|authMode|keepAlive|cc|port|host|gso|dnsttPublicKey|socksUsername|socksPassword|sshEnabled|sshUsername|sshPassword
 *
 * Decoded profile format v4 (pipe-delimited):
 * v4|tunnelType|name|domain|resolvers|authMode|keepAlive|cc|port|host|gso|dnsttPublicKey|socksUsername|socksPassword|sshEnabled|sshUsername|sshPassword|sshPort|forwardDnsThroughSsh
 *
 * Decoded profile format v5 (pipe-delimited):
 * v5|tunnelType|name|domain|resolvers|authMode|keepAlive|cc|port|host|gso|dnsttPublicKey|socksUsername|socksPassword|sshEnabled|sshUsername|sshPassword|sshPort|forwardDnsThroughSsh|sshHost
 *
 * Decoded profile format v6 (same fields as v5, adds slipstream_ssh tunnel type):
 * v6|tunnelType|name|domain|resolvers|authMode|keepAlive|cc|port|host|gso|dnsttPublicKey|socksUsername|socksPassword|sshEnabled|sshUsername|sshPassword|sshPort|forwardDnsThroughSsh|sshHost
 *
 * Decoded profile format v7 (extends v6 with useServerDns):
 * v7|tunnelType|name|domain|resolvers|authMode|keepAlive|cc|port|host|gso|dnsttPublicKey|socksUsername|socksPassword|sshEnabled|sshUsername|sshPassword|sshPort|forwardDnsThroughSsh|sshHost|useServerDns
 *
 * Decoded profile format v8 (extends v7 with dohUrl):
 * v8|tunnelType|name|domain|resolvers|authMode|keepAlive|cc|port|host|gso|dnsttPublicKey|socksUsername|socksPassword|sshEnabled|sshUsername|sshPassword|sshPort|forwardDnsThroughSsh|sshHost|useServerDns|dohUrl
 *
 * Decoded profile format v9 (extends v8 with dnsTransport):
 * v9|tunnelType|name|domain|resolvers|authMode|keepAlive|cc|port|host|gso|dnsttPublicKey|socksUsername|socksPassword|sshEnabled|sshUsername|sshPassword|sshPort|forwardDnsThroughSsh|sshHost|useServerDns|dohUrl|dnsTransport
 *
 * Decoded profile format v10 (same fields as v9, adds snowflake tunnel type):
 * v10|tunnelType|name|domain|resolvers|authMode|keepAlive|cc|port|host|gso|dnsttPublicKey|socksUsername|socksPassword|sshEnabled|sshUsername|sshPassword|sshPort|forwardDnsThroughSsh|sshHost|useServerDns|dohUrl|dnsTransport
 *
 * Decoded profile format v11 (extends v10 with SSH key auth):
 * v11|tunnelType|name|domain|resolvers|authMode|keepAlive|cc|port|host|gso|dnsttPublicKey|socksUsername|socksPassword|sshEnabled|sshUsername|sshPassword|sshPort|forwardDnsThroughSsh|sshHost|useServerDns|dohUrl|dnsTransport|sshAuthType|sshPrivateKey(b64)|sshKeyPassphrase(b64)
 *
 * Decoded profile format v12 (extends v11 with Tor bridge lines):
 * v12|..same as v11..|torBridgeLines(b64)
 *
 * v13 (legacy, idlePollMode field ignored — parsed as v12)
 */
@Singleton
class ConfigImporter @Inject constructor() {

    companion object {
        private const val SCHEME = "slipnet://"
        private const val MODE_SLIPSTREAM = "ss"
        private const val MODE_SLIPSTREAM_SSH = "slipstream_ssh"
        private const val MODE_DNSTT = "dnstt"
        private const val MODE_DNSTT_SSH = "dnstt_ssh"
        private const val MODE_SSH = "ssh"
        private const val MODE_DOH = "doh"
        private const val MODE_SNOWFLAKE = "snowflake"
        private const val FIELD_DELIMITER = "|"
        private const val RESOLVER_DELIMITER = ","
        private const val RESOLVER_PART_DELIMITER = ":"
        private const val V1_FIELD_COUNT = 11
        private const val V2_FIELD_COUNT = 14
        private const val V3_FIELD_COUNT = 17
        private const val V4_FIELD_COUNT = 18
        private const val V5_FIELD_COUNT = 20
        private const val V6_FIELD_COUNT = 20
        private const val V7_FIELD_COUNT = 21
        private const val V8_FIELD_COUNT = 22
        private const val V9_FIELD_COUNT = 23
        private const val V10_FIELD_COUNT = 23
        private const val V11_FIELD_COUNT = 26
        private const val V12_FIELD_COUNT = 27
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
            "3" -> parseProfileV3(fields, lineNum)
            "4" -> parseProfileV4(fields, lineNum)
            "5" -> parseProfileV5(fields, lineNum)
            "6" -> parseProfileV6(fields, lineNum)
            "7" -> parseProfileV7(fields, lineNum)
            "8" -> parseProfileV8(fields, lineNum)
            "9" -> parseProfileV9(fields, lineNum)
            "10" -> parseProfileV10(fields, lineNum)
            "11" -> parseProfileV11(fields, lineNum)
            "12" -> parseProfileV12(fields, lineNum)
            "13" -> parseProfileV13(fields, lineNum)
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
        val port = fields[8].toIntOrNull() ?: 1080
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
            MODE_SLIPSTREAM_SSH -> TunnelType.SLIPSTREAM_SSH
            MODE_DNSTT -> TunnelType.DNSTT
            MODE_DNSTT_SSH -> TunnelType.DNSTT_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
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
        val port = fields[8].toIntOrNull() ?: 1080
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

        // SSH-only profiles don't need resolvers
        val resolvers = parseResolvers(resolversStr)
        if (resolvers.isEmpty() && tunnelType != TunnelType.SSH && tunnelType != TunnelType.DOH) {
            return ProfileParseResult.Error("Line $lineNum: At least one resolver is required")
        }

        if (port !in 1..65535) {
            return ProfileParseResult.Error("Line $lineNum: Invalid port $port")
        }

        // For DNSTT/DNSTT_SSH, validate public key
        if (tunnelType == TunnelType.DNSTT || tunnelType == TunnelType.DNSTT_SSH) {
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

    private fun parseProfileV3(fields: List<String>, lineNum: Int): ProfileParseResult {
        if (fields.size < V3_FIELD_COUNT) {
            return ProfileParseResult.Error("Line $lineNum: Invalid v3 format (expected $V3_FIELD_COUNT fields, got ${fields.size})")
        }

        val tunnelTypeStr = fields[1]
        val tunnelType = when (tunnelTypeStr) {
            MODE_SLIPSTREAM -> TunnelType.SLIPSTREAM
            MODE_SLIPSTREAM_SSH -> TunnelType.SLIPSTREAM_SSH
            MODE_DNSTT -> TunnelType.DNSTT
            MODE_DNSTT_SSH -> TunnelType.DNSTT_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
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
        val port = fields[8].toIntOrNull() ?: 1080
        val host = fields[9]
        val gso = fields[10] == "1"
        val dnsttPublicKey = fields[11]
        val socksUsername = fields[12].takeIf { it.isNotBlank() }
        val socksPassword = fields[13].takeIf { it.isNotBlank() }
        val sshEnabled = fields[14] == "1"
        val sshUsername = fields[15]
        val sshPassword = fields[16]

        if (name.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Profile name is required")
        }
        if (domain.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Domain is required")
        }

        // SSH-only profiles don't need resolvers
        val resolvers = parseResolvers(resolversStr)
        if (resolvers.isEmpty() && tunnelType != TunnelType.SSH && tunnelType != TunnelType.DOH) {
            return ProfileParseResult.Error("Line $lineNum: At least one resolver is required")
        }

        if (port !in 1..65535) {
            return ProfileParseResult.Error("Line $lineNum: Invalid port $port")
        }

        // For DNSTT/DNSTT_SSH, validate public key
        if (tunnelType == TunnelType.DNSTT || tunnelType == TunnelType.DNSTT_SSH) {
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
            socksPassword = socksPassword,
            sshUsername = sshUsername,
            sshPassword = sshPassword
        )

        return ProfileParseResult.Success(profile)
    }

    private fun parseProfileV4(fields: List<String>, lineNum: Int): ProfileParseResult {
        if (fields.size < V4_FIELD_COUNT) {
            return ProfileParseResult.Error("Line $lineNum: Invalid v4 format (expected $V4_FIELD_COUNT fields, got ${fields.size})")
        }

        val tunnelTypeStr = fields[1]
        val tunnelType = when (tunnelTypeStr) {
            MODE_SLIPSTREAM -> TunnelType.SLIPSTREAM
            MODE_SLIPSTREAM_SSH -> TunnelType.SLIPSTREAM_SSH
            MODE_DNSTT -> TunnelType.DNSTT
            MODE_DNSTT_SSH -> TunnelType.DNSTT_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
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
        val port = fields[8].toIntOrNull() ?: 1080
        val host = fields[9]
        val gso = fields[10] == "1"
        val dnsttPublicKey = fields[11]
        val socksUsername = fields[12].takeIf { it.isNotBlank() }
        val socksPassword = fields[13].takeIf { it.isNotBlank() }
        val sshEnabled = fields[14] == "1"
        val sshUsername = fields[15]
        val sshPassword = fields[16]
        val sshPort = fields[17].toIntOrNull() ?: 22
        val forwardDnsThroughSsh = fields.getOrNull(18)?.let { it == "1" } ?: false

        if (name.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Profile name is required")
        }
        if (domain.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Domain is required")
        }

        // SSH-only profiles don't need resolvers
        val resolvers = parseResolvers(resolversStr)
        if (resolvers.isEmpty() && tunnelType != TunnelType.SSH && tunnelType != TunnelType.DOH) {
            return ProfileParseResult.Error("Line $lineNum: At least one resolver is required")
        }

        if (port !in 1..65535) {
            return ProfileParseResult.Error("Line $lineNum: Invalid port $port")
        }

        // For DNSTT/DNSTT_SSH, validate public key
        if (tunnelType == TunnelType.DNSTT || tunnelType == TunnelType.DNSTT_SSH) {
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
            socksPassword = socksPassword,
            sshUsername = sshUsername,
            sshPassword = sshPassword,
            sshPort = sshPort
        )

        return ProfileParseResult.Success(profile)
    }

    private fun parseProfileV5(fields: List<String>, lineNum: Int): ProfileParseResult {
        if (fields.size < V5_FIELD_COUNT) {
            return ProfileParseResult.Error("Line $lineNum: Invalid v5 format (expected $V5_FIELD_COUNT fields, got ${fields.size})")
        }

        val tunnelTypeStr = fields[1]
        val tunnelType = when (tunnelTypeStr) {
            MODE_SLIPSTREAM -> TunnelType.SLIPSTREAM
            MODE_SLIPSTREAM_SSH -> TunnelType.SLIPSTREAM_SSH
            MODE_DNSTT -> TunnelType.DNSTT
            MODE_DNSTT_SSH -> TunnelType.DNSTT_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
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
        val port = fields[8].toIntOrNull() ?: 1080
        val host = fields[9]
        val gso = fields[10] == "1"
        val dnsttPublicKey = fields[11]
        val socksUsername = fields[12].takeIf { it.isNotBlank() }
        val socksPassword = fields[13].takeIf { it.isNotBlank() }
        val sshEnabled = fields[14] == "1"
        val sshUsername = fields[15]
        val sshPassword = fields[16]
        val sshPort = fields[17].toIntOrNull() ?: 22
        val forwardDnsThroughSsh = fields[18] == "1"
        val sshHost = fields[19]

        if (name.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Profile name is required")
        }
        if (domain.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Domain is required")
        }

        // SSH-only profiles don't need resolvers
        val resolvers = parseResolvers(resolversStr)
        if (resolvers.isEmpty() && tunnelType != TunnelType.SSH && tunnelType != TunnelType.DOH) {
            return ProfileParseResult.Error("Line $lineNum: At least one resolver is required")
        }

        if (port !in 1..65535) {
            return ProfileParseResult.Error("Line $lineNum: Invalid port $port")
        }

        // For DNSTT/DNSTT_SSH, validate public key
        if (tunnelType == TunnelType.DNSTT || tunnelType == TunnelType.DNSTT_SSH) {
            val keyError = validateDnsttPublicKey(dnsttPublicKey)
            if (keyError != null) {
                return ProfileParseResult.Error("Line $lineNum: $keyError")
            }
        }

        // For DNSTT_SSH, validate SSH credentials
        if (tunnelType == TunnelType.DNSTT_SSH) {
            if (sshUsername.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: DNSTT+SSH profiles require SSH username")
            }
            if (sshPassword.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: DNSTT+SSH profiles require SSH password")
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
            socksPassword = socksPassword,
            sshUsername = sshUsername,
            sshPassword = sshPassword,
            sshPort = sshPort,
            sshHost = sshHost
        )

        return ProfileParseResult.Success(profile)
    }

    private fun parseProfileV6(fields: List<String>, lineNum: Int): ProfileParseResult {
        if (fields.size < V6_FIELD_COUNT) {
            return ProfileParseResult.Error("Line $lineNum: Invalid v6 format (expected $V6_FIELD_COUNT fields, got ${fields.size})")
        }

        val tunnelTypeStr = fields[1]
        val tunnelType = when (tunnelTypeStr) {
            MODE_SLIPSTREAM -> TunnelType.SLIPSTREAM
            MODE_SLIPSTREAM_SSH -> TunnelType.SLIPSTREAM_SSH
            MODE_DNSTT -> TunnelType.DNSTT
            MODE_DNSTT_SSH -> TunnelType.DNSTT_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
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
        val port = fields[8].toIntOrNull() ?: 1080
        val host = fields[9]
        val gso = fields[10] == "1"
        val dnsttPublicKey = fields[11]
        val socksUsername = fields[12].takeIf { it.isNotBlank() }
        val socksPassword = fields[13].takeIf { it.isNotBlank() }
        val sshEnabled = fields[14] == "1"
        val sshUsername = fields[15]
        val sshPassword = fields[16]
        val sshPort = fields[17].toIntOrNull() ?: 22
        val forwardDnsThroughSsh = fields[18] == "1"
        val sshHost = fields[19]

        if (name.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Profile name is required")
        }
        if (domain.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Domain is required")
        }

        // SSH-only profiles don't need resolvers
        val resolvers = parseResolvers(resolversStr)
        if (resolvers.isEmpty() && tunnelType != TunnelType.SSH && tunnelType != TunnelType.DOH) {
            return ProfileParseResult.Error("Line $lineNum: At least one resolver is required")
        }

        if (port !in 1..65535) {
            return ProfileParseResult.Error("Line $lineNum: Invalid port $port")
        }

        // For DNSTT/DNSTT_SSH, validate public key
        if (tunnelType == TunnelType.DNSTT || tunnelType == TunnelType.DNSTT_SSH) {
            val keyError = validateDnsttPublicKey(dnsttPublicKey)
            if (keyError != null) {
                return ProfileParseResult.Error("Line $lineNum: $keyError")
            }
        }

        // For SSH tunnel types, validate SSH credentials
        if (tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.SLIPSTREAM_SSH) {
            if (sshUsername.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: ${tunnelType.displayName} profiles require SSH username")
            }
            if (sshPassword.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: ${tunnelType.displayName} profiles require SSH password")
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
            socksPassword = socksPassword,
            sshUsername = sshUsername,
            sshPassword = sshPassword,
            sshPort = sshPort,
            sshHost = sshHost
        )

        return ProfileParseResult.Success(profile)
    }

    private fun parseProfileV7(fields: List<String>, lineNum: Int): ProfileParseResult {
        if (fields.size < V7_FIELD_COUNT) {
            return ProfileParseResult.Error("Line $lineNum: Invalid v7 format (expected $V7_FIELD_COUNT fields, got ${fields.size})")
        }

        val tunnelTypeStr = fields[1]
        val tunnelType = when (tunnelTypeStr) {
            MODE_SLIPSTREAM -> TunnelType.SLIPSTREAM
            MODE_SLIPSTREAM_SSH -> TunnelType.SLIPSTREAM_SSH
            MODE_DNSTT -> TunnelType.DNSTT
            MODE_DNSTT_SSH -> TunnelType.DNSTT_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
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
        val port = fields[8].toIntOrNull() ?: 1080
        val host = fields[9]
        val gso = fields[10] == "1"
        val dnsttPublicKey = fields[11]
        val socksUsername = fields[12].takeIf { it.isNotBlank() }
        val socksPassword = fields[13].takeIf { it.isNotBlank() }
        val sshUsername = fields[15]
        val sshPassword = fields[16]
        val sshPort = fields[17].toIntOrNull() ?: 22
        val sshHost = fields[19]
        val useServerDns = fields[20] == "1"

        if (name.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Profile name is required")
        }
        if (domain.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Domain is required")
        }

        val resolvers = parseResolvers(resolversStr)
        if (resolvers.isEmpty() && tunnelType != TunnelType.SSH && tunnelType != TunnelType.DOH) {
            return ProfileParseResult.Error("Line $lineNum: At least one resolver is required")
        }

        if (port !in 1..65535) {
            return ProfileParseResult.Error("Line $lineNum: Invalid port $port")
        }

        if (tunnelType == TunnelType.DNSTT || tunnelType == TunnelType.DNSTT_SSH) {
            val keyError = validateDnsttPublicKey(dnsttPublicKey)
            if (keyError != null) {
                return ProfileParseResult.Error("Line $lineNum: $keyError")
            }
        }

        if (tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.SLIPSTREAM_SSH || tunnelType == TunnelType.SSH) {
            if (sshUsername.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: ${tunnelType.displayName} profiles require SSH username")
            }
            if (sshPassword.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: ${tunnelType.displayName} profiles require SSH password")
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
            socksPassword = socksPassword,
            sshUsername = sshUsername,
            sshPassword = sshPassword,
            sshPort = sshPort,
            sshHost = sshHost,
            useServerDns = useServerDns
        )

        return ProfileParseResult.Success(profile)
    }

    private fun parseProfileV8(fields: List<String>, lineNum: Int): ProfileParseResult {
        if (fields.size < V8_FIELD_COUNT) {
            return ProfileParseResult.Error("Line $lineNum: Invalid v8 format (expected $V8_FIELD_COUNT fields, got ${fields.size})")
        }

        val tunnelTypeStr = fields[1]
        val tunnelType = when (tunnelTypeStr) {
            MODE_SLIPSTREAM -> TunnelType.SLIPSTREAM
            MODE_SLIPSTREAM_SSH -> TunnelType.SLIPSTREAM_SSH
            MODE_DNSTT -> TunnelType.DNSTT
            MODE_DNSTT_SSH -> TunnelType.DNSTT_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
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
        val port = fields[8].toIntOrNull() ?: 1080
        val host = fields[9]
        val gso = fields[10] == "1"
        val dnsttPublicKey = fields[11]
        val socksUsername = fields[12].takeIf { it.isNotBlank() }
        val socksPassword = fields[13].takeIf { it.isNotBlank() }
        val sshUsername = fields[15]
        val sshPassword = fields[16]
        val sshPort = fields[17].toIntOrNull() ?: 22
        val sshHost = fields[19]
        val useServerDns = fields[20] == "1"
        val dohUrl = fields[21]

        if (name.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Profile name is required")
        }
        if (tunnelType != TunnelType.DOH && tunnelType != TunnelType.SNOWFLAKE && domain.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Domain is required")
        }

        val resolvers = parseResolvers(resolversStr)
        if (resolvers.isEmpty() && tunnelType != TunnelType.SSH && tunnelType != TunnelType.DOH && tunnelType != TunnelType.SNOWFLAKE) {
            return ProfileParseResult.Error("Line $lineNum: At least one resolver is required")
        }

        if (port !in 1..65535) {
            return ProfileParseResult.Error("Line $lineNum: Invalid port $port")
        }

        if (tunnelType == TunnelType.DNSTT || tunnelType == TunnelType.DNSTT_SSH) {
            val keyError = validateDnsttPublicKey(dnsttPublicKey)
            if (keyError != null) {
                return ProfileParseResult.Error("Line $lineNum: $keyError")
            }
        }

        if (tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.SLIPSTREAM_SSH || tunnelType == TunnelType.SSH) {
            if (sshUsername.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: ${tunnelType.displayName} profiles require SSH username")
            }
            if (sshPassword.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: ${tunnelType.displayName} profiles require SSH password")
            }
        }

        if (tunnelType == TunnelType.DOH) {
            if (dohUrl.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: DOH profiles require a DoH server URL")
            }
            if (!dohUrl.startsWith("https://")) {
                return ProfileParseResult.Error("Line $lineNum: DoH URL must start with https://")
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
            socksPassword = socksPassword,
            sshUsername = sshUsername,
            sshPassword = sshPassword,
            sshPort = sshPort,
            sshHost = sshHost,
            useServerDns = useServerDns,
            dohUrl = dohUrl
        )

        return ProfileParseResult.Success(profile)
    }

    private fun parseProfileV9(fields: List<String>, lineNum: Int): ProfileParseResult {
        if (fields.size < V9_FIELD_COUNT) {
            return ProfileParseResult.Error("Line $lineNum: Invalid v9 format (expected $V9_FIELD_COUNT fields, got ${fields.size})")
        }

        val tunnelTypeStr = fields[1]
        val tunnelType = when (tunnelTypeStr) {
            MODE_SLIPSTREAM -> TunnelType.SLIPSTREAM
            MODE_SLIPSTREAM_SSH -> TunnelType.SLIPSTREAM_SSH
            MODE_DNSTT -> TunnelType.DNSTT
            MODE_DNSTT_SSH -> TunnelType.DNSTT_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
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
        val port = fields[8].toIntOrNull() ?: 1080
        val host = fields[9]
        val gso = fields[10] == "1"
        val dnsttPublicKey = fields[11]
        val socksUsername = fields[12].takeIf { it.isNotBlank() }
        val socksPassword = fields[13].takeIf { it.isNotBlank() }
        val sshUsername = fields[15]
        val sshPassword = fields[16]
        val sshPort = fields[17].toIntOrNull() ?: 22
        val sshHost = fields[19]
        val useServerDns = fields[20] == "1"
        val dohUrl = fields[21]
        val dnsTransport = DnsTransport.fromValue(fields[22])

        if (name.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Profile name is required")
        }
        if (tunnelType != TunnelType.DOH && tunnelType != TunnelType.SNOWFLAKE && domain.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Domain is required")
        }

        val resolvers = parseResolvers(resolversStr)
        val isDnsttBased = tunnelType == TunnelType.DNSTT || tunnelType == TunnelType.DNSTT_SSH
        val skipResolvers = tunnelType == TunnelType.SSH || tunnelType == TunnelType.DOH ||
                tunnelType == TunnelType.SNOWFLAKE ||
                (isDnsttBased && dnsTransport == DnsTransport.DOH)
        if (resolvers.isEmpty() && !skipResolvers) {
            return ProfileParseResult.Error("Line $lineNum: At least one resolver is required")
        }

        if (port !in 1..65535) {
            return ProfileParseResult.Error("Line $lineNum: Invalid port $port")
        }

        if (isDnsttBased) {
            val keyError = validateDnsttPublicKey(dnsttPublicKey)
            if (keyError != null) {
                return ProfileParseResult.Error("Line $lineNum: $keyError")
            }
        }

        if (tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.SLIPSTREAM_SSH || tunnelType == TunnelType.SSH) {
            if (sshUsername.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: ${tunnelType.displayName} profiles require SSH username")
            }
            if (sshPassword.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: ${tunnelType.displayName} profiles require SSH password")
            }
        }

        val needsDohUrl = tunnelType == TunnelType.DOH || (isDnsttBased && dnsTransport == DnsTransport.DOH)
        if (needsDohUrl) {
            if (dohUrl.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: DoH URL is required")
            }
            if (!dohUrl.startsWith("https://")) {
                return ProfileParseResult.Error("Line $lineNum: DoH URL must start with https://")
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
            socksPassword = socksPassword,
            sshUsername = sshUsername,
            sshPassword = sshPassword,
            sshPort = sshPort,
            sshHost = sshHost,
            useServerDns = useServerDns,
            dohUrl = dohUrl,
            dnsTransport = dnsTransport
        )

        return ProfileParseResult.Success(profile)
    }

    /**
     * Parse v10 profile format (same fields as v9, adds snowflake tunnel type).
     */
    private fun parseProfileV10(fields: List<String>, lineNum: Int): ProfileParseResult {
        if (fields.size < V10_FIELD_COUNT) {
            return ProfileParseResult.Error("Line $lineNum: Invalid v10 format (expected $V10_FIELD_COUNT fields, got ${fields.size})")
        }
        // v10 has the same field layout as v9, just delegate
        return parseProfileV9(fields, lineNum)
    }

    /**
     * Parse v11 profile format (extends v10 with SSH key auth fields).
     */
    private fun parseProfileV11(fields: List<String>, lineNum: Int): ProfileParseResult {
        if (fields.size < V11_FIELD_COUNT) {
            return ProfileParseResult.Error("Line $lineNum: Invalid v11 format (expected $V11_FIELD_COUNT fields, got ${fields.size})")
        }

        val tunnelTypeStr = fields[1]
        val tunnelType = when (tunnelTypeStr) {
            MODE_SLIPSTREAM -> TunnelType.SLIPSTREAM
            MODE_SLIPSTREAM_SSH -> TunnelType.SLIPSTREAM_SSH
            MODE_DNSTT -> TunnelType.DNSTT
            MODE_DNSTT_SSH -> TunnelType.DNSTT_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
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
        val port = fields[8].toIntOrNull() ?: 1080
        val host = fields[9]
        val gso = fields[10] == "1"
        val dnsttPublicKey = fields[11]
        val socksUsername = fields[12].takeIf { it.isNotBlank() }
        val socksPassword = fields[13].takeIf { it.isNotBlank() }
        val sshUsername = fields[15]
        val sshPassword = fields[16]
        val sshPort = fields[17].toIntOrNull() ?: 22
        val sshHost = fields[19]
        val useServerDns = fields[20] == "1"
        val dohUrl = fields[21]
        val dnsTransport = DnsTransport.fromValue(fields[22])
        val sshAuthType = SshAuthType.fromValue(fields[23])
        val sshPrivateKey = try {
            String(Base64.decode(fields[24], Base64.NO_WRAP), Charsets.UTF_8)
        } catch (_: Exception) { "" }
        val sshKeyPassphrase = try {
            String(Base64.decode(fields[25], Base64.NO_WRAP), Charsets.UTF_8)
        } catch (_: Exception) { "" }

        if (name.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Profile name is required")
        }
        if (tunnelType != TunnelType.DOH && tunnelType != TunnelType.SNOWFLAKE && domain.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Domain is required")
        }

        val resolvers = parseResolvers(resolversStr)
        val isDnsttBased = tunnelType == TunnelType.DNSTT || tunnelType == TunnelType.DNSTT_SSH
        val skipResolvers = tunnelType == TunnelType.SSH || tunnelType == TunnelType.DOH ||
                tunnelType == TunnelType.SNOWFLAKE ||
                (isDnsttBased && dnsTransport == DnsTransport.DOH)
        if (resolvers.isEmpty() && !skipResolvers) {
            return ProfileParseResult.Error("Line $lineNum: At least one resolver is required")
        }

        if (port !in 1..65535) {
            return ProfileParseResult.Error("Line $lineNum: Invalid port $port")
        }

        if (isDnsttBased) {
            val keyError = validateDnsttPublicKey(dnsttPublicKey)
            if (keyError != null) {
                return ProfileParseResult.Error("Line $lineNum: $keyError")
            }
        }

        if (tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.SLIPSTREAM_SSH || tunnelType == TunnelType.SSH) {
            if (sshUsername.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: ${tunnelType.displayName} profiles require SSH username")
            }
            if (sshAuthType == SshAuthType.PASSWORD && sshPassword.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: ${tunnelType.displayName} profiles require SSH password")
            }
            if (sshAuthType == SshAuthType.KEY && sshPrivateKey.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: ${tunnelType.displayName} profiles require SSH private key")
            }
        }

        val needsDohUrl = tunnelType == TunnelType.DOH || (isDnsttBased && dnsTransport == DnsTransport.DOH)
        if (needsDohUrl) {
            if (dohUrl.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: DoH URL is required")
            }
            if (!dohUrl.startsWith("https://")) {
                return ProfileParseResult.Error("Line $lineNum: DoH URL must start with https://")
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
            socksPassword = socksPassword,
            sshUsername = sshUsername,
            sshPassword = sshPassword,
            sshPort = sshPort,
            sshHost = sshHost,
            useServerDns = useServerDns,
            dohUrl = dohUrl,
            dnsTransport = dnsTransport,
            sshAuthType = sshAuthType,
            sshPrivateKey = sshPrivateKey,
            sshKeyPassphrase = sshKeyPassphrase
        )

        return ProfileParseResult.Success(profile)
    }

    /**
     * Parse v12 profile format (extends v11 with Tor bridge lines).
     */
    private fun parseProfileV12(fields: List<String>, lineNum: Int): ProfileParseResult {
        if (fields.size < V12_FIELD_COUNT) {
            return ProfileParseResult.Error("Line $lineNum: Invalid v12 format (expected $V12_FIELD_COUNT fields, got ${fields.size})")
        }

        val tunnelTypeStr = fields[1]
        val tunnelType = when (tunnelTypeStr) {
            MODE_SLIPSTREAM -> TunnelType.SLIPSTREAM
            MODE_SLIPSTREAM_SSH -> TunnelType.SLIPSTREAM_SSH
            MODE_DNSTT -> TunnelType.DNSTT
            MODE_DNSTT_SSH -> TunnelType.DNSTT_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
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
        val port = fields[8].toIntOrNull() ?: 1080
        val host = fields[9]
        val gso = fields[10] == "1"
        val dnsttPublicKey = fields[11]
        val socksUsername = fields[12].takeIf { it.isNotBlank() }
        val socksPassword = fields[13].takeIf { it.isNotBlank() }
        val sshUsername = fields[15]
        val sshPassword = fields[16]
        val sshPort = fields[17].toIntOrNull() ?: 22
        val sshHost = fields[19]
        val useServerDns = fields[20] == "1"
        val dohUrl = fields[21]
        val dnsTransport = DnsTransport.fromValue(fields[22])
        val sshAuthType = SshAuthType.fromValue(fields[23])
        val sshPrivateKey = try {
            String(Base64.decode(fields[24], Base64.NO_WRAP), Charsets.UTF_8)
        } catch (_: Exception) { "" }
        val sshKeyPassphrase = try {
            String(Base64.decode(fields[25], Base64.NO_WRAP), Charsets.UTF_8)
        } catch (_: Exception) { "" }

        // v12 new field: bridge lines (base64-encoded)
        val torBridgeLines = try {
            String(Base64.decode(fields[26], Base64.NO_WRAP), Charsets.UTF_8)
        } catch (_: Exception) { "" }

        if (name.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Profile name is required")
        }
        if (tunnelType != TunnelType.DOH && tunnelType != TunnelType.SNOWFLAKE && domain.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Domain is required")
        }

        val resolvers = parseResolvers(resolversStr)
        val isDnsttBased = tunnelType == TunnelType.DNSTT || tunnelType == TunnelType.DNSTT_SSH
        val skipResolvers = tunnelType == TunnelType.SSH || tunnelType == TunnelType.DOH ||
                tunnelType == TunnelType.SNOWFLAKE ||
                (isDnsttBased && dnsTransport == DnsTransport.DOH)
        if (resolvers.isEmpty() && !skipResolvers) {
            return ProfileParseResult.Error("Line $lineNum: At least one resolver is required")
        }

        if (port !in 1..65535) {
            return ProfileParseResult.Error("Line $lineNum: Invalid port $port")
        }

        if (isDnsttBased) {
            val keyError = validateDnsttPublicKey(dnsttPublicKey)
            if (keyError != null) {
                return ProfileParseResult.Error("Line $lineNum: $keyError")
            }
        }

        if (tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.SLIPSTREAM_SSH || tunnelType == TunnelType.SSH) {
            if (sshUsername.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: ${tunnelType.displayName} profiles require SSH username")
            }
            if (sshAuthType == SshAuthType.PASSWORD && sshPassword.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: ${tunnelType.displayName} profiles require SSH password")
            }
            if (sshAuthType == SshAuthType.KEY && sshPrivateKey.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: ${tunnelType.displayName} profiles require SSH private key")
            }
        }

        val needsDohUrl = tunnelType == TunnelType.DOH || (isDnsttBased && dnsTransport == DnsTransport.DOH)
        if (needsDohUrl) {
            if (dohUrl.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: DoH URL is required")
            }
            if (!dohUrl.startsWith("https://")) {
                return ProfileParseResult.Error("Line $lineNum: DoH URL must start with https://")
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
            socksPassword = socksPassword,
            sshUsername = sshUsername,
            sshPassword = sshPassword,
            sshPort = sshPort,
            sshHost = sshHost,
            useServerDns = useServerDns,
            dohUrl = dohUrl,
            dnsTransport = dnsTransport,
            sshAuthType = sshAuthType,
            sshPrivateKey = sshPrivateKey,
            sshKeyPassphrase = sshKeyPassphrase,
            torBridgeLines = torBridgeLines
        )

        return ProfileParseResult.Success(profile)
    }

    // v13 legacy: same as v12 with an extra idlePollMode field (ignored)
    private fun parseProfileV13(fields: List<String>, lineNum: Int): ProfileParseResult {
        return parseProfileV12(fields, lineNum)
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
