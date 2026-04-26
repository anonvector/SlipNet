package app.slipnet.data.export

import android.util.Base64
import app.slipnet.domain.model.CongestionControl
import app.slipnet.domain.model.DnsResolver
import app.slipnet.domain.model.DnsTransport
import app.slipnet.domain.model.ResolverMode
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.SshAuthType
import app.slipnet.domain.model.TunnelType
import app.slipnet.util.BundleCrypto
import app.slipnet.util.LockPasswordUtil
import javax.inject.Inject
import javax.inject.Singleton

sealed class ImportResult {
    data class Success(
        val profiles: List<ServerProfile>,
        val warnings: List<String> = emptyList()
    ) : ImportResult()

    data class Error(val message: String) : ImportResult()

    /** Input contains an encrypted bundle; caller must prompt for a password and retry. */
    data object NeedsPassword : ImportResult()
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
 * NOTE: Position 20 (useServerDns) is deprecated and ignored since v1.8.6 (now a global setting).
 * It is safe to reuse this position for a new field in v14+. Parsers v7-v13 skip it,
 * and v1-v6 don't have it. Just bump VERSION to "14" and add a parseProfileV14.
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
 * Decoded profile format v13 (extends v12 with DNSTT authoritative mode):
 * v13|..same as v12..|dnsttAuthoritative
 *
 * Decoded profile format v14 (extends v13 with NaiveProxy fields):
 * v14|..same as v13..|naivePort|naiveUsername|naivePassword(b64)
 *
 * Decoded profile format v15 (extends v14 with locked profile fields):
 * v15|..same as v14..|isLocked|lockPasswordHash
 *
 * Decoded profile format v16 (extends v15 with locked profile enhancements):
 * v16|..same as v15..|expirationDate|allowSharing|boundDeviceId
 *
 * Decoded profile format v17 (extends v16 with hidden resolvers):
 * v17|..same as v16..|resolversHidden|hiddenResolvers
 *
 * Decoded profile format v18 (extends v17 with stealth mode, DNS payload size, SOCKS5 port):
 * v18|..same as v17..|noizdnsStealth|dnsPayloadSize|socks5ServerPort
 *
 */
@Singleton
class ConfigImporter @Inject constructor() {

    companion object {
        private const val SCHEME = "slipnet://"
        private const val ENCRYPTED_SCHEME = "slipnet-enc://"
        private const val BUNDLE_ENCRYPTED_SCHEME = "slipnet-bundle-enc://"
        private const val MODE_SLIPSTREAM = "ss"
        private const val MODE_SLIPSTREAM_SSH = "slipstream_ssh"
        private const val MODE_DNSTT = "dnstt"
        private const val MODE_DNSTT_SSH = "dnstt_ssh"
        private const val MODE_NOIZDNS = "sayedns"
        private const val MODE_NOIZDNS_SSH = "sayedns_ssh"
        private const val MODE_SSH = "ssh"
        private const val MODE_DOH = "doh"
        private const val MODE_SNOWFLAKE = "snowflake"
        private const val MODE_NAIVE_SSH = "naive_ssh"
        private const val MODE_NAIVE = "naive"
        private const val MODE_SOCKS5 = "socks5"
        private const val MODE_VAYDNS = "vaydns"
        private const val MODE_VAYDNS_SSH = "vaydns_ssh"
        private const val MODE_VLESS = "vless"
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
        private const val V13_FIELD_COUNT = 28
        private const val V14_FIELD_COUNT = 31
        private const val V15_FIELD_COUNT = 33
        private const val V16_FIELD_COUNT = 36
        private const val V17_FIELD_COUNT = 38
        private const val V18_FIELD_COUNT = 41
        private const val CURRENT_MAX_VERSION = 28
        private const val VLESS_SCHEME = "vless://"
    }

    fun parseAndImport(
        input: String,
        localDeviceId: String = "",
        bundlePassword: String? = null
    ): ImportResult {
        val trimmedInput = input.trim()

        // Password-encrypted bundle: the whole input is one base64 blob.
        // We unwrap it here and let the normal line-loop parse the decrypted
        // multi-line bundle below.
        val expanded = if (trimmedInput.startsWith(BUNDLE_ENCRYPTED_SCHEME, ignoreCase = true)) {
            if (bundlePassword.isNullOrEmpty()) return ImportResult.NeedsPassword
            val encoded = trimmedInput.substring(BUNDLE_ENCRYPTED_SCHEME.length)
            val encryptedBytes = try {
                Base64.decode(encoded, Base64.NO_WRAP)
            } catch (e: Exception) {
                return ImportResult.Error("Failed to decode encrypted bundle")
            }
            try {
                BundleCrypto.decrypt(encryptedBytes, bundlePassword)
            } catch (e: BundleCrypto.DecryptionException) {
                return ImportResult.Error(e.message ?: "Failed to decrypt bundle")
            }
        } else {
            trimmedInput
        }

        val lines = expanded.lines().filter { it.isNotBlank() }

        if (lines.isEmpty()) {
            return ImportResult.Error("No profiles found in input")
        }

        val profiles = mutableListOf<ServerProfile>()
        val warnings = mutableListOf<String>()

        for ((index, line) in lines.withIndex()) {
            val trimmedLine = line.trim()

            // Handle standard vless:// URIs
            if (trimmedLine.startsWith(VLESS_SCHEME, ignoreCase = true)) {
                val result = parseVlessUri(trimmedLine, index + 1)
                when (result) {
                    is ProfileParseResult.Success -> profiles.add(result.profile)
                    is ProfileParseResult.Warning -> warnings.add(result.message)
                    is ProfileParseResult.Error -> warnings.add(result.message)
                }
                continue
            }

            if (trimmedLine.startsWith(ENCRYPTED_SCHEME, ignoreCase = true)) {
                val encoded = trimmedLine.substring(ENCRYPTED_SCHEME.length)
                val encryptedBytes = try {
                    Base64.decode(encoded, Base64.NO_WRAP)
                } catch (e: Exception) {
                    warnings.add("Line ${index + 1}: Failed to decode, skipping")
                    continue
                }

                val decoded = try {
                    LockPasswordUtil.decryptConfig(encryptedBytes)
                } catch (e: Exception) {
                    warnings.add("Line ${index + 1}: Failed to decrypt, skipping")
                    continue
                }

                val parseResult = parseProfile(decoded, index + 1)
                when (parseResult) {
                    is ProfileParseResult.Success -> {
                        val profile = parseResult.profile
                        if (profile.boundDeviceId.isNotEmpty() && localDeviceId.isNotEmpty() && profile.boundDeviceId != localDeviceId) {
                            warnings.add("Line ${index + 1}: Profile is bound to a different device, skipping")
                        } else {
                            profiles.add(profile)
                            val version = decoded.split(FIELD_DELIMITER).firstOrNull()?.toIntOrNull()
                            if (version != null && version > CURRENT_MAX_VERSION) {
                                warnings.add("Line ${index + 1}: Exported from a newer app version — some settings may be missing")
                            }
                        }
                    }
                    is ProfileParseResult.Warning -> warnings.add(parseResult.message)
                    is ProfileParseResult.Error -> warnings.add(parseResult.message)
                }
                continue
            }

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
                is ProfileParseResult.Success -> {
                    val profile = parseResult.profile
                    if (profile.boundDeviceId.isNotEmpty() && localDeviceId.isNotEmpty() && profile.boundDeviceId != localDeviceId) {
                        warnings.add("Line ${index + 1}: Profile is bound to a different device, skipping")
                    } else {
                        profiles.add(profile)
                        val version = decoded.split(FIELD_DELIMITER).firstOrNull()?.toIntOrNull()
                        if (version != null && version > CURRENT_MAX_VERSION) {
                            warnings.add("Line ${index + 1}: Exported from a newer app version — some settings may be missing")
                        }
                    }
                }
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
            "14" -> parseProfileV14(fields, lineNum)
            "15" -> parseProfileV15(fields, lineNum)
            "16" -> parseProfileV16(fields, lineNum)
            "17" -> parseProfileV17(fields, lineNum)
            "18" -> parseProfileV18(fields, lineNum)
            "19" -> parseProfileV19(fields, lineNum)
            "20" -> parseProfileV20(fields, lineNum)
            "21" -> parseProfileV21(fields, lineNum)
            "22" -> parseProfileV22(fields, lineNum)
            "23" -> parseProfileV23(fields, lineNum)
            "24" -> parseProfileV24(fields, lineNum)
            "25" -> parseProfileV25(fields, lineNum)
            "26" -> parseProfileV26(fields, lineNum)
            "27" -> parseProfileV27(fields, lineNum)
            "28" -> parseProfileV28(fields, lineNum)
            else -> {
                // Forward compatibility: try the highest known parser for newer versions.
                // Extra trailing fields are safely ignored (parsers only check minimum count).
                val versionNum = version.toIntOrNull()
                if (versionNum != null && versionNum > 28) {
                    parseProfileV28(fields, lineNum)
                } else {
                    ProfileParseResult.Error("Line $lineNum: Unsupported version '$version'")
                }
            }
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
        val keepAlive = fields[6].toIntOrNull() ?: 5000
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
            MODE_NOIZDNS -> TunnelType.NOIZDNS
            MODE_NOIZDNS_SSH -> TunnelType.NOIZDNS_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
            MODE_NAIVE_SSH -> TunnelType.NAIVE_SSH
            MODE_NAIVE -> TunnelType.NAIVE
            MODE_SOCKS5 -> TunnelType.SOCKS5
            MODE_VAYDNS -> TunnelType.VAYDNS
            MODE_VAYDNS_SSH -> TunnelType.VAYDNS_SSH
            MODE_VLESS -> TunnelType.VLESS

            else -> {
                return ProfileParseResult.Warning("Line $lineNum: Unsupported tunnel type '$tunnelTypeStr', skipping")
            }
        }

        val name = fields[2]
        val domain = fields[3]
        val resolversStr = fields[4]
        val authMode = fields[5] == "1"
        val keepAlive = fields[6].toIntOrNull() ?: 5000
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
        if (resolvers.isEmpty() && tunnelType != TunnelType.SSH && tunnelType != TunnelType.DOH && tunnelType != TunnelType.SOCKS5 && tunnelType != TunnelType.VLESS) {
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
            MODE_NOIZDNS -> TunnelType.NOIZDNS
            MODE_NOIZDNS_SSH -> TunnelType.NOIZDNS_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
            MODE_NAIVE_SSH -> TunnelType.NAIVE_SSH
            MODE_NAIVE -> TunnelType.NAIVE
            MODE_SOCKS5 -> TunnelType.SOCKS5
            MODE_VAYDNS -> TunnelType.VAYDNS
            MODE_VAYDNS_SSH -> TunnelType.VAYDNS_SSH
            MODE_VLESS -> TunnelType.VLESS

            else -> {
                return ProfileParseResult.Warning("Line $lineNum: Unsupported tunnel type '$tunnelTypeStr', skipping")
            }
        }

        val name = fields[2]
        val domain = fields[3]
        val resolversStr = fields[4]
        val authMode = fields[5] == "1"
        val keepAlive = fields[6].toIntOrNull() ?: 5000
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
        if (resolvers.isEmpty() && tunnelType != TunnelType.SSH && tunnelType != TunnelType.DOH && tunnelType != TunnelType.SOCKS5 && tunnelType != TunnelType.VLESS) {
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
            MODE_NOIZDNS -> TunnelType.NOIZDNS
            MODE_NOIZDNS_SSH -> TunnelType.NOIZDNS_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
            MODE_NAIVE_SSH -> TunnelType.NAIVE_SSH
            MODE_NAIVE -> TunnelType.NAIVE
            MODE_SOCKS5 -> TunnelType.SOCKS5
            MODE_VAYDNS -> TunnelType.VAYDNS
            MODE_VAYDNS_SSH -> TunnelType.VAYDNS_SSH
            MODE_VLESS -> TunnelType.VLESS

            else -> {
                return ProfileParseResult.Warning("Line $lineNum: Unsupported tunnel type '$tunnelTypeStr', skipping")
            }
        }

        val name = fields[2]
        val domain = fields[3]
        val resolversStr = fields[4]
        val authMode = fields[5] == "1"
        val keepAlive = fields[6].toIntOrNull() ?: 5000
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
        if (resolvers.isEmpty() && tunnelType != TunnelType.SSH && tunnelType != TunnelType.DOH && tunnelType != TunnelType.SOCKS5 && tunnelType != TunnelType.VLESS) {
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
            MODE_NOIZDNS -> TunnelType.NOIZDNS
            MODE_NOIZDNS_SSH -> TunnelType.NOIZDNS_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
            MODE_NAIVE_SSH -> TunnelType.NAIVE_SSH
            MODE_NAIVE -> TunnelType.NAIVE
            MODE_SOCKS5 -> TunnelType.SOCKS5
            MODE_VAYDNS -> TunnelType.VAYDNS
            MODE_VAYDNS_SSH -> TunnelType.VAYDNS_SSH
            MODE_VLESS -> TunnelType.VLESS

            else -> {
                return ProfileParseResult.Warning("Line $lineNum: Unsupported tunnel type '$tunnelTypeStr', skipping")
            }
        }

        val name = fields[2]
        val domain = fields[3]
        val resolversStr = fields[4]
        val authMode = fields[5] == "1"
        val keepAlive = fields[6].toIntOrNull() ?: 5000
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
        if (resolvers.isEmpty() && tunnelType != TunnelType.SSH && tunnelType != TunnelType.DOH && tunnelType != TunnelType.SOCKS5 && tunnelType != TunnelType.VLESS) {
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
            MODE_NOIZDNS -> TunnelType.NOIZDNS
            MODE_NOIZDNS_SSH -> TunnelType.NOIZDNS_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
            MODE_NAIVE_SSH -> TunnelType.NAIVE_SSH
            MODE_NAIVE -> TunnelType.NAIVE
            MODE_SOCKS5 -> TunnelType.SOCKS5
            MODE_VAYDNS -> TunnelType.VAYDNS
            MODE_VAYDNS_SSH -> TunnelType.VAYDNS_SSH
            MODE_VLESS -> TunnelType.VLESS

            else -> {
                return ProfileParseResult.Warning("Line $lineNum: Unsupported tunnel type '$tunnelTypeStr', skipping")
            }
        }

        val name = fields[2]
        val domain = fields[3]
        val resolversStr = fields[4]
        val authMode = fields[5] == "1"
        val keepAlive = fields[6].toIntOrNull() ?: 5000
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
        if (resolvers.isEmpty() && tunnelType != TunnelType.SSH && tunnelType != TunnelType.DOH && tunnelType != TunnelType.SOCKS5 && tunnelType != TunnelType.VLESS) {
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
            MODE_NOIZDNS -> TunnelType.NOIZDNS
            MODE_NOIZDNS_SSH -> TunnelType.NOIZDNS_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
            MODE_NAIVE_SSH -> TunnelType.NAIVE_SSH
            MODE_NAIVE -> TunnelType.NAIVE
            MODE_SOCKS5 -> TunnelType.SOCKS5
            MODE_VAYDNS -> TunnelType.VAYDNS
            MODE_VAYDNS_SSH -> TunnelType.VAYDNS_SSH
            MODE_VLESS -> TunnelType.VLESS

            else -> {
                return ProfileParseResult.Warning("Line $lineNum: Unsupported tunnel type '$tunnelTypeStr', skipping")
            }
        }

        val name = fields[2]
        val domain = fields[3]
        val resolversStr = fields[4]
        val authMode = fields[5] == "1"
        val keepAlive = fields[6].toIntOrNull() ?: 5000
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
        // fields[20] was useServerDns — ignored (removed, now global setting)

        if (name.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Profile name is required")
        }
        if (domain.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Domain is required")
        }

        val resolvers = parseResolvers(resolversStr)
        if (resolvers.isEmpty() && tunnelType != TunnelType.SSH && tunnelType != TunnelType.DOH && tunnelType != TunnelType.SOCKS5 && tunnelType != TunnelType.VLESS) {
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

        if (tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.NOIZDNS_SSH || tunnelType == TunnelType.SLIPSTREAM_SSH || tunnelType == TunnelType.SSH || tunnelType == TunnelType.NAIVE_SSH) {
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
            MODE_NOIZDNS -> TunnelType.NOIZDNS
            MODE_NOIZDNS_SSH -> TunnelType.NOIZDNS_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
            MODE_NAIVE_SSH -> TunnelType.NAIVE_SSH
            MODE_NAIVE -> TunnelType.NAIVE
            MODE_SOCKS5 -> TunnelType.SOCKS5
            MODE_VAYDNS -> TunnelType.VAYDNS
            MODE_VAYDNS_SSH -> TunnelType.VAYDNS_SSH
            MODE_VLESS -> TunnelType.VLESS

            else -> {
                return ProfileParseResult.Warning("Line $lineNum: Unsupported tunnel type '$tunnelTypeStr', skipping")
            }
        }

        val name = fields[2]
        val domain = fields[3]
        val resolversStr = fields[4]
        val authMode = fields[5] == "1"
        val keepAlive = fields[6].toIntOrNull() ?: 5000
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
        // fields[20] was useServerDns — ignored (removed, now global setting)
        val dohUrl = fields[21]

        if (name.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Profile name is required")
        }
        if (tunnelType != TunnelType.DOH && tunnelType != TunnelType.SNOWFLAKE && domain.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Domain is required")
        }

        val resolvers = parseResolvers(resolversStr)
        if (resolvers.isEmpty() && tunnelType != TunnelType.SSH && tunnelType != TunnelType.DOH && tunnelType != TunnelType.SNOWFLAKE && tunnelType != TunnelType.SOCKS5 && tunnelType != TunnelType.VLESS) {
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

        if (tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.NOIZDNS_SSH || tunnelType == TunnelType.SLIPSTREAM_SSH || tunnelType == TunnelType.SSH || tunnelType == TunnelType.NAIVE_SSH) {
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
            MODE_NOIZDNS -> TunnelType.NOIZDNS
            MODE_NOIZDNS_SSH -> TunnelType.NOIZDNS_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
            MODE_NAIVE_SSH -> TunnelType.NAIVE_SSH
            MODE_NAIVE -> TunnelType.NAIVE
            MODE_SOCKS5 -> TunnelType.SOCKS5
            MODE_VAYDNS -> TunnelType.VAYDNS
            MODE_VAYDNS_SSH -> TunnelType.VAYDNS_SSH
            MODE_VLESS -> TunnelType.VLESS

            else -> {
                return ProfileParseResult.Warning("Line $lineNum: Unsupported tunnel type '$tunnelTypeStr', skipping")
            }
        }

        val name = fields[2]
        val domain = fields[3]
        val resolversStr = fields[4]
        val authMode = fields[5] == "1"
        val keepAlive = fields[6].toIntOrNull() ?: 5000
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
        // fields[20] was useServerDns — ignored (removed, now global setting)
        val dohUrl = fields[21]
        val dnsTransport = DnsTransport.fromValue(fields[22])

        if (name.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Profile name is required")
        }
        if (tunnelType != TunnelType.DOH && tunnelType != TunnelType.SNOWFLAKE && domain.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Domain is required")
        }

        val resolvers = parseResolvers(resolversStr)
        val isDnsttBased = tunnelType == TunnelType.DNSTT || tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.NOIZDNS || tunnelType == TunnelType.NOIZDNS_SSH
        val skipResolvers = tunnelType == TunnelType.SSH || tunnelType == TunnelType.DOH ||
                tunnelType == TunnelType.SNOWFLAKE || tunnelType == TunnelType.SOCKS5 ||
                tunnelType == TunnelType.VLESS ||
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

        if (tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.NOIZDNS_SSH || tunnelType == TunnelType.SLIPSTREAM_SSH || tunnelType == TunnelType.SSH || tunnelType == TunnelType.NAIVE_SSH) {
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
            MODE_NOIZDNS -> TunnelType.NOIZDNS
            MODE_NOIZDNS_SSH -> TunnelType.NOIZDNS_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
            MODE_NAIVE_SSH -> TunnelType.NAIVE_SSH
            MODE_NAIVE -> TunnelType.NAIVE
            MODE_SOCKS5 -> TunnelType.SOCKS5
            MODE_VAYDNS -> TunnelType.VAYDNS
            MODE_VAYDNS_SSH -> TunnelType.VAYDNS_SSH
            MODE_VLESS -> TunnelType.VLESS

            else -> {
                return ProfileParseResult.Warning("Line $lineNum: Unsupported tunnel type '$tunnelTypeStr', skipping")
            }
        }

        val name = fields[2]
        val domain = fields[3]
        val resolversStr = fields[4]
        val authMode = fields[5] == "1"
        val keepAlive = fields[6].toIntOrNull() ?: 5000
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
        // fields[20] was useServerDns — ignored (removed, now global setting)
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
        val isDnsttBased = tunnelType == TunnelType.DNSTT || tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.NOIZDNS || tunnelType == TunnelType.NOIZDNS_SSH
        val skipResolvers = tunnelType == TunnelType.SSH || tunnelType == TunnelType.DOH ||
                tunnelType == TunnelType.SNOWFLAKE || tunnelType == TunnelType.SOCKS5 ||
                tunnelType == TunnelType.VLESS ||
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

        if (tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.NOIZDNS_SSH || tunnelType == TunnelType.SLIPSTREAM_SSH || tunnelType == TunnelType.SSH || tunnelType == TunnelType.NAIVE_SSH) {
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
            MODE_NOIZDNS -> TunnelType.NOIZDNS
            MODE_NOIZDNS_SSH -> TunnelType.NOIZDNS_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
            MODE_NAIVE_SSH -> TunnelType.NAIVE_SSH
            MODE_NAIVE -> TunnelType.NAIVE
            MODE_SOCKS5 -> TunnelType.SOCKS5
            MODE_VAYDNS -> TunnelType.VAYDNS
            MODE_VAYDNS_SSH -> TunnelType.VAYDNS_SSH
            MODE_VLESS -> TunnelType.VLESS

            else -> {
                return ProfileParseResult.Warning("Line $lineNum: Unsupported tunnel type '$tunnelTypeStr', skipping")
            }
        }

        val name = fields[2]
        val domain = fields[3]
        val resolversStr = fields[4]
        val authMode = fields[5] == "1"
        val keepAlive = fields[6].toIntOrNull() ?: 5000
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
        // fields[20] was useServerDns — ignored (removed, now global setting)
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
        val isDnsttBased = tunnelType == TunnelType.DNSTT || tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.NOIZDNS || tunnelType == TunnelType.NOIZDNS_SSH
        val skipResolvers = tunnelType == TunnelType.SSH || tunnelType == TunnelType.DOH ||
                tunnelType == TunnelType.SNOWFLAKE || tunnelType == TunnelType.SOCKS5 ||
                tunnelType == TunnelType.VLESS ||
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

        if (tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.NOIZDNS_SSH || tunnelType == TunnelType.SLIPSTREAM_SSH || tunnelType == TunnelType.SSH || tunnelType == TunnelType.NAIVE_SSH) {
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
            dohUrl = dohUrl,
            dnsTransport = dnsTransport,
            sshAuthType = sshAuthType,
            sshPrivateKey = sshPrivateKey,
            sshKeyPassphrase = sshKeyPassphrase,
            torBridgeLines = torBridgeLines
        )

        return ProfileParseResult.Success(profile)
    }


    /**
     * Parse v13 profile format (extends v12 with reduced query rate).
     */
    private fun parseProfileV13(fields: List<String>, lineNum: Int): ProfileParseResult {
        if (fields.size < V13_FIELD_COUNT) {
            return ProfileParseResult.Error("Line $lineNum: Invalid v13 format (expected $V13_FIELD_COUNT fields, got ${fields.size})")
        }

        val tunnelTypeStr = fields[1]
        val tunnelType = when (tunnelTypeStr) {
            MODE_SLIPSTREAM -> TunnelType.SLIPSTREAM
            MODE_SLIPSTREAM_SSH -> TunnelType.SLIPSTREAM_SSH
            MODE_DNSTT -> TunnelType.DNSTT
            MODE_DNSTT_SSH -> TunnelType.DNSTT_SSH
            MODE_NOIZDNS -> TunnelType.NOIZDNS
            MODE_NOIZDNS_SSH -> TunnelType.NOIZDNS_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
            MODE_NAIVE_SSH -> TunnelType.NAIVE_SSH
            MODE_NAIVE -> TunnelType.NAIVE
            MODE_SOCKS5 -> TunnelType.SOCKS5
            MODE_VAYDNS -> TunnelType.VAYDNS
            MODE_VAYDNS_SSH -> TunnelType.VAYDNS_SSH
            MODE_VLESS -> TunnelType.VLESS

            else -> {
                return ProfileParseResult.Warning("Line $lineNum: Unsupported tunnel type '$tunnelTypeStr', skipping")
            }
        }

        val name = fields[2]
        val domain = fields[3]
        val resolversStr = fields[4]
        val authMode = fields[5] == "1"
        val keepAlive = fields[6].toIntOrNull() ?: 5000
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
        // fields[20] was useServerDns — ignored (removed, now global setting)
        val dohUrl = fields[21]
        val dnsTransport = DnsTransport.fromValue(fields[22])
        val sshAuthType = SshAuthType.fromValue(fields[23])
        val sshPrivateKey = try {
            String(Base64.decode(fields[24], Base64.NO_WRAP), Charsets.UTF_8)
        } catch (_: Exception) { "" }
        val sshKeyPassphrase = try {
            String(Base64.decode(fields[25], Base64.NO_WRAP), Charsets.UTF_8)
        } catch (_: Exception) { "" }
        val torBridgeLines = try {
            String(Base64.decode(fields[26], Base64.NO_WRAP), Charsets.UTF_8)
        } catch (_: Exception) { "" }

        // v13 new field: DNSTT authoritative mode
        val dnsttAuthoritative = fields[27] == "1"

        if (name.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Profile name is required")
        }
        if (tunnelType != TunnelType.DOH && tunnelType != TunnelType.SNOWFLAKE && domain.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Domain is required")
        }

        val resolvers = parseResolvers(resolversStr)
        val isDnsttBased = tunnelType == TunnelType.DNSTT || tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.NOIZDNS || tunnelType == TunnelType.NOIZDNS_SSH
        val skipResolvers = tunnelType == TunnelType.SSH || tunnelType == TunnelType.DOH ||
                tunnelType == TunnelType.SNOWFLAKE || tunnelType == TunnelType.SOCKS5 ||
                tunnelType == TunnelType.VLESS ||
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

        if (tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.NOIZDNS_SSH || tunnelType == TunnelType.SLIPSTREAM_SSH || tunnelType == TunnelType.SSH || tunnelType == TunnelType.NAIVE_SSH) {
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
            dohUrl = dohUrl,
            dnsTransport = dnsTransport,
            sshAuthType = sshAuthType,
            sshPrivateKey = sshPrivateKey,
            sshKeyPassphrase = sshKeyPassphrase,
            torBridgeLines = torBridgeLines,
            dnsttAuthoritative = dnsttAuthoritative
        )

        return ProfileParseResult.Success(profile)
    }

    /**
     * Parse v14 profile format (extends v13 with NaiveProxy fields).
     */
    private fun parseProfileV14(fields: List<String>, lineNum: Int): ProfileParseResult {
        if (fields.size < V14_FIELD_COUNT) {
            return ProfileParseResult.Error("Line $lineNum: Invalid v14 format (expected $V14_FIELD_COUNT fields, got ${fields.size})")
        }

        val tunnelTypeStr = fields[1]
        val tunnelType = when (tunnelTypeStr) {
            MODE_SLIPSTREAM -> TunnelType.SLIPSTREAM
            MODE_SLIPSTREAM_SSH -> TunnelType.SLIPSTREAM_SSH
            MODE_DNSTT -> TunnelType.DNSTT
            MODE_DNSTT_SSH -> TunnelType.DNSTT_SSH
            MODE_NOIZDNS -> TunnelType.NOIZDNS
            MODE_NOIZDNS_SSH -> TunnelType.NOIZDNS_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
            MODE_NAIVE_SSH -> TunnelType.NAIVE_SSH
            MODE_NAIVE -> TunnelType.NAIVE
            MODE_SOCKS5 -> TunnelType.SOCKS5
            MODE_VAYDNS -> TunnelType.VAYDNS
            MODE_VAYDNS_SSH -> TunnelType.VAYDNS_SSH
            MODE_VLESS -> TunnelType.VLESS

            else -> {
                return ProfileParseResult.Warning("Line $lineNum: Unsupported tunnel type '$tunnelTypeStr', skipping")
            }
        }

        val name = fields[2]
        val domain = fields[3]
        val resolversStr = fields[4]
        val authMode = fields[5] == "1"
        val keepAlive = fields[6].toIntOrNull() ?: 5000
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
        // fields[20] was useServerDns — ignored (removed, now global setting)
        val dohUrl = fields[21]
        val dnsTransport = DnsTransport.fromValue(fields[22])
        val sshAuthType = SshAuthType.fromValue(fields[23])
        val sshPrivateKey = try {
            String(Base64.decode(fields[24], Base64.NO_WRAP), Charsets.UTF_8)
        } catch (_: Exception) { "" }
        val sshKeyPassphrase = try {
            String(Base64.decode(fields[25], Base64.NO_WRAP), Charsets.UTF_8)
        } catch (_: Exception) { "" }
        val torBridgeLines = try {
            String(Base64.decode(fields[26], Base64.NO_WRAP), Charsets.UTF_8)
        } catch (_: Exception) { "" }
        val dnsttAuthoritative = fields[27] == "1"

        // v14 new fields: NaiveProxy
        val naivePort = fields[28].toIntOrNull() ?: 443
        val naiveUsername = fields[29]
        val naivePassword = try {
            String(Base64.decode(fields[30], Base64.NO_WRAP), Charsets.UTF_8)
        } catch (_: Exception) { "" }
        // fields[31] was naiveSni (removed) — ignored if present

        if (name.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Profile name is required")
        }
        if (tunnelType != TunnelType.DOH && tunnelType != TunnelType.SNOWFLAKE && domain.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Domain is required")
        }

        val resolvers = parseResolvers(resolversStr)
        val isDnsttBased = tunnelType == TunnelType.DNSTT || tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.NOIZDNS || tunnelType == TunnelType.NOIZDNS_SSH
        val skipResolvers = tunnelType == TunnelType.SSH || tunnelType == TunnelType.DOH ||
                tunnelType == TunnelType.SNOWFLAKE || tunnelType == TunnelType.SOCKS5 ||
                tunnelType == TunnelType.NAIVE_SSH || tunnelType == TunnelType.NAIVE ||
                tunnelType == TunnelType.VLESS ||
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

        if (tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.NOIZDNS_SSH || tunnelType == TunnelType.SLIPSTREAM_SSH || tunnelType == TunnelType.SSH || tunnelType == TunnelType.NAIVE_SSH) {
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

        // NaiveProxy validation
        if (tunnelType == TunnelType.NAIVE_SSH || tunnelType == TunnelType.NAIVE) {
            if (naiveUsername.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: NaiveProxy profiles require proxy username")
            }
            if (naivePassword.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: NaiveProxy profiles require proxy password")
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
            dohUrl = dohUrl,
            dnsTransport = dnsTransport,
            sshAuthType = sshAuthType,
            sshPrivateKey = sshPrivateKey,
            sshKeyPassphrase = sshKeyPassphrase,
            torBridgeLines = torBridgeLines,
            dnsttAuthoritative = dnsttAuthoritative,
            naivePort = naivePort,
            naiveUsername = naiveUsername,
            naivePassword = naivePassword
        )

        return ProfileParseResult.Success(profile)
    }

    private fun parseProfileV15(fields: List<String>, lineNum: Int): ProfileParseResult {
        if (fields.size < V15_FIELD_COUNT) {
            return ProfileParseResult.Error("Line $lineNum: Invalid v15 format (expected $V15_FIELD_COUNT fields, got ${fields.size})")
        }

        val tunnelTypeStr = fields[1]
        val tunnelType = when (tunnelTypeStr) {
            MODE_SLIPSTREAM -> TunnelType.SLIPSTREAM
            MODE_SLIPSTREAM_SSH -> TunnelType.SLIPSTREAM_SSH
            MODE_DNSTT -> TunnelType.DNSTT
            MODE_DNSTT_SSH -> TunnelType.DNSTT_SSH
            MODE_NOIZDNS -> TunnelType.NOIZDNS
            MODE_NOIZDNS_SSH -> TunnelType.NOIZDNS_SSH
            MODE_SSH -> TunnelType.SSH
            MODE_DOH -> TunnelType.DOH
            MODE_SNOWFLAKE -> TunnelType.SNOWFLAKE
            MODE_NAIVE_SSH -> TunnelType.NAIVE_SSH
            MODE_NAIVE -> TunnelType.NAIVE
            MODE_SOCKS5 -> TunnelType.SOCKS5
            MODE_VAYDNS -> TunnelType.VAYDNS
            MODE_VAYDNS_SSH -> TunnelType.VAYDNS_SSH
            MODE_VLESS -> TunnelType.VLESS

            else -> {
                return ProfileParseResult.Warning("Line $lineNum: Unsupported tunnel type '$tunnelTypeStr', skipping")
            }
        }

        val name = fields[2]
        val domain = fields[3]
        val resolversStr = fields[4]
        val authMode = fields[5] == "1"
        val keepAlive = fields[6].toIntOrNull() ?: 5000
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
        // fields[20] was useServerDns — ignored
        val dohUrl = fields[21]
        val dnsTransport = DnsTransport.fromValue(fields[22])
        val sshAuthType = SshAuthType.fromValue(fields[23])
        val sshPrivateKey = try {
            String(Base64.decode(fields[24], Base64.NO_WRAP), Charsets.UTF_8)
        } catch (_: Exception) { "" }
        val sshKeyPassphrase = try {
            String(Base64.decode(fields[25], Base64.NO_WRAP), Charsets.UTF_8)
        } catch (_: Exception) { "" }
        val torBridgeLines = try {
            String(Base64.decode(fields[26], Base64.NO_WRAP), Charsets.UTF_8)
        } catch (_: Exception) { "" }
        val dnsttAuthoritative = fields[27] == "1"
        val naivePort = fields[28].toIntOrNull() ?: 443
        val naiveUsername = fields[29]
        val naivePassword = try {
            String(Base64.decode(fields[30], Base64.NO_WRAP), Charsets.UTF_8)
        } catch (_: Exception) { "" }

        // v15 new fields: locked profile
        val isLocked = fields[31] == "1"
        val lockPasswordHash = fields[32]

        if (name.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Profile name is required")
        }
        if (tunnelType != TunnelType.DOH && tunnelType != TunnelType.SNOWFLAKE && domain.isBlank()) {
            return ProfileParseResult.Error("Line $lineNum: Domain is required")
        }

        val resolvers = parseResolvers(resolversStr)
        val isDnsttBased = tunnelType == TunnelType.DNSTT || tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.NOIZDNS || tunnelType == TunnelType.NOIZDNS_SSH
        val skipResolvers = tunnelType == TunnelType.SSH || tunnelType == TunnelType.DOH ||
                tunnelType == TunnelType.SNOWFLAKE || tunnelType == TunnelType.SOCKS5 ||
                tunnelType == TunnelType.NAIVE_SSH || tunnelType == TunnelType.NAIVE ||
                tunnelType == TunnelType.VLESS ||
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

        if (tunnelType == TunnelType.DNSTT_SSH || tunnelType == TunnelType.NOIZDNS_SSH || tunnelType == TunnelType.SLIPSTREAM_SSH || tunnelType == TunnelType.SSH || tunnelType == TunnelType.NAIVE_SSH) {
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

        if (tunnelType == TunnelType.NAIVE_SSH || tunnelType == TunnelType.NAIVE) {
            if (naiveUsername.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: NaiveProxy profiles require proxy username")
            }
            if (naivePassword.isBlank()) {
                return ProfileParseResult.Error("Line $lineNum: NaiveProxy profiles require proxy password")
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
            dohUrl = dohUrl,
            dnsTransport = dnsTransport,
            sshAuthType = sshAuthType,
            sshPrivateKey = sshPrivateKey,
            sshKeyPassphrase = sshKeyPassphrase,
            torBridgeLines = torBridgeLines,
            dnsttAuthoritative = dnsttAuthoritative,
            naivePort = naivePort,
            naiveUsername = naiveUsername,
            naivePassword = naivePassword,
            isLocked = isLocked,
            lockPasswordHash = lockPasswordHash
        )

        return ProfileParseResult.Success(profile)
    }

    private fun parseProfileV16(fields: List<String>, lineNum: Int): ProfileParseResult {
        // v16 extends v15 with 3 new fields; fall back to v15 parser for the base fields
        if (fields.size < V15_FIELD_COUNT) {
            return ProfileParseResult.Error("Line $lineNum: Invalid v16 format (expected at least $V15_FIELD_COUNT fields, got ${fields.size})")
        }

        // Parse the v15 base first
        val baseResult = parseProfileV15(fields, lineNum)
        if (baseResult !is ProfileParseResult.Success) return baseResult

        // Extract v16 fields (positions 33-35), defaulting if absent
        val expirationDate = if (fields.size > 33) fields[33].toLongOrNull() ?: 0L else 0L
        val allowSharing = if (fields.size > 34) fields[34] == "1" else false
        val boundDeviceId = if (fields.size > 35) fields[35] else ""

        val profile = baseResult.profile.copy(
            expirationDate = expirationDate,
            allowSharing = allowSharing,
            boundDeviceId = boundDeviceId
        )

        return ProfileParseResult.Success(profile)
    }

    private fun parseProfileV17(fields: List<String>, lineNum: Int): ProfileParseResult {
        // v17 extends v16 with 2 new fields; fall back to v16 parser for the base fields
        if (fields.size < V16_FIELD_COUNT) {
            return ProfileParseResult.Error("Line $lineNum: Invalid v17 format (expected at least $V16_FIELD_COUNT fields, got ${fields.size})")
        }

        // Extract v17 fields (positions 36-37), defaulting if absent
        val resolversHidden = if (fields.size > 36) fields[36] == "1" else false
        val hiddenResolversStr = if (fields.size > 37) fields[37] else ""

        // If resolvers are hidden, put the hidden resolvers into position 4 before parsing v16
        val effectiveFields = if (resolversHidden && hiddenResolversStr.isNotBlank()) {
            fields.toMutableList().also { it[4] = hiddenResolversStr }
        } else {
            fields
        }

        val baseResult = parseProfileV16(effectiveFields, lineNum)
        if (baseResult !is ProfileParseResult.Success) return baseResult

        val profile = baseResult.profile.copy(
            resolversHidden = resolversHidden,
            defaultResolvers = if (resolversHidden) baseResult.profile.resolvers else emptyList()
        )

        return ProfileParseResult.Success(profile)
    }

    private fun parseProfileV18(fields: List<String>, lineNum: Int): ProfileParseResult {
        // v18 extends v17 with 3 new fields; fall back to v17 parser for the base fields
        if (fields.size < V17_FIELD_COUNT) {
            return ProfileParseResult.Error("Line $lineNum: Invalid v18 format (expected at least $V17_FIELD_COUNT fields, got ${fields.size})")
        }

        val baseResult = parseProfileV17(fields, lineNum)
        if (baseResult !is ProfileParseResult.Success) return baseResult

        // Extract v18 fields (positions 38-40), defaulting if absent
        val noizdnsStealth = if (fields.size > 38) fields[38] == "1" else false
        val dnsPayloadSize = if (fields.size > 39) fields[39].toIntOrNull() ?: 0 else 0
        val socks5ServerPort = if (fields.size > 40) fields[40].toIntOrNull() ?: 1080 else 1080

        val profile = baseResult.profile.copy(
            noizdnsStealth = noizdnsStealth,
            dnsPayloadSize = dnsPayloadSize,
            socks5ServerPort = socks5ServerPort
        )

        return ProfileParseResult.Success(profile)
    }

    private fun parseProfileV19(fields: List<String>, lineNum: Int): ProfileParseResult {
        // v19 extends v18 with 3 new VayDNS fields; fall back to v18 parser for the base fields
        val baseResult = parseProfileV18(fields, lineNum)
        if (baseResult !is ProfileParseResult.Success) return baseResult

        // Extract v19 fields (positions 41-43), defaulting if absent
        val vaydnsDnsttCompat = if (fields.size > 41) fields[41] == "1" else false
        val vaydnsRecordType = if (fields.size > 42) fields[42].ifBlank { "txt" } else "txt"
        val vaydnsMaxQnameLen = if (fields.size > 43) fields[43].toIntOrNull() ?: 101 else 101
        val vaydnsRps = if (fields.size > 44) fields[44].toDoubleOrNull() ?: 0.0 else 0.0

        val profile = baseResult.profile.copy(
            vaydnsDnsttCompat = vaydnsDnsttCompat,
            vaydnsRecordType = vaydnsRecordType,
            vaydnsMaxQnameLen = vaydnsMaxQnameLen,
            vaydnsRps = vaydnsRps
        )

        return ProfileParseResult.Success(profile)
    }

    private fun parseProfileV20(fields: List<String>, lineNum: Int): ProfileParseResult {
        // v20 extends v19 with 5 new VayDNS advanced fields
        val baseResult = parseProfileV19(fields, lineNum)
        if (baseResult !is ProfileParseResult.Success) return baseResult

        // Extract v20 fields (positions 45-49), defaulting if absent
        val vaydnsIdleTimeout = if (fields.size > 45) fields[45].toIntOrNull() ?: 0 else 0
        val vaydnsKeepalive = if (fields.size > 46) fields[46].toIntOrNull() ?: 0 else 0
        val vaydnsUdpTimeout = if (fields.size > 47) fields[47].toIntOrNull() ?: 0 else 0
        val vaydnsMaxNumLabels = if (fields.size > 48) fields[48].toIntOrNull() ?: 0 else 0
        val vaydnsClientIdSize = if (fields.size > 49) fields[49].toIntOrNull() ?: 0 else 0

        val profile = baseResult.profile.copy(
            vaydnsIdleTimeout = vaydnsIdleTimeout,
            vaydnsKeepalive = vaydnsKeepalive,
            vaydnsUdpTimeout = vaydnsUdpTimeout,
            vaydnsMaxNumLabels = vaydnsMaxNumLabels,
            vaydnsClientIdSize = vaydnsClientIdSize
        )

        return ProfileParseResult.Success(profile)
    }

    private fun parseProfileV21(fields: List<String>, lineNum: Int): ProfileParseResult {
        // v21 extends v20 with SSH over TLS, HTTP CONNECT proxy, and WebSocket fields
        val baseResult = parseProfileV20(fields, lineNum)
        if (baseResult !is ProfileParseResult.Success) return baseResult

        // TLS + HTTP proxy fields (positions 50-54)
        val sshTlsEnabled = if (fields.size > 50) fields[50] == "1" else false
        val sshTlsSni = if (fields.size > 51) fields[51] else ""
        val sshHttpProxyHost = if (fields.size > 52) fields[52] else ""
        val sshHttpProxyPort = if (fields.size > 53) fields[53].toIntOrNull() ?: 8080 else 8080
        val sshHttpProxyCustomHost = if (fields.size > 54) fields[54] else ""

        // WebSocket fields (positions 55-58)
        val sshWsEnabled = if (fields.size > 55) fields[55] == "1" else false
        val sshWsPath = if (fields.size > 56) fields[56].ifBlank { "/" } else "/"
        val sshWsUseTls = if (fields.size > 57) fields[57] == "1" else true
        val sshWsCustomHost = if (fields.size > 58) fields[58] else ""

        val profile = baseResult.profile.copy(
            sshTlsEnabled = sshTlsEnabled,
            sshTlsSni = sshTlsSni,
            sshHttpProxyHost = sshHttpProxyHost,
            sshHttpProxyPort = sshHttpProxyPort,
            sshHttpProxyCustomHost = sshHttpProxyCustomHost,
            sshWsEnabled = sshWsEnabled,
            sshWsPath = sshWsPath,
            sshWsUseTls = sshWsUseTls,
            sshWsCustomHost = sshWsCustomHost
        )

        return ProfileParseResult.Success(profile)
    }

    private fun parseProfileV22(fields: List<String>, lineNum: Int): ProfileParseResult {
        // v22 extends v21 with SSH payload (raw prefix for DPI bypass)
        val baseResult = parseProfileV21(fields, lineNum)
        if (baseResult !is ProfileParseResult.Success) return baseResult

        // SSH payload (position 59, base64-encoded)
        val sshPayload = if (fields.size > 59) {
            try {
                String(android.util.Base64.decode(fields[59], android.util.Base64.NO_WRAP), Charsets.UTF_8)
            } catch (_: Exception) { "" }
        } else ""

        val profile = baseResult.profile.copy(
            sshPayload = sshPayload
        )

        return ProfileParseResult.Success(profile)
    }

    private fun parseProfileV23(fields: List<String>, lineNum: Int): ProfileParseResult {
        // v23 extends v22 with resolver mode (fanout/roundrobin)
        val baseResult = parseProfileV22(fields, lineNum)
        if (baseResult !is ProfileParseResult.Success) return baseResult

        // Resolver mode (position 60)
        val resolverMode = if (fields.size > 60) {
            ResolverMode.fromValue(fields[60])
        } else ResolverMode.FANOUT

        val profile = baseResult.profile.copy(
            resolverMode = resolverMode
        )

        return ProfileParseResult.Success(profile)
    }

    private fun parseProfileV24(fields: List<String>, lineNum: Int): ProfileParseResult {
        // v24 extends v23 with round-robin spread count
        val baseResult = parseProfileV23(fields, lineNum)
        if (baseResult !is ProfileParseResult.Success) return baseResult

        // RR spread count (position 61)
        val rrSpreadCount = if (fields.size > 61) {
            fields[61].toIntOrNull()?.coerceIn(1, 5) ?: 3
        } else 3

        val profile = baseResult.profile.copy(
            rrSpreadCount = rrSpreadCount
        )

        return ProfileParseResult.Success(profile)
    }

    /**
     * Parse a standard VLESS URI:
     * vless://uuid@server:port?type=ws&security=tls&path=/ws&host=domain&sni=domain&fp=chrome#name
     *
     * Supported query params:
     * - type: transport type (ws, tcp, grpc) — only ws is supported
     * - security: tls, none
     * - path: WebSocket path
     * - host: WebSocket Host header / TLS SNI
     * - sni: TLS SNI (overrides host for SNI)
     * - headerType: (ignored)
     * - fp: fingerprint (ignored)
     * - fragment: comma-separated fragment settings (e.g., "100,sni_split")
     * - cdn: CDN IP override
     * - cdn-port: CDN port override
     *
     * Fragment after # is the profile name.
     */
    private fun parseVlessUri(uri: String, lineNum: Int): ProfileParseResult {
        try {
            // Strip scheme
            val withoutScheme = uri.removePrefix("vless://").removePrefix("VLESS://")

            // Split fragment (profile name)
            val (mainPart, profileName) = if ('#' in withoutScheme) {
                val idx = withoutScheme.indexOf('#')
                withoutScheme.substring(0, idx) to java.net.URLDecoder.decode(withoutScheme.substring(idx + 1), "UTF-8")
            } else {
                withoutScheme to "VLESS"
            }

            // Split userinfo@host:port?params
            val atIdx = mainPart.indexOf('@')
            if (atIdx < 0) return ProfileParseResult.Error("Line $lineNum: Invalid VLESS URI — missing UUID")
            val uuid = mainPart.substring(0, atIdx)

            val afterAt = mainPart.substring(atIdx + 1)
            val queryIdx = afterAt.indexOf('?')
            val hostPort = if (queryIdx >= 0) afterAt.substring(0, queryIdx) else afterAt
            val queryString = if (queryIdx >= 0) afterAt.substring(queryIdx + 1) else ""

            // Parse host:port (handle bracketed IPv6 like [::1]:443)
            val server: String
            val port: Int
            if (hostPort.startsWith('[')) {
                val closeBracket = hostPort.indexOf(']')
                if (closeBracket < 0) return ProfileParseResult.Error("Line $lineNum: Invalid IPv6 address in VLESS URI")
                server = hostPort.substring(1, closeBracket)
                port = if (closeBracket + 1 < hostPort.length && hostPort[closeBracket + 1] == ':') {
                    hostPort.substring(closeBracket + 2).toIntOrNull() ?: 443
                } else 443
            } else {
                val colonIdx = hostPort.lastIndexOf(':')
                if (colonIdx > 0 && hostPort.indexOf(':') == colonIdx) {
                    // Single colon — host:port
                    server = hostPort.substring(0, colonIdx)
                    port = hostPort.substring(colonIdx + 1).toIntOrNull() ?: 443
                } else {
                    server = hostPort
                    port = 443
                }
            }

            // Parse query params
            val params = mutableMapOf<String, String>()
            if (queryString.isNotBlank()) {
                queryString.split('&').forEach { param ->
                    val eqIdx = param.indexOf('=')
                    if (eqIdx > 0) {
                        val key = param.substring(0, eqIdx)
                        val value = java.net.URLDecoder.decode(param.substring(eqIdx + 1), "UTF-8")
                        params[key] = value
                    }
                }
            }

            val transport = params["type"] ?: "tcp"
            val security = params["security"] ?: "tls"
            val wsPath = params["path"] ?: "/"
            val wsHost = params["host"] ?: server
            val sni = params["sni"] ?: wsHost
            val cdnIp = params["cdn"] ?: server
            val cdnPort = params["cdn-port"]?.toIntOrNull() ?: port

            // Fragment settings from query params (optional). Default ON with
            // the strong DPI-evasion preset so pasted VLESS URIs are usable on
            // restrictive networks out of the box. Users can disable or
            // downgrade in the editor. The URI can override each field
            // explicitly via `fragment=<delay>,<strategy>`.
            val fragmentParam = params["fragment"]
            val fragmentEnabled = if (fragmentParam != null) fragmentParam.isNotBlank() else true
            val fragmentParts = (fragmentParam ?: "").split(',')
            val fragmentDelay = fragmentParts.getOrNull(0)?.toIntOrNull() ?: 300
            val fragmentStrategy = fragmentParts.getOrNull(1)?.takeIf { it in listOf("sni_split", "half", "multi", "micro", "fake", "disorder") } ?: "micro"

            val normalizedTransport = when (transport) {
                "ws", "websocket" -> "ws"
                "tcp", "raw" -> "tcp"
                else -> return ProfileParseResult.Warning("Line $lineNum: Only VLESS over WebSocket is supported — '$transport' transport is not available")
            }

            // Only WebSocket transport is supported.
            if (normalizedTransport != "ws") {
                return ProfileParseResult.Warning("Line $lineNum: Only VLESS over WebSocket is supported — this config uses '$transport' transport")
            }

            val normalizedSecurity = when (security) {
                "tls", "reality" -> "tls"
                "none", "" -> "none"
                else -> "tls"
            }

            // Validate UUID
            val hexUuid = uuid.replace("-", "")
            if (hexUuid.length != 32 || !hexUuid.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
                return ProfileParseResult.Error("Line $lineNum: Invalid VLESS UUID")
            }

            // domain  = WS Host header (routing hostname, used as SNI when vlessSni is empty)
            // vlessSni = explicit TLS SNI — only stored when the URI's sni=
            //            differs from host= (legitimate CDN setups where the
            //            cert hostname ≠ the origin routing hostname, or a
            //            DPI-evasion decoy on direct servers).
            val profile = ServerProfile(
                name = profileName,
                domain = wsHost,
                tunnelType = TunnelType.VLESS,
                vlessUuid = uuid,
                vlessSecurity = normalizedSecurity,
                vlessTransport = normalizedTransport,
                vlessWsPath = wsPath,
                cdnIp = cdnIp,
                cdnPort = cdnPort,
                sniFragmentEnabled = fragmentEnabled,
                sniFragmentStrategy = fragmentStrategy,
                sniFragmentDelayMs = fragmentDelay,
                vlessSni = if (sni != wsHost) sni else ""
            )

            return ProfileParseResult.Success(profile)
        } catch (e: Exception) {
            return ProfileParseResult.Error("Line $lineNum: Failed to parse VLESS URI: ${e.message}")
        }
    }

    private fun parseProfileV25(fields: List<String>, lineNum: Int): ProfileParseResult {
        // v25 extends v24 with VLESS + SNI fragmentation fields
        val baseResult = parseProfileV24(fields, lineNum)
        if (baseResult !is ProfileParseResult.Success) return baseResult

        // VLESS UUID (position 62)
        val vlessUuid = if (fields.size > 62) fields[62] else ""
        // VLESS security (position 63)
        val vlessSecurity = if (fields.size > 63 && fields[63].isNotBlank()) fields[63] else "tls"
        // VLESS transport (position 64)
        val vlessTransport = if (fields.size > 64 && fields[64].isNotBlank()) fields[64] else "ws"
        // VLESS WebSocket path (position 65)
        val vlessWsPath = if (fields.size > 65 && fields[65].isNotBlank()) fields[65] else "/"
        // CDN IP (position 66)
        val cdnIp = if (fields.size > 66) fields[66] else ""
        // CDN port (position 67)
        val cdnPort = if (fields.size > 67) fields[67].toIntOrNull() ?: 443 else 443
        // SNI fragment enabled (position 68)
        val sniFragmentEnabled = if (fields.size > 68) fields[68] == "1" else true
        // SNI fragment strategy (position 69)
        val sniFragmentStrategy = if (fields.size > 69 && fields[69].isNotBlank()) fields[69] else "sni_split"
        // SNI fragment delay (position 70)
        val sniFragmentDelayMs = if (fields.size > 70) fields[70].toIntOrNull() ?: 100 else 100
        // Legacy "fake SNI" field (position 71). v25–v27 used one SNI field
        // that got overloaded by the URI importer — any sni= that differed
        // from host= was stuffed here. Map it to the single vlessSni going
        // forward. Only VLESS profiles ever populated position 71, so this is
        // a no-op for other tunnel types.
        val legacyFakeSni = if (fields.size > 71) fields[71] else ""

        val profile = baseResult.profile.copy(
            vlessUuid = vlessUuid,
            vlessSecurity = vlessSecurity,
            vlessTransport = vlessTransport,
            vlessWsPath = vlessWsPath,
            cdnIp = cdnIp,
            cdnPort = cdnPort,
            sniFragmentEnabled = sniFragmentEnabled,
            sniFragmentStrategy = sniFragmentStrategy,
            sniFragmentDelayMs = sniFragmentDelayMs,
            vlessSni = legacyFakeSni
        )

        return ProfileParseResult.Success(profile)
    }

    // v26 extends v25 with DPI evasion options
    private fun parseProfileV26(fields: List<String>, lineNum: Int): ProfileParseResult {
        val baseResult = parseProfileV25(fields, lineNum)
        if (baseResult !is ProfileParseResult.Success) return baseResult

        // ClientHello padding (position 72)
        val chPaddingEnabled = if (fields.size > 72) fields[72] == "1" else false
        // WS header obfuscation (position 73)
        val wsHeaderObfuscation = if (fields.size > 73) fields[73] == "1" else false
        // WS cover traffic (position 74)
        val wsPaddingEnabled = if (fields.size > 74) fields[74] == "1" else false

        // SNI spoof TTL for fake/disorder strategies (position 75)
        val sniSpoofTtl = if (fields.size > 75) fields[75].toIntOrNull()?.coerceIn(1, 64) ?: 8 else 8

        val profile = baseResult.profile.copy(
            chPaddingEnabled = chPaddingEnabled,
            wsHeaderObfuscation = wsHeaderObfuscation,
            wsPaddingEnabled = wsPaddingEnabled,
            sniSpoofTtl = sniSpoofTtl
        )

        return ProfileParseResult.Success(profile)
    }

    // v27 extends v26 with the decoy hostname used in the `fake` fragment strategy
    // and the optional TCP MSS override on the CDN socket.
    private fun parseProfileV27(fields: List<String>, lineNum: Int): ProfileParseResult {
        val baseResult = parseProfileV26(fields, lineNum)
        if (baseResult !is ProfileParseResult.Success) return baseResult

        // Decoy hostname for `fake` strategy (position 76, empty = built-in default)
        val fakeDecoyHost = if (fields.size > 76) fields[76] else ""

        // TCP MSS override on CDN socket (position 77).
        // 0 = auto, 40..1400 = explicit cap, < 0 = force-disable. Anything else coerced to 0.
        val tcpMaxSeg = if (fields.size > 77) {
            val raw = fields[77].toIntOrNull() ?: 0
            when {
                raw == 0 -> 0
                raw < 0 -> -1
                else -> raw.coerceIn(40, 1400)
            }
        } else 0

        val profile = baseResult.profile.copy(
            fakeDecoyHost = fakeDecoyHost,
            tcpMaxSeg = tcpMaxSeg
        )
        return ProfileParseResult.Success(profile)
    }

    // v28 moves the SNI to a dedicated trailing field (position 78) so legacy
    // position 71 (the old conflated "fake SNI" slot) is deprecated. When
    // present, position 78 wins over anything parseProfileV25 pulled from
    // position 71. Older exports without field 78 keep working via v25's
    // legacy mapping.
    private fun parseProfileV28(fields: List<String>, lineNum: Int): ProfileParseResult {
        val baseResult = parseProfileV27(fields, lineNum)
        if (baseResult !is ProfileParseResult.Success) return baseResult

        return if (fields.size > 78) {
            ProfileParseResult.Success(baseResult.profile.copy(vlessSni = fields[78]))
        } else {
            baseResult
        }
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
