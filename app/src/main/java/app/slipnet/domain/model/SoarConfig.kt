package app.slipnet.domain.model

import android.util.Base64

/**
 * Shared Soar tunnel settings and validation (profile editor and config import).
 *
 * Soar (github.com/getlantern/soar) authenticates its server with an Ed25519
 * key. `soar-server pubkey` prints it as base64; hex is accepted too.
 */
object SoarConfig {
    const val TCP_AUTO = "auto"
    const val TCP_ON = "on"
    const val TCP_ONLY = "only"
    const val TCP_OFF = "off"

    /** TCP/53 path modes, in the order the editor shows them. */
    val TCP_MODES = listOf(TCP_AUTO, TCP_ON, TCP_ONLY, TCP_OFF)

    /** Countries with bundled resolver lists in Soar ("" = global list only). */
    val DISCOVERY_COUNTRIES = listOf("", "IR", "RU", "CN")

    /** Discovery candidates: Soar's bundled lists, the app's resolver list, or the profile's own. */
    const val LIST_SOAR = "soar"
    const val LIST_APP = "app"
    const val LIST_CUSTOM = "custom"

    /** Discovery lists, in the order the editor shows them. */
    val DISCOVERY_LISTS = listOf(LIST_SOAR, LIST_APP, LIST_CUSTOM)

    /** Most entries a custom discovery list may hold (it is stored and exported with the profile). */
    const val MAX_CUSTOM_CANDIDATES = 5000

    private const val KEY_SIZE = 32

    fun normalizeTcpMode(mode: String): String =
        mode.trim().lowercase().takeIf { it in TCP_MODES } ?: TCP_AUTO

    fun normalizeCountry(country: String): String =
        country.trim().uppercase().takeIf { it.length == 2 && it.all { c -> c in 'A'..'Z' } } ?: ""

    fun normalizeDiscoveryList(list: String): String =
        list.trim().lowercase().takeIf { it in DISCOVERY_LISTS } ?: LIST_SOAR

    /** Splits a custom discovery list (commas, spaces or new lines) into distinct entries. */
    fun splitCandidates(text: String): List<String> =
        text.split(',', ' ', '\t', '\r', '\n').map { it.trim() }.filter { it.isNotEmpty() }.distinct()

    /** Stored form of a custom discovery list: distinct entries, comma-separated. */
    fun normalizeCandidates(text: String): String = splitCandidates(text).joinToString(",")

    /** Returns an error message, or null if [text] is a usable custom discovery list. */
    fun validateCandidates(text: String): String? {
        val entries = splitCandidates(text)
        if (entries.isEmpty()) return "Add at least one resolver to the custom list"
        if (entries.size > MAX_CUSTOM_CANDIDATES) {
            return "Custom list can hold at most $MAX_CUSTOM_CANDIDATES resolvers"
        }
        entries.firstOrNull { !isIpCandidate(it) }?.let {
            return "\"$it\" is not an IP address (use IP or IP:port)"
        }
        return null
    }

    /**
     * Soar takes "ip" or "ip:port" ("[v6]:port" for IPv6) and can't resolve
     * hostnames on Android. IPv6 is only checked for its characters; Soar
     * skips any it can't parse.
     */
    private fun isIpCandidate(entry: String): Boolean {
        if (entry.startsWith("[")) {
            val end = entry.indexOf(']')
            if (end < 0) return false
            val rest = entry.substring(end + 1)
            return isIpv6(entry.substring(1, end)) &&
                (rest.isEmpty() || (rest.startsWith(":") && isPort(rest.substring(1))))
        }
        if (entry.count { it == ':' } > 1) return isIpv6(entry)
        val host = entry.substringBefore(':')
        return isIpv4(host) && (!entry.contains(':') || isPort(entry.substringAfter(':')))
    }

    private fun isIpv4(s: String): Boolean {
        val parts = s.split('.')
        return parts.size == 4 && parts.all { p ->
            p.isNotEmpty() && p.length <= 3 && p.all { it.isDigit() } && p.toInt() <= 255
        }
    }

    private fun isIpv6(s: String): Boolean =
        s.count { it == ':' } >= 2 && s.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }

    private fun isPort(s: String): Boolean = s.toIntOrNull()?.let { it in 1..65535 } ?: false

    /** Returns an error message, or null if [key] is a valid Soar server public key. */
    fun validatePublicKey(key: String): String? {
        val trimmed = key.trim()
        if (trimmed.isEmpty()) return "Soar profiles require the server public key"
        if (decodePublicKey(trimmed) == null) {
            return "Public key must be the 32-byte Ed25519 key from `soar-server pubkey` (base64 or hex)"
        }
        return null
    }

    private fun decodePublicKey(key: String): ByteArray? {
        if (key.length == KEY_SIZE * 2 && key.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
            return key.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        }
        for (flags in intArrayOf(Base64.NO_WRAP, Base64.NO_WRAP or Base64.URL_SAFE)) {
            val bytes = try {
                Base64.decode(key, flags)
            } catch (_: IllegalArgumentException) {
                null
            }
            if (bytes != null && bytes.size == KEY_SIZE) return bytes
        }
        return null
    }
}
