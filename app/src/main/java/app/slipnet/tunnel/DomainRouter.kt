package app.slipnet.tunnel

import android.content.Context
import app.slipnet.util.AppLog as Log
import app.slipnet.data.local.datastore.DomainRoutingMode
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Country codes for geo-bypass routing.
 */
enum class GeoBypassCountry(val code: String, val displayName: String) {
    IR("ir", "Iran"),
    CN("cn", "China"),
    RU("ru", "Russia");

    companion object {
        fun fromCode(code: String): GeoBypassCountry {
            return entries.find { it.code == code } ?: IR
        }
    }
}

/**
 * Loaded geo-bypass data: sorted CIDR ranges + domestic domain set.
 */
class GeoBypassData(
    val ipRangeStarts: LongArray,
    val ipRangeEnds: LongArray,
    val domains: Set<String>
) {
    companion object {
        val EMPTY = GeoBypassData(LongArray(0), LongArray(0), emptySet())
    }
}

/**
 * Decides whether a connection should bypass the VPN tunnel based on domain name,
 * geo-bypass CIDR ranges, and geo-bypass domestic domain lists.
 * Used in conjunction with [ProtocolSniffer] to implement domain-based routing.
 */
class DomainRouter(
    val enabled: Boolean,
    private val mode: DomainRoutingMode,
    private val domains: Set<String>,
    private val geoBypassEnabled: Boolean = false,
    private val geoBypass: GeoBypassData = GeoBypassData.EMPTY
) {
    companion object {
        private const val TAG = "DomainRouter"
        private const val DIRECT_CONNECT_TIMEOUT_MS = 10_000

        val DISABLED = DomainRouter(
            enabled = false,
            mode = DomainRoutingMode.BYPASS,
            domains = emptySet(),
            geoBypassEnabled = false,
            geoBypass = GeoBypassData.EMPTY
        )

        /**
         * Check if [host] is an IP address literal (IPv4 or IPv6).
         */
        fun isIpAddress(host: String): Boolean {
            // IPv4: digits and dots only
            if (host.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))) return true
            // IPv6: contains colons
            if (host.contains(':')) return true
            return false
        }

        /**
         * Load geo-bypass data (CIDR ranges + domain list) from assets for the given country.
         */
        fun loadGeoData(context: Context, country: GeoBypassCountry): GeoBypassData {
            val starts = mutableListOf<Long>()
            val ends = mutableListOf<Long>()
            val domains = mutableSetOf<String>()

            // Load CIDR ranges
            try {
                context.assets.open("geo/${country.code}.cidr").use { stream ->
                    BufferedReader(InputStreamReader(stream)).use { reader ->
                        reader.forEachLine { line ->
                            val trimmed = line.trim()
                            if (trimmed.isNotEmpty()) {
                                val range = parseCidr(trimmed)
                                if (range != null) {
                                    starts.add(range.first)
                                    ends.add(range.second)
                                }
                            }
                        }
                    }
                }
                Log.i(TAG, "Loaded ${starts.size} CIDR ranges for ${country.displayName}")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load CIDR ranges for ${country.code}: ${e.message}")
            }

            // Load domain list
            try {
                context.assets.open("geo/${country.code}.domains").use { stream ->
                    BufferedReader(InputStreamReader(stream)).use { reader ->
                        reader.forEachLine { line ->
                            val trimmed = line.trim().lowercase()
                            if (trimmed.isNotEmpty()) {
                                domains.add(trimmed)
                            }
                        }
                    }
                }
                Log.i(TAG, "Loaded ${domains.size} domains for ${country.displayName}")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load domains for ${country.code}: ${e.message}")
            }

            // Sort ranges by start IP for binary search
            val indices = starts.indices.sortedBy { starts[it] }
            val sortedStarts = LongArray(indices.size) { starts[indices[it]] }
            val sortedEnds = LongArray(indices.size) { ends[indices[it]] }

            return GeoBypassData(sortedStarts, sortedEnds, domains)
        }

        /**
         * Parse a CIDR notation string (e.g., "192.168.1.0/24") into a start/end IP range.
         * Returns null if parsing fails.
         */
        internal fun parseCidr(cidr: String): Pair<Long, Long>? {
            val parts = cidr.split('/')
            if (parts.size != 2) return null
            val ip = ipToLong(parts[0]) ?: return null
            val prefix = parts[1].toIntOrNull() ?: return null
            if (prefix < 0 || prefix > 32) return null
            val mask = if (prefix == 0) 0L else (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
            val start = ip and mask
            val end = start or (mask.inv() and 0xFFFFFFFFL)
            return start to end
        }

        /**
         * Convert an IPv4 address string to a Long.
         */
        internal fun ipToLong(ip: String): Long? {
            val octets = ip.split('.')
            if (octets.size != 4) return null
            var result = 0L
            for (octet in octets) {
                val value = octet.toIntOrNull() ?: return null
                if (value < 0 || value > 255) return null
                result = (result shl 8) or value.toLong()
            }
            return result
        }
    }

    /**
     * Determine whether traffic to [host] should bypass the VPN tunnel.
     *
     * Checks in order:
     * 1. Domain routing rules (BYPASS / ONLY_VPN mode)
     * 2. Geo-bypass: domestic domain suffix match
     * 3. Geo-bypass: IP address CIDR range match (binary search)
     */
    fun shouldBypass(host: String): Boolean {
        // Check domain routing rules first
        if (enabled && domains.isNotEmpty()) {
            val matches = domainMatchesList(host)
            val domainResult = when (mode) {
                DomainRoutingMode.BYPASS -> matches
                DomainRoutingMode.ONLY_VPN -> !matches
            }
            if (domainResult) return true
        }

        // Check geo-bypass
        if (geoBypassEnabled) {
            // Check domestic domain list
            if (!isIpAddress(host) && geoBypassDomainMatch(host)) {
                Log.d(TAG, "Geo-bypass domain match: $host")
                return true
            }
            // Check IP ranges
            if (isIpAddress(host) && !host.contains(':')) {
                val ipLong = ipToLong(host)
                if (ipLong != null && ipInRanges(ipLong)) {
                    Log.d(TAG, "Geo-bypass IP match: $host")
                    return true
                }
            }
        }

        return false
    }

    /**
     * Create a direct TCP connection bypassing the tunnel.
     * Relies on addDisallowedApplication (app is excluded from VPN) so the socket
     * automatically goes direct without needing protect().
     */
    fun createDirectConnection(host: String, port: Int, timeoutMs: Int = DIRECT_CONNECT_TIMEOUT_MS): Socket {
        val socket = Socket()
        socket.connect(InetSocketAddress(host, port), timeoutMs)
        socket.tcpNoDelay = true
        Log.d(TAG, "Direct connection to $host:$port established")
        return socket
    }

    private fun domainMatchesList(input: String): Boolean {
        val normalizedInput = input.lowercase().trimEnd('.')
        return domains.any { rule ->
            val normalizedRule = rule.lowercase().trimEnd('.')
            normalizedInput == normalizedRule || normalizedInput.endsWith(".$normalizedRule")
        }
    }

    /**
     * Suffix-match against geo-bypass domain list.
     * Handles both TLD entries (e.g., ".ir") and full domains (e.g., "digikala.com").
     */
    private fun geoBypassDomainMatch(host: String): Boolean {
        val normalized = host.lowercase().trimEnd('.')
        return geoBypass.domains.any { rule ->
            val normalizedRule = rule.trimEnd('.')
            if (normalizedRule.startsWith('.')) {
                // TLD rule: ".ir" matches "example.ir" and "sub.example.ir"
                normalized.endsWith(normalizedRule) || normalized == normalizedRule.removePrefix(".")
            } else {
                normalized == normalizedRule || normalized.endsWith(".$normalizedRule")
            }
        }
    }

    /**
     * Binary search to check if an IP address falls within any of the CIDR ranges.
     * Ranges must be sorted by start IP.
     */
    private fun ipInRanges(ip: Long): Boolean {
        val starts = geoBypass.ipRangeStarts
        val ends = geoBypass.ipRangeEnds
        if (starts.isEmpty()) return false

        // Binary search: find the last range whose start <= ip
        var low = 0
        var high = starts.size - 1
        var result = -1
        while (low <= high) {
            val mid = (low + high) ushr 1
            if (starts[mid] <= ip) {
                result = mid
                low = mid + 1
            } else {
                high = mid - 1
            }
        }
        // Check if ip falls within the found range
        return result >= 0 && ip <= ends[result]
    }
}
