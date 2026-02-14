package app.slipnet.tunnel

import android.util.Log
import app.slipnet.data.local.datastore.DomainRoutingMode
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Decides whether a connection should bypass the VPN tunnel based on domain name.
 * Used in conjunction with [ProtocolSniffer] to implement domain-based routing.
 */
class DomainRouter(
    val enabled: Boolean,
    private val mode: DomainRoutingMode,
    private val domains: Set<String>
) {
    companion object {
        private const val TAG = "DomainRouter"
        private const val DIRECT_CONNECT_TIMEOUT_MS = 10_000

        val DISABLED = DomainRouter(enabled = false, mode = DomainRoutingMode.BYPASS, domains = emptySet())

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
    }

    /**
     * Determine whether traffic to [domain] should bypass the VPN tunnel.
     *
     * - BYPASS mode: returns true if domain matches the list (listed domains go direct)
     * - ONLY_VPN mode: returns true if domain does NOT match the list (only listed domains use VPN)
     *
     * Domain matching is suffix-based: rule "google.com" matches "www.google.com".
     */
    fun shouldBypass(domain: String): Boolean {
        if (!enabled || domains.isEmpty()) return false

        val matches = domainMatchesList(domain)
        return when (mode) {
            DomainRoutingMode.BYPASS -> matches
            DomainRoutingMode.ONLY_VPN -> !matches
        }
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
}
