package app.slipnet.domain.model

import app.slipnet.BuildConfig

data class ServerProfile(
    val id: Long = 0,
    val name: String,
    val domain: String = "",
    val resolvers: List<DnsResolver> = emptyList(),
    val authoritativeMode: Boolean = false,
    val keepAliveInterval: Int = 5000,
    val congestionControl: CongestionControl = CongestionControl.BBR,
    val gsoEnabled: Boolean = false,
    val tcpListenPort: Int = 1080,
    val tcpListenHost: String = "127.0.0.1",
    val socksUsername: String? = null,
    val socksPassword: String? = null,
    val isActive: Boolean = false,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
    // Tunnel type selection (DNSTT is more stable)
    val tunnelType: TunnelType = TunnelType.DNSTT,
    // DNSTT-specific fields
    val dnsttPublicKey: String = "",
    // SSH tunnel fields (used for SSH-only and DNSTT+SSH tunnel types)
    val sshUsername: String = "",
    val sshPassword: String = "",
    val sshPort: Int = 22,
    // SSH host as seen from DNSTT server (for DNSTT+SSH, default 127.0.0.1 for co-located servers)
    val sshHost: String = "127.0.0.1",
    // DoH (DNS over HTTPS) server URL
    val dohUrl: String = "",
    // Timestamp of last successful connection (0 = never connected)
    val lastConnectedAt: Long = 0,
    // DNS transport for DNSTT tunnel types (UDP, DoH, DoT)
    val dnsTransport: DnsTransport = DnsTransport.UDP,
    // SSH authentication type (password or key)
    val sshAuthType: SshAuthType = SshAuthType.PASSWORD,
    // SSH private key (PEM content)
    val sshPrivateKey: String = "",
    // SSH key passphrase (optional)
    val sshKeyPassphrase: String = "",
    // Custom Tor bridge lines (one per line). Empty = use built-in Snowflake.
    // Transport is auto-detected from bridge line prefix (obfs4, webtunnel, meek_lite, etc.)
    val torBridgeLines: String = "",
    // User-defined sort order for profile list (lower = higher in list)
    val sortOrder: Int = 0,
    // When true, DNSTT uses aggressive query rates (authoritative mode for own servers)
    val dnsttAuthoritative: Boolean = false,
    // NaiveProxy fields (NAIVE_SSH tunnel type)
    val naivePort: Int = 443,
    val naiveUsername: String = "",
    val naivePassword: String = "",
    // Locked profile (UI-level only — full data stays in DB for VPN service)
    val isLocked: Boolean = false,
    val lockPasswordHash: String = "",
    // Locked profile enhancements (v16)
    val expirationDate: Long = 0,
    val allowSharing: Boolean = false,
    val boundDeviceId: String = "",
    // NoizDNS stealth mode: trades speed for DPI resistance (jitter, slow polling, cover traffic)
    val noizdnsStealth: Boolean = false,
    // DNS query payload size cap (KCP MTU). 0 = full capacity (default).
    // Lower values produce smaller, less conspicuous DNS queries.
    val dnsPayloadSize: Int = 0,
    // When true, resolvers are hidden from the user (set during import of hidden-resolver profiles)
    val resolversHidden: Boolean = false,
    // SOCKS5 proxy server port (for SOCKS5 tunnel type)
    val socks5ServerPort: Int = 1080
) {
    val isExpired: Boolean get() = expirationDate > 0 && System.currentTimeMillis() > expirationDate
}

data class DnsResolver(
    val host: String,
    val port: Int = 53,
    val authoritative: Boolean = false
)

enum class CongestionControl(val value: String) {
    BBR("bbr"),
    DCUBIC("dcubic");

    companion object {
        fun fromValue(value: String): CongestionControl {
            return entries.find { it.value == value } ?: BBR
        }
    }
}

enum class TunnelType(val value: String, val displayName: String) {
    SLIPSTREAM("slipstream", "Slipstream"),
    SLIPSTREAM_SSH("slipstream_ssh", "Slipstream + SSH"),
    DNSTT("dnstt", "DNSTT"),
    DNSTT_SSH("dnstt_ssh", "DNSTT + SSH"),
    NOIZDNS("sayedns", "NoizDNS"),
    NOIZDNS_SSH("sayedns_ssh", "NoizDNS + SSH"),
    SSH("ssh", "SSH"),
    DOH("doh", "DOH (DNS over HTTPS)"),
    SNOWFLAKE("snowflake", "Tor"),
    NAIVE_SSH("naive_ssh", "NaiveProxy + SSH"),
    NAIVE("naive", "NaiveProxy"),
    SOCKS5("socks5", "SOCKS5 Proxy");

    companion object {
        fun fromValue(value: String): TunnelType {
            return entries.find { it.value == value } ?: DNSTT
        }
    }
}

fun TunnelType.isAvailable(): Boolean = when (this) {
    TunnelType.SNOWFLAKE -> BuildConfig.INCLUDE_TOR
    TunnelType.NAIVE, TunnelType.NAIVE_SSH -> BuildConfig.INCLUDE_NAIVE
    else -> true
}

enum class SshAuthType(val value: String) {
    PASSWORD("password"),
    KEY("key");

    companion object {
        fun fromValue(value: String): SshAuthType {
            return entries.find { it.value == value } ?: PASSWORD
        }
    }
}

enum class DnsTransport(val value: String, val displayName: String) {
    UDP("udp", "UDP"),
    TCP("tcp", "TCP"),
    DOT("dot", "DoT"),
    DOH("doh", "DoH");

    companion object {
        fun fromValue(value: String): DnsTransport {
            return entries.find { it.value == value } ?: UDP
        }
    }
}


