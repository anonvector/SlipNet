package app.slipnet.domain.model

data class ServerProfile(
    val id: Long = 0,
    val name: String,
    val domain: String = "",
    val resolvers: List<DnsResolver> = emptyList(),
    val authoritativeMode: Boolean = false,
    val keepAliveInterval: Int = 200,
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
    // When true, DNS queries go to server's local resolver (127.0.0.53) instead of VPN DNS (e.g. 1.1.1.1)
    val useServerDns: Boolean = false,
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
    val sortOrder: Int = 0
)

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
    SSH("ssh", "SSH"),
    DOH("doh", "DOH (DNS over HTTPS)"),
    SNOWFLAKE("snowflake", "Tor");

    companion object {
        fun fromValue(value: String): TunnelType {
            return entries.find { it.value == value } ?: DNSTT
        }
    }
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
    DOT("dot", "DoT"),
    DOH("doh", "DoH");

    companion object {
        fun fromValue(value: String): DnsTransport {
            return entries.find { it.value == value } ?: UDP
        }
    }
}



