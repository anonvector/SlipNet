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
    val tcpListenPort: Int = 10800,
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
    // SSH tunnel fields
    val sshEnabled: Boolean = false,
    val sshUsername: String = "",
    val sshPassword: String = ""
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
    SLIPSTREAM("slipstream", "Slipstream (Experimental)"),
    DNSTT("dnstt", "DNSTT");

    companion object {
        fun fromValue(value: String): TunnelType {
            return entries.find { it.value == value } ?: DNSTT
        }
    }
}

