package app.slipnet.domain.model

data class ServerProfile(
    val id: Long = 0,
    val name: String,
    val domain: String,
    val resolvers: List<DnsResolver>,
    val authoritativeMode: Boolean = false,
    val keepAliveInterval: Int = 200,
    val congestionControl: CongestionControl = CongestionControl.BBR,
    val tcpListenPort: Int = 10800,
    val tcpListenHost: String = "127.0.0.1",
    val gsoEnabled: Boolean = false,
    val isActive: Boolean = false,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis()
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
