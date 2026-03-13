package app.slipnet.domain.model

/**
 * A chain of VPN profiles connected in sequence.
 * Traffic flows: outermost (first) → ... → innermost (last) → Internet.
 *
 * Example: [DNSTT, SSH] means DNS tunnel carries SSH, SSH provides SOCKS5.
 */
data class ProfileChain(
    val id: Long = 0,
    val name: String,
    val profileIds: List<Long>,
    val isActive: Boolean = false,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
    val sortOrder: Int = 0
)
