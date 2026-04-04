package app.slipnet.domain.model

/**
 * What a tunnel type provides when used as an intermediate layer in a chain.
 */
enum class LayerOutput {
    /** Raw TCP port forwarding (no SOCKS5 handshake needed). */
    RAW_TCP,
    /** SOCKS5 proxy (caller must send SOCKS5 CONNECT). */
    SOCKS5
}

/**
 * Validate and describe chain compatibility for tunnel types.
 *
 * Bridges are Kotlin object singletons, so a chain cannot contain two profiles
 * that use the same underlying bridge. The bridge groups are:
 * - DnsttBridge: DNSTT, NOIZDNS
 * - SlipstreamBridge: SLIPSTREAM
 * - SshTunnelBridge: SSH (and the SSH layer in combo types)
 * - NaiveBridge: NAIVE
 * - SnowflakeBridge/TorSocksBridge: SNOWFLAKE
 *
 * In a chain, combo types (DNSTT_SSH, SLIPSTREAM_SSH, etc.) are NOT used.
 * Each profile contributes exactly one layer using its single-layer tunnel type.
 * Valid single-layer types for chaining: DNSTT, NOIZDNS, SLIPSTREAM, SSH, NAIVE, SNOWFLAKE, DOH.
 */
object ChainValidation {

    /** Tunnel types that can be used in a chain (single-layer types only). */
    val CHAINABLE_TYPES = setOf(
        TunnelType.DNSTT, TunnelType.NOIZDNS, TunnelType.VAYDNS, TunnelType.SLIPSTREAM,
        TunnelType.SSH, TunnelType.NAIVE, TunnelType.SNOWFLAKE, TunnelType.DOH,
        TunnelType.SOCKS5
    )

    /** Tunnel types that can serve as an intermediate (non-final) layer. */
    val CAN_BE_INTERMEDIATE = setOf(
        TunnelType.DNSTT, TunnelType.NOIZDNS, TunnelType.VAYDNS, TunnelType.SLIPSTREAM,
        TunnelType.NAIVE, TunnelType.SNOWFLAKE, TunnelType.SOCKS5,
        TunnelType.SSH
    )

    /** Tunnel types that can serve as the final (innermost) layer. */
    val CAN_BE_FINAL = setOf(
        TunnelType.SSH, TunnelType.DNSTT, TunnelType.NOIZDNS, TunnelType.VAYDNS,
        TunnelType.SLIPSTREAM, TunnelType.NAIVE, TunnelType.SNOWFLAKE, TunnelType.DOH,
        TunnelType.SOCKS5
    )

    /** What a tunnel type provides to the next layer in the chain. */
    fun outputType(type: TunnelType): LayerOutput? = when (type) {
        // Standalone DNSTT/NoizDNS/Slipstream tunnel to a remote Dante SOCKS5 proxy,
        // so the next layer must perform a SOCKS5 handshake (with auth) to connect.
        TunnelType.DNSTT, TunnelType.NOIZDNS, TunnelType.VAYDNS -> LayerOutput.SOCKS5
        TunnelType.SLIPSTREAM -> LayerOutput.SOCKS5
        TunnelType.SSH -> LayerOutput.SOCKS5
        TunnelType.NAIVE -> LayerOutput.SOCKS5
        TunnelType.SNOWFLAKE -> LayerOutput.SOCKS5
        TunnelType.SOCKS5 -> LayerOutput.SOCKS5
        else -> null
    }

    /** What transport the tunnel type can consume from a previous layer. */
    fun canConsumeInput(type: TunnelType, input: LayerOutput): Boolean = when (type) {
        TunnelType.SSH -> true  // SSH can connect over raw TCP or SOCKS5
        TunnelType.SOCKS5 -> true  // SOCKS5 outbound traffic is routed through VPN/previous layer
        TunnelType.DNSTT, TunnelType.NOIZDNS, TunnelType.VAYDNS -> input == LayerOutput.SOCKS5  // needs SOCKS5 for resolver bypass
        TunnelType.NAIVE -> true  // NaiveProxy outbound is routed through VPN/previous layer
        TunnelType.SLIPSTREAM -> false  // Slipstream connects to its own server directly
        TunnelType.DOH -> false
        TunnelType.SNOWFLAKE -> false
        else -> false
    }

    /**
     * Map tunnel type to its singleton bridge group name.
     * Two profiles with the same bridge group cannot coexist in a chain.
     */
    fun bridgeGroup(type: TunnelType): String = when (type) {
        TunnelType.DNSTT, TunnelType.NOIZDNS -> "dnstt"
        TunnelType.VAYDNS -> "vaydns"
        TunnelType.SLIPSTREAM -> "slipstream"
        TunnelType.SSH -> "ssh"
        TunnelType.NAIVE -> "naive"
        TunnelType.SNOWFLAKE -> "snowflake"
        TunnelType.DOH -> "doh"
        TunnelType.SOCKS5 -> "socks5"
        else -> type.value
    }

    /**
     * Whether the tunnel type needs the VPN interface established before starting.
     * Types that use addDisallowedApplication need VPN first.
     * Slipstream uses JNI protect_socket so it can start before VPN.
     */
    fun needsVpnFirst(type: TunnelType): Boolean = when (type) {
        TunnelType.SLIPSTREAM -> false
        TunnelType.SNOWFLAKE -> false
        else -> true
    }

    /**
     * Validate a chain of profiles. Returns null if valid, or an error message.
     */
    fun validate(profiles: List<ServerProfile>): String? {
        if (profiles.size < 2) return "Chain must have at least 2 profiles"
        if (profiles.size > 4) return "Chain cannot have more than 4 layers"

        // Check all types are single-layer chainable
        for ((i, p) in profiles.withIndex()) {
            if (p.tunnelType !in CHAINABLE_TYPES) {
                return "${p.name}: ${p.tunnelType.displayName} cannot be used in a chain (use single-layer types)"
            }
        }

        // Check no duplicate bridge groups (SSH supports multi-instance)
        val groups = mutableSetOf<String>()
        for (p in profiles) {
            val group = bridgeGroup(p.tunnelType)
            if (group == "ssh" || group == "socks5") continue  // SSH and SOCKS5 support multiple instances
            if (!groups.add(group)) {
                return "Cannot have two profiles using the same tunnel type (${p.tunnelType.displayName})"
            }
        }

        // Check intermediate layers can provide output
        for (i in 0 until profiles.size - 1) {
            val p = profiles[i]
            if (p.tunnelType !in CAN_BE_INTERMEDIATE) {
                return "${p.name}: ${p.tunnelType.displayName} cannot be used as intermediate layer"
            }
            val output = outputType(p.tunnelType)
                ?: return "${p.name}: ${p.tunnelType.displayName} cannot provide output to next layer"

            // Check next layer can consume this output
            val next = profiles[i + 1]
            if (!canConsumeInput(next.tunnelType, output)) {
                return "${next.name} (${next.tunnelType.displayName}) cannot connect through ${p.name} (${p.tunnelType.displayName})"
            }
        }

        // Check final layer
        val last = profiles.last()
        if (last.tunnelType !in CAN_BE_FINAL) {
            return "${last.name}: ${last.tunnelType.displayName} cannot be used as final layer"
        }

        return null
    }
}
