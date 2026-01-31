package app.slipnet.data.native

/**
 * Resolver configuration for DNS tunneling.
 */
data class ResolverConfig(
    val host: String,
    val port: Int = 53,
    val authoritative: Boolean = false
) {
    companion object {
        /**
         * Common public DNS resolvers.
         */
        val GOOGLE_DNS = ResolverConfig("8.8.8.8", 53)
        val CLOUDFLARE_DNS = ResolverConfig("1.1.1.1", 53)
        val QUAD9_DNS = ResolverConfig("9.9.9.9", 53)
    }
}

/**
 * Configuration for the native VPN tunnel.
 * Uses direct connection mode where the slipstream server handles target routing.
 */
data class NativeConfig(
    /** Domain for DNS tunneling (e.g., "tunnel.example.com") */
    val domain: String,

    /** DNS resolvers to use for tunneling */
    val resolvers: List<ResolverConfig>,

    /** Whether to use authoritative mode for all resolvers */
    val authoritativeMode: Boolean = false,

    /** Keep-alive interval in milliseconds */
    val keepAliveInterval: Int = 200,

    /** Congestion control algorithm (bbr, dcubic) */
    val congestionControl: String = "bbr",

    /** TUN device file descriptor */
    val tunFd: Int = -1,

    /** DNS server for app DNS queries (optional, defaults to 8.8.8.8:53) */
    val dnsServer: String? = null
) {
    companion object {
        /**
         * Create a configuration for direct connection mode.
         */
        fun create(
            domain: String,
            resolvers: List<ResolverConfig>,
            keepAliveInterval: Int = 200,
            congestionControl: String = "bbr"
        ) = NativeConfig(
            domain = domain,
            resolvers = resolvers,
            keepAliveInterval = keepAliveInterval,
            congestionControl = congestionControl
        )

        /**
         * Create NativeConfig from a ServerProfile.
         */
        fun fromProfile(
            profile: app.slipnet.domain.model.ServerProfile,
            tunFd: Int
        ): NativeConfig {
            val resolvers = profile.resolvers.map { resolver ->
                ResolverConfig(
                    host = resolver.host,
                    port = resolver.port,
                    authoritative = resolver.authoritative
                )
            }

            return NativeConfig(
                domain = profile.domain,
                resolvers = resolvers,
                authoritativeMode = profile.authoritativeMode,
                keepAliveInterval = profile.keepAliveInterval,
                congestionControl = profile.congestionControl.value,
                tunFd = tunFd
            )
        }
    }

    /**
     * Create a copy with the TUN file descriptor set.
     */
    fun withTunFd(fd: Int) = copy(tunFd = fd)

    /**
     * Validate the configuration.
     */
    fun validate(): List<String> {
        val errors = mutableListOf<String>()

        if (domain.isBlank()) {
            errors.add("Domain is required")
        }

        if (resolvers.isEmpty()) {
            errors.add("At least one resolver is required")
        }

        resolvers.forEachIndexed { index, resolver ->
            if (resolver.host.isBlank()) {
                errors.add("Resolver ${index + 1} host is required")
            }
            if (resolver.port !in 1..65535) {
                errors.add("Resolver ${index + 1} port must be between 1 and 65535")
            }
        }

        if (keepAliveInterval < 0) {
            errors.add("Keep-alive interval must be non-negative")
        }

        if (congestionControl !in listOf("bbr", "dcubic", "cubic", "reno")) {
            errors.add("Invalid congestion control algorithm: $congestionControl")
        }

        return errors
    }

    /**
     * Check if the configuration is valid.
     */
    fun isValid() = validate().isEmpty()
}
