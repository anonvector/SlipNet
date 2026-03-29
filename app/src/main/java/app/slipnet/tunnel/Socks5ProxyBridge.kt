package app.slipnet.tunnel

/**
 * Singleton facade for SOCKS5 proxy bridge management.
 *
 * Delegates all operations to a default [Socks5ProxyInstance] for backward compatibility.
 * For chains that require multiple simultaneous SOCKS5 bridges, use [createInstance] / [stopInstance].
 */
object Socks5ProxyBridge {

    // ── Default instance (backward compatibility) ───────────────────────

    private val defaultInstance = Socks5ProxyInstance("default")

    var debugLogging: Boolean
        get() = defaultInstance.debugLogging
        set(value) { defaultInstance.debugLogging = value }

    var domainRouter: DomainRouter
        get() = defaultInstance.domainRouter
        set(value) { defaultInstance.domainRouter = value }

    var uploadLimiter: RateLimiter?
        get() = defaultInstance.uploadLimiter
        set(value) { defaultInstance.uploadLimiter = value }

    var downloadLimiter: RateLimiter?
        get() = defaultInstance.downloadLimiter
        set(value) { defaultInstance.downloadLimiter = value }

    fun start(
        remoteHost: String,
        remotePort: Int,
        remoteUsername: String?,
        remotePassword: String?,
        listenPort: Int,
        listenHost: String = "127.0.0.1",
        dnsHost: String = "8.8.8.8"
    ): Result<Unit> = defaultInstance.start(
        remoteHost, remotePort, remoteUsername, remotePassword,
        listenPort, listenHost, dnsHost
    )

    fun stop() = defaultInstance.stop()
    fun isRunning(): Boolean = defaultInstance.isRunning()
    fun isClientHealthy(): Boolean = defaultInstance.isClientHealthy()
    fun getTunnelTxBytes(): Long = defaultInstance.getTunnelTxBytes()
    fun getTunnelRxBytes(): Long = defaultInstance.getTunnelRxBytes()
    fun resetTrafficStats() = defaultInstance.resetTrafficStats()

    // ── Instance Registry (for chains with multiple SOCKS5 layers) ──────

    private val instances = mutableMapOf<String, Socks5ProxyInstance>()

    @Synchronized
    fun createInstance(id: String): Socks5ProxyInstance {
        instances[id]?.stop()
        val instance = Socks5ProxyInstance(id)
        instance.debugLogging = debugLogging
        instance.domainRouter = domainRouter
        instances[id] = instance
        return instance
    }

    @Synchronized
    fun getInstance(id: String): Socks5ProxyInstance? = instances[id]

    @Synchronized
    fun stopInstance(id: String) {
        instances.remove(id)?.stop()
    }

    @Synchronized
    fun stopAllInstances() {
        instances.values.forEach { it.stop() }
        instances.clear()
    }

    fun stopAll() {
        defaultInstance.stop()
        stopAllInstances()
    }
}
