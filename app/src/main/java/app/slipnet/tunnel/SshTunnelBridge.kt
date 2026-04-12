package app.slipnet.tunnel

import app.slipnet.domain.model.SshAuthType

/**
 * Singleton facade for SSH tunnel management.
 *
 * Delegates all operations to a default [SshTunnelInstance] for backward compatibility.
 * For chains that require multiple simultaneous SSH tunnels, use [createInstance] / [stopInstance].
 */
object SshTunnelBridge {

    // ── Default instance (backward compatibility) ───────────────────────

    private val defaultInstance = SshTunnelInstance("default")

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

    var localAuthUsername: String?
        get() = defaultInstance.localAuthUsername
        set(value) { defaultInstance.localAuthUsername = value }

    var localAuthPassword: String?
        get() = defaultInstance.localAuthPassword
        set(value) { defaultInstance.localAuthPassword = value }

    fun configure(cipher: String?, compression: Boolean, maxChannels: Int) =
        defaultInstance.configure(cipher, compression, maxChannels)

    fun startDirect(
        tunnelHost: String,
        tunnelPort: Int,
        sshUsername: String,
        sshPassword: String,
        listenPort: Int,
        listenHost: String = "127.0.0.1",
        forwardDnsThroughSsh: Boolean = false,
        sshAuthType: SshAuthType = SshAuthType.PASSWORD,
        sshPrivateKey: String = "",
        sshKeyPassphrase: String = "",
        remoteDnsHost: String = "8.8.8.8",
        remoteDnsFallback: String = "1.1.1.1",
        tlsEnabled: Boolean = false,
        tlsSni: String = "",
        sshPayload: String = ""
    ): Result<Unit> = defaultInstance.startDirect(
        tunnelHost, tunnelPort, sshUsername, sshPassword,
        listenPort, listenHost, forwardDnsThroughSsh,
        sshAuthType, sshPrivateKey, sshKeyPassphrase,
        remoteDnsHost, remoteDnsFallback,
        tlsEnabled, tlsSni, sshPayload
    )

    fun startOverHttpProxy(
        sshHost: String,
        sshPort: Int,
        sshUsername: String,
        sshPassword: String,
        proxyHost: String,
        proxyPort: Int,
        customHostHeader: String = "",
        listenPort: Int,
        listenHost: String = "127.0.0.1",
        blockDirectDns: Boolean = true,
        sshAuthType: SshAuthType = SshAuthType.PASSWORD,
        sshPrivateKey: String = "",
        sshKeyPassphrase: String = "",
        remoteDnsHost: String = "8.8.8.8",
        remoteDnsFallback: String = "1.1.1.1",
        tlsEnabled: Boolean = false,
        tlsSni: String = ""
    ): Result<Unit> = defaultInstance.startOverHttpProxy(
        sshHost, sshPort, sshUsername, sshPassword,
        proxyHost, proxyPort, customHostHeader,
        listenPort, listenHost, blockDirectDns,
        sshAuthType, sshPrivateKey, sshKeyPassphrase,
        remoteDnsHost, remoteDnsFallback,
        tlsEnabled, tlsSni
    )

    fun startOverWebSocket(
        sshHost: String,
        sshPort: Int,
        sshUsername: String,
        sshPassword: String,
        wsPath: String = "/",
        wsUseTls: Boolean = true,
        wsCustomHost: String = "",
        wsTlsSni: String = "",
        listenPort: Int,
        listenHost: String = "127.0.0.1",
        blockDirectDns: Boolean = true,
        sshAuthType: SshAuthType = SshAuthType.PASSWORD,
        sshPrivateKey: String = "",
        sshKeyPassphrase: String = "",
        remoteDnsHost: String = "8.8.8.8",
        remoteDnsFallback: String = "1.1.1.1"
    ): Result<Unit> = defaultInstance.startOverWebSocket(
        sshHost, sshPort, sshUsername, sshPassword,
        wsPath, wsUseTls, wsCustomHost, wsTlsSni,
        listenPort, listenHost, blockDirectDns,
        sshAuthType, sshPrivateKey, sshKeyPassphrase,
        remoteDnsHost, remoteDnsFallback
    )

    fun startOverProxy(
        sshHost: String,
        sshPort: Int,
        sshUsername: String,
        sshPassword: String,
        proxyHost: String,
        proxyPort: Int,
        listenPort: Int,
        listenHost: String = "127.0.0.1",
        blockDirectDns: Boolean = false,
        sshAuthType: SshAuthType = SshAuthType.PASSWORD,
        sshPrivateKey: String = "",
        sshKeyPassphrase: String = "",
        remoteDnsHost: String = "8.8.8.8",
        remoteDnsFallback: String = "1.1.1.1"
    ): Result<Unit> = defaultInstance.startOverProxy(
        sshHost, sshPort, sshUsername, sshPassword,
        proxyHost, proxyPort, listenPort, listenHost,
        blockDirectDns, sshAuthType, sshPrivateKey, sshKeyPassphrase,
        remoteDnsHost, remoteDnsFallback
    )

    fun startOverSocks5Proxy(
        sshHost: String,
        sshPort: Int,
        sshUsername: String,
        sshPassword: String,
        proxyHost: String,
        proxyPort: Int,
        socksUsername: String?,
        socksPassword: String?,
        listenPort: Int,
        listenHost: String = "127.0.0.1",
        blockDirectDns: Boolean = true,
        sshAuthType: SshAuthType = SshAuthType.PASSWORD,
        sshPrivateKey: String = "",
        sshKeyPassphrase: String = "",
        remoteDnsHost: String = "8.8.8.8",
        remoteDnsFallback: String = "1.1.1.1",
        naiveMode: Boolean = false
    ): Result<Unit> = defaultInstance.startOverSocks5Proxy(
        sshHost, sshPort, sshUsername, sshPassword,
        proxyHost, proxyPort, socksUsername, socksPassword,
        listenPort, listenHost, blockDirectDns, sshAuthType, sshPrivateKey, sshKeyPassphrase,
        remoteDnsHost, remoteDnsFallback, naiveMode
    )

    fun stop() = defaultInstance.stop()
    fun isRunning(): Boolean = defaultInstance.isRunning()
    fun isClientHealthy(): Boolean = defaultInstance.isClientHealthy()
    fun isDnsPoolDead(): Boolean = defaultInstance.isDnsPoolDead()
    fun probeSessionAlive(timeoutMs: Int = 10000): Boolean = defaultInstance.probeSessionAlive(timeoutMs)
    fun getTunnelTxBytes(): Long = defaultInstance.getTunnelTxBytes()
    fun getTunnelRxBytes(): Long = defaultInstance.getTunnelRxBytes()
    fun resetTrafficStats() = defaultInstance.resetTrafficStats()

    // ── Instance Registry (for chains with multiple SSH layers) ─────────

    private val instances = mutableMapOf<String, SshTunnelInstance>()

    /**
     * Create (or replace) a named SSH tunnel instance for chain usage.
     * The instance inherits current [debugLogging] and [domainRouter] settings.
     */
    @Synchronized
    fun createInstance(id: String): SshTunnelInstance {
        instances[id]?.stop()
        val instance = SshTunnelInstance(id)
        instance.debugLogging = debugLogging
        instance.domainRouter = domainRouter
        instances[id] = instance
        return instance
    }

    @Synchronized
    fun getInstance(id: String): SshTunnelInstance? = instances[id]

    @Synchronized
    fun stopInstance(id: String) {
        instances.remove(id)?.stop()
    }

    /** Stop all chain instances (does NOT stop the default instance). */
    @Synchronized
    fun stopAllInstances() {
        instances.values.forEach { it.stop() }
        instances.clear()
    }

    /** Stop everything — default instance + all chain instances. */
    fun stopAll() {
        defaultInstance.stop()
        stopAllInstances()
    }

    /** Aggregate TX bytes across default + all chain instances. */
    fun getAllTunnelTxBytes(): Long {
        var total = defaultInstance.getTunnelTxBytes()
        synchronized(this) { instances.values.forEach { total += it.getTunnelTxBytes() } }
        return total
    }

    /** Aggregate RX bytes across default + all chain instances. */
    fun getAllTunnelRxBytes(): Long {
        var total = defaultInstance.getTunnelRxBytes()
        synchronized(this) { instances.values.forEach { total += it.getTunnelRxBytes() } }
        return total
    }
}
