package app.slipnet.tunnel

import app.slipnet.util.AppLog as Log
import app.slipnet.domain.model.SshAuthType
import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.JSch
import com.jcraft.jsch.ProxySOCKS5
import com.jcraft.jsch.Session
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.SequenceInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock

/**
 * SSH tunnel bridge that creates a local SOCKS5 proxy through an SSH connection.
 *
 * Traffic flow (SSH-only):
 * App -> hev-socks5-tunnel -> [SSH SOCKS5 :listenPort] -> SSH direct-tcpip -> Server
 */
object SshTunnelBridge {
    private const val TAG = "SshTunnelBridge"
    @Volatile var debugLogging = false
    @Volatile var domainRouter: DomainRouter = DomainRouter.DISABLED
    private fun logd(msg: String) { if (debugLogging) Log.d(TAG, msg) }
    private const val BIND_MAX_RETRIES = 10
    private const val BIND_RETRY_DELAY_MS = 200L
    private const val BUFFER_SIZE = 65536  // 64KB for better throughput
    private const val CONNECT_TIMEOUT_MS = 30000
    private const val CHANNEL_CONNECT_TIMEOUT_MS = 15000  // shorter for channels
    private const val KEEPALIVE_INTERVAL_MS = 15000
    private const val DNS_SSH_MAX_FAILURES = 3
    private const val DEFAULT_MAX_CHANNELS = 32
    private const val CHANNEL_ACQUIRE_TIMEOUT_MS = 30000L
    private const val CHANNEL_RETRY_COUNT = 2
    private const val CHANNEL_RETRY_DELAY_MS = 100L  // fast retry
    private const val DNS_POOL_SIZE = 10
    private const val DNS_KEEPALIVE_INTERVAL_MS = 20_000L
    // systemd-resolved stub listener (standard on Ubuntu/Debian servers)
    private const val SERVER_DNS_HOST = "127.0.0.53"
    // Fallback DNS when server has no local resolver (works on any server)
    private const val FALLBACK_DNS_HOST = "8.8.8.8"
    // Auto cipher: prefer hardware-accelerated ciphers first
    private const val AUTO_CIPHER_ORDER =
        "aes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes256-ctr"

    private var channelSemaphore = Semaphore(DEFAULT_MAX_CHANNELS)
    // Configurable settings (set before start, read during session setup)
    private var configCipher: String? = null       // null = auto
    private var configCompression: Boolean = false
    private var configMaxChannels: Int = DEFAULT_MAX_CHANNELS
    private var session: Session? = null
    private var serverSocket: ServerSocket? = null
    private var acceptorThread: Thread? = null
    private var executor: ExecutorService? = null
    private val running = AtomicBoolean(false)
    // When true, DNS queries are sent directly via DatagramSocket (for DNSTT+SSH).
    // When false, DNS queries are forwarded through SSH direct-tcpip (for SSH-only).
    private var directDns = true
    // Consecutive DNS-via-SSH failure count. After DNS_SSH_MAX_FAILURES, auto-switch to direct.
    private val dnsSshFailCount = AtomicInteger(0)
    // When true, DNS fallback to direct DatagramSocket is disabled (DNSTT+SSH mode).
    // This prevents DNS leaks: if DNS-via-SSH fails, the query fails rather than leaking.
    private var preventDnsFallback = false
    // When non-null, override DNS target in forwardDnsViaSsh to the SSH server's local
    // resolver. In DNSTT+SSH mode, the SSH server's firewall may block outgoing TCP 53
    // to external DNS servers, but 127.0.0.1:53 (local resolver) always works.
    private var sshDnsHost: String? = null
    // Persistent DNS workers: pre-opened SSH channels shared across all FWD_UDP handlers.
    // Eliminates per-query channel open overhead (the main DNSTT bottleneck).
    private class DnsWorker(
        val channel: ChannelDirectTCPIP,
        val input: InputStream,
        val output: OutputStream,
        val lock: ReentrantLock = ReentrantLock()
    ) {
        val isAlive: Boolean get() = channel.isConnected
    }
    private val dnsWorkers = arrayOfNulls<DnsWorker>(DNS_POOL_SIZE)
    private val dnsRoundRobin = AtomicInteger(0)
    private var dnsTargetHost: String = "1.1.1.1"
    // Per-worker creation locks to prevent duplicate recreation by concurrent threads
    private val workerCreationLocks = Array(DNS_POOL_SIZE) { ReentrantLock() }
    private var dnsKeepaliveJob: Future<*>? = null

    /**
     * Configure SSH tunnel settings. Call before startDirect/startOverProxy/startOverSocks5Proxy.
     *
     * @param cipher JSch cipher config string, or null for auto (fastest available)
     * @param compression Whether to enable zlib compression
     * @param maxChannels Maximum concurrent SSH channels
     */
    fun configure(cipher: String?, compression: Boolean, maxChannels: Int) {
        configCipher = cipher
        configCompression = compression
        configMaxChannels = maxChannels.coerceIn(4, 64)
        channelSemaphore = Semaphore(configMaxChannels)
        Log.i(TAG, "Configured: cipher=${cipher ?: "auto"}, compression=$compression, maxChannels=$configMaxChannels")
    }

    /**
     * Apply cipher and compression settings to a JSch session.
     */
    private fun applySessionConfig(session: Session) {
        session.setConfig("StrictHostKeyChecking", "no")
        session.setServerAliveInterval(KEEPALIVE_INTERVAL_MS)
        session.setServerAliveCountMax(3)

        // Cipher
        val cipher = configCipher
        if (cipher != null) {
            session.setConfig("cipher.s2c", cipher)
            session.setConfig("cipher.c2s", cipher)
        } else {
            session.setConfig("cipher.s2c", AUTO_CIPHER_ORDER)
            session.setConfig("cipher.c2s", AUTO_CIPHER_ORDER)
        }

        // Compression
        if (configCompression) {
            session.setConfig("compression.s2c", "zlib@openssh.com,zlib,none")
            session.setConfig("compression.c2s", "zlib@openssh.com,zlib,none")
        } else {
            session.setConfig("compression.s2c", "none")
            session.setConfig("compression.c2s", "none")
        }
    }

    /**
     * Start SSH tunnel: JSch connects directly to the given host/port.
     *
     * @param tunnelHost Local tunnel host (e.g., 127.0.0.1)
     * @param tunnelPort Local tunnel port (DNSTT listen port)
     * @param sshUsername SSH username
     * @param sshPassword SSH password
     * @param listenPort Local port for the SSH SOCKS5 proxy
     * @param listenHost Local host for the SSH SOCKS5 proxy
     * @return Result indicating success or failure
     */
    fun startDirect(
        tunnelHost: String,
        tunnelPort: Int,
        sshUsername: String,
        sshPassword: String,
        listenPort: Int,
        listenHost: String = "127.0.0.1",
        forwardDnsThroughSsh: Boolean = false,
        useServerDns: Boolean = false,
        sshAuthType: SshAuthType = SshAuthType.PASSWORD,
        sshPrivateKey: String = "",
        sshKeyPassphrase: String = ""
    ): Result<Unit> {
        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting SSH tunnel (direct mode)")
        Log.i(TAG, "  Tunnel: $tunnelHost:$tunnelPort")
        Log.i(TAG, "  SSH User: $sshUsername")
        Log.i(TAG, "  SOCKS5 Listen: $listenHost:$listenPort")
        Log.i(TAG, "  DNS through SSH: $forwardDnsThroughSsh")
        Log.i(TAG, "  Use server DNS: $useServerDns")
        Log.i(TAG, "========================================")

        stop()
        directDns = !forwardDnsThroughSsh
        // When useServerDns is true, route DNS to server's local resolver (systemd-resolved)
        sshDnsHost = if (useServerDns) SERVER_DNS_HOST else null
        dnsSshFailCount.set(0)

        return try {
            // Connect SSH directly through the tunnel port
            // DNSTT forwards raw TCP to the remote SSH server
            val jsch = JSch()
            if (sshAuthType == SshAuthType.KEY && sshPrivateKey.isNotBlank()) {
                jsch.addIdentity(
                    "ssh-key",
                    sshPrivateKey.toByteArray(Charsets.UTF_8),
                    null,
                    if (sshKeyPassphrase.isNotBlank()) sshKeyPassphrase.toByteArray(Charsets.UTF_8) else null
                )
            }
            val newSession = jsch.getSession(sshUsername, tunnelHost, tunnelPort)
            if (sshAuthType == SshAuthType.KEY) {
                newSession.setConfig("PreferredAuthentications", "publickey")
            } else {
                newSession.setPassword(sshPassword)
            }
            applySessionConfig(newSession)
            newSession.connect(CONNECT_TIMEOUT_MS)

            if (!newSession.isConnected) {
                return Result.failure(RuntimeException("SSH session failed to connect"))
            }

            session = newSession
            Log.i(TAG, "SSH session connected (direct mode, auth=${sshAuthType.value})")

            startSocksServer(listenHost, listenPort)

            Log.i(TAG, "SSH SOCKS5 proxy started on $listenHost:$listenPort")

            // Pre-warm DNS channel pool in background
            if (!directDns) prewarmDnsChannels()

            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start SSH tunnel", e)
            stop()
            Result.failure(e)
        }
    }

    /**
     * Start SSH tunnel through DNSTT.
     * DNSTT is a raw TCP tunnel (not a SOCKS5 proxy): connections to its local port
     * are tunneled through DNS directly to the DNSTT server's forward-address (the SSH server).
     * JSch connects directly to DNSTT's local port; no SOCKS5 handshake is needed.
     * DNS queries are attempted through SSH first (DNS-over-TCP via direct-tcpip).
     * If SSH DNS fails repeatedly, falls back to direct DNS via DatagramSocket
     * (bypasses VPN since the app is excluded via addDisallowedApplication).
     *
     * @param sshHost SSH server host (informational — the DNSTT server's forward-address)
     * @param sshPort SSH server port (informational — configured on the DNSTT server)
     * @param sshUsername SSH username
     * @param sshPassword SSH password
     * @param proxyHost DNSTT local tunnel host (e.g., 127.0.0.1)
     * @param proxyPort DNSTT local tunnel port (e.g., 1080)
     * @param listenPort Local port for the SSH SOCKS5 proxy
     * @param listenHost Local host for the SSH SOCKS5 proxy
     * @return Result indicating success or failure
     */
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
        useServerDns: Boolean = false,
        sshAuthType: SshAuthType = SshAuthType.PASSWORD,
        sshPrivateKey: String = "",
        sshKeyPassphrase: String = ""
    ): Result<Unit> {
        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting SSH tunnel (over tunnel)")
        Log.i(TAG, "  SSH target: $sshHost:$sshPort")
        Log.i(TAG, "  SSH User: $sshUsername")
        Log.i(TAG, "  Tunnel: $proxyHost:$proxyPort")
        Log.i(TAG, "  SOCKS5 Listen: $listenHost:$listenPort")
        Log.i(TAG, "  Block direct DNS: $blockDirectDns")
        Log.i(TAG, "  Use server DNS: $useServerDns")
        Log.i(TAG, "========================================")

        stop()
        directDns = false
        preventDnsFallback = blockDirectDns
        // When useServerDns is true, route DNS to server's local resolver (systemd-resolved).
        // Otherwise, let the original target (e.g. 1.1.1.1) pass through via SSH direct-tcpip.
        sshDnsHost = if (useServerDns) SERVER_DNS_HOST else null
        dnsSshFailCount.set(0)

        return try {
            val jsch = JSch()
            if (sshAuthType == SshAuthType.KEY && sshPrivateKey.isNotBlank()) {
                jsch.addIdentity(
                    "ssh-key",
                    sshPrivateKey.toByteArray(Charsets.UTF_8),
                    null,
                    if (sshKeyPassphrase.isNotBlank()) sshKeyPassphrase.toByteArray(Charsets.UTF_8) else null
                )
            }
            // Connect directly to the tunnel's local port. The tunnel (DNSTT/Slipstream)
            // forwards raw TCP to the SSH server. No SOCKS5 handshake is needed.
            val newSession = jsch.getSession(sshUsername, proxyHost, proxyPort)
            if (sshAuthType == SshAuthType.KEY) {
                newSession.setConfig("PreferredAuthentications", "publickey")
            } else {
                newSession.setPassword(sshPassword)
            }
            applySessionConfig(newSession)
            newSession.connect(CONNECT_TIMEOUT_MS)

            if (!newSession.isConnected) {
                return Result.failure(RuntimeException("SSH session failed to connect through DNSTT"))
            }

            session = newSession
            Log.i(TAG, "SSH session connected (over DNSTT tunnel, auth=${sshAuthType.value})")

            startSocksServer(listenHost, listenPort)

            Log.i(TAG, "SSH SOCKS5 proxy started on $listenHost:$listenPort (over DNSTT)")

            // Pre-warm DNS channel pool in background
            prewarmDnsChannels()

            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start SSH tunnel over DNSTT", e)
            stop()
            Result.failure(e)
        }
    }

    /**
     * Start SSH tunnel through a SOCKS5 proxy (Slipstream/Dante).
     * Unlike DNSTT (raw TCP tunnel), Slipstream exposes a real SOCKS5 proxy.
     * JSch uses ProxySOCKS5 to send a SOCKS5 CONNECT through Slipstream to reach the SSH server.
     * DNS queries are routed through SSH direct-tcpip to the SSH server's local resolver.
     *
     * @param sshHost SSH server host (as seen from the Slipstream/Dante server)
     * @param sshPort SSH server port
     * @param sshUsername SSH username
     * @param sshPassword SSH password
     * @param proxyHost Slipstream local SOCKS5 proxy host (e.g., 127.0.0.1)
     * @param proxyPort Slipstream local SOCKS5 proxy port (e.g., 1080)
     * @param socksUsername SOCKS5 proxy username (for Dante auth, optional)
     * @param socksPassword SOCKS5 proxy password (for Dante auth, optional)
     * @param listenPort Local port for the SSH SOCKS5 proxy
     * @param listenHost Local host for the SSH SOCKS5 proxy
     * @return Result indicating success or failure
     */
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
        sshAuthType: SshAuthType = SshAuthType.PASSWORD,
        sshPrivateKey: String = "",
        sshKeyPassphrase: String = ""
    ): Result<Unit> {
        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting SSH tunnel (over Slipstream SOCKS5 proxy)")
        Log.i(TAG, "  SSH target: $sshHost:$sshPort")
        Log.i(TAG, "  SSH User: $sshUsername")
        Log.i(TAG, "  Slipstream proxy: $proxyHost:$proxyPort")
        Log.i(TAG, "  SOCKS5 auth: ${if (!socksUsername.isNullOrBlank()) "enabled" else "disabled"}")
        Log.i(TAG, "  SOCKS5 Listen: $listenHost:$listenPort")
        Log.i(TAG, "  DNS: through SSH to server's local resolver")
        Log.i(TAG, "========================================")

        stop()
        directDns = false
        preventDnsFallback = false
        // Route DNS to server's local resolver or let original target pass through
        sshDnsHost = null // startOverSocks5Proxy doesn't take useServerDns yet
        dnsSshFailCount.set(0)

        return try {
            val jsch = JSch()
            if (sshAuthType == SshAuthType.KEY && sshPrivateKey.isNotBlank()) {
                jsch.addIdentity(
                    "ssh-key",
                    sshPrivateKey.toByteArray(Charsets.UTF_8),
                    null,
                    if (sshKeyPassphrase.isNotBlank()) sshKeyPassphrase.toByteArray(Charsets.UTF_8) else null
                )
            }
            // Create session targeting the real SSH server
            val newSession = jsch.getSession(sshUsername, sshHost, sshPort)
            if (sshAuthType == SshAuthType.KEY) {
                newSession.setConfig("PreferredAuthentications", "publickey")
            } else {
                newSession.setPassword(sshPassword)
            }

            // Set up SOCKS5 proxy through Slipstream
            val proxy = ProxySOCKS5(proxyHost, proxyPort)
            if (!socksUsername.isNullOrBlank() && !socksPassword.isNullOrBlank()) {
                proxy.setUserPasswd(socksUsername, socksPassword)
            }
            newSession.setProxy(proxy)
            applySessionConfig(newSession)
            newSession.connect(CONNECT_TIMEOUT_MS)

            if (!newSession.isConnected) {
                return Result.failure(RuntimeException("SSH session failed to connect through Slipstream"))
            }

            session = newSession
            Log.i(TAG, "SSH session connected (over Slipstream SOCKS5 proxy, auth=${sshAuthType.value})")

            startSocksServer(listenHost, listenPort)

            Log.i(TAG, "SSH SOCKS5 proxy started on $listenHost:$listenPort (over Slipstream)")

            // Pre-warm DNS channel pool in background (DNS goes through SSH)
            prewarmDnsChannels()

            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start SSH tunnel over Slipstream", e)
            stop()
            Result.failure(e)
        }
    }

    /**
     * Stop the SSH tunnel and SOCKS5 proxy.
     */
    fun stop() {
        if (!running.getAndSet(false) && session == null && serverSocket == null) {
            return
        }
        logd("Stopping SSH tunnel...")

        // Close server socket to unblock accept()
        try {
            serverSocket?.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error closing server socket: ${e.message}")
        }
        serverSocket = null

        // Interrupt acceptor thread
        acceptorThread?.interrupt()
        acceptorThread = null

        // Shutdown thread pool (interrupts all running tasks)
        try {
            executor?.shutdownNow()
        } catch (_: Exception) {}
        executor = null

        // Stop DNS keepalive
        dnsKeepaliveJob?.cancel(true)
        dnsKeepaliveJob = null

        // Close persistent DNS workers
        for (i in dnsWorkers.indices) {
            val w = dnsWorkers[i] ?: continue
            try { w.channel.disconnect() } catch (_: Exception) {}
            dnsWorkers[i] = null
        }

        // Disconnect SSH session
        try {
            session?.disconnect()
        } catch (e: Exception) {
            Log.w(TAG, "Error disconnecting SSH: ${e.message}")
        }
        session = null
        preventDnsFallback = false
        sshDnsHost = null

        logd("SSH tunnel stopped")
    }

    /**
     * Check if the SSH tunnel is running.
     */
    fun isRunning(): Boolean {
        return running.get()
    }

    /**
     * Check if the SSH tunnel is healthy.
     */
    fun isClientHealthy(): Boolean {
        val s = session ?: return false
        val ss = serverSocket ?: return false
        return running.get() && s.isConnected && !ss.isClosed
    }

    /**
     * Common SOCKS5 server setup — extracted from start methods to reduce duplication.
     */
    private fun startSocksServer(listenHost: String, listenPort: Int) {
        val pool = Executors.newCachedThreadPool { r ->
            Thread(r, "ssh-socks5-worker").also { it.isDaemon = true }
        }
        executor = pool

        val ss = bindServerSocket(listenHost, listenPort)
        serverSocket = ss
        running.set(true)

        acceptorThread = Thread({
            logd("Acceptor thread started")
            while (running.get() && !Thread.currentThread().isInterrupted) {
                try {
                    val clientSocket = ss.accept()
                    handleConnection(clientSocket)
                } catch (e: Exception) {
                    if (running.get()) {
                        Log.w(TAG, "Accept error: ${e.message}")
                    }
                }
            }
            logd("Acceptor thread exited")
        }, "ssh-socks5-acceptor").also { it.isDaemon = true; it.start() }
    }

    /**
     * Create persistent DNS workers — pre-opened SSH channels to the DNS server.
     * All FWD_UDP handlers share these workers, eliminating per-query channel open overhead.
     *
     * For DNSTT+SSH (preventDnsFallback mode), uses the SSH server's local resolver
     * (127.0.0.53) by default. External DNS servers (e.g. 1.1.1.1) close TCP connections
     * after idle timeout, killing workers and causing DNS cascade failures.
     */
    private fun prewarmDnsChannels() {
        val s = session ?: return
        // Prefer user-configured sshDnsHost. For DNSTT+SSH, default to server's local
        // resolver which is faster and doesn't close TCP connections aggressively.
        dnsTargetHost = sshDnsHost ?: if (preventDnsFallback) SERVER_DNS_HOST else "1.1.1.1"
        Log.i(TAG, "DNS workers target: $dnsTargetHost:53 (preventDnsFallback=$preventDnsFallback)")
        executor?.submit {
            for (i in 0 until DNS_POOL_SIZE) {
                if (!running.get()) break
                try {
                    val ch = s.openChannel("direct-tcpip") as ChannelDirectTCPIP
                    ch.setHost(dnsTargetHost)
                    ch.setPort(53)
                    ch.connect(CHANNEL_CONNECT_TIMEOUT_MS)
                    dnsWorkers[i] = DnsWorker(ch, ch.inputStream, ch.outputStream)
                    logd("DNS worker ${i + 1}/$DNS_POOL_SIZE ready → $dnsTargetHost:53")
                } catch (e: Exception) {
                    if (i == 0 && dnsTargetHost == SERVER_DNS_HOST) {
                        // Server has no local resolver — fall back to public DNS
                        Log.w(TAG, "DNS worker 1 failed on $SERVER_DNS_HOST, falling back to $FALLBACK_DNS_HOST")
                        dnsTargetHost = FALLBACK_DNS_HOST
                        try {
                            val fallbackCh = s.openChannel("direct-tcpip") as ChannelDirectTCPIP
                            fallbackCh.setHost(dnsTargetHost)
                            fallbackCh.setPort(53)
                            fallbackCh.connect(CHANNEL_CONNECT_TIMEOUT_MS)
                            dnsWorkers[i] = DnsWorker(fallbackCh, fallbackCh.inputStream, fallbackCh.outputStream)
                            logd("DNS worker 1/$DNS_POOL_SIZE ready → $dnsTargetHost:53 (fallback)")
                            continue
                        } catch (e2: Exception) {
                            logd("DNS worker 1 fallback also failed: ${e2.message}")
                            break
                        }
                    }
                    logd("DNS worker ${i + 1} failed: ${e.message}")
                    break
                }
            }
        }
        startDnsKeepalive()
    }

    /**
     * Recreate a dead DNS worker synchronously with creation lock.
     * Used by both the keepalive thread and inline recreation in forwardDnsViaSsh.
     * Returns the new worker if created, null if lock contention or failure.
     */
    private fun recreateDnsWorkerSync(idx: Int, s: Session): DnsWorker? {
        try {
            if (!workerCreationLocks[idx].tryLock(1, TimeUnit.SECONDS)) return null
        } catch (_: InterruptedException) {
            return null
        }
        try {
            // Double-check: another thread may have already recreated it
            val existing = dnsWorkers[idx]
            if (existing != null && existing.isAlive) return existing
            existing?.let { try { it.channel.disconnect() } catch (_: Exception) {} }

            if (!s.isConnected || !running.get()) return null

            val ch = s.openChannel("direct-tcpip") as ChannelDirectTCPIP
            ch.setHost(dnsTargetHost)
            ch.setPort(53)
            ch.connect(CHANNEL_CONNECT_TIMEOUT_MS)
            val worker = DnsWorker(ch, ch.inputStream, ch.outputStream)
            dnsWorkers[idx] = worker
            logd("DNS worker $idx recreated")
            return worker
        } catch (e: Exception) {
            logd("DNS worker $idx recreation failed: ${e.message}")
            dnsWorkers[idx] = null
            return null
        } finally {
            workerCreationLocks[idx].unlock()
        }
    }

    /**
     * Periodic health check for DNS workers. Detects dead workers proactively
     * and recreates them before they're needed, preventing cascade failures.
     */
    private fun startDnsKeepalive() {
        dnsKeepaliveJob?.cancel(true)
        dnsKeepaliveJob = executor?.submit {
            try {
                Thread.sleep(DNS_KEEPALIVE_INTERVAL_MS)
            } catch (_: InterruptedException) { return@submit }

            while (running.get() && !Thread.currentThread().isInterrupted) {
                val s = session
                if (s == null || !s.isConnected) break

                var deadCount = 0
                for (i in 0 until DNS_POOL_SIZE) {
                    val worker = dnsWorkers[i]
                    if (worker == null || !worker.isAlive) {
                        deadCount++
                        recreateDnsWorkerSync(i, s)
                    }
                }
                if (deadCount > 0) {
                    logd("DNS keepalive: $deadCount dead workers found, recreation attempted")
                }

                try {
                    Thread.sleep(DNS_KEEPALIVE_INTERVAL_MS)
                } catch (_: InterruptedException) { break }
            }
        }
    }

    private fun bindServerSocket(host: String, port: Int): ServerSocket {
        val ss = ServerSocket()
        ss.reuseAddress = true
        var lastException: java.net.BindException? = null
        repeat(BIND_MAX_RETRIES) { attempt ->
            try {
                ss.bind(InetSocketAddress(host, port))
                if (attempt > 0) Log.i(TAG, "Port $port bound after ${attempt + 1} attempts")
                return ss
            } catch (e: java.net.BindException) {
                lastException = e
                if (attempt < BIND_MAX_RETRIES - 1) {
                    Log.w(TAG, "Port $port in use, retrying in ${BIND_RETRY_DELAY_MS}ms (attempt ${attempt + 1}/$BIND_MAX_RETRIES)")
                    Thread.sleep(BIND_RETRY_DELAY_MS)
                }
            }
        }
        ss.close()
        throw lastException ?: java.net.BindException("Failed to bind to port $port")
    }

    private fun handleConnection(clientSocket: Socket) {
        val pool = executor ?: return
        pool.submit {
            try {
                clientSocket.use { socket ->
                    socket.soTimeout = 30000 // timeout for SOCKS5 handshake
                    socket.tcpNoDelay = true  // disable Nagle's for lower latency
                    socket.receiveBufferSize = BUFFER_SIZE
                    socket.sendBufferSize = BUFFER_SIZE
                    val input = socket.getInputStream()
                    val output = socket.getOutputStream()

                    // SOCKS5 greeting
                    val version = input.read()
                    if (version != 0x05) {
                        Log.w(TAG, "Invalid SOCKS5 version: $version")
                        return@submit
                    }
                    val nMethods = input.read()
                    val methods = ByteArray(nMethods)
                    input.readFully(methods)

                    // Respond: no authentication required
                    output.write(byteArrayOf(0x05, 0x00))
                    output.flush()

                    // SOCKS5 CONNECT request
                    val ver = input.read() // version
                    val cmd = input.read() // command
                    input.read() // reserved

                    if (ver != 0x05 || (cmd != 0x01 && cmd != 0x05)) {
                        // Send failure response (command not supported)
                        output.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                        output.flush()
                        return@submit
                    }

                    // Parse address
                    val addrType = input.read()
                    val destHost: String
                    val destPort: Int

                    when (addrType) {
                        0x01 -> { // IPv4
                            val addr = ByteArray(4)
                            input.readFully(addr)
                            destHost = addr.joinToString(".") { (it.toInt() and 0xFF).toString() }
                        }
                        0x03 -> { // Domain name
                            val len = input.read()
                            val domain = ByteArray(len)
                            input.readFully(domain)
                            destHost = String(domain)
                        }
                        0x04 -> { // IPv6
                            val addr = ByteArray(16)
                            input.readFully(addr)
                            destHost = formatIpv6(addr)
                        }
                        else -> {
                            output.write(byteArrayOf(0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                            output.flush()
                            return@submit
                        }
                    }

                    val portHigh = input.read()
                    val portLow = input.read()
                    destPort = (portHigh shl 8) or portLow

                    // Handle FWD_UDP (cmd 0x05) - hev-socks5-tunnel's UDP-over-TCP extension
                    if (cmd == 0x05) {
                        socket.soTimeout = 0 // FWD_UDP is long-lived
                        handleFwdUdp(input, output)
                        return@submit
                    }

                    // Block DNS-over-TLS (port 853): Android Private DNS wastes SSH
                    // channels through DNSTT. DNS is handled via persistent workers on port 53.
                    if (destPort == 853) {
                        output.write(byteArrayOf(0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                        output.flush()
                        return@submit
                    }

                    // Domain routing check
                    val router = domainRouter
                    if (router.enabled) {
                        handleConnectWithRouting(router, destHost, destPort, socket, input, output)
                        return@submit
                    }

                    // Original flow — SSH tunnel
                    connectViaSsh(destHost, destPort, socket, input, output, true)
                }
            } catch (e: Exception) {
                if (running.get()) {
                    logd("Connection handler error: ${e.message}")
                }
            }
        }
    }

    private fun handleConnectWithRouting(
        router: DomainRouter,
        destHost: String,
        destPort: Int,
        clientSocket: Socket,
        clientInput: InputStream,
        clientOutput: OutputStream
    ) {
        var effectiveHost = destHost
        var sniffBuffer: ByteArray? = null
        var sniffLen = 0
        var wasEarlyReply = false

        if (DomainRouter.isIpAddress(destHost)) {
            // IP address — sniff to recover domain
            clientOutput.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            clientOutput.flush()
            clientSocket.soTimeout = 3000
            wasEarlyReply = true

            val result = ProtocolSniffer.sniff(clientInput)
            if (result.domain != null) {
                effectiveHost = result.domain
                logd("CONNECT: sniffed domain=$effectiveHost from IP=$destHost")
            }
            sniffBuffer = result.bufferedData
            sniffLen = result.bufferedLength
        }

        if (router.shouldBypass(effectiveHost)) {
            // Direct connection — bypass SSH tunnel
            logd("CONNECT: bypassing tunnel for $effectiveHost:$destPort")
            try {
                val directSocket = router.createDirectConnection(destHost, destPort)
                if (!wasEarlyReply) {
                    clientOutput.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    clientOutput.flush()
                }
                clientSocket.soTimeout = 0
                val effectiveInput = if (sniffLen > 0)
                    SequenceInputStream(ByteArrayInputStream(sniffBuffer!!, 0, sniffLen), clientInput)
                else clientInput
                bridgeDirect(effectiveInput, clientOutput, directSocket)
            } catch (e: Exception) {
                logd("CONNECT: direct connection failed for $effectiveHost:$destPort: ${e.message}")
                if (!wasEarlyReply) {
                    try {
                        clientOutput.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                        clientOutput.flush()
                    } catch (_: Exception) {}
                }
            }
            return
        }

        // Tunnel path via SSH
        clientSocket.soTimeout = 0
        val effectiveInput = if (sniffLen > 0)
            SequenceInputStream(ByteArrayInputStream(sniffBuffer!!, 0, sniffLen), clientInput)
        else clientInput
        connectViaSsh(destHost, destPort, clientSocket, effectiveInput, clientOutput, !wasEarlyReply)
    }

    /**
     * Connect via SSH direct-tcpip channel and bridge bidirectionally.
     * If [sendReply] is true, sends SOCKS5 success reply after channel opens.
     */
    private fun connectViaSsh(
        destHost: String,
        destPort: Int,
        clientSocket: Socket,
        clientInput: InputStream,
        clientOutput: OutputStream,
        sendReply: Boolean
    ) {
        val currentSession = session
        if (currentSession == null || !currentSession.isConnected) {
            Log.w(TAG, "CONNECT: SSH session not available for $destHost:$destPort")
            if (sendReply) {
                clientOutput.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                clientOutput.flush()
            }
            return
        }

        val channel: ChannelDirectTCPIP
        if (!channelSemaphore.tryAcquire(CHANNEL_ACQUIRE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
            Log.w(TAG, "CONNECT: channel semaphore timeout for $destHost:$destPort")
            if (sendReply) {
                clientOutput.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                clientOutput.flush()
            }
            return
        }
        try {
            channel = openChannelWithRetry(currentSession, destHost, destPort)
        } catch (e: Exception) {
            channelSemaphore.release()
            logd("CONNECT: SSH channel failed for $destHost:$destPort: ${e.message}")
            if (sendReply) {
                clientOutput.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                clientOutput.flush()
            }
            return
        }
        channelSemaphore.release()

        logd("CONNECT: $destHost:$destPort OK")

        if (sendReply) {
            clientOutput.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            clientOutput.flush()
        }

        clientSocket.soTimeout = 0

        // Bridge data bidirectionally
        val channelInput = channel.inputStream
        val channelOutput = channel.outputStream

        val bridgePool = executor
        val c2sFuture = bridgePool?.submit {
            try {
                copyStream(clientInput, channelOutput)
            } catch (_: Exception) {
            } finally {
                try { channelOutput.close() } catch (_: Exception) {}
            }
        }

        try {
            copyStream(channelInput, clientOutput)
        } catch (_: Exception) {
        } finally {
            try { channel.disconnect() } catch (_: Exception) {}
            c2sFuture?.cancel(true)
        }
    }

    private fun bridgeDirect(clientInput: InputStream, clientOutput: OutputStream, directSocket: Socket) {
        directSocket.use { remote ->
            remote.tcpNoDelay = true
            val remoteInput = remote.getInputStream()
            val remoteOutput = remote.getOutputStream()

            val bridgePool = executor
            val c2sFuture = bridgePool?.submit {
                try {
                    copyStream(clientInput, remoteOutput)
                } catch (_: Exception) {
                } finally {
                    try { remoteOutput.close() } catch (_: Exception) {}
                }
            }

            try {
                copyStream(remoteInput, clientOutput)
            } catch (_: Exception) {
            } finally {
                try { remote.close() } catch (_: Exception) {}
                c2sFuture?.cancel(true)
            }
        }
    }

    /**
     * Open an SSH direct-tcpip channel with retry logic.
     * Retries on transient "channel is not opened" failures with a short delay.
     */
    private fun openChannelWithRetry(
        session: Session,
        host: String,
        port: Int
    ): ChannelDirectTCPIP {
        var lastException: Exception? = null
        for (attempt in 0..CHANNEL_RETRY_COUNT) {
            if (attempt > 0) {
                Thread.sleep(CHANNEL_RETRY_DELAY_MS)
            }
            try {
                val channel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
                channel.setHost(host)
                channel.setPort(port)
                channel.connect(CHANNEL_CONNECT_TIMEOUT_MS)
                return channel
            } catch (e: Exception) {
                lastException = e
                if (!session.isConnected) throw e // session dead, no point retrying
                logd("Channel open attempt ${attempt + 1}/${CHANNEL_RETRY_COUNT + 1} failed for $host:$port: ${e.message}")
            }
        }
        throw lastException!!
    }

    /**
     * Handle FWD_UDP (cmd 0x05) - hev-socks5-tunnel's UDP-over-TCP extension.
     * Reads encapsulated UDP packets from the TCP stream. DNS queries (port 53)
     * are forwarded through SSH or directly depending on mode.
     * Non-DNS UDP is dropped since SSH only supports TCP.
     */
    private fun handleFwdUdp(input: InputStream, output: OutputStream) {
        // Send success response (bound to 0.0.0.0:0)
        output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
        output.flush()

        logd("FWD_UDP session established")

        while (running.get() && !Thread.currentThread().isInterrupted) {
            // Read 3-byte header: [datlen_hi, datlen_lo, hdrlen]
            val hdr = ByteArray(3)
            input.readFully(hdr)

            val datLen = ((hdr[0].toInt() and 0xFF) shl 8) or (hdr[1].toInt() and 0xFF)
            val hdrLen = hdr[2].toInt() and 0xFF
            val addrLen = hdrLen - 3

            if (addrLen <= 0 || datLen <= 0) {
                Log.w(TAG, "FWD_UDP: invalid header (datLen=$datLen, hdrLen=$hdrLen)")
                break
            }

            // Read address (SOCKS5 format: ATYP + addr + port)
            val addrBytes = ByteArray(addrLen)
            input.readFully(addrBytes)

            // Read payload
            val payload = ByteArray(datLen)
            input.readFully(payload)

            // Parse destination
            val dest = parseSocksAddress(addrBytes)
            if (dest == null) {
                Log.w(TAG, "FWD_UDP: failed to parse address")
                continue
            }

            // Forward the packet
            try {
                val response = forwardUdpPacket(dest.first, dest.second, payload)
                if (response != null && response.isNotEmpty()) {
                    val respHdr = ByteArray(3)
                    respHdr[0] = ((response.size shr 8) and 0xFF).toByte()
                    respHdr[1] = (response.size and 0xFF).toByte()
                    respHdr[2] = (3 + addrLen).toByte()

                    synchronized(output) {
                        output.write(respHdr)
                        output.write(addrBytes)
                        output.write(response)
                        output.flush()
                    }
                }
            } catch (e: Exception) {
                logd("FWD_UDP forward to ${dest.first}:${dest.second} failed: ${e.message}")
            }
        }

        logd("FWD_UDP session ended")
    }

    /**
     * Parse a SOCKS5 address from raw bytes (ATYP + address + port).
     */
    private fun parseSocksAddress(addrBytes: ByteArray): Pair<String, Int>? {
        if (addrBytes.isEmpty()) return null

        return when (addrBytes[0].toInt() and 0xFF) {
            0x01 -> { // IPv4
                if (addrBytes.size < 7) return null
                val host = "${addrBytes[1].toInt() and 0xFF}.${addrBytes[2].toInt() and 0xFF}.${addrBytes[3].toInt() and 0xFF}.${addrBytes[4].toInt() and 0xFF}"
                val port = ((addrBytes[5].toInt() and 0xFF) shl 8) or (addrBytes[6].toInt() and 0xFF)
                Pair(host, port)
            }
            0x03 -> { // Domain
                val len = addrBytes[1].toInt() and 0xFF
                if (addrBytes.size < 2 + len + 2) return null
                val host = String(addrBytes, 2, len)
                val port = ((addrBytes[2 + len].toInt() and 0xFF) shl 8) or (addrBytes[3 + len].toInt() and 0xFF)
                Pair(host, port)
            }
            0x04 -> { // IPv6
                if (addrBytes.size < 19) return null
                val parts = mutableListOf<String>()
                for (i in 0 until 16 step 2) {
                    val value = ((addrBytes[1 + i].toInt() and 0xFF) shl 8) or (addrBytes[2 + i].toInt() and 0xFF)
                    parts.add(String.format("%x", value))
                }
                val host = parts.joinToString(":")
                val port = ((addrBytes[17].toInt() and 0xFF) shl 8) or (addrBytes[18].toInt() and 0xFF)
                Pair(host, port)
            }
            else -> null
        }
    }

    /**
     * Forward a UDP packet. DNS queries (port 53) are either sent directly via
     * DatagramSocket (DNSTT+SSH mode) or through the SSH tunnel as DNS-over-TCP
     * (SSH-only mode). QUIC (UDP 443) gets a Version Negotiation response to
     * force immediate TCP fallback. Other non-DNS UDP is dropped.
     */
    private fun forwardUdpPacket(host: String, port: Int, payload: ByteArray): ByteArray? {
        if (port == 53) {
            if (directDns || (!preventDnsFallback && dnsSshFailCount.get() >= DNS_SSH_MAX_FAILURES)) {
                return forwardDnsDirect(host, payload)
            }
            // Try DNS via SSH
            val result = forwardDnsViaSsh(host, payload)
            if (result != null) {
                dnsSshFailCount.set(0)
                return result
            }
            val fails = dnsSshFailCount.incrementAndGet()
            // When preventDnsFallback is true (DNSTT+SSH), never fall back to direct DNS
            // to prevent DNS leaks. The query simply fails.
            if (preventDnsFallback) {
                logd("FWD_UDP: DNS via SSH failed, no fallback (leak prevention)")
                return null
            }
            if (fails == DNS_SSH_MAX_FAILURES) {
                Log.w(TAG, "FWD_UDP: DNS via SSH failed $fails times, switching to direct DNS")
            }
            return forwardDnsDirect(host, payload)
        }

        // Non-DNS UDP: drop (SSH tunnel only supports TCP).
        // QUIC (UDP 443) is rejected at the C level with ICMP Port Unreachable
        // before it reaches here, so browsers fall back to TCP instantly.
        logd("FWD_UDP: dropping UDP to $host:$port")
        return null
    }

    /**
     * Forward DNS query directly via UDP, bypassing the VPN tunnel.
     * Used in DNSTT+SSH mode where the app is excluded from VPN routing.
     */
    private fun forwardDnsDirect(host: String, payload: ByteArray): ByteArray? {
        val socket = DatagramSocket()
        try {
            socket.soTimeout = 5000 // 5s timeout for DNS

            val address = InetAddress.getByName(host)
            val request = DatagramPacket(payload, payload.size, address, 53)
            socket.send(request)

            val buffer = ByteArray(4096)
            val response = DatagramPacket(buffer, buffer.size)
            socket.receive(response)

            return buffer.copyOf(response.length)
        } catch (e: Exception) {
            logd("FWD_UDP: direct DNS to $host failed: ${e.message}")
            return null
        } finally {
            socket.close()
        }
    }

    /**
     * Send a DNS-over-TCP query through a worker's SSH channel.
     * Caller MUST hold the worker's lock. Format: [2-byte big-endian length][DNS message]
     */
    private fun sendDnsQuery(worker: DnsWorker, payload: ByteArray): ByteArray? {
        val lenBuf = ByteArray(2)
        lenBuf[0] = ((payload.size shr 8) and 0xFF).toByte()
        lenBuf[1] = (payload.size and 0xFF).toByte()
        worker.output.write(lenBuf)
        worker.output.write(payload)
        worker.output.flush()

        val respLen = ByteArray(2)
        readFullyFromStream(worker.input, respLen)
        val responseLength = ((respLen[0].toInt() and 0xFF) shl 8) or (respLen[1].toInt() and 0xFF)

        if (responseLength <= 0 || responseLength > 65535) return null

        val response = ByteArray(responseLength)
        readFullyFromStream(worker.input, response)
        return response
    }

    /**
     * Forward DNS query through persistent SSH DNS workers with multi-phase resilience:
     *
     * Phase 1: Try ALL existing live workers round-robin (non-blocking lock).
     * Phase 2: If all dead/busy, recreate ONE worker inline and use it.
     * Phase 3: Last resort — open a per-query SSH channel (still through SSH, no DNS leak).
     *
     * This ensures DNS works even when workers die (e.g., remote DNS server closes TCP),
     * with graceful degradation instead of total failure.
     */
    private fun forwardDnsViaSsh(host: String, payload: ByteArray): ByteArray? {
        val currentSession = session
        if (currentSession == null || !currentSession.isConnected) {
            Log.w(TAG, "FWD_UDP: SSH session not available for DNS")
            return null
        }

        val startIdx = (dnsRoundRobin.getAndIncrement() and 0x7FFFFFFF) % DNS_POOL_SIZE

        // Phase 1: Try all existing live workers (non-blocking lock to avoid waiting)
        for (i in 0 until DNS_POOL_SIZE) {
            val idx = (startIdx + i) % DNS_POOL_SIZE
            val worker = dnsWorkers[idx] ?: continue
            if (!worker.isAlive) {
                dnsWorkers[idx] = null
                continue
            }
            if (!worker.lock.tryLock()) continue // non-blocking — skip busy workers
            try {
                if (!worker.isAlive) {
                    dnsWorkers[idx] = null
                    continue
                }
                val result = sendDnsQuery(worker, payload)
                if (result != null) return result
                // Bad response length — worker might be OK, just skip
            } catch (e: Exception) {
                logd("FWD_UDP: DNS worker $idx failed: ${e.message}")
                dnsWorkers[idx] = null
            } finally {
                worker.lock.unlock()
            }
        }

        // Phase 2: All workers dead/busy — recreate one inline and use it immediately.
        // Only try one recreation to avoid blocking too long (channel open through DNSTT ~500ms).
        for (i in 0 until DNS_POOL_SIZE) {
            val idx = (startIdx + i) % DNS_POOL_SIZE
            val newWorker = recreateDnsWorkerSync(idx, currentSession) ?: continue
            if (!newWorker.lock.tryLock(5, TimeUnit.SECONDS)) continue
            try {
                val result = sendDnsQuery(newWorker, payload)
                if (result != null) return result
            } catch (e: Exception) {
                logd("FWD_UDP: recreated DNS worker $idx failed: ${e.message}")
                dnsWorkers[idx] = null
            } finally {
                newWorker.lock.unlock()
            }
            break // Only try one inline recreation
        }

        // Phase 3: Last resort — open a per-query SSH channel.
        // This is still through SSH (no DNS leak), just slower due to channel open overhead.
        return forwardDnsViaSshFallback(currentSession, host, payload)
    }

    /**
     * Fallback: open a one-shot SSH channel for a single DNS query.
     * Used when persistent workers aren't ready yet or have all died.
     */
    private fun forwardDnsViaSshFallback(currentSession: Session, host: String, payload: ByteArray): ByteArray? {
        val dnsHost = dnsTargetHost

        if (!channelSemaphore.tryAcquire(CHANNEL_ACQUIRE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
            return null
        }

        var channel: ChannelDirectTCPIP? = null
        try {
            channel = openChannelWithRetry(currentSession, dnsHost, 53)

            val chOut = channel.outputStream
            val chIn = channel.inputStream

            val lenBuf = ByteArray(2)
            lenBuf[0] = ((payload.size shr 8) and 0xFF).toByte()
            lenBuf[1] = (payload.size and 0xFF).toByte()
            chOut.write(lenBuf)
            chOut.write(payload)
            chOut.flush()

            val respLen = ByteArray(2)
            readFullyFromStream(chIn, respLen)
            val responseLength = ((respLen[0].toInt() and 0xFF) shl 8) or (respLen[1].toInt() and 0xFF)

            if (responseLength <= 0 || responseLength > 65535) return null

            val response = ByteArray(responseLength)
            readFullyFromStream(chIn, response)
            return response
        } catch (e: Exception) {
            logd("FWD_UDP: DNS fallback to $dnsHost failed: ${e.message}")
            return null
        } finally {
            channel?.let { try { it.disconnect() } catch (_: Exception) {} }
            channelSemaphore.release()
        }
    }

    private fun readFullyFromStream(input: InputStream, buffer: ByteArray) {
        var offset = 0
        while (offset < buffer.size) {
            val bytesRead = input.read(buffer, offset, buffer.size - offset)
            if (bytesRead == -1) throw java.io.IOException("Unexpected end of stream")
            offset += bytesRead
        }
    }

    private fun copyStream(input: InputStream, output: OutputStream) {
        val buffer = ByteArray(BUFFER_SIZE)
        while (!Thread.currentThread().isInterrupted) {
            val bytesRead = input.read(buffer)
            if (bytesRead == -1) break
            output.write(buffer, 0, bytesRead)
            // Flush when no more data is immediately available
            if (input.available() == 0) {
                output.flush()
            }
        }
        output.flush()
    }

    private fun InputStream.readFully(buffer: ByteArray) {
        var offset = 0
        while (offset < buffer.size) {
            val bytesRead = this.read(buffer, offset, buffer.size - offset)
            if (bytesRead == -1) throw java.io.IOException("Unexpected end of stream")
            offset += bytesRead
        }
    }

    private fun formatIpv6(addr: ByteArray): String {
        val parts = mutableListOf<String>()
        for (i in 0 until 16 step 2) {
            val value = ((addr[i].toInt() and 0xFF) shl 8) or (addr[i + 1].toInt() and 0xFF)
            parts.add(String.format("%x", value))
        }
        return parts.joinToString(":")
    }

}
