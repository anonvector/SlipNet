package app.slipnet.tunnel

import app.slipnet.util.AppLog as Log
import java.io.BufferedOutputStream
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.SequenceInputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * SOCKS5 bridge for standalone NaiveProxy mode.
 *
 * NaiveProxy (Chromium-based) only supports SOCKS5 CONNECT (0x01) with NO_AUTH.
 * hev-socks5-tunnel sends FWD_UDP (0x05) for DNS. This bridge sits between
 * hev-socks5-tunnel and NaiveProxy:
 *
 * - CONNECT (0x01): Chains to NaiveProxy's SOCKS5 (NO_AUTH)
 * - FWD_UDP (0x05) DNS: DNS-over-TCP through persistent worker pool via NaiveProxy,
 *   falls back to DoH (Cloudflare 1.1.1.1) if all workers fail.
 * - FWD_UDP (0x05) non-DNS: Dropped silently (browser falls back to TCP CONNECT)
 *
 * Traffic flow:
 * App -> TUN -> hev-socks5-tunnel -> NaiveSocksBridge (proxyPort)
 *   TCP: -> SOCKS5 CONNECT (no auth) -> NaiveProxy (proxyPort+1) -> Caddy HTTPS -> Server
 *   DNS: -> FWD_UDP -> persistent DNS worker pool (via NaiveProxy CONNECT to 8.8.8.8:53) -> DNS-over-TCP
 */
object NaiveSocksBridge {
    private const val TAG = "NaiveSocksBridge"
    @Volatile var debugLogging = false
    @Volatile var domainRouter: DomainRouter = DomainRouter.DISABLED
    private fun logd(msg: String) { if (debugLogging) Log.d(TAG, msg) }
    private const val BIND_MAX_RETRIES = 10
    private const val BIND_RETRY_DELAY_MS = 200L
    private const val BUFFER_SIZE = 65536  // 64KB for better throughput
    private const val TCP_CONNECT_TIMEOUT_MS = 10000
    private const val DNS_POOL_SIZE = 5
    private const val DNS_KEEPALIVE_INTERVAL_MS = 40_000L
    private const val DNS_WORKER_TIMEOUT_MS = 15_000
    private const val PRIMARY_DNS_HOST = "8.8.8.8"
    private const val FALLBACK_DNS_HOST = "1.1.1.1"

    private var naiveHost: String = "127.0.0.1"
    private var naivePort: Int = 0
    private var serverSocket: ServerSocket? = null
    private var acceptorThread: Thread? = null
    private val running = AtomicBoolean(false)
    private val connectionThreads = CopyOnWriteArrayList<Thread>()
    private val remoteSockets = CopyOnWriteArrayList<Socket>()

    // --- DNS Worker Pool ---
    private class DnsWorker(
        val socket: Socket,
        val input: InputStream,
        val output: OutputStream,
        val lock: ReentrantLock = ReentrantLock()
    ) {
        val isAlive: Boolean get() = !socket.isClosed && socket.isConnected
    }

    private val dnsWorkers = arrayOfNulls<DnsWorker>(DNS_POOL_SIZE)
    private val dnsRoundRobin = AtomicInteger(0)
    private var dnsTargetHost: String = PRIMARY_DNS_HOST
    private var dnsFallbackHost: String = FALLBACK_DNS_HOST
    private val workerCreationLocks = Array(DNS_POOL_SIZE) { ReentrantLock() }
    private var dnsKeepaliveThread: Thread? = null

    fun start(
        naivePort: Int,
        naiveHost: String = "127.0.0.1",
        listenPort: Int,
        listenHost: String = "127.0.0.1",
        dnsServer: String? = null,
        dnsFallback: String? = null
    ): Result<Unit> {
        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting NaiveProxy SOCKS5 bridge")
        Log.i(TAG, "  NaiveProxy: $naiveHost:$naivePort")
        Log.i(TAG, "  Listen: $listenHost:$listenPort")
        Log.i(TAG, "  DNS: ${dnsServer ?: PRIMARY_DNS_HOST} (fallback: ${dnsFallback ?: FALLBACK_DNS_HOST})")
        Log.i(TAG, "========================================")

        stop()
        this.naiveHost = naiveHost
        this.naivePort = naivePort
        this.dnsTargetHost = dnsServer ?: PRIMARY_DNS_HOST
        this.dnsFallbackHost = dnsFallback ?: FALLBACK_DNS_HOST

        return try {
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
            }, "naive-bridge-acceptor").also { it.isDaemon = true; it.start() }

            // Pre-warm DNS worker pool in background
            prewarmDnsWorkers()

            Log.i(TAG, "Bridge started on $listenHost:$listenPort")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start bridge", e)
            stop()
            Result.failure(e)
        }
    }

    fun stop() {
        if (!running.getAndSet(false) && serverSocket == null) {
            return
        }
        logd("Stopping bridge...")

        try { serverSocket?.close() } catch (_: Exception) {}
        serverSocket = null

        acceptorThread?.interrupt()
        acceptorThread = null

        dnsKeepaliveThread?.interrupt()
        dnsKeepaliveThread = null

        for (i in 0 until DNS_POOL_SIZE) {
            val worker = dnsWorkers[i]
            dnsWorkers[i] = null
            if (worker != null) {
                try { worker.socket.close() } catch (_: Exception) {}
            }
        }

        for (sock in remoteSockets) {
            try { sock.close() } catch (_: Exception) {}
        }
        remoteSockets.clear()

        for (thread in connectionThreads) {
            thread.interrupt()
        }
        connectionThreads.clear()

        logd("Bridge stopped")
    }

    fun isRunning(): Boolean = running.get()

    fun isClientHealthy(): Boolean {
        val ss = serverSocket ?: return false
        return running.get() && !ss.isClosed
    }

    // --- DNS Worker Pool Management ---

    private fun prewarmDnsWorkers() {
        Log.i(TAG, "DNS workers target: $dnsTargetHost:53 (fallback: $dnsFallbackHost, pool=$DNS_POOL_SIZE)")
        val thread = Thread({
            for (i in 0 until DNS_POOL_SIZE) {
                if (!running.get() || Thread.currentThread().isInterrupted) break
                try {
                    val worker = createDnsWorker()
                    if (worker != null) {
                        dnsWorkers[i] = worker
                        logd("DNS worker ${i + 1}/$DNS_POOL_SIZE ready → $dnsTargetHost:53")
                    } else {
                        logd("DNS worker ${i + 1} creation returned null")
                        break
                    }
                } catch (e: Exception) {
                    if (i == 0) {
                        Log.w(TAG, "DNS worker 1 failed on $dnsTargetHost, falling back to $dnsFallbackHost")
                        dnsTargetHost = dnsFallbackHost
                        try {
                            val fallbackWorker = createDnsWorker()
                            if (fallbackWorker != null) {
                                dnsWorkers[i] = fallbackWorker
                                logd("DNS worker 1/$DNS_POOL_SIZE ready → $dnsTargetHost:53 (fallback)")
                                continue
                            }
                        } catch (e2: Exception) {
                            logd("DNS worker 1 fallback also failed: ${e2.message}")
                            break
                        }
                    }
                    logd("DNS worker ${i + 1} failed: ${e.message}")
                    break
                }
            }
            val count = dnsWorkers.count { it != null }
            Log.i(TAG, "DNS worker pool: $count/$DNS_POOL_SIZE ready → $dnsTargetHost:53")
        }, "naive-dns-prewarm")
        thread.isDaemon = true
        thread.start()
        startDnsKeepalive()
    }

    /**
     * Create a single DNS worker: Socket → NaiveProxy SOCKS5 (NO_AUTH) → CONNECT to DNS:53.
     */
    private fun createDnsWorker(): DnsWorker? {
        val sock = Socket()
        try {
            sock.connect(InetSocketAddress(naiveHost, naivePort), TCP_CONNECT_TIMEOUT_MS)
            sock.soTimeout = DNS_WORKER_TIMEOUT_MS
            sock.tcpNoDelay = true

            val sockIn = sock.getInputStream()
            val sockOut = sock.getOutputStream()

            // SOCKS5 greeting: NO_AUTH only
            if (!performSocksGreeting(sockIn, sockOut)) {
                sock.close()
                return null
            }

            // SOCKS5 CONNECT to DNS server:53
            val dnsAddr = buildDnsTargetAddr(dnsTargetHost)
            val connectReq = byteArrayOf(0x05, 0x01, 0x00) + dnsAddr
            sockOut.write(connectReq)
            sockOut.flush()

            if (!readSocksConnectResponse(sockIn)) {
                logd("DNS worker: CONNECT to $dnsTargetHost:53 failed")
                sock.close()
                return null
            }

            return DnsWorker(sock, sockIn, sockOut)
        } catch (e: Exception) {
            try { sock.close() } catch (_: Exception) {}
            throw e
        }
    }

    private fun recreateDnsWorkerSync(idx: Int): DnsWorker? {
        try {
            if (!workerCreationLocks[idx].tryLock(1, TimeUnit.SECONDS)) return null
        } catch (_: InterruptedException) {
            return null
        }
        try {
            val existing = dnsWorkers[idx]
            if (existing != null && existing.isAlive) return existing
            existing?.let { try { it.socket.close() } catch (_: Exception) {} }

            if (!running.get()) return null

            val worker = createDnsWorker()
            dnsWorkers[idx] = worker
            if (worker != null) logd("DNS worker $idx recreated")
            return worker
        } catch (e: Exception) {
            logd("DNS worker $idx recreation failed: ${e.message}")
            dnsWorkers[idx] = null
            return null
        } finally {
            workerCreationLocks[idx].unlock()
        }
    }

    private fun startDnsKeepalive() {
        dnsKeepaliveThread?.interrupt()
        dnsKeepaliveThread = Thread({
            try {
                Thread.sleep(DNS_KEEPALIVE_INTERVAL_MS)
            } catch (_: InterruptedException) { return@Thread }

            while (running.get() && !Thread.currentThread().isInterrupted) {
                var deadCount = 0
                for (i in 0 until DNS_POOL_SIZE) {
                    val worker = dnsWorkers[i]
                    if (worker == null || !worker.isAlive) {
                        deadCount++
                        recreateDnsWorkerSync(i)
                    }
                }
                if (deadCount > 0) {
                    logd("DNS keepalive: $deadCount dead workers found, recreation attempted")
                }

                try {
                    Thread.sleep(DNS_KEEPALIVE_INTERVAL_MS)
                } catch (_: InterruptedException) { break }
            }
        }, "naive-dns-keepalive").also { it.isDaemon = true; it.start() }
    }

    private fun buildDnsTargetAddr(host: String): ByteArray {
        val parts = host.split(".")
        return byteArrayOf(
            0x01,                               // ATYP: IPv4
            parts[0].toInt().toByte(),
            parts[1].toInt().toByte(),
            parts[2].toInt().toByte(),
            parts[3].toInt().toByte(),
            0x00, 0x35                          // port 53
        )
    }

    private fun sendDnsQuery(worker: DnsWorker, payload: ByteArray): ByteArray? {
        val lenBuf = ByteArray(2)
        lenBuf[0] = ((payload.size shr 8) and 0xFF).toByte()
        lenBuf[1] = (payload.size and 0xFF).toByte()
        worker.output.write(lenBuf)
        worker.output.write(payload)
        worker.output.flush()

        val respLen = ByteArray(2)
        worker.input.readFully(respLen)
        val responseLength = ((respLen[0].toInt() and 0xFF) shl 8) or (respLen[1].toInt() and 0xFF)

        if (responseLength <= 0 || responseLength > 65535) return null

        val response = ByteArray(responseLength)
        worker.input.readFully(response)
        return response
    }

    /**
     * Forward DNS query through persistent worker pool with multi-phase resilience:
     * Phase 1: Try ALL existing live workers round-robin (non-blocking lock).
     * Phase 2: If all dead/busy, recreate ONE worker inline and use it.
     * Phase 3: Last resort — open a per-query connection (still through NaiveProxy).
     * Phase 4: DoH fallback if all TCP methods fail.
     */
    private fun forwardDnsPooled(payload: ByteArray): ByteArray? {
        val startIdx = (dnsRoundRobin.getAndIncrement() and 0x7FFFFFFF) % DNS_POOL_SIZE

        // Phase 1: Try all existing live workers
        for (i in 0 until DNS_POOL_SIZE) {
            val idx = (startIdx + i) % DNS_POOL_SIZE
            val worker = dnsWorkers[idx] ?: continue
            if (!worker.isAlive) {
                dnsWorkers[idx] = null
                continue
            }
            if (!worker.lock.tryLock()) continue
            try {
                if (!worker.isAlive) {
                    dnsWorkers[idx] = null
                    continue
                }
                val result = sendDnsQuery(worker, payload)
                if (result != null) return result
            } catch (e: Exception) {
                logd("FWD_UDP: DNS worker $idx failed: ${e.message}")
                dnsWorkers[idx] = null
            } finally {
                worker.lock.unlock()
            }
        }

        // Phase 2: All workers dead/busy — recreate one inline
        for (i in 0 until DNS_POOL_SIZE) {
            val idx = (startIdx + i) % DNS_POOL_SIZE
            val newWorker = recreateDnsWorkerSync(idx) ?: continue
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
            break
        }

        // Phase 3: Per-query fallback
        logd("FWD_UDP: all workers failed, falling back to per-query connection")
        val tcpResult = forwardDnsTcpOneShot(payload)
        if (tcpResult != null) return tcpResult

        // Phase 4: DoH fallback
        return forwardDnsDoH(payload)
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
        val thread = Thread({
            try {
                clientSocket.use { socket ->
                    socket.soTimeout = 30000
                    socket.tcpNoDelay = true
                    socket.receiveBufferSize = BUFFER_SIZE
                    socket.sendBufferSize = BUFFER_SIZE
                    val input = socket.getInputStream()
                    val output = socket.getOutputStream()

                    // SOCKS5 greeting
                    val version = input.read()
                    if (version != 0x05) {
                        Log.w(TAG, "Invalid SOCKS5 version: $version")
                        return@Thread
                    }
                    val nMethods = input.read()
                    val methods = ByteArray(nMethods)
                    input.readFully(methods)

                    // Respond: no authentication required
                    output.write(byteArrayOf(0x05, 0x00))
                    output.flush()

                    // SOCKS5 request
                    val ver = input.read()
                    val cmd = input.read()
                    input.read() // reserved

                    if (ver != 0x05 || (cmd != 0x01 && cmd != 0x05)) {
                        output.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                        output.flush()
                        return@Thread
                    }

                    // Parse address
                    val addrType = input.read()
                    val destHost: String
                    val rawAddr: ByteArray

                    when (addrType) {
                        0x01 -> { // IPv4
                            val addr = ByteArray(4)
                            input.readFully(addr)
                            destHost = addr.joinToString(".") { (it.toInt() and 0xFF).toString() }
                            rawAddr = byteArrayOf(0x01) + addr
                        }
                        0x03 -> { // Domain name
                            val len = input.read()
                            val domain = ByteArray(len)
                            input.readFully(domain)
                            destHost = String(domain)
                            rawAddr = byteArrayOf(0x03, len.toByte()) + domain
                        }
                        0x04 -> { // IPv6
                            val addr = ByteArray(16)
                            input.readFully(addr)
                            destHost = formatIpv6(addr)
                            rawAddr = byteArrayOf(0x04) + addr
                        }
                        else -> {
                            output.write(byteArrayOf(0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                            output.flush()
                            return@Thread
                        }
                    }

                    val portHigh = input.read()
                    val portLow = input.read()
                    val destPort = (portHigh shl 8) or portLow
                    val portBytes = byteArrayOf(portHigh.toByte(), portLow.toByte())

                    // Handle FWD_UDP (cmd 0x05)
                    if (cmd == 0x05) {
                        socket.soTimeout = 0
                        handleFwdUdp(input, output)
                        return@Thread
                    }

                    // Handle CONNECT (cmd 0x01) — chain through NaiveProxy
                    handleConnect(destHost, destPort, rawAddr, portBytes, socket, input, output)
                }
            } catch (e: Exception) {
                if (running.get()) {
                    logd("Connection handler error: ${e.message}")
                }
            }
        }, "naive-bridge-handler")
        thread.isDaemon = true
        connectionThreads.add(thread)
        thread.start()

        connectionThreads.removeAll { !it.isAlive }
    }

    private fun handleConnect(
        destHost: String,
        destPort: Int,
        rawAddr: ByteArray,
        portBytes: ByteArray,
        clientSocket: Socket,
        clientInput: InputStream,
        clientOutput: OutputStream
    ) {
        val router = domainRouter
        if (router.enabled) {
            handleConnectWithRouting(router, destHost, destPort, rawAddr, portBytes, clientSocket, clientInput, clientOutput)
            return
        }

        connectViaNaive(destHost, destPort, rawAddr, portBytes, clientSocket, clientInput, clientOutput, true)
    }

    private fun handleConnectWithRouting(
        router: DomainRouter,
        destHost: String,
        destPort: Int,
        rawAddr: ByteArray,
        portBytes: ByteArray,
        clientSocket: Socket,
        clientInput: InputStream,
        clientOutput: OutputStream
    ) {
        var effectiveHost = destHost
        var sniffBuffer: ByteArray? = null
        var sniffLen = 0
        var wasEarlyReply = false

        if (DomainRouter.isIpAddress(destHost)) {
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

        clientSocket.soTimeout = 0
        val effectiveInput = if (sniffLen > 0)
            SequenceInputStream(ByteArrayInputStream(sniffBuffer!!, 0, sniffLen), clientInput)
        else clientInput
        connectViaNaive(destHost, destPort, rawAddr, portBytes, clientSocket, effectiveInput, clientOutput, !wasEarlyReply)
    }

    /**
     * Connect through NaiveProxy's SOCKS5 proxy (NO_AUTH) and bridge bidirectionally.
     */
    private fun connectViaNaive(
        destHost: String,
        destPort: Int,
        rawAddr: ByteArray,
        portBytes: ByteArray,
        clientSocket: Socket,
        clientInput: InputStream,
        clientOutput: OutputStream,
        sendReply: Boolean
    ) {
        val remoteSocket: Socket
        try {
            remoteSocket = Socket()
            remoteSocket.connect(InetSocketAddress(naiveHost, naivePort), TCP_CONNECT_TIMEOUT_MS)
            remoteSocket.tcpNoDelay = true
            remoteSockets.add(remoteSocket)
        } catch (e: Exception) {
            logd("CONNECT: failed to connect to NaiveProxy: ${e.message}")
            if (sendReply) {
                clientOutput.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                clientOutput.flush()
            }
            return
        }

        try {
            val remoteInput = remoteSocket.getInputStream()
            val remoteOutput = remoteSocket.getOutputStream()

            // SOCKS5 greeting to NaiveProxy (NO_AUTH)
            remoteOutput.write(byteArrayOf(0x05, 0x01, 0x00))
            remoteOutput.flush()

            val greetResp = ByteArray(2)
            remoteInput.readFully(greetResp)
            if (greetResp[0] != 0x05.toByte() || (greetResp[1].toInt() and 0xFF) == 0xFF) {
                Log.w(TAG, "CONNECT: NaiveProxy rejected greeting (${greetResp[0]}, ${greetResp[1]})")
                if (sendReply) {
                    clientOutput.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    clientOutput.flush()
                }
                remoteSocket.close()
                return
            }

            // SOCKS5 CONNECT request
            val connectReq = byteArrayOf(0x05, 0x01, 0x00) + rawAddr + portBytes
            remoteOutput.write(connectReq)
            remoteOutput.flush()

            // Read CONNECT response
            val connRespHeader = ByteArray(4)
            remoteInput.readFully(connRespHeader)

            if (connRespHeader[1] != 0x00.toByte()) {
                logd("CONNECT: NaiveProxy rejected to $destHost:$destPort (rep=${connRespHeader[1]})")
                if (sendReply) {
                    clientOutput.write(byteArrayOf(0x05, connRespHeader[1], 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    clientOutput.flush()
                }
                remoteSocket.close()
                return
            }

            // Read remaining response bytes based on address type
            when (connRespHeader[3].toInt() and 0xFF) {
                0x01 -> { val rest = ByteArray(6); remoteInput.readFully(rest) }
                0x03 -> { val len = remoteInput.read(); val rest = ByteArray(len + 2); remoteInput.readFully(rest) }
                0x04 -> { val rest = ByteArray(18); remoteInput.readFully(rest) }
            }

            logd("CONNECT: $destHost:$destPort OK (via NaiveProxy)")

            if (sendReply) {
                clientOutput.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                clientOutput.flush()
            }

            clientSocket.soTimeout = 0

            // Bridge bidirectionally
            remoteSocket.use { remote ->
                val t1 = Thread({
                    try {
                        copyStream(clientInput, remoteOutput)
                    } catch (_: Exception) {
                    } finally {
                        try { remoteOutput.close() } catch (_: Exception) {}
                    }
                }, "naive-bridge-c2s")
                t1.isDaemon = true
                t1.start()

                try {
                    copyStream(remoteInput, clientOutput)
                } catch (_: Exception) {
                } finally {
                    try { remote.close() } catch (_: Exception) {}
                    remoteSockets.remove(remote)
                    t1.interrupt()
                }
            }
        } catch (e: Exception) {
            logd("CONNECT: chain error for $destHost:$destPort: ${e.message}")
            if (sendReply) {
                try {
                    clientOutput.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    clientOutput.flush()
                } catch (_: Exception) {}
            }
            try { remoteSocket.close() } catch (_: Exception) {}
            remoteSockets.remove(remoteSocket)
        }
    }

    private fun bridgeDirect(clientInput: InputStream, clientOutput: OutputStream, directSocket: Socket) {
        directSocket.use { remote ->
            remote.tcpNoDelay = true
            val remoteInput = remote.getInputStream()
            val remoteOutput = remote.getOutputStream()

            val t1 = Thread({
                try {
                    copyStream(clientInput, remoteOutput)
                } catch (_: Exception) {
                } finally {
                    try { remoteOutput.close() } catch (_: Exception) {}
                }
            }, "naive-bridge-direct-c2s")
            t1.isDaemon = true
            t1.start()

            try {
                copyStream(remoteInput, clientOutput)
            } catch (_: Exception) {
            } finally {
                try { remote.close() } catch (_: Exception) {}
                t1.interrupt()
            }
        }
    }

    private fun handleFwdUdp(input: InputStream, output: OutputStream) {
        output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
        output.flush()

        logd("FWD_UDP session established")

        while (running.get() && !Thread.currentThread().isInterrupted) {
            val hdr = ByteArray(3)
            input.readFully(hdr)

            val datLen = ((hdr[0].toInt() and 0xFF) shl 8) or (hdr[1].toInt() and 0xFF)
            val hdrLen = hdr[2].toInt() and 0xFF
            val addrLen = hdrLen - 3

            if (addrLen <= 0 || datLen <= 0) {
                Log.w(TAG, "FWD_UDP: invalid header (datLen=$datLen, hdrLen=$hdrLen)")
                break
            }

            val addrBytes = ByteArray(addrLen)
            input.readFully(addrBytes)

            val payload = ByteArray(datLen)
            input.readFully(payload)

            val dest = parseSocksAddress(addrBytes)
            if (dest == null) {
                Log.w(TAG, "FWD_UDP: failed to parse address")
                continue
            }

            try {
                val response = if (dest.second == 53) {
                    forwardDnsPooled(payload)
                } else {
                    // Non-DNS UDP: drop silently
                    null
                }

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
                logd("FWD_UDP: forward to ${dest.first}:${dest.second} failed: ${e.message}")
            }
        }

        logd("FWD_UDP session ended")
    }

    private fun forwardDnsTcpOneShot(payload: ByteArray): ByteArray? {
        var sock: Socket? = null
        try {
            sock = Socket()
            sock.connect(InetSocketAddress(naiveHost, naivePort), TCP_CONNECT_TIMEOUT_MS)
            sock.soTimeout = DNS_WORKER_TIMEOUT_MS
            sock.tcpNoDelay = true

            val sockIn = sock.getInputStream()
            val sockOut = sock.getOutputStream()

            if (!performSocksGreeting(sockIn, sockOut)) return null

            val dnsAddr = buildDnsTargetAddr(dnsTargetHost)
            val connectReq = byteArrayOf(0x05, 0x01, 0x00) + dnsAddr
            sockOut.write(connectReq)
            sockOut.flush()

            if (!readSocksConnectResponse(sockIn)) {
                logd("DNS-TCP oneshot: CONNECT to $dnsTargetHost:53 failed")
                return null
            }

            val lenPrefix = byteArrayOf(
                ((payload.size shr 8) and 0xFF).toByte(),
                (payload.size and 0xFF).toByte()
            )
            sockOut.write(lenPrefix)
            sockOut.write(payload)
            sockOut.flush()

            val respLenBytes = ByteArray(2)
            sockIn.readFully(respLenBytes)
            val respLen = ((respLenBytes[0].toInt() and 0xFF) shl 8) or (respLenBytes[1].toInt() and 0xFF)

            if (respLen <= 0 || respLen > 65535) {
                logd("DNS-TCP oneshot: invalid response length $respLen")
                return null
            }

            val response = ByteArray(respLen)
            sockIn.readFully(response)

            logd("DNS-TCP oneshot: $dnsTargetHost resolved (${response.size} bytes)")
            return response
        } catch (e: Exception) {
            logd("DNS-TCP oneshot: $dnsTargetHost failed: ${e.message}")
            return null
        } finally {
            try { sock?.close() } catch (_: Exception) {}
        }
    }

    /**
     * Forward DNS query via DoH through NaiveProxy SOCKS5 CONNECT to 1.1.1.1:443.
     */
    private fun forwardDnsDoH(payload: ByteArray): ByteArray? {
        var rawSocket: Socket? = null
        var sslSocket: SSLSocket? = null
        try {
            rawSocket = Socket()
            rawSocket.connect(InetSocketAddress(naiveHost, naivePort), TCP_CONNECT_TIMEOUT_MS)
            rawSocket.soTimeout = DNS_WORKER_TIMEOUT_MS
            rawSocket.tcpNoDelay = true

            val rawIn = rawSocket.getInputStream()
            val rawOut = rawSocket.getOutputStream()

            if (!performSocksGreeting(rawIn, rawOut)) return null

            // SOCKS5 CONNECT to Cloudflare DoH (1.1.1.1:443)
            rawOut.write(byteArrayOf(
                0x05, 0x01, 0x00, 0x01,        // SOCKS5 CONNECT IPv4
                0x01, 0x01, 0x01, 0x01,        // 1.1.1.1
                0x01, 0xBB.toByte()            // port 443
            ))
            rawOut.flush()

            if (!readSocksConnectResponse(rawIn)) {
                logd("DoH DNS: CONNECT to 1.1.1.1:443 failed")
                return null
            }

            val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
            sslSocket = sslFactory.createSocket(rawSocket, "cloudflare-dns.com", 443, true) as SSLSocket
            sslSocket.startHandshake()

            val tlsIn = sslSocket.inputStream
            val tlsOut = sslSocket.outputStream

            val httpReq = ("POST /dns-query HTTP/1.1\r\n" +
                "Host: cloudflare-dns.com\r\n" +
                "Content-Type: application/dns-message\r\n" +
                "Accept: application/dns-message\r\n" +
                "Content-Length: ${payload.size}\r\n" +
                "Connection: close\r\n" +
                "\r\n").toByteArray()
            tlsOut.write(httpReq)
            tlsOut.write(payload)
            tlsOut.flush()

            return readDoHResponse(tlsIn)
        } catch (e: Exception) {
            logd("DoH DNS failed: ${e.message}")
            return null
        } finally {
            try { sslSocket?.close() } catch (_: Exception) {}
            try { rawSocket?.close() } catch (_: Exception) {}
        }
    }

    /**
     * Perform SOCKS5 greeting with NO_AUTH (0x00).
     */
    private fun performSocksGreeting(input: InputStream, output: OutputStream): Boolean {
        output.write(byteArrayOf(0x05, 0x01, 0x00))
        output.flush()

        val greetResp = ByteArray(2)
        input.readFully(greetResp)
        return greetResp[0] == 0x05.toByte() && greetResp[1] == 0x00.toByte()
    }

    private fun readSocksConnectResponse(input: InputStream): Boolean {
        val connResp = ByteArray(4)
        input.readFully(connResp)
        if (connResp[1] != 0x00.toByte()) return false
        when (connResp[3].toInt() and 0xFF) {
            0x01 -> { val r = ByteArray(6); input.readFully(r) }
            0x03 -> { val l = input.read(); val r = ByteArray(l + 2); input.readFully(r) }
            0x04 -> { val r = ByteArray(18); input.readFully(r) }
        }
        return true
    }

    private fun readDoHResponse(input: InputStream): ByteArray? {
        val headerLines = mutableListOf<String>()
        val lineBuf = StringBuilder()
        var prevByte = -1
        while (true) {
            val b = input.read()
            if (b == -1) break
            if (prevByte == '\r'.code && b == '\n'.code) {
                val line = lineBuf.toString()
                lineBuf.clear()
                if (line.isEmpty()) break
                headerLines.add(line)
            } else if (b != '\r'.code) {
                lineBuf.append(b.toChar())
            }
            prevByte = b
        }

        if (headerLines.isEmpty()) return null
        val statusLine = headerLines[0]
        if (!statusLine.contains(" 200")) {
            logd("DoH: $statusLine")
            return null
        }

        val contentLength = headerLines
            .find { it.startsWith("Content-Length:", ignoreCase = true) }
            ?.substringAfter(":")?.trim()?.toIntOrNull()

        return if (contentLength != null && contentLength in 1..65535) {
            val body = ByteArray(contentLength)
            input.readFully(body)
            body
        } else {
            input.readBytes().takeIf { it.isNotEmpty() }
        }
    }

    private fun parseSocksAddress(addrBytes: ByteArray): Pair<String, Int>? {
        if (addrBytes.isEmpty()) return null

        return when (addrBytes[0].toInt() and 0xFF) {
            0x01 -> {
                if (addrBytes.size < 7) return null
                val host = "${addrBytes[1].toInt() and 0xFF}.${addrBytes[2].toInt() and 0xFF}.${addrBytes[3].toInt() and 0xFF}.${addrBytes[4].toInt() and 0xFF}"
                val port = ((addrBytes[5].toInt() and 0xFF) shl 8) or (addrBytes[6].toInt() and 0xFF)
                Pair(host, port)
            }
            0x03 -> {
                val len = addrBytes[1].toInt() and 0xFF
                if (addrBytes.size < 2 + len + 2) return null
                val host = String(addrBytes, 2, len)
                val port = ((addrBytes[2 + len].toInt() and 0xFF) shl 8) or (addrBytes[3 + len].toInt() and 0xFF)
                Pair(host, port)
            }
            0x04 -> {
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

    private fun copyStream(input: InputStream, output: OutputStream) {
        val buffered = BufferedOutputStream(output, BUFFER_SIZE)
        val buffer = ByteArray(BUFFER_SIZE)
        while (!Thread.currentThread().isInterrupted) {
            val bytesRead = input.read(buffer)
            if (bytesRead == -1) break
            buffered.write(buffer, 0, bytesRead)
            if (bytesRead < BUFFER_SIZE || input.available() == 0) {
                buffered.flush()
            }
        }
        buffered.flush()
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
