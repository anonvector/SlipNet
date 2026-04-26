package app.slipnet.tunnel

import app.slipnet.util.AppLog as Log
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * VLESS tunnel bridge for Cloudflare CDN with SNI fragmentation.
 *
 * Provides a local SOCKS5 proxy that tunnels traffic through:
 *   App -> hev-socks5-tunnel -> VlessBridge SOCKS5 (listenPort)
 *     -> SniFragmentForwarder (listenPort+1) -> CDN IP:443
 *       -> TLS (fragmented ClientHello) -> WebSocket upgrade -> VLESS protocol
 *         -> Cloudflare CDN -> Your VLESS Server -> Internet
 *
 * VLESS protocol is extremely simple:
 * - Client sends: version(1) + UUID(16) + addons_len(1) + command(1) + port(2) + addr_type(1) + addr + payload
 * - Server responds: version(1) + addons_len(1) + raw data
 * - After the header exchange, it's raw bidirectional TCP data with no framing.
 */
object VlessBridge {
    private const val TAG = "VlessBridge"
    private const val BUFFER_SIZE = 65536
    private const val TCP_CONNECT_TIMEOUT_MS = 30000
    private const val BIND_MAX_RETRIES = 10
    private const val BIND_RETRY_DELAY_MS = 200L

    // VLESS constants
    private const val VLESS_VERSION: Byte = 0x00
    private const val VLESS_CMD_TCP: Byte = 0x01
    private const val VLESS_ADDR_IPV4: Byte = 0x01
    private const val VLESS_ADDR_DOMAIN: Byte = 0x02
    private const val VLESS_ADDR_IPV6: Byte = 0x03

    var debugLogging = false
    private fun logd(msg: String) { if (debugLogging) Log.d(TAG, msg) }

    private var fragmentForwarder: SniFragmentForwarder? = null
    private var serverSocket: ServerSocket? = null
    private var acceptorThread: Thread? = null
    private val running = AtomicBoolean(false)
    private val connectionThreads = CopyOnWriteArrayList<Thread>()
    private val tunnelTxBytes = AtomicLong(0)
    private val tunnelRxBytes = AtomicLong(0)

    // Configuration (set before start)
    private var cdnIp: String = ""
    private var cdnPort: Int = 443
    private var serverDomain: String = ""
    private var vlessUuid: String = ""
    private var security: String = "tls"
    private var transport: String = "ws"
    private var wsPath: String = "/"
    private var fragmentStrategy: String = "sni_split"
    private var fragmentDelayMs: Int = 100
    private var sniSpoofTtl: Int = 8
    private var fakeDecoyHost: String = ""
    private var tcpMaxSeg: Int = 0
    private var vlessSni: String = ""
    private var fragmentEnabled: Boolean = true
    private var chPaddingEnabled: Boolean = false
    private var wsHeaderObfuscation: Boolean = false
    private var wsPaddingEnabled: Boolean = false
    private val random = SecureRandom()

    fun start(
        listenPort: Int,
        listenHost: String = "127.0.0.1",
        cdnIp: String,
        cdnPort: Int = 443,
        serverDomain: String,
        vlessUuid: String,
        security: String = "tls",
        transport: String = "ws",
        wsPath: String = "/",
        fragmentEnabled: Boolean = true,
        fragmentStrategy: String = "sni_split",
        fragmentDelayMs: Int = 100,
        sniSpoofTtl: Int = 8,
        fakeDecoyHost: String = "",
        tcpMaxSeg: Int = 0,
        vlessSni: String = "",
        chPaddingEnabled: Boolean = false,
        wsHeaderObfuscation: Boolean = false,
        wsPaddingEnabled: Boolean = false
    ): Result<Unit> {
        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting VLESS Bridge")
        Log.i(TAG, "  CDN: $cdnIp:$cdnPort")
        Log.i(TAG, "  Domain: $serverDomain")
        Log.i(TAG, "  UUID: ${vlessUuid.take(8)}...")
        Log.i(TAG, "  Security: $security")
        Log.i(TAG, "  Transport: $transport")
        if (transport == "ws") Log.i(TAG, "  WS Path: $wsPath")
        Log.i(TAG, "  Fragment: $fragmentEnabled (strategy=$fragmentStrategy, delay=${fragmentDelayMs}ms, spoofTtl=$sniSpoofTtl)")
        if (fragmentStrategy == "fake" && fakeDecoyHost.isNotBlank()) Log.i(TAG, "  Fake Decoy Host: $fakeDecoyHost")
        if (vlessSni.isNotBlank()) Log.i(TAG, "  TLS SNI: $vlessSni")
        Log.i(TAG, "  CH Padding: $chPaddingEnabled | WS Header Obfuscation: $wsHeaderObfuscation | WS Padding: $wsPaddingEnabled")
        Log.i(TAG, "  Listen: $listenHost:$listenPort")
        Log.i(TAG, "========================================")

        stop()

        this.cdnIp = cdnIp
        this.cdnPort = cdnPort
        this.serverDomain = serverDomain
        this.vlessUuid = vlessUuid
        this.security = security
        this.transport = transport
        this.wsPath = wsPath
        this.fragmentEnabled = fragmentEnabled
        this.fragmentStrategy = fragmentStrategy
        this.fragmentDelayMs = fragmentDelayMs
        this.sniSpoofTtl = sniSpoofTtl
        this.fakeDecoyHost = fakeDecoyHost
        this.tcpMaxSeg = tcpMaxSeg
        this.vlessSni = vlessSni
        this.chPaddingEnabled = chPaddingEnabled
        this.wsHeaderObfuscation = wsHeaderObfuscation
        this.wsPaddingEnabled = wsPaddingEnabled

        return try {
            // Step 1: Start fragment forwarder if enabled
            if (fragmentEnabled) {
                val fragmentPort = listenPort + 1
                fragmentForwarder = SniFragmentForwarder("vless").apply {
                    this.connectIp = cdnIp
                    this.connectPort = cdnPort
                    this.fragmentStrategy = fragmentStrategy
                    this.fragmentDelayMs = fragmentDelayMs
                    this.chPaddingEnabled = chPaddingEnabled
                    this.lowTtl = sniSpoofTtl
                    this.fakeDecoyHost = fakeDecoyHost
                    this.tcpMaxSeg = tcpMaxSeg
                    this.debugLogging = debugLogging
                }
                val fragResult = fragmentForwarder!!.start(fragmentPort, "127.0.0.1")
                if (fragResult.isFailure) {
                    return Result.failure(fragResult.exceptionOrNull()
                        ?: Exception("Failed to start fragment forwarder"))
                }
                Log.i(TAG, "Fragment forwarder started on port $fragmentPort")
            }

            // Step 2: Start SOCKS5 server
            val ss = bindServerSocket(listenHost, listenPort)
            serverSocket = ss
            running.set(true)

            acceptorThread = Thread({
                logd("SOCKS5 acceptor started")
                while (running.get() && !Thread.currentThread().isInterrupted) {
                    try {
                        val client = ss.accept()
                        val t = Thread({
                            handleSocks5Connection(client)
                        }, "vless-conn-${System.nanoTime()}")
                        t.isDaemon = true
                        connectionThreads.add(t)
                        t.start()
                    } catch (e: Exception) {
                        if (running.get()) Log.w(TAG, "Accept error: ${e.message}")
                    }
                }
                logd("SOCKS5 acceptor exited")
            }, "vless-acceptor")
            acceptorThread!!.isDaemon = true
            acceptorThread!!.start()

            Log.i(TAG, "VLESS Bridge started on $listenHost:$listenPort")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VLESS bridge: ${e.message}", e)
            stop()
            Result.failure(e)
        }
    }

    fun stop() {
        if (!running.getAndSet(false) && fragmentForwarder == null) return
        Log.i(TAG, "Stopping VLESS Bridge")
        try { serverSocket?.close() } catch (_: Exception) {}
        acceptorThread?.interrupt()
        connectionThreads.forEach { it.interrupt() }
        connectionThreads.clear()
        fragmentForwarder?.stop()
        fragmentForwarder = null
        serverSocket = null
        acceptorThread = null
    }

    fun isRunning(): Boolean = running.get() && serverSocket?.isClosed == false
    fun isClientHealthy(): Boolean = isRunning()
    fun getTunnelTxBytes(): Long = tunnelTxBytes.get()
    fun getTunnelRxBytes(): Long = tunnelRxBytes.get()

    fun resetTrafficStats() {
        tunnelTxBytes.set(0)
        tunnelRxBytes.set(0)
    }

    /**
     * Structural probe: verifies the parts of the connection that depend on
     * *your* config — TCP to the CDN, TLS (correct SNI), and the WebSocket
     * upgrade (correct WS path). Catches wrong `cdnIp`, wrong `serverDomain`,
     * wrong `wsPath`.
     *
     * Intentionally does NOT send a VLESS CONNECT with a destination: CF
     * Workers commonly filter outbound destinations (e.g., port 80) and would
     * close the WS frame even on a perfectly valid setup, producing false
     * negatives. UUID / backend-routing misconfigurations surface as "0 bytes
     * transferred" thanks to honest byte counting in [handleVlessTcp] /
     * [handleVlessWs], which is good enough — and has no false positives.
     *
     * Must be called after [start] has returned success.
     */
    fun probe(timeoutMs: Int = 10_000): Result<Unit> {
        if (!isRunning()) return Result.failure(IllegalStateException("VlessBridge not running"))
        var raw: Socket? = null
        var tunnel: Socket? = null
        return try {
            val sock = Socket()
            raw = sock
            sock.tcpNoDelay = true
            val target = if (fragmentEnabled) {
                val fragPort = (serverSocket?.localPort ?: 0) + 1
                InetSocketAddress("127.0.0.1", fragPort)
            } else {
                InetSocketAddress(cdnIp, cdnPort)
            }
            sock.connect(target, TCP_CONNECT_TIMEOUT_MS)
            sock.soTimeout = timeoutMs

            val tIn: InputStream
            val tOut: OutputStream
            if (security == "none") {
                tunnel = sock
                tIn = BufferedInputStream(sock.getInputStream())
                tOut = sock.getOutputStream()
            } else {
                val sni = resolveSni()
                val sslCtx = SSLContext.getInstance("TLS")
                sslCtx.init(null, trustAllManagers(), SecureRandom())
                val ssl = sslCtx.socketFactory.createSocket(sock, sni, cdnPort, true) as SSLSocket
                ssl.sslParameters = ssl.sslParameters.apply {
                    serverNames = listOf(SNIHostName(sni))
                }
                ssl.soTimeout = timeoutMs
                ssl.startHandshake()
                tunnel = ssl
                tIn = BufferedInputStream(ssl.getInputStream())
                tOut = ssl.getOutputStream()
            }

            // For WS transport, verify the upgrade completes — that confirms
            // the WS path is correct and the Worker is accepting clients.
            // For TCP transport there's nothing else to probe structurally
            // (VLESS auth happens per-flow and we deliberately skip it here).
            if (transport == "ws") {
                val wsKey = generateWsKey()
                tOut.write(buildWsUpgradeRequest(wsKey).toByteArray(Charsets.US_ASCII))
                tOut.flush()
                val statusLine = readLine(tIn) ?: throw Exception("No WS response (wrong CDN/domain?)")
                if ("101" !in statusLine) throw Exception("WS upgrade failed: $statusLine (check wsPath)")
                // Drain response headers so the server finishes its write.
                while (true) { val line = readLine(tIn) ?: break; if (line.isEmpty()) break }
            }

            Log.i(TAG, "VLESS probe succeeded (structural)")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.w(TAG, "VLESS probe failed: ${e.javaClass.simpleName} ${e.message}")
            Result.failure(e)
        } finally {
            try { tunnel?.close() } catch (_: Exception) {}
            try { raw?.close() } catch (_: Exception) {}
        }
    }

    // ── SOCKS5 Handling ──────────────────────────────────────────────

    private fun handleSocks5Connection(client: Socket) {
        try {
            Log.d(TAG, "SOCKS5 connection from ${client.remoteSocketAddress}")
            client.tcpNoDelay = true
            val input = BufferedInputStream(client.getInputStream())
            val output = client.getOutputStream()

            // SOCKS5 greeting: version(1) + nmethods(1) + methods(n)
            val ver = input.read()
            if (ver != 0x05) { client.close(); return }
            val nMethods = input.read()
            val methods = ByteArray(nMethods)
            readFully(input, methods)
            // Reply: no auth required
            output.write(byteArrayOf(0x05, 0x00))
            output.flush()

            // SOCKS5 request: ver(1) + cmd(1) + rsv(1) + atyp(1) + addr + port(2)
            val reqVer = input.read()
            val cmd = input.read()
            val rsv = input.read()
            val atyp = input.read()

            if (reqVer != 0x05 || cmd != 0x01) {
                // Only CONNECT is supported
                output.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                output.flush()
                client.close()
                return
            }

            val destHost: String
            val destPort: Int

            when (atyp) {
                0x01 -> { // IPv4
                    val addr = ByteArray(4)
                    readFully(input, addr)
                    destHost = "${addr[0].toInt() and 0xFF}.${addr[1].toInt() and 0xFF}.${addr[2].toInt() and 0xFF}.${addr[3].toInt() and 0xFF}"
                }
                0x03 -> { // Domain
                    val len = input.read()
                    val domain = ByteArray(len)
                    readFully(input, domain)
                    destHost = String(domain, Charsets.US_ASCII)
                }
                0x04 -> { // IPv6
                    val addr = ByteArray(16)
                    readFully(input, addr)
                    val sb = StringBuilder()
                    for (i in 0 until 16 step 2) {
                        if (i > 0) sb.append(':')
                        sb.append(String.format("%02x%02x", addr[i], addr[i + 1]))
                    }
                    destHost = sb.toString()
                }
                else -> {
                    client.close(); return
                }
            }

            val portHi = input.read()
            val portLo = input.read()
            destPort = (portHi shl 8) or portLo

            Log.d(TAG, "SOCKS5 CONNECT $destHost:$destPort")

            // Reply success (we'll connect through VLESS)
            output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            output.flush()

            // Read first payload from client (e.g., TLS ClientHello) to bundle with VLESS header.
            // This avoids a deadlock where the remote server waits for data before responding.
            val firstPayload = ByteArray(BUFFER_SIZE)
            val firstPayloadLen = input.read(firstPayload)
            val initialData = if (firstPayloadLen > 0) firstPayload.copyOf(firstPayloadLen) else ByteArray(0)
            logd("First payload from client: ${initialData.size} bytes for $destHost:$destPort")

            // Establish VLESS tunnel to destination
            handleVlessConnect(client, destHost, destPort, initialData)

        } catch (e: Exception) {
            Log.e(TAG, "SOCKS5 error: ${e.message}")
        } finally {
            try { client.close() } catch (_: Exception) {}
            connectionThreads.remove(Thread.currentThread())
        }
    }

    // ── VLESS Connection ─────────────────────────────────────────────

    private fun handleVlessConnect(client: Socket, destHost: String, destPort: Int, initialData: ByteArray = ByteArray(0)) {
        // Step 1: TCP connect (through fragment forwarder if enabled, or direct to CDN)
        val raw: Socket
        if (fragmentEnabled) {
            val fragmentPort = (serverSocket?.localPort ?: 0) + 1
            raw = Socket()
            raw.connect(InetSocketAddress("127.0.0.1", fragmentPort), TCP_CONNECT_TIMEOUT_MS)
        } else {
            raw = Socket()
            raw.connect(InetSocketAddress(cdnIp, cdnPort), TCP_CONNECT_TIMEOUT_MS)
        }
        raw.tcpNoDelay = true

        try {
            // Step 2: TLS handshake (or skip for security=none)
            val tunnelIn: InputStream
            val tunnelOut: OutputStream
            val tunnelSocket: Socket

            if (security == "none") {
                logd("Skipping TLS (security=none)")
                tunnelSocket = raw
                tunnelIn = BufferedInputStream(raw.getInputStream())
                tunnelOut = raw.getOutputStream()
            } else {
                val sni = resolveSni()
                val sslCtx = SSLContext.getInstance("TLS")
                sslCtx.init(null, trustAllManagers(), SecureRandom())
                val sslSocket = sslCtx.socketFactory.createSocket(raw, sni, cdnPort, true) as SSLSocket
                sslSocket.sslParameters = sslSocket.sslParameters.apply {
                    serverNames = listOf(SNIHostName(sni))
                }
                sslSocket.startHandshake()
                Log.d(TAG, "TLS handshake complete (${sslSocket.session.protocol})")
                tunnelSocket = sslSocket
                tunnelIn = BufferedInputStream(sslSocket.getInputStream())
                tunnelOut = sslSocket.getOutputStream()
            }

            if (transport == "tcp") {
                handleVlessTcp(client, tunnelIn, tunnelOut, destHost, destPort, initialData)
            } else {
                handleVlessWs(client, tunnelSocket, tunnelIn, tunnelOut, destHost, destPort, initialData)
            }

        } catch (e: Exception) {
            Log.e(TAG, "VLESS connect error for $destHost:$destPort: ${e.message}")
        } finally {
            try { raw.close() } catch (_: Exception) {}
        }
    }

    /**
     * TCP transport: VLESS header + raw bidirectional relay (no WebSocket framing).
     *
     * NOT EXPOSED IN THE UI — WebSocket is the only user-selectable transport.
     * The profile editor has no transport selector, and the URI importer rejects
     * `type=tcp` with a warning. Reason: SlipNet's VLESS is positioned as a
     * CDN-fronted tunnel, and raw TCP defeats that (no CDN to hide behind, no
     * TLS ClientHello for SNI fragmentation to fragment). Re-expose only if a
     * concrete non-CDN use case shows up.
     */
    private fun handleVlessTcp(client: Socket, tunnelIn: InputStream, tunnelOut: OutputStream, destHost: String, destPort: Int, initialData: ByteArray = ByteArray(0)) {

        // Send VLESS header + initial payload in one write
        val uuid = parseUUID(vlessUuid)
        val vlessHeader = buildVlessRequest(uuid, destHost, destPort)
        tunnelOut.write(vlessHeader)
        if (initialData.isNotEmpty()) {
            tunnelOut.write(initialData)
        }
        tunnelOut.flush()

        // Read VLESS response: version(1) + addons_len(1) + [addons] + optional payload
        val respVersion = tunnelIn.read()
        if (respVersion < 0) throw Exception("No VLESS response")
        val respAddonsLen = tunnelIn.read()
        if (respAddonsLen < 0) throw Exception("Truncated VLESS response")
        if (respAddonsLen > 0) {
            val addons = ByteArray(respAddonsLen)
            readFully(tunnelIn, addons)
        }

        // Only count the buffered payload as "transferred" once the handshake
        // has actually succeeded — otherwise a misconfigured tunnel racks up
        // phantom upload bytes on bytes that never reach a real server.
        if (initialData.isNotEmpty()) tunnelTxBytes.addAndGet(initialData.size.toLong())

        logd("VLESS/TCP session established for $destHost:$destPort")

        // Raw bidirectional relay (no WS framing)
        relayRaw(client, tunnelIn, tunnelOut)
    }

    /**
     * WebSocket transport: WS upgrade with VLESS early data + WS-framed relay.
     *
     * WebSocket transport: WS upgrade + VLESS header as WS frame.
     */
    private fun handleVlessWs(client: Socket, tunnelSocket: Socket, tunnelIn: InputStream, tunnelOut: OutputStream, destHost: String, destPort: Int, initialData: ByteArray = ByteArray(0)) {
        val wsKey = generateWsKey()
        val upgrade = buildWsUpgradeRequest(wsKey)
        tunnelOut.write(upgrade.toByteArray(Charsets.US_ASCII))
        tunnelOut.flush()

        // Read and log the full 101 response
        val statusLine = readLine(tunnelIn)
        if (statusLine == null || "101" !in statusLine) {
            Log.w(TAG, "WebSocket upgrade failed: $statusLine")
            tunnelSocket.close()
            return
        }
        val responseHeaders = mutableListOf(statusLine)
        while (true) {
            val line = readLine(tunnelIn) ?: break
            if (line.isEmpty()) break
            responseHeaders.add(line)
        }
        Log.d(TAG, "WS upgrade for $destHost:$destPort — ${responseHeaders.joinToString(" | ")}")

        // Send VLESS header + initial payload bundled in a single WS frame.
        // The remote server needs the first payload (e.g., TLS ClientHello) to respond,
        // which triggers the Worker to send back the VLESS response.
        val uuid = parseUUID(vlessUuid)
        val vlessHeader = buildVlessRequest(uuid, destHost, destPort)
        val bundled = if (initialData.isNotEmpty()) {
            vlessHeader + initialData
        } else {
            vlessHeader
        }
        Log.d(TAG, "VLESS request (${vlessHeader.size}b header + ${initialData.size}b payload) for $destHost:$destPort")
        writeWsFrame(tunnelOut, bundled)

        // Read server response — log raw bytes for debugging
        val b0 = tunnelIn.read()
        if (b0 < 0) throw Exception("No VLESS response (EOF)")
        val b1 = tunnelIn.read()
        if (b1 < 0) throw Exception("No VLESS response (EOF after b0=${String.format("%02x", b0)})")

        // Only credit the buffered payload once the server actually answered.
        if (initialData.isNotEmpty()) tunnelTxBytes.addAndGet(initialData.size.toLong())
        val opcode = b0 and 0x0F
        val fin = (b0 and 0x80) != 0
        val masked = (b1 and 0x80) != 0
        var payloadLen = (b1 and 0x7F).toLong()
        Log.d(TAG, "WS frame: fin=$fin opcode=$opcode masked=$masked len=$payloadLen for $destHost:$destPort")

        if (opcode == 0x08) throw Exception("Server sent WS close frame")

        if (payloadLen == 126L) {
            val h = tunnelIn.read(); val l = tunnelIn.read()
            if (h < 0 || l < 0) throw Exception("Truncated extended length")
            payloadLen = ((h shl 8) or l).toLong()
        } else if (payloadLen == 127L) {
            var len = 0L
            for (i in 0 until 8) { val b = tunnelIn.read(); if (b < 0) throw Exception("Truncated 64-bit length"); len = (len shl 8) or b.toLong() }
            payloadLen = len
        }

        var maskKey: ByteArray? = null
        if (masked) { maskKey = ByteArray(4); readFully(tunnelIn, maskKey) }

        if (payloadLen > 16 * 1024 * 1024) throw Exception("Frame too large: $payloadLen")

        val payload = ByteArray(payloadLen.toInt())
        if (payloadLen > 0) {
            readFully(tunnelIn, payload)
            if (maskKey != null) { for (i in payload.indices) { payload[i] = (payload[i].toInt() xor maskKey[i % 4].toInt()).toByte() } }
        }

        Log.d(TAG, "VLESS response (${payload.size}b): ${payload.take(16).joinToString(" ") { String.format("%02x", it) }} for $destHost:$destPort")

        if (payload.size < 2) throw Exception("Invalid VLESS response (${payload.size} bytes)")
        val respAddonsLen = payload[1].toInt() and 0xFF
        val responsePayloadOffset = 2 + respAddonsLen
        if (responsePayloadOffset < payload.size) {
            val initialData = payload.copyOfRange(responsePayloadOffset, payload.size)
            client.getOutputStream().write(initialData)
            client.getOutputStream().flush()
            tunnelRxBytes.addAndGet(initialData.size.toLong())
        }

        Log.i(TAG, "VLESS/WS session established for $destHost:$destPort")

        // Bidirectional relay with WS framing
        relayVless(client, tunnelIn, tunnelOut)
    }

    /**
     * Raw bidirectional relay for TCP transport (no WebSocket framing).
     */
    private fun relayRaw(client: Socket, tlsIn: InputStream, tlsOut: OutputStream) {
        val executor = Executors.newFixedThreadPool(2)
        val clientIn = client.getInputStream()
        val clientOut = client.getOutputStream()

        // Client -> VLESS server (raw)
        val f1 = executor.submit {
            try {
                val buf = ByteArray(BUFFER_SIZE)
                while (!Thread.currentThread().isInterrupted) {
                    val n = clientIn.read(buf)
                    if (n <= 0) break
                    tlsOut.write(buf, 0, n)
                    tlsOut.flush()
                    tunnelTxBytes.addAndGet(n.toLong())
                }
            } catch (_: Exception) {}
        }

        // VLESS server -> Client (raw)
        val f2 = executor.submit {
            try {
                val buf = ByteArray(BUFFER_SIZE)
                while (!Thread.currentThread().isInterrupted) {
                    val n = tlsIn.read(buf)
                    if (n <= 0) break
                    clientOut.write(buf, 0, n)
                    clientOut.flush()
                    tunnelRxBytes.addAndGet(n.toLong())
                }
            } catch (_: Exception) {}
        }

        try { f1.get() } catch (_: Exception) {}
        try { f2.get() } catch (_: Exception) {}
        executor.shutdownNow()
    }

    /**
     * Build VLESS request header.
     * Format: version(1) + UUID(16) + addons_len(1) + command(1) + port(2) + addr_type(1) + addr
     */
    private fun buildVlessRequest(uuid: ByteArray, host: String, port: Int): ByteArray {
        val buf = ByteArrayOutputStream()
        buf.write(VLESS_VERSION.toInt())
        buf.write(uuid)
        buf.write(0) // addons length = 0

        buf.write(VLESS_CMD_TCP.toInt())
        buf.write(port shr 8 and 0xFF)
        buf.write(port and 0xFF)

        // Check if host is an IP address
        val ipv4Regex = Regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")
        if (ipv4Regex.matches(host)) {
            buf.write(VLESS_ADDR_IPV4.toInt())
            host.split('.').forEach { buf.write(it.toInt()) }
        } else if (host.contains(':')) {
            // IPv6
            buf.write(VLESS_ADDR_IPV6.toInt())
            val parts = expandIPv6(host)
            for (part in parts) {
                buf.write(part shr 8 and 0xFF)
                buf.write(part and 0xFF)
            }
        } else {
            // Domain
            buf.write(VLESS_ADDR_DOMAIN.toInt())
            val domainBytes = host.toByteArray(Charsets.US_ASCII)
            buf.write(domainBytes.size)
            buf.write(domainBytes)
        }

        return buf.toByteArray()
    }

    /**
     * Relay data between client and WebSocket-framed VLESS tunnel.
     * Client side is raw TCP; tunnel side uses WebSocket binary frames.
     */
    private fun relayVless(client: Socket, wsInput: InputStream, wsOutput: OutputStream) {
        val threadCount = if (wsPaddingEnabled) 3 else 2
        val executor = Executors.newFixedThreadPool(threadCount)
        val clientIn = client.getInputStream()
        val clientOut = client.getOutputStream()

        // Client -> VLESS (wrap in WS frames)
        val f1 = executor.submit {
            try {
                val buf = ByteArray(BUFFER_SIZE)
                while (!Thread.currentThread().isInterrupted) {
                    val n = clientIn.read(buf)
                    if (n <= 0) break
                    synchronized(wsOutput) {
                        writeWsFrame(wsOutput, buf.copyOf(n))
                    }
                    tunnelTxBytes.addAndGet(n.toLong())
                }
            } catch (_: Exception) {}
        }

        // VLESS -> Client (unwrap WS frames)
        val f2 = executor.submit {
            try {
                while (!Thread.currentThread().isInterrupted) {
                    val frame = readWsFrame(wsInput) ?: break
                    if (frame.isEmpty()) continue
                    clientOut.write(frame)
                    clientOut.flush()
                    tunnelRxBytes.addAndGet(frame.size.toLong())
                }
            } catch (_: Exception) {}
        }

        // Cover traffic: send random-size WS ping frames at random intervals
        val f3 = if (wsPaddingEnabled) executor.submit {
            try {
                while (!Thread.currentThread().isInterrupted) {
                    val delay = 500 + random.nextInt(2000) // 0.5-2.5s between pings
                    Thread.sleep(delay.toLong())
                    val pingSize = 4 + random.nextInt(120) // 4-124 bytes
                    val pingPayload = ByteArray(pingSize)
                    random.nextBytes(pingPayload)
                    synchronized(wsOutput) {
                        writeWsFrame(wsOutput, pingPayload, opcode = 0x09)
                    }
                }
            } catch (_: Exception) {}
        } else null

        try { f1.get() } catch (_: Exception) {}
        try { f2.get() } catch (_: Exception) {}
        try { f3?.get() } catch (_: Exception) {}
        executor.shutdownNow()
    }

    // ── WebSocket Framing (RFC 6455) ─────────────────────────────────

    /**
     * Write a WebSocket frame with masking (client must mask).
     * Default opcode 0x02 = binary, 0x09 = ping.
     */
    private fun writeWsFrame(out: OutputStream, payload: ByteArray, opcode: Int = 0x02) {
        val header = ByteArrayOutputStream()
        // FIN + opcode
        header.write(0x80 or opcode)
        // Mask bit set (client) + length
        val len = payload.size
        when {
            len <= 125 -> header.write(0x80 or len)
            len <= 65535 -> {
                header.write(0x80 or 126)
                header.write(len shr 8 and 0xFF)
                header.write(len and 0xFF)
            }
            else -> {
                header.write(0x80 or 127)
                for (i in 7 downTo 0) {
                    header.write((len.toLong() shr (i * 8) and 0xFF).toInt())
                }
            }
        }
        // Masking key
        val mask = ByteArray(4)
        SecureRandom().nextBytes(mask)
        header.write(mask)

        // Masked payload
        val masked = ByteArray(len)
        for (i in 0 until len) {
            masked[i] = (payload[i].toInt() xor mask[i % 4].toInt()).toByte()
        }

        out.write(header.toByteArray())
        out.write(masked)
        out.flush()
    }

    /**
     * Read a WebSocket frame. Returns payload bytes, or null on EOF/close.
     */
    private fun readWsFrame(input: InputStream): ByteArray? {
        val b0 = input.read()
        if (b0 < 0) return null
        val b1 = input.read()
        if (b1 < 0) return null

        val opcode = b0 and 0x0F
        val masked = (b1 and 0x80) != 0
        var payloadLen = (b1 and 0x7F).toLong()

        if (payloadLen == 126L) {
            val h = input.read()
            val l = input.read()
            if (h < 0 || l < 0) return null
            payloadLen = ((h shl 8) or l).toLong()
        } else if (payloadLen == 127L) {
            var len = 0L
            for (i in 0 until 8) {
                val b = input.read()
                if (b < 0) return null
                len = (len shl 8) or b.toLong()
            }
            payloadLen = len
        }

        var maskKey: ByteArray? = null
        if (masked) {
            maskKey = ByteArray(4)
            readFully(input, maskKey)
        }

        if (payloadLen > 16 * 1024 * 1024) return null // 16MB sanity limit

        val payload = ByteArray(payloadLen.toInt())
        if (payloadLen > 0) {
            readFully(input, payload)
            if (maskKey != null) {
                for (i in payload.indices) {
                    payload[i] = (payload[i].toInt() xor maskKey[i % 4].toInt()).toByte()
                }
            }
        }

        return when (opcode) {
            0x01, 0x02, 0x00 -> payload // text, binary, continuation
            0x08 -> null // close
            0x09 -> { // ping -> pong
                // Server shouldn't mask, we just read it. Don't reply with pong for simplicity.
                ByteArray(0)
            }
            0x0A -> ByteArray(0) // pong (ignore)
            else -> payload
        }
    }

    // ── DPI Evasion ──────────────────────────────────────────────────

    /** Browser User-Agent strings for header obfuscation. */
    private val userAgents = listOf(
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.64 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.101 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36"
    )

    /**
     * Build the WebSocket upgrade request.
     *
     * When header obfuscation is enabled, adds browser-like headers (User-Agent, Accept, etc.)
     * and randomizes header order to defeat DPI that fingerprints by header structure.
     */
    private fun buildWsUpgradeRequest(wsKey: String): String {
        if (!wsHeaderObfuscation) {
            return "GET $wsPath HTTP/1.1\r\n" +
                    "Host: $serverDomain\r\n" +
                    "Upgrade: websocket\r\n" +
                    "Connection: Upgrade\r\n" +
                    "Sec-WebSocket-Key: $wsKey\r\n" +
                    "Sec-WebSocket-Version: 13\r\n" +
                    "\r\n"
        }

        val headers = mutableListOf(
            "Host: $serverDomain",
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Key: $wsKey",
            "Sec-WebSocket-Version: 13",
            "User-Agent: ${userAgents[random.nextInt(userAgents.size)]}",
            "Accept-Language: en-US,en;q=0.9",
            "Accept-Encoding: gzip, deflate, br",
            "Cache-Control: no-cache",
            "Pragma: no-cache"
        )
        headers.shuffle(random)

        return "GET $wsPath HTTP/1.1\r\n" +
                headers.joinToString("\r\n") + "\r\n\r\n"
    }

    // ── Utility ──────────────────────────────────────────────────────

    /**
     * SNI for the CDN TLS handshake: the explicit [vlessSni], or the WS Host
     * ([serverDomain]) when none is set. Matches V2Ray's single-serverName model.
     */
    private fun resolveSni(): String = vlessSni.ifBlank { serverDomain }

    private fun parseUUID(uuid: String): ByteArray {
        val hex = uuid.replace("-", "")
        require(hex.length == 32) { "Invalid UUID: $uuid" }
        val bytes = ByteArray(16)
        for (i in 0 until 16) {
            bytes[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return bytes
    }

    private fun generateWsKey(): String {
        val bytes = ByteArray(16)
        SecureRandom().nextBytes(bytes)
        return android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
    }

    private fun readFully(input: InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n <= 0) throw java.io.EOFException("Unexpected EOF")
            off += n
        }
    }

    private fun readLine(input: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = input.read()
            if (b < 0) return if (sb.isEmpty()) null else sb.toString()
            if (b == '\n'.code) {
                val s = sb.toString()
                return if (s.endsWith('\r')) s.dropLast(1) else s
            }
            sb.append(b.toChar())
        }
    }

    private fun expandIPv6(addr: String): List<Int> {
        // Simple IPv6 expansion — enough for address encoding
        val parts = addr.split(':').map { if (it.isEmpty()) 0 else it.toInt(16) }
        if (parts.size == 8) return parts
        // Handle :: expansion
        val result = mutableListOf<Int>()
        val sections = addr.split("::")
        val left = if (sections[0].isEmpty()) emptyList() else sections[0].split(':').map { it.toInt(16) }
        val right = if (sections.size > 1 && sections[1].isNotEmpty()) sections[1].split(':').map { it.toInt(16) } else emptyList()
        result.addAll(left)
        repeat(8 - left.size - right.size) { result.add(0) }
        result.addAll(right)
        return result
    }

    private fun trustAllManagers(): Array<TrustManager> = arrayOf(object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    })

    private fun bindServerSocket(host: String, port: Int): ServerSocket {
        for (attempt in 0 until BIND_MAX_RETRIES) {
            try {
                val ss = ServerSocket()
                ss.reuseAddress = true
                ss.bind(InetSocketAddress(host, port))
                return ss
            } catch (e: Exception) {
                if (attempt < BIND_MAX_RETRIES - 1) {
                    Thread.sleep(BIND_RETRY_DELAY_MS)
                } else throw e
            }
        }
        throw IllegalStateException("Failed to bind after $BIND_MAX_RETRIES attempts")
    }
}
