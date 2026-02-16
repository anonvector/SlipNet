package app.slipnet.tunnel

import app.slipnet.util.AppLog as Log
import java.io.BufferedOutputStream
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
import java.net.URL
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * A known DoH server with name, URL, and pre-resolved IP addresses (IPv4 + IPv6).
 * Pre-resolved IPs bypass ISP DNS when the app is excluded from VPN via addDisallowedApplication.
 */
data class DohServer(
    val name: String,
    val url: String,
    val ips: List<String> = emptyList()
)

/**
 * Complete list of known DoH servers.
 * IPs sourced from Intra app (Jigsaw/Google) + additional providers.
 */
val DOH_SERVERS = listOf(
    // --- Major global providers ---
    DohServer(
        "Google", "https://dns.google/dns-query",
        listOf("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844")
    ),
    DohServer(
        "Cloudflare", "https://cloudflare-dns.com/dns-query",
        listOf("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001")
    ),
    DohServer(
        "Cloudflare 1.1.1.1", "https://1.1.1.1/dns-query",
        listOf("1.1.1.1")
    ),
    DohServer(
        "Quad9", "https://dns.quad9.net/dns-query",
        listOf("9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::fe:9")
    ),
    DohServer(
        "OpenDNS", "https://doh.opendns.com/dns-query",
        listOf("146.112.41.2", "2620:119:fc::2")
    ),
    DohServer(
        "CleanBrowsing", "https://doh.cleanbrowsing.org/doh/security-filter/",
        listOf("185.228.168.9", "185.228.169.9", "2a0d:2a00:1::2", "2a0d:2a00:2::2")
    ),
    DohServer(
        "Canadian Shield", "https://private.canadianshield.cira.ca/dns-query",
        listOf("149.112.121.10", "149.112.122.10", "2620:10a:80bb::10", "2620:10a:80bc::10")
    ),
    // --- Privacy-focused ---
    DohServer(
        "Mullvad", "https://base.dns.mullvad.net/dns-query",
        listOf("194.242.2.2", "2a07:e340::2")
    ),
    DohServer(
        "Applied Privacy", "https://doh.applied-privacy.net/query"
    ),
    DohServer(
        "Digitale Gesellschaft", "https://dns.digitale-gesellschaft.ch/dns-query",
        listOf("185.95.218.42", "185.95.218.43", "2a05:fc84::42", "2a05:fc84::43")
    ),
    DohServer(
        "DNS.SB", "https://doh.dns.sb/dns-query",
        listOf("185.222.222.222", "45.11.45.11")
    ),
    DohServer(
        "42l Association", "https://doh.42l.fr/dns-query",
        listOf("45.155.171.163", "2a09:6382:4000:3:45:155:171:163")
    ),
    // --- Regional ---
    DohServer(
        "Andrews & Arnold", "https://dns.aa.net.uk/dns-query",
        listOf("217.169.20.22", "217.169.20.23", "2001:8b0::2022", "2001:8b0::2023")
    ),
    DohServer("IIJ Japan", "https://public.dns.iij.jp/dns-query"),
    // --- Additional ---
    DohServer(
        "DNS for Family", "https://dns-doh.dnsforfamily.com/dns-query",
        listOf("78.47.64.161")
    ),
    DohServer("Rethink DNS", "https://sky.rethinkdns.com/dns-query"),
    DohServer("JoinDNS4EU", "https://unfiltered.joindns4.eu/dns-query"),
)

/**
 * DNS-over-HTTPS bridge that creates a local SOCKS5 proxy.
 * DNS queries (port 53) are encrypted via HTTPS (RFC 8484).
 * All other traffic is proxied directly (no encryption).
 *
 * Uses OkHttp with HTTP/2, connection pooling, and pre-resolved IP addresses
 * for known DoH servers to bypass ISP DNS resolution.
 *
 * Traffic flow:
 * App DNS -> TUN -> hev-socks5-tunnel -> FWD_UDP (0x05) -> DohBridge -> HTTPS POST to DoH server
 * App TCP -> TUN -> hev-socks5-tunnel -> CONNECT (0x01) -> DohBridge -> Direct Socket.connect
 * App UDP -> TUN -> hev-socks5-tunnel -> FWD_UDP (0x05) -> DohBridge -> Direct DatagramSocket
 */
object DohBridge {
    private const val TAG = "DohBridge"
    @Volatile var debugLogging = false
    @Volatile var domainRouter: DomainRouter = DomainRouter.DISABLED
    private fun logd(msg: String) { if (debugLogging) Log.d(TAG, msg) }
    private const val BIND_MAX_RETRIES = 10
    private const val BIND_RETRY_DELAY_MS = 200L
    private const val BUFFER_SIZE = 32768
    private const val TCP_CONNECT_TIMEOUT_MS = 10000

    /** Hostname → IPs lookup built from [DOH_SERVERS] for the custom OkHttp DNS resolver. */
    private val serverIpMap: Map<String, List<String>> by lazy {
        DOH_SERVERS
            .filter { it.ips.isNotEmpty() }
            .associate { server ->
                try { URL(server.url).host } catch (_: Exception) { "" } to server.ips
            }
            .filterKeys { it.isNotEmpty() }
    }

    private var dohUrl: String = ""
    private var serverSocket: ServerSocket? = null
    private var acceptorThread: Thread? = null
    private val running = AtomicBoolean(false)
    private val connectionThreads = CopyOnWriteArrayList<Thread>()
    @Volatile
    private var httpClient: OkHttpClient? = null

    /**
     * Create an OkHttpClient configured for DoH with:
     * - HTTP/2 (like Intra's Go HTTP client)
     * - Connection pooling and reuse
     * - Custom DNS resolver with pre-resolved IPs for known DoH servers
     */
    internal fun createHttpClient(): OkHttpClient {
        return OkHttpClient.Builder()
            .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .writeTimeout(5, TimeUnit.SECONDS)
            .dns(object : Dns {
                override fun lookup(hostname: String): List<InetAddress> {
                    // Pre-resolved IPs (fast, bypass ISP DNS)
                    val preResolved = serverIpMap[hostname]?.mapNotNull { ip ->
                        try { InetAddress.getByName(ip) } catch (_: Exception) { null }
                    } ?: emptyList()

                    // System DNS as fallback (handles stale/outdated pre-resolved IPs)
                    val systemResolved = try {
                        Dns.SYSTEM.lookup(hostname)
                    } catch (_: Exception) { emptyList() }

                    // Combine: pre-resolved first, then system DNS (deduplicated)
                    val combined = (preResolved + systemResolved)
                        .distinctBy { it.hostAddress }

                    if (combined.isNotEmpty()) {
                        if (preResolved.isNotEmpty()) {
                            logd("DNS: $hostname → ${combined.size} IPs (${preResolved.size} pre-resolved + system)")
                        }
                        return combined
                    }

                    throw java.net.UnknownHostException("No addresses for $hostname")
                }
            })
            .build()
    }

    /**
     * Start the DoH SOCKS5 proxy.
     *
     * @param dohUrl DoH server URL (e.g., "https://cloudflare-dns.com/dns-query")
     * @param listenPort Local port for the SOCKS5 proxy
     * @param listenHost Local host for the SOCKS5 proxy
     * @return Result indicating success or failure
     */
    fun start(dohUrl: String, listenPort: Int, listenHost: String = "127.0.0.1"): Result<Unit> {
        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting DoH bridge")
        Log.i(TAG, "  DoH URL: $dohUrl")
        Log.i(TAG, "  Listen: $listenHost:$listenPort")
        Log.i(TAG, "========================================")

        stop()
        this.dohUrl = dohUrl
        httpClient = createHttpClient()

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
            }, "doh-socks5-acceptor").also { it.isDaemon = true; it.start() }

            Log.i(TAG, "DoH SOCKS5 proxy started on $listenHost:$listenPort")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start DoH bridge", e)
            stop()
            Result.failure(e)
        }
    }

    /**
     * Stop the DoH bridge.
     */
    fun stop() {
        if (!running.getAndSet(false) && serverSocket == null) {
            return
        }
        logd("Stopping DoH bridge...")

        try {
            serverSocket?.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error closing server socket: ${e.message}")
        }
        serverSocket = null

        acceptorThread?.interrupt()
        acceptorThread = null

        for (thread in connectionThreads) {
            thread.interrupt()
        }
        connectionThreads.clear()

        httpClient?.let { client ->
            client.dispatcher.cancelAll()
            client.connectionPool.evictAll()
        }
        httpClient = null

        logd("DoH bridge stopped")
    }

    fun isRunning(): Boolean = running.get()

    fun isClientHealthy(): Boolean {
        val ss = serverSocket ?: return false
        return running.get() && !ss.isClosed
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
                            return@Thread
                        }
                    }

                    val portHigh = input.read()
                    val portLow = input.read()
                    val destPort = (portHigh shl 8) or portLow

                    // Handle FWD_UDP (cmd 0x05)
                    if (cmd == 0x05) {
                        socket.soTimeout = 0
                        handleFwdUdp(input, output)
                        return@Thread
                    }

                    // Block DNS-over-TLS (port 853) to prevent Android Private DNS
                    // from bypassing our DoH. This forces fallback to plain DNS (port 53).
                    if (destPort == 853) {
                        logd("CONNECT: blocking DoT to $destHost:853 (forcing plain DNS)")
                        output.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                        output.flush()
                        return@Thread
                    }

                    // Intercept DNS-over-TCP (port 53) and forward through DoH
                    if (destPort == 53) {
                        logd("CONNECT: intercepting DNS-over-TCP to $destHost:53")
                        output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                        output.flush()
                        socket.soTimeout = 30000
                        handleDnsTcp(input, output)
                        return@Thread
                    }

                    // Handle CONNECT (cmd 0x01) — direct TCP proxy
                    handleConnect(destHost, destPort, socket, input, output)
                }
            } catch (e: Exception) {
                if (running.get()) {
                    logd("Connection handler error: ${e.message}")
                }
            }
        }, "doh-socks5-handler")
        thread.isDaemon = true
        connectionThreads.add(thread)
        thread.start()

        connectionThreads.removeAll { !it.isAlive }
    }

    /**
     * Handle SOCKS5 CONNECT — direct TCP proxy (no encryption).
     * With domain routing: sniffs TLS SNI / HTTP Host for routing decisions.
     * Note: DohBridge CONNECT traffic is already direct, so routing mainly adds logging.
     */
    private fun handleConnect(
        destHost: String,
        destPort: Int,
        clientSocket: Socket,
        clientInput: InputStream,
        clientOutput: OutputStream
    ) {
        val router = domainRouter
        if (router.enabled) {
            handleConnectWithRouting(router, destHost, destPort, clientSocket, clientInput, clientOutput)
            return
        }

        // Original flow — direct connect
        connectDirect(destHost, destPort, clientSocket, clientInput, clientOutput, true)
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
            logd("CONNECT: domain routing bypass for $effectiveHost:$destPort (already direct)")
        }

        // DohBridge always connects directly — just handle the sniffed buffer
        clientSocket.soTimeout = 0
        val effectiveInput = if (sniffLen > 0)
            SequenceInputStream(ByteArrayInputStream(sniffBuffer!!, 0, sniffLen), clientInput)
        else clientInput
        connectDirect(destHost, destPort, clientSocket, effectiveInput, clientOutput, !wasEarlyReply)
    }

    private fun connectDirect(
        destHost: String,
        destPort: Int,
        clientSocket: Socket,
        clientInput: InputStream,
        clientOutput: OutputStream,
        sendReply: Boolean
    ) {
        val remoteSocket: Socket
        try {
            remoteSocket = Socket()
            remoteSocket.connect(InetSocketAddress(destHost, destPort), TCP_CONNECT_TIMEOUT_MS)
        } catch (e: Exception) {
            logd("CONNECT: failed to connect to $destHost:$destPort: ${e.message}")
            if (sendReply) {
                clientOutput.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                clientOutput.flush()
            }
            return
        }

        logd("CONNECT: $destHost:$destPort OK")

        if (sendReply) {
            clientOutput.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            clientOutput.flush()
        }

        clientSocket.soTimeout = 0

        remoteSocket.use { remote ->
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
            }, "doh-bridge-c2s")
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

    /**
     * Handle DNS-over-TCP (SOCKS5 CONNECT to port 53).
     * Reads DNS messages with 2-byte length prefix, forwards via DoH, writes back.
     */
    private fun handleDnsTcp(input: InputStream, output: OutputStream) {
        try {
            while (running.get() && !Thread.currentThread().isInterrupted) {
                // DNS-over-TCP framing: [2-byte length (big-endian)] [DNS message]
                val b1 = input.read()
                if (b1 == -1) break
                val b2 = input.read()
                if (b2 == -1) break

                val msgLen = ((b1 and 0xFF) shl 8) or (b2 and 0xFF)
                if (msgLen <= 0 || msgLen > 65535) {
                    Log.w(TAG, "DNS-TCP: invalid message length: $msgLen")
                    break
                }

                val dnsQuery = ByteArray(msgLen)
                input.readFully(dnsQuery)

                val response = forwardDnsViaDoH(dnsQuery)
                if (response != null && response.isNotEmpty()) {
                    synchronized(output) {
                        output.write((response.size shr 8) and 0xFF)
                        output.write(response.size and 0xFF)
                        output.write(response)
                        output.flush()
                    }
                } else {
                    logd("DNS-TCP: DoH returned no response")
                    break
                }
            }
        } catch (e: Exception) {
            if (running.get()) {
                logd("DNS-TCP: session ended: ${e.message}")
            }
        }
    }

    /**
     * Handle FWD_UDP (cmd 0x05) — hev-socks5-tunnel's UDP-over-TCP extension.
     * DNS queries (port 53) are forwarded via DoH HTTPS.
     * Non-DNS UDP is forwarded directly via DatagramSocket.
     */
    private fun handleFwdUdp(input: InputStream, output: OutputStream) {
        // Send success response
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
     * Forward a UDP packet.
     * DNS queries (port 53) go via DoH HTTPS.
     * Non-DNS UDP is forwarded directly.
     */
    private fun forwardUdpPacket(host: String, port: Int, payload: ByteArray): ByteArray? {
        return if (port == 53) {
            forwardDnsViaDoH(payload)
        } else {
            forwardUdpDirect(host, port, payload)
        }
    }

    /**
     * Forward DNS query via DoH (HTTPS POST, RFC 8484).
     * Uses OkHttp with HTTP/2 and pre-resolved server IPs.
     */
    private fun forwardDnsViaDoH(payload: ByteArray): ByteArray? {
        val client = httpClient ?: return null
        return try {
            val body = payload.toRequestBody("application/dns-message".toMediaType())
            val request = Request.Builder()
                .url(dohUrl)
                .post(body)
                .header("Accept", "application/dns-message")
                .build()

            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    response.body?.bytes()
                } else {
                    Log.w(TAG, "DoH: HTTP ${response.code}")
                    null
                }
            }
        } catch (e: Exception) {
            logd("DoH: failed: ${e.message}")
            null
        }
    }

    /**
     * Forward non-DNS UDP directly via DatagramSocket.
     */
    private fun forwardUdpDirect(host: String, port: Int, payload: ByteArray): ByteArray? {
        val socket = DatagramSocket()
        try {
            socket.soTimeout = 5000
            val address = InetAddress.getByName(host)
            val request = DatagramPacket(payload, payload.size, address, port)
            socket.send(request)

            val buffer = ByteArray(4096)
            val response = DatagramPacket(buffer, buffer.size)
            socket.receive(response)

            return buffer.copyOf(response.length)
        } catch (e: Exception) {
            logd("FWD_UDP: direct UDP to $host:$port failed: ${e.message}")
            return null
        } finally {
            socket.close()
        }
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
