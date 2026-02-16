package app.slipnet.tunnel

import android.os.ParcelFileDescriptor
import app.slipnet.util.AppLog as Log
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Configuration for the Kotlin tunnel manager
 */
data class KotlinTunnelConfig(
    val domain: String,
    val resolvers: List<ResolverConfig>,
    val slipstreamPort: Int = SlipstreamBridge.DEFAULT_SLIPSTREAM_PORT,
    val slipstreamHost: String = "127.0.0.1",
    val dnsServer: String = "8.8.8.8",
    val congestionControl: String = "bbr",
    val keepAliveInterval: Int = 200,
    val gsoEnabled: Boolean = false,
    // Network Optimization Settings
    val dnsTimeout: Int = 5000,
    val connectionTimeout: Int = 30000,
    val bufferSize: Int = 524288, // 512KB
    val connectionPoolSize: Int = 10,
    val verboseLogging: Boolean = false,
    // DNS forwarding through SSH (for SSH-only mode)
    // When > 0, DNS queries are sent via TCP to this local port (SSH port-forwarded)
    val dnsForwardPort: Int = 0
)

data class ResolverConfig(
    val host: String,
    val port: Int,
    val authoritative: Boolean
)

/**
 * Kotlin-based tunnel manager that handles TUN packet processing.
 * Uses the Rust slipstream client for DNS tunneling.
 */
class KotlinTunnelManager(
    private val config: KotlinTunnelConfig,
    private val tunFd: ParcelFileDescriptor,
    private val onSlipstreamStart: (String, List<ResolverConfig>) -> Boolean,
    private val onSlipstreamStop: () -> Unit,
    private val vpnProtect: ((DatagramSocket) -> Boolean)? = null
) {
    companion object {
        private const val TAG = "KotlinTunnelManager"
        private const val CLEANUP_INTERVAL_MS = 60_000L
    }

    // Use config setting for verbose logging
    private val verboseLogging: Boolean get() = config.verboseLogging

    // Helper to avoid Log.v overhead when disabled
    private inline fun logV(message: () -> String) {
        if (verboseLogging) Log.v(TAG, message())
    }

    private val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private val isRunning = AtomicBoolean(false)

    private lateinit var tunInterface: TunInterface
    private val natTable = NatTable()
    private val connections = ConcurrentHashMap<Long, TunnelConnection>()

    // Channel for packets going to TUN - limited size to prevent memory buildup
    private val toTunChannel = Channel<ByteArray>(64)

    // Pending connections (waiting for tunnel to establish)
    private val pendingConnections = ConcurrentHashMap<Long, PendingTunnelConnection>()

    // Direct UDP sessions (for UDP traffic that bypasses the tunnel)
    private val directUdpSessions = ConcurrentHashMap<String, DirectUdpSession>()

    // Connection pool for faster connection establishment
    // Larger pool size for DNS tunneling which is inherently slow
    private val connectionPool = Socks5ConnectionPool(
        slipstreamPort = config.slipstreamPort,
        poolSize = config.connectionPoolSize,
        scope = scope,
        bufferSize = config.bufferSize,
        connectionTimeout = config.connectionTimeout,
        verboseLogging = config.verboseLogging
    )

    // Stats
    private val bytesSent = AtomicLong(0)
    private val bytesReceived = AtomicLong(0)
    private val packetsSent = AtomicLong(0)
    private val packetsReceived = AtomicLong(0)

    /**
     * Start the tunnel
     */
    suspend fun start(): Result<Unit> = withContext(Dispatchers.IO) {
        if (isRunning.getAndSet(true)) {
            return@withContext Result.failure(Exception("Tunnel already running"))
        }

        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting Kotlin tunnel manager")
        Log.i(TAG, "  Domain: ${config.domain}")
        Log.i(TAG, "  Resolvers: ${config.resolvers.joinToString { "${it.host}:${it.port}${if (it.authoritative) " (auth)" else ""}" }}")
        Log.i(TAG, "  SOCKS5 proxy: ${config.slipstreamHost}:${config.slipstreamPort}")
        Log.i(TAG, "  DNS server: ${config.dnsServer}")
        Log.i(TAG, "  Congestion control: ${config.congestionControl}")
        Log.i(TAG, "  Keep-alive: ${config.keepAliveInterval}ms")
        Log.i(TAG, "  GSO: ${config.gsoEnabled}")
        Log.i(TAG, "  DNS timeout: ${config.dnsTimeout}ms")
        Log.i(TAG, "  Connection timeout: ${config.connectionTimeout}ms")
        Log.i(TAG, "  Buffer size: ${config.bufferSize} bytes")
        Log.i(TAG, "  Connection pool size: ${config.connectionPoolSize}")
        Log.i(TAG, "========================================")

        try {
            // Initialize TUN interface
            tunInterface = TunInterface(tunFd)
            Log.i(TAG, "TUN interface initialized")

            // Start slipstream client (via JNI callback)
            val started = onSlipstreamStart(config.domain, config.resolvers)
            if (!started) {
                Log.e(TAG, "Tunnel client failed to start")
                isRunning.set(false)
                throw Exception("Tunnel client failed to start")
            }

            // Wait for slipstream to be ready
            delay(500)

            // Start connection pool
            connectionPool.start()

            // Start packet processing
            startPacketProcessing()

            // Start cleanup task
            startCleanupTask()

            Log.i(TAG, "Kotlin tunnel manager started successfully")
            Result.success(Unit)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start tunnel: ${e.message}")
            isRunning.set(false)
            Result.failure(e)
        }
    }

    /**
     * Stop the tunnel
     */
    fun stop() {
        if (!isRunning.getAndSet(false)) return

        Log.i(TAG, "Stopping Kotlin tunnel manager")

        // Close all connections
        connections.values.forEach { it.close() }
        connections.clear()

        // Clear pending connections
        pendingConnections.clear()

        // Close direct UDP sessions
        directUdpSessions.values.forEach { it.close() }
        directUdpSessions.clear()

        // Stop connection pool
        connectionPool.stop()

        // Clear NAT table
        natTable.clear()

        // Close TUN interface
        if (::tunInterface.isInitialized) {
            tunInterface.close()
        }

        // Stop slipstream client
        onSlipstreamStop()

        // Cancel all coroutines
        scope.cancel()

        Log.i(TAG, "Kotlin tunnel manager stopped")
    }

    private fun startPacketProcessing() {
        // TUN reader task - high priority IO dispatcher
        scope.launch(Dispatchers.IO) {
            Log.i(TAG, "TUN reader started")
            while (isRunning.get()) {
                try {
                    val packet = tunInterface.readPacket()
                    if (packet != null && packet.isNotEmpty()) {
                        bytesSent.addAndGet(packet.size.toLong())
                        packetsSent.incrementAndGet()
                        processOutboundPacket(packet)
                    }
                    // No delay - blocking read handles waiting
                } catch (e: Exception) {
                    // Silently ignore read errors unless stopped
                    if (!isRunning.get()) break
                }
            }
            Log.i(TAG, "TUN reader stopped")
        }

        // TUN writer task
        scope.launch(Dispatchers.IO) {
            Log.i(TAG, "TUN writer started")
            for (packet in toTunChannel) {
                if (!isRunning.get()) break
                try {
                    tunInterface.writePacket(packet)
                    bytesReceived.addAndGet(packet.size.toLong())
                    packetsReceived.incrementAndGet()
                } catch (e: Exception) {
                    // Silently ignore write errors
                }
            }
            Log.i(TAG, "TUN writer stopped")
        }
    }

    private fun startCleanupTask() {
        scope.launch {
            while (isRunning.get()) {
                delay(CLEANUP_INTERVAL_MS)
                val removed = natTable.cleanupExpired()
                if (removed > 0) {
                    if (verboseLogging) Log.d(TAG, "Cleaned up $removed expired NAT entries")
                }
            }
        }
    }

    private suspend fun processOutboundPacket(packet: ByteArray) {
        // Quick check for IPv6 - drop early without full parsing
        if (packet.isNotEmpty() && (packet[0].toInt() ushr 4) == 6) {
            return  // Drop IPv6 silently
        }

        val ipPacket = IpPacketParser.parse(packet) ?: return

        // Handle DNS queries specially (UDP port 53)
        if (ipPacket.isUdp) {
            val udpDstPort = extractUdpDstPort(packet, ipPacket.version)
            if (udpDstPort == 53) {
                handleDnsQuery(packet, ipPacket)
                return
            }
            // Forward all other UDP traffic through the tunnel
            handleUdpPacket(ipPacket)
            return
        }

        // Handle TCP
        if (ipPacket.isTcp) {
            handleTcpPacket(ipPacket)
        }
    }

    private fun extractUdpDstPort(packet: ByteArray, version: Int): Int {
        val offset = if (version == 4) {
            val ihl = (packet[0].toInt() and 0x0F) * 4
            ihl + 2 // Skip src port
        } else {
            40 + 2
        }
        return if (packet.size > offset + 1) {
            ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
        } else 0
    }

    private suspend fun handleDnsQuery(packet: ByteArray, ipPacket: IpPacket) {
        // Extract UDP payload (DNS query)
        val version = ipPacket.version
        val headerLen = if (version == 4) {
            (packet[0].toInt() and 0x0F) * 4
        } else {
            40
        }

        // UDP header is 8 bytes, payload starts after
        val udpStart = headerLen
        if (packet.size < udpStart + 8) return

        val srcPort = ((packet[udpStart].toInt() and 0xFF) shl 8) or (packet[udpStart + 1].toInt() and 0xFF)
        val dstPort = ((packet[udpStart + 2].toInt() and 0xFF) shl 8) or (packet[udpStart + 3].toInt() and 0xFF)
        val udpPayload = packet.copyOfRange(udpStart + 8, packet.size)

        if (udpPayload.isEmpty()) return

        // Cache addresses to avoid repeated calls
        val dstAddress = ipPacket.dstAddress
        val srcAddress = ipPacket.srcAddress

        // Forward DNS query - use TCP through SSH if dnsForwardPort is set, otherwise direct UDP
        scope.launch(Dispatchers.IO) {
            try {
                val dnsResponse = if (config.dnsForwardPort > 0) {
                    // Route DNS through SSH tunnel via TCP (DNS-over-TCP)
                    forwardDnsQueryViaTcp(udpPayload, "127.0.0.1", config.dnsForwardPort)
                } else {
                    // Direct UDP to DNS server (outside VPN)
                    forwardDnsQuery(udpPayload, config.dnsServer, 53)
                }
                if (dnsResponse != null) {
                    val responsePacket = buildUdpResponsePacket(
                        srcAddr = dstAddress,
                        srcPort = dstPort,
                        dstAddr = srcAddress,
                        dstPort = srcPort,
                        payload = dnsResponse,
                        isIpv4 = version == 4
                    )
                    if (responsePacket != null) {
                        sendToTun(responsePacket)
                    }
                }
            } catch (e: Exception) {
                // Silently ignore DNS failures to reduce log spam
            }
        }
    }

    /**
     * Extract the query name from a DNS packet for logging
     */
    private fun extractDnsQueryName(dnsPayload: ByteArray): String {
        if (dnsPayload.size < 12) return "invalid"

        // DNS header is 12 bytes, query starts after
        var offset = 12
        val parts = mutableListOf<String>()

        while (offset < dnsPayload.size) {
            val len = dnsPayload[offset].toInt() and 0xFF
            if (len == 0) break
            if (offset + 1 + len > dnsPayload.size) break

            parts.add(String(dnsPayload, offset + 1, len, Charsets.US_ASCII))
            offset += 1 + len
        }

        return if (parts.isNotEmpty()) parts.joinToString(".") else "empty"
    }

    /**
     * Handle non-DNS UDP packets.
     * Uses direct UDP forwarding via protected sockets.
     * EXCEPTION: UDP port 443 (QUIC/HTTP3) is BLOCKED so apps fall back to TCP,
     * which goes through the tunnel and hides the user's IP.
     */
    private suspend fun handleUdpPacket(ipPacket: IpPacket) {
        val version = ipPacket.version
        val headerLen = if (version == 4) {
            (ipPacket.rawData[0].toInt() and 0x0F) * 4
        } else {
            40
        }

        val packet = ipPacket.rawData
        if (packet.size < headerLen + 8) return

        val udpStart = headerLen
        val srcPort = ((packet[udpStart].toInt() and 0xFF) shl 8) or (packet[udpStart + 1].toInt() and 0xFF)
        val dstPort = ((packet[udpStart + 2].toInt() and 0xFF) shl 8) or (packet[udpStart + 3].toInt() and 0xFF)

        // Block QUIC (UDP port 443) to force apps to use TCP, which goes through the tunnel
        // This ensures the user's IP is hidden for HTTPS traffic
        if (dstPort == 443) {
            if (verboseLogging) Log.v(TAG, "Blocking QUIC (UDP:443) to force TCP fallback")
            return
        }

        val udpPayload = packet.copyOfRange(udpStart + 8, packet.size)

        if (udpPayload.isEmpty()) return

        val srcAddr = ipPacket.srcAddress
        val dstAddr = ipPacket.dstAddress

        // Create a unique key for this UDP "session" - use a more efficient format
        val sessionKey = "${srcAddr.hashCode()}:$srcPort->${dstAddr.hashCode()}:$dstPort"

        // Check if session exists - if so, send directly without launching coroutine
        val existingSession = directUdpSessions[sessionKey]
        if (existingSession != null) {
            existingSession.sendPacket(dstAddr, dstPort, udpPayload)
            return
        }

        // New session - launch coroutine to set it up
        scope.launch(Dispatchers.IO) {
            try {
                handleDirectUdp(sessionKey, srcAddr, srcPort, dstAddr, dstPort, udpPayload, version)
            } catch (e: Exception) {
                // Silently ignore UDP failures
            }
        }
    }

    /**
     * Handle UDP directly via protected sockets (bypasses tunnel)
     */
    private suspend fun handleDirectUdp(
        sessionKey: String,
        srcAddr: InetAddress,
        srcPort: Int,
        dstAddr: InetAddress,
        dstPort: Int,
        payload: ByteArray,
        ipVersion: Int
    ) {
        // Get or create direct UDP session
        val session = directUdpSessions.getOrPut(sessionKey) {
            DirectUdpSession(
                sessionKey = sessionKey,
                srcAddr = srcAddr,
                srcPort = srcPort,
                ipVersion = ipVersion,
                vpnProtect = vpnProtect,
                onPacketReceived = { respSrcAddr, respSrcPort, data ->
                    scope.launch {
                        val responsePacket = buildUdpResponsePacket(
                            srcAddr = respSrcAddr,
                            srcPort = respSrcPort,
                            dstAddr = srcAddr,
                            dstPort = srcPort,
                            payload = data,
                            isIpv4 = ipVersion == 4
                        )
                        if (responsePacket != null) {
                            sendToTun(responsePacket)
                        }
                    }
                }
            ).also { it.startReceiver(scope) }
        }

        session.sendPacket(dstAddr, dstPort, payload)
    }

    /**
     * Direct UDP session for UDP traffic that bypasses the tunnel
     */
    private inner class DirectUdpSession(
        val sessionKey: String,
        val srcAddr: InetAddress,
        val srcPort: Int,
        val ipVersion: Int,
        val vpnProtect: ((DatagramSocket) -> Boolean)?,
        val onPacketReceived: (InetAddress, Int, ByteArray) -> Unit
    ) {
        private val socket = DatagramSocket()
        private var receiverJob: Job? = null
        private val isClosed = AtomicBoolean(false)

        init {
            vpnProtect?.invoke(socket)
            if (verboseLogging) Log.d(TAG, "Direct UDP session created for $sessionKey, socket protected")
        }

        fun sendPacket(dstAddr: InetAddress, dstPort: Int, data: ByteArray) {
            if (isClosed.get()) return
            try {
                val packet = DatagramPacket(data, data.size, dstAddr, dstPort)
                socket.send(packet)
                if (verboseLogging) Log.d(TAG, "Direct UDP: sent ${data.size} bytes to ${dstAddr.hostAddress}:$dstPort")
            } catch (e: Exception) {
                Log.e(TAG, "Direct UDP send failed: ${e.message}")
            }
        }

        fun startReceiver(scope: CoroutineScope) {
            receiverJob = scope.launch(Dispatchers.IO) {
                val buffer = ByteArray(65535)
                socket.soTimeout = config.connectionTimeout

                while (isActive && !isClosed.get()) {
                    try {
                        val packet = DatagramPacket(buffer, buffer.size)
                        socket.receive(packet)
                        val data = buffer.copyOf(packet.length)
                        if (verboseLogging) Log.d(TAG, "Direct UDP: received ${data.size} bytes from ${packet.address.hostAddress}:${packet.port}")
                        onPacketReceived(packet.address, packet.port, data)
                    } catch (e: java.net.SocketTimeoutException) {
                        // Timeout, cleanup if no activity
                        if (!isActive) break
                    } catch (e: Exception) {
                        if (!isClosed.get()) {
                            Log.e(TAG, "Direct UDP receive error: ${e.message}")
                        }
                        break
                    }
                }

                close()
            }
        }

        fun close() {
            if (isClosed.getAndSet(true)) return
            receiverJob?.cancel()
            try { socket.close() } catch (e: Exception) {}
            directUdpSessions.remove(sessionKey)
            if (verboseLogging) Log.d(TAG, "Direct UDP session closed: $sessionKey")
        }
    }

    private suspend fun forwardDnsQuery(query: ByteArray, dnsServer: String, port: Int): ByteArray? {
        return withContext(Dispatchers.IO) {
            try {
                val socket = java.net.DatagramSocket()
                // Protect the socket so it doesn't go through VPN
                val protected = vpnProtect?.invoke(socket)
                if (protected == false) {
                    Log.e(TAG, "Failed to protect DNS socket - this may cause routing loop")
                    // Continue anyway - some devices may not require protection
                } else if (protected == null) {
                    Log.w(TAG, "No VPN protect callback - DNS may not work correctly")
                } else {
                    if (verboseLogging) Log.d(TAG, "DNS socket protected successfully")
                }

                socket.soTimeout = config.dnsTimeout

                val serverAddr = java.net.InetAddress.getByName(dnsServer)
                if (verboseLogging) Log.d(TAG, "Sending DNS query (${query.size} bytes) to $dnsServer:$port")
                val requestPacket = java.net.DatagramPacket(query, query.size, serverAddr, port)
                socket.send(requestPacket)

                val responseBuffer = ByteArray(4096) // Support larger DNS responses (DNSSEC, etc.)
                val responsePacket = java.net.DatagramPacket(responseBuffer, responseBuffer.size)
                socket.receive(responsePacket)

                socket.close()

                if (verboseLogging) Log.i(TAG, "DNS response received: ${responsePacket.length} bytes from ${responsePacket.address?.hostAddress}")
                responseBuffer.copyOf(responsePacket.length)
            } catch (e: java.net.SocketTimeoutException) {
                Log.e(TAG, "DNS query timed out to $dnsServer:$port - check if socket protection is working")
                null
            } catch (e: Exception) {
                Log.e(TAG, "DNS query failed: ${e.message}")
                null
            }
        }
    }

    /**
     * Forward DNS query via TCP (DNS-over-TCP).
     * Used when DNS needs to go through SSH tunnel (port forwarding).
     * TCP DNS uses a 2-byte length prefix before the DNS message.
     */
    private suspend fun forwardDnsQueryViaTcp(query: ByteArray, host: String, port: Int): ByteArray? {
        return withContext(Dispatchers.IO) {
            var socket: Socket? = null
            try {
                socket = Socket()
                socket.soTimeout = config.dnsTimeout
                socket.connect(InetSocketAddress(host, port), config.dnsTimeout)

                val output = socket.getOutputStream()
                val input = socket.getInputStream()

                // DNS-over-TCP: 2-byte length prefix + DNS message
                val lengthPrefix = ByteArray(2)
                lengthPrefix[0] = ((query.size shr 8) and 0xFF).toByte()
                lengthPrefix[1] = (query.size and 0xFF).toByte()

                output.write(lengthPrefix)
                output.write(query)
                output.flush()

                if (verboseLogging) Log.d(TAG, "DNS-over-TCP: sent ${query.size} bytes to $host:$port")

                // Read response length prefix
                val responseLengthBytes = ByteArray(2)
                var bytesRead = 0
                while (bytesRead < 2) {
                    val read = input.read(responseLengthBytes, bytesRead, 2 - bytesRead)
                    if (read == -1) {
                        Log.e(TAG, "DNS-over-TCP: connection closed while reading length")
                        return@withContext null
                    }
                    bytesRead += read
                }

                val responseLength = ((responseLengthBytes[0].toInt() and 0xFF) shl 8) or
                        (responseLengthBytes[1].toInt() and 0xFF)

                if (responseLength <= 0 || responseLength > 65535) {
                    Log.e(TAG, "DNS-over-TCP: invalid response length: $responseLength")
                    return@withContext null
                }

                // Read response body
                val responseBuffer = ByteArray(responseLength)
                bytesRead = 0
                while (bytesRead < responseLength) {
                    val read = input.read(responseBuffer, bytesRead, responseLength - bytesRead)
                    if (read == -1) {
                        Log.e(TAG, "DNS-over-TCP: connection closed while reading response")
                        return@withContext null
                    }
                    bytesRead += read
                }

                if (verboseLogging) Log.i(TAG, "DNS-over-TCP: received $responseLength bytes from $host:$port")
                responseBuffer

            } catch (e: java.net.SocketTimeoutException) {
                Log.e(TAG, "DNS-over-TCP: query timed out to $host:$port")
                null
            } catch (e: Exception) {
                Log.e(TAG, "DNS-over-TCP: query failed: ${e.message}")
                null
            } finally {
                try { socket?.close() } catch (e: Exception) {}
            }
        }
    }

    private fun buildUdpResponsePacket(
        srcAddr: InetAddress,
        srcPort: Int,
        dstAddr: InetAddress,
        dstPort: Int,
        payload: ByteArray,
        isIpv4: Boolean
    ): ByteArray? {
        val udpLen = 8 + payload.size

        return if (isIpv4) {
            val totalLen = 20 + udpLen
            val packet = ByteArray(totalLen)

            // IPv4 header
            packet[0] = 0x45.toByte() // Version + IHL
            packet[1] = 0x00.toByte() // DSCP + ECN
            packet[2] = ((totalLen shr 8) and 0xFF).toByte()
            packet[3] = (totalLen and 0xFF).toByte()
            packet[4] = 0x00.toByte() // Identification
            packet[5] = 0x00.toByte()
            packet[6] = 0x40.toByte() // Flags (Don't Fragment)
            packet[7] = 0x00.toByte()
            packet[8] = 64.toByte() // TTL
            packet[9] = 17.toByte() // Protocol (UDP)
            packet[10] = 0x00.toByte() // Checksum placeholder
            packet[11] = 0x00.toByte()

            // Source IP
            System.arraycopy(srcAddr.address, 0, packet, 12, 4)
            // Destination IP
            System.arraycopy(dstAddr.address, 0, packet, 16, 4)

            // Calculate IP checksum
            val ipChecksum = calculateIpChecksum(packet, 0, 20)
            packet[10] = ((ipChecksum shr 8) and 0xFF).toByte()
            packet[11] = (ipChecksum and 0xFF).toByte()

            // UDP header
            packet[20] = ((srcPort shr 8) and 0xFF).toByte()
            packet[21] = (srcPort and 0xFF).toByte()
            packet[22] = ((dstPort shr 8) and 0xFF).toByte()
            packet[23] = (dstPort and 0xFF).toByte()
            packet[24] = ((udpLen shr 8) and 0xFF).toByte()
            packet[25] = (udpLen and 0xFF).toByte()
            packet[26] = 0x00.toByte() // UDP checksum placeholder
            packet[27] = 0x00.toByte()

            // Payload
            System.arraycopy(payload, 0, packet, 28, payload.size)

            // Calculate UDP checksum (optional for IPv4 but good practice)
            val udpChecksum = calculateUdpChecksum(srcAddr.address, dstAddr.address, packet, 20, udpLen, false)
            packet[26] = ((udpChecksum shr 8) and 0xFF).toByte()
            packet[27] = (udpChecksum and 0xFF).toByte()

            packet
        } else {
            val totalLen = 40 + udpLen
            val packet = ByteArray(totalLen)

            // IPv6 header
            packet[0] = 0x60.toByte()
            packet[1] = 0x00.toByte()
            packet[2] = 0x00.toByte()
            packet[3] = 0x00.toByte()
            packet[4] = ((udpLen shr 8) and 0xFF).toByte()
            packet[5] = (udpLen and 0xFF).toByte()
            packet[6] = 17.toByte() // Next header (UDP)
            packet[7] = 64.toByte() // Hop limit

            // Source IP
            System.arraycopy(srcAddr.address, 0, packet, 8, 16)
            // Destination IP
            System.arraycopy(dstAddr.address, 0, packet, 24, 16)

            // UDP header
            packet[40] = ((srcPort shr 8) and 0xFF).toByte()
            packet[41] = (srcPort and 0xFF).toByte()
            packet[42] = ((dstPort shr 8) and 0xFF).toByte()
            packet[43] = (dstPort and 0xFF).toByte()
            packet[44] = ((udpLen shr 8) and 0xFF).toByte()
            packet[45] = (udpLen and 0xFF).toByte()
            packet[46] = 0x00.toByte() // UDP checksum placeholder
            packet[47] = 0x00.toByte()

            // Payload
            System.arraycopy(payload, 0, packet, 48, payload.size)

            // Calculate UDP checksum (required for IPv6)
            val udpChecksum = calculateUdpChecksum(srcAddr.address, dstAddr.address, packet, 40, udpLen, true)
            packet[46] = ((udpChecksum shr 8) and 0xFF).toByte()
            packet[47] = (udpChecksum and 0xFF).toByte()

            packet
        }
    }

    private fun calculateIpChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        while (i < offset + length) {
            if (i == offset + 10) { // Skip checksum field
                i += 2
                continue
            }
            val word = if (i + 1 < offset + length) {
                ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            } else {
                (data[i].toInt() and 0xFF) shl 8
            }
            sum += word
            i += 2
        }
        while (sum > 0xFFFF) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.inv() and 0xFFFF).toInt()
    }

    /**
     * Calculate UDP checksum (required for IPv6, optional for IPv4)
     * Includes pseudo-header as per RFC 768/2460
     */
    private fun calculateUdpChecksum(
        srcAddr: ByteArray,
        dstAddr: ByteArray,
        udpData: ByteArray,
        udpOffset: Int,
        udpLength: Int,
        isIpv6: Boolean
    ): Int {
        var sum = 0L

        // Pseudo-header
        // Source address
        for (i in srcAddr.indices step 2) {
            val word = if (i + 1 < srcAddr.size) {
                ((srcAddr[i].toInt() and 0xFF) shl 8) or (srcAddr[i + 1].toInt() and 0xFF)
            } else {
                (srcAddr[i].toInt() and 0xFF) shl 8
            }
            sum += word
        }

        // Destination address
        for (i in dstAddr.indices step 2) {
            val word = if (i + 1 < dstAddr.size) {
                ((dstAddr[i].toInt() and 0xFF) shl 8) or (dstAddr[i + 1].toInt() and 0xFF)
            } else {
                (dstAddr[i].toInt() and 0xFF) shl 8
            }
            sum += word
        }

        // Protocol (UDP = 17)
        sum += 17

        // UDP length
        sum += udpLength

        // UDP header and data (skip checksum field at offset 6-7 within UDP header)
        var i = udpOffset
        val end = udpOffset + udpLength
        while (i < end) {
            // Skip checksum field (bytes 6-7 of UDP header)
            if (i == udpOffset + 6) {
                i += 2
                continue
            }
            val word = if (i + 1 < end) {
                ((udpData[i].toInt() and 0xFF) shl 8) or (udpData[i + 1].toInt() and 0xFF)
            } else {
                (udpData[i].toInt() and 0xFF) shl 8
            }
            sum += word
            i += 2
        }

        // Fold 32-bit sum to 16 bits
        while (sum > 0xFFFF) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }

        val checksum = (sum.inv() and 0xFFFF).toInt()
        // UDP checksum of 0 should be sent as 0xFFFF
        return if (checksum == 0) 0xFFFF else checksum
    }

    private suspend fun handleTcpPacket(ipPacket: IpPacket) {
        val tcpHeader = ipPacket.tcpHeader ?: return
        val key = IpPacketParser.extractConnectionKey(ipPacket) ?: return

        // Handle SYN - new connection
        if (tcpHeader.isSyn && !tcpHeader.isAck) {
            if (verboseLogging) Log.i(TAG, "SYN from ${key.srcAddress}:${key.srcPort} to ${key.dstAddress}:${key.dstPort}")
            handleNewConnection(key, tcpHeader.seqNum)
            return
        }

        // Handle data
        if (tcpHeader.payload.isNotEmpty()) {
            val entry = natTable.get(key)
            if (entry != null) {
                val conn = connections[entry.streamId]
                if (conn != null) {
                    if (verboseLogging) Log.v(TAG, "[${entry.streamId}] Forwarding ${tcpHeader.payload.size} bytes to tunnel")
                    conn.sendData(tcpHeader.payload)
                    conn.updateClientSeq(tcpHeader.seqNum, tcpHeader.payload.size)
                    // Send immediate ACK to acknowledge received data
                    conn.sendAck()
                } else {
                    // Check if this is a pending connection (SOCKS5 still connecting)
                    val pending = pendingConnections[entry.streamId]
                    if (pending != null) {
                        if (verboseLogging) Log.d(TAG, "[${entry.streamId}] Buffering ${tcpHeader.payload.size} bytes (connection pending)")
                        pending.bufferData(tcpHeader.payload, tcpHeader.seqNum)
                        // Send ACK for buffered data
                        pending.sendAckForBufferedData()
                    } else {
                        // Connection closed but NAT entry still exists (TIME_WAIT)
                        // Silently drop the packet - this is normal after FIN
                        if (verboseLogging) Log.v(TAG, "[${entry.streamId}] Dropping late packet (connection closed)")
                    }
                }
            } else {
                // Only log as warning if this is not a known closed connection
                if (verboseLogging) Log.v(TAG, "Dropping packet - no NAT entry for ${key.dstAddress}:${key.dstPort}")
            }
        }

        // Handle ACK
        if (tcpHeader.isAck) {
            val entry = natTable.get(key)
            if (entry != null) {
                connections[entry.streamId]?.handleAck(tcpHeader.ackNum)
            }
        }

        // Handle FIN - use graceful close to allow pending writes to complete
        if (tcpHeader.isFin) {
            val entry = natTable.get(key)
            if (entry != null) {
                val conn = connections[entry.streamId]
                if (conn != null) {
                    if (verboseLogging) Log.d(TAG, "FIN received for stream ${entry.streamId}")
                    conn.handleClientFin()
                }
                // else: connection already closed, ignore late FIN
            }
        }

        // Handle RST
        if (tcpHeader.isRst) {
            val entry = natTable.get(key)
            if (entry != null) {
                val conn = connections[entry.streamId]
                if (conn != null) {
                    if (verboseLogging) Log.d(TAG, "RST received for stream ${entry.streamId}")
                    conn.close()
                }
                // else: connection already closed, ignore late RST
            }
        }
    }

    private suspend fun handleNewConnection(key: ConnectionKey, clientIsn: Long) {
        val (entry, isNew) = natTable.getOrCreate(key)

        if (!isNew) {
            // Check if this is a SYN retransmit for a pending or established connection
            val conn = connections[entry.streamId]
            if (conn != null) {
                // Connection exists, this is likely a SYN retransmit - resend SYN-ACK
                if (verboseLogging) Log.d(TAG, "[${entry.streamId}] SYN retransmit, resending SYN-ACK")
                conn.resendSynAck()
            } else {
                // Check if connection is still pending (tunnel connecting)
                val pending = pendingConnections[entry.streamId]
                if (pending != null) {
                    if (verboseLogging) Log.d(TAG, "[${entry.streamId}] SYN retransmit (pending), resending SYN-ACK")
                    scope.launch { pending.sendSynAck() }
                } else {
                    Log.w(TAG, "[${entry.streamId}] SYN retransmit but no connection found")
                }
            }
            return
        }

        if (verboseLogging) {
            Log.i(TAG, "========================================")
            Log.i(TAG, "New TCP connection request:")
            Log.i(TAG, "  Stream ID: ${entry.streamId}")
            Log.i(TAG, "  Source: ${key.srcAddress}:${key.srcPort}")
            Log.i(TAG, "  Destination: ${key.dstAddress}:${key.dstPort}")
            Log.i(TAG, "  Client ISN: $clientIsn")
            Log.i(TAG, "========================================")
        }

        // Create a pending connection that can receive SYN-ACK retransmits
        val pendingConnection = PendingTunnelConnection(
            streamId = entry.streamId,
            srcAddr = key.srcAddress,
            srcPort = key.srcPort,
            dstAddr = key.dstAddress,
            dstPort = key.dstPort,
            clientIsn = clientIsn,
            onPacketToTun = { packet -> sendToTun(packet) }
        )

        // Store pending connection for data buffering
        pendingConnections[entry.streamId] = pendingConnection

        // Send SYN-ACK immediately to prevent TCP timeout
        pendingConnection.sendSynAck()

        // Connect through slipstream in background (using connection pool)
        scope.launch {
            try {
                if (verboseLogging) Log.i(TAG, "[${entry.streamId}] Connecting to slipstream...")

                // Use connection pool for faster establishment
                val socket = connectionPool.connectTo(
                    dstAddr = key.dstAddress,
                    dstPort = key.dstPort,
                    streamId = entry.streamId
                )

                if (socket == null) {
                    Log.e(TAG, "[${entry.streamId}] Slipstream connection failed")
                    throw Exception("Slipstream connection failed")
                }

                if (verboseLogging) Log.i(TAG, "[${entry.streamId}] Slipstream connected!")

                // Remove from pending and upgrade to full connection
                pendingConnections.remove(entry.streamId)
                val connection = pendingConnection.upgrade(socket) { id -> onConnectionClosed(id, key) }

                connections[entry.streamId] = connection
                natTable.update(key) { it.tcpState = TcpState.ESTABLISHED }

                if (verboseLogging) Log.d(TAG, "[${entry.streamId}] Starting TunnelConnection...")
                connection.start()
                if (verboseLogging) Log.d(TAG, "[${entry.streamId}] TunnelConnection started")

            } catch (e: Exception) {
                Log.e(TAG, "[${entry.streamId}] Failed to establish connection: ${e.message}", e)

                // Cleanup pending connection
                pendingConnections.remove(entry.streamId)
                natTable.remove(key)

                // Send RST to the client
                sendRst(key, clientIsn)
            }
        }
    }

    /**
     * Perform SOCKS5 handshake with the proxy server
     * Returns true if successful, false otherwise
     */
    private suspend fun performSocks5Handshake(
        socket: java.net.Socket,
        streamId: Long,
        dstAddr: InetAddress,
        dstPort: Int
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            val input = socket.getInputStream()
            val output = socket.getOutputStream()

            // Set socket timeout for handshake
            // DNS tunneling is slow - use longer timeout
            socket.soTimeout = 45000 // 45 seconds for DNS tunneling

            // Step 1: Send greeting (version 5, 1 auth method, no auth)
            val greeting = byteArrayOf(0x05, 0x01, 0x00)
            output.write(greeting)
            output.flush()
            if (verboseLogging) Log.v(TAG, "[$streamId] SOCKS5: Sent greeting")

            // Step 2: Read auth response
            val authResponse = ByteArray(2)
            var bytesRead = 0
            while (bytesRead < 2) {
                val read = input.read(authResponse, bytesRead, 2 - bytesRead)
                if (read == -1) {
                    Log.e(TAG, "[$streamId] SOCKS5: Connection closed during auth response")
                    return@withContext false
                }
                bytesRead += read
            }

            if (authResponse[0] != 0x05.toByte()) {
                Log.e(TAG, "[$streamId] SOCKS5: Invalid version in auth response: ${authResponse[0]}")
                return@withContext false
            }
            if (authResponse[1] != 0x00.toByte()) {
                Log.e(TAG, "[$streamId] SOCKS5: Auth method rejected: ${authResponse[1]}")
                return@withContext false
            }
            if (verboseLogging) Log.v(TAG, "[$streamId] SOCKS5: Auth OK")

            // Step 3: Send CONNECT request
            val addressBytes = dstAddr.address
            val isIpv4 = addressBytes.size == 4

            val connectRequest = if (isIpv4) {
                // IPv4 address
                ByteArray(10).apply {
                    this[0] = 0x05 // Version
                    this[1] = 0x01 // CONNECT command
                    this[2] = 0x00 // Reserved
                    this[3] = 0x01 // Address type: IPv4
                    System.arraycopy(addressBytes, 0, this, 4, 4)
                    this[8] = ((dstPort shr 8) and 0xFF).toByte()
                    this[9] = (dstPort and 0xFF).toByte()
                }
            } else {
                // IPv6 address
                ByteArray(22).apply {
                    this[0] = 0x05 // Version
                    this[1] = 0x01 // CONNECT command
                    this[2] = 0x00 // Reserved
                    this[3] = 0x04 // Address type: IPv6
                    System.arraycopy(addressBytes, 0, this, 4, 16)
                    this[20] = ((dstPort shr 8) and 0xFF).toByte()
                    this[21] = (dstPort and 0xFF).toByte()
                }
            }

            output.write(connectRequest)
            output.flush()
            if (verboseLogging) Log.d(TAG, "[$streamId] SOCKS5: Sent CONNECT to ${dstAddr.hostAddress}:$dstPort")

            // Step 4: Read CONNECT response
            // Response format: VER REP RSV ATYP BND.ADDR BND.PORT
            val responseHeader = ByteArray(4)
            bytesRead = 0
            while (bytesRead < 4) {
                val read = input.read(responseHeader, bytesRead, 4 - bytesRead)
                if (read == -1) {
                    Log.e(TAG, "[$streamId] SOCKS5: Connection closed during connect response")
                    return@withContext false
                }
                bytesRead += read
            }

            if (responseHeader[0] != 0x05.toByte()) {
                Log.e(TAG, "[$streamId] SOCKS5: Invalid version in connect response: ${responseHeader[0]}")
                return@withContext false
            }

            val replyCode = responseHeader[1].toInt() and 0xFF
            if (replyCode != 0x00) {
                val errorMsg = when (replyCode) {
                    0x01 -> "General SOCKS server failure"
                    0x02 -> "Connection not allowed by ruleset"
                    0x03 -> "Network unreachable"
                    0x04 -> "Host unreachable"
                    0x05 -> "Connection refused"
                    0x06 -> "TTL expired"
                    0x07 -> "Command not supported"
                    0x08 -> "Address type not supported"
                    else -> "Unknown error"
                }
                Log.e(TAG, "[$streamId] SOCKS5: Connect failed - $errorMsg (code: $replyCode)")
                return@withContext false
            }

            // Read the rest of the response (bound address)
            val addrType = responseHeader[3].toInt() and 0xFF
            val remainingBytes = when (addrType) {
                0x01 -> 4 + 2  // IPv4 + port
                0x04 -> 16 + 2 // IPv6 + port
                0x03 -> {
                    // Domain name - first byte is length
                    val lenByte = input.read()
                    if (lenByte == -1) {
                        Log.e(TAG, "[$streamId] SOCKS5: Connection closed reading domain length")
                        return@withContext false
                    }
                    lenByte + 2 // domain + port
                }
                else -> {
                    Log.e(TAG, "[$streamId] SOCKS5: Unknown address type: $addrType")
                    return@withContext false
                }
            }

            // Read and discard the bound address
            val boundAddr = ByteArray(remainingBytes)
            bytesRead = 0
            while (bytesRead < remainingBytes) {
                val read = input.read(boundAddr, bytesRead, remainingBytes - bytesRead)
                if (read == -1) {
                    Log.e(TAG, "[$streamId] SOCKS5: Connection closed reading bound address")
                    return@withContext false
                }
                bytesRead += read
            }

            // Reset socket timeout (will be handled by connection)
            socket.soTimeout = 0

            if (verboseLogging) Log.i(TAG, "[$streamId] SOCKS5: CONNECT successful to ${dstAddr.hostAddress}:$dstPort")
            true

        } catch (e: java.net.SocketTimeoutException) {
            Log.e(TAG, "[$streamId] SOCKS5: Handshake timed out")
            false
        } catch (e: Exception) {
            Log.e(TAG, "[$streamId] SOCKS5: Handshake error: ${e.message}")
            false
        }
    }

    /**
     * Pending connection that can handle SYN-ACK before tunnel is ready
     */
    private inner class PendingTunnelConnection(
        val streamId: Long,
        val srcAddr: InetAddress,
        val srcPort: Int,
        val dstAddr: InetAddress,
        val dstPort: Int,
        val clientIsn: Long,
        val onPacketToTun: suspend (ByteArray) -> Unit
    ) {
        private var ourIsn: Long = (Math.random() * Int.MAX_VALUE).toLong()
        private var ourSeqNum: Long = ourIsn
        private var clientAckNum: Long = clientIsn + 1
        private val bufferedData = mutableListOf<ByteArray>()

        suspend fun sendSynAck() {
            val packet = TcpPacketBuilder.buildSynAck(
                srcAddr = dstAddr,
                srcPort = dstPort,
                dstAddr = srcAddr,
                dstPort = srcPort,
                seqNum = ourIsn,
                ackNum = clientAckNum
            )
            if (packet != null) {
                if (verboseLogging) Log.i(TAG, "[$streamId] >>> SYN-ACK (early): seq=$ourIsn ack=$clientAckNum")
                onPacketToTun(packet)
                ourSeqNum = ourIsn + 1
            }
        }

        fun bufferData(data: ByteArray, seqNum: Long) {
            bufferedData.add(data)
            val expectedAck = seqNum + data.size
            if (expectedAck > clientAckNum) {
                clientAckNum = expectedAck
            }
            if (verboseLogging) Log.d(TAG, "[$streamId] Buffered ${data.size} bytes while connecting (total buffered: ${bufferedData.size} chunks)")
        }

        suspend fun sendAckForBufferedData() {
            val packet = TcpPacketBuilder.buildAck(
                srcAddr = dstAddr,
                srcPort = dstPort,
                dstAddr = srcAddr,
                dstPort = srcPort,
                seqNum = ourSeqNum,
                ackNum = clientAckNum
            )
            if (packet != null) {
                if (verboseLogging) Log.d(TAG, "[$streamId] >>> ACK (pending): seq=$ourSeqNum ack=$clientAckNum")
                onPacketToTun(packet)
            }
        }

        fun upgrade(socket: java.net.Socket, onConnectionClosed: (Long) -> Unit): TunnelConnection {
            return TunnelConnection(
                streamId = streamId,
                srcAddr = srcAddr,
                srcPort = srcPort,
                dstAddr = dstAddr,
                dstPort = dstPort,
                clientIsn = clientIsn,
                socket = socket,
                onPacketToTun = onPacketToTun,
                onConnectionClosed = onConnectionClosed,
                initialSeqNum = ourSeqNum,
                initialAckNum = clientAckNum,
                bufferedData = bufferedData.toList(),
                verboseLogging = config.verboseLogging
            )
        }
    }

    private suspend fun sendToTun(packet: ByteArray) {
        toTunChannel.send(packet)
    }

    private suspend fun sendRst(key: ConnectionKey, clientSeq: Long) {
        val packet = TcpPacketBuilder.buildRst(
            srcAddr = key.dstAddress,
            srcPort = key.dstPort,
            dstAddr = key.srcAddress,
            dstPort = key.srcPort,
            seqNum = 0,
            ackNum = clientSeq + 1
        )
        if (packet != null) {
            sendToTun(packet)
        }
    }

    private fun onConnectionClosed(streamId: Long, key: ConnectionKey) {
        connections.remove(streamId)
        // Delay NAT entry removal to handle late packets (TIME_WAIT-like behavior)
        scope.launch {
            delay(2000) // 2 second delay before removing NAT entry
            natTable.remove(key)
            if (verboseLogging) Log.d(TAG, "Connection $streamId NAT entry removed")
        }
        if (verboseLogging) Log.d(TAG, "Connection $streamId closed")
    }

    /**
     * Get traffic statistics
     */
    fun getStats(): TrafficStats = TrafficStats(
        bytesSent = bytesSent.get(),
        bytesReceived = bytesReceived.get(),
        packetsSent = packetsSent.get(),
        packetsReceived = packetsReceived.get(),
        activeConnections = connections.size.toLong()
    )

    data class TrafficStats(
        val bytesSent: Long,
        val bytesReceived: Long,
        val packetsSent: Long,
        val packetsReceived: Long,
        val activeConnections: Long
    )
}

/**
 * Connection pool for Direct protocol connections to slipstream.
 *
 * Direct Protocol: addr_type | address | port | data...
 * - addr_type 0x01 = IPv4 (4 bytes)
 * - addr_type 0x04 = IPv6 (16 bytes)
 * Server parses header and connects directly - no round-trip handshake!
 */
class Socks5ConnectionPool(
    private val slipstreamPort: Int,
    private val poolSize: Int = 3,
    private val scope: CoroutineScope,
    private val bufferSize: Int = 524288,
    private val connectionTimeout: Int = 30000,
    private val verboseLogging: Boolean = false
) {
    companion object {
        private const val TAG = "DirectPool"
    }

    // Pool of pre-connected sockets (just TCP connected, no protocol yet)
    private val pool = java.util.concurrent.LinkedBlockingQueue<PooledSocket>(poolSize)
    private val isRunning = AtomicBoolean(false)
    private var replenishJob: Job? = null

    data class PooledSocket(
        val socket: Socket,
        val createdAt: Long = System.currentTimeMillis()
    ) {
        fun isValid(): Boolean {
            return !socket.isClosed && socket.isConnected &&
                   (System.currentTimeMillis() - createdAt) < 120000 // 120 second max age
        }
    }

    /**
     * Start the connection pool
     */
    fun start() {
        if (isRunning.getAndSet(true)) return
        if (verboseLogging) Log.i(TAG, "Starting connection pool (size=$poolSize)")

        // Initial pool fill
        scope.launch(Dispatchers.IO) {
            repeat(poolSize) {
                tryAddConnection()
            }
        }

        // Background replenishment - less aggressive
        replenishJob = scope.launch(Dispatchers.IO) {
            while (isRunning.get()) {
                delay(500) // Check every 500ms instead of 50ms
                if (pool.size < poolSize && isRunning.get()) {
                    tryAddConnection()
                }
            }
        }
    }

    /**
     * Stop the connection pool
     */
    fun stop() {
        isRunning.set(false)
        replenishJob?.cancel()

        // Close all pooled connections
        while (true) {
            val conn = pool.poll() ?: break
            try { conn.socket.close() } catch (e: Exception) { }
        }
        if (verboseLogging) Log.i(TAG, "Direct connection pool stopped")
    }

    /**
     * Get a pre-connected socket from the pool.
     */
    private fun getPooledSocket(): Socket? {
        while (true) {
            val conn = pool.poll() ?: return null
            if (conn.isValid()) {
                if (verboseLogging) Log.v(TAG, "Got pooled socket (${pool.size} remaining)")
                return conn.socket
            }
            // Socket is stale, close it and try next
            try { conn.socket.close() } catch (e: Exception) { }
        }
    }

    /**
     * Try to add a new TCP connection to the pool
     */
    private suspend fun tryAddConnection() {
        if (!isRunning.get()) return

        try {
            val socket = Socket()
            socket.tcpNoDelay = true
            socket.keepAlive = true
            socket.sendBufferSize = bufferSize
            socket.receiveBufferSize = bufferSize

            socket.connect(InetSocketAddress("127.0.0.1", slipstreamPort), connectionTimeout / 3)

            val conn = PooledSocket(socket)
            if (!pool.offer(conn)) {
                socket.close()
            } else {
                if (verboseLogging) Log.v(TAG, "Added socket to pool (${pool.size}/$poolSize)")
            }
        } catch (e: Exception) {
            if (verboseLogging) Log.v(TAG, "Failed to create pooled socket: ${e.message}")
        }
    }

    /**
     * Connect to destination via local slipstream SOCKS5 proxy.
     * Returns the socket ready for data transfer, or null on failure.
     */
    suspend fun connectTo(dstAddr: InetAddress, dstPort: Int, streamId: Long): Socket? {
        return connectViaSocks5(dstAddr, dstPort, streamId)
    }

    /**
     * Connect using SOCKS5 protocol to the local slipstream proxy.
     * Slipstream then tunnels the traffic through DNS to the destination.
     */
    private suspend fun connectViaSocks5(dstAddr: InetAddress, dstPort: Int, streamId: Long): Socket? {
        // Retry logic for DNS tunnel which can be slow under load
        val maxRetries = 3
        var lastException: Exception? = null

        for (attempt in 1..maxRetries) {
            val socket = tryConnectViaSocks5(dstAddr, dstPort, streamId, attempt)
            if (socket != null) {
                return socket
            }
            if (attempt < maxRetries) {
                if (verboseLogging) Log.i(TAG, "[$streamId] SOCKS5: Retrying connection (attempt ${attempt + 1}/$maxRetries)")
                kotlinx.coroutines.delay(1000) // 1 second delay before retry
            }
        }

        return null
    }

    private suspend fun tryConnectViaSocks5(dstAddr: InetAddress, dstPort: Int, streamId: Long, attempt: Int): Socket? {
        // Don't use pooled sockets for SOCKS5 - each connection needs its own handshake
        if (attempt == 1) {
            if (verboseLogging) Log.i(TAG, "[$streamId] SOCKS5: Connecting to slipstream at 127.0.0.1:$slipstreamPort")
        }

        val socket = Socket()
        socket.tcpNoDelay = true
        socket.keepAlive = true
        socket.sendBufferSize = bufferSize
        socket.receiveBufferSize = bufferSize

        try {
            withContext(Dispatchers.IO) {
                socket.connect(InetSocketAddress("127.0.0.1", slipstreamPort), connectionTimeout / 2)
            }
        } catch (e: Exception) {
            Log.e(TAG, "[$streamId] SOCKS5: Failed to connect to slipstream: ${e.message}")
            try { socket.close() } catch (ex: Exception) { }
            return null
        }

        return withContext(Dispatchers.IO) {
            try {
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                // Use configured connection timeout for handshake (with some buffer for slow DNS tunnels)
                socket.soTimeout = (connectionTimeout * 1.5).toInt().coerceAtLeast(30000)

                // Step 1: Send SOCKS5 greeting (version 5, 1 auth method, no auth)
                output.write(byteArrayOf(0x05, 0x01, 0x00))
                output.flush()

                // Step 2: Read auth response
                val authResponse = ByteArray(2)
                if (readFully(input, authResponse) != 2) {
                    Log.e(TAG, "[$streamId] SOCKS5: Failed to read auth response")
                    socket.close()
                    return@withContext null
                }

                if (authResponse[0] != 0x05.toByte() || authResponse[1] != 0x00.toByte()) {
                    Log.e(TAG, "[$streamId] SOCKS5: Auth rejected (ver=${authResponse[0]}, method=${authResponse[1]})")
                    socket.close()
                    return@withContext null
                }

                // Step 3: Send CONNECT request
                val addressBytes = dstAddr.address
                val isIpv4 = addressBytes.size == 4

                val connectRequest = if (isIpv4) {
                    ByteArray(10).apply {
                        this[0] = 0x05  // Version
                        this[1] = 0x01  // CONNECT command
                        this[2] = 0x00  // Reserved
                        this[3] = 0x01  // IPv4
                        System.arraycopy(addressBytes, 0, this, 4, 4)
                        this[8] = (dstPort shr 8).toByte()
                        this[9] = (dstPort and 0xFF).toByte()
                    }
                } else {
                    ByteArray(22).apply {
                        this[0] = 0x05  // Version
                        this[1] = 0x01  // CONNECT command
                        this[2] = 0x00  // Reserved
                        this[3] = 0x04  // IPv6
                        System.arraycopy(addressBytes, 0, this, 4, 16)
                        this[20] = (dstPort shr 8).toByte()
                        this[21] = (dstPort and 0xFF).toByte()
                    }
                }

                output.write(connectRequest)
                output.flush()

                // Step 4: Read CONNECT response
                val responseHeader = ByteArray(4)
                if (readFully(input, responseHeader) != 4) {
                    Log.e(TAG, "[$streamId] SOCKS5: Failed to read connect response")
                    socket.close()
                    return@withContext null
                }

                if (responseHeader[0] != 0x05.toByte()) {
                    Log.e(TAG, "[$streamId] SOCKS5: Invalid version in response: ${responseHeader[0]}")
                    socket.close()
                    return@withContext null
                }

                if (responseHeader[1] != 0x00.toByte()) {
                    val statusCode = responseHeader[1].toInt() and 0xFF
                    val statusMsg = when (statusCode) {
                        1 -> "general SOCKS server failure"
                        2 -> "connection not allowed by ruleset"
                        3 -> "network unreachable"
                        4 -> "host unreachable"
                        5 -> "connection refused"
                        6 -> "TTL expired"
                        7 -> "command not supported"
                        8 -> "address type not supported"
                        else -> "unknown error"
                    }
                    Log.e(TAG, "[$streamId] SOCKS5: Connect failed with status $statusCode: $statusMsg")
                    socket.close()
                    return@withContext null
                }

                // Read the rest of the response based on address type
                val addrType = responseHeader[3].toInt() and 0xFF
                val remainingBytes = when (addrType) {
                    0x01 -> 4 + 2  // IPv4 + port
                    0x04 -> 16 + 2 // IPv6 + port
                    0x03 -> {
                        // Domain name - read length first
                        val lenByte = ByteArray(1)
                        if (readFully(input, lenByte) != 1) {
                            socket.close()
                            return@withContext null
                        }
                        (lenByte[0].toInt() and 0xFF) + 2
                    }
                    else -> {
                        Log.e(TAG, "[$streamId] SOCKS5: Unknown address type: $addrType")
                        socket.close()
                        return@withContext null
                    }
                }

                val remaining = ByteArray(remainingBytes)
                if (readFully(input, remaining) != remainingBytes) {
                    Log.e(TAG, "[$streamId] SOCKS5: Failed to read full response")
                    socket.close()
                    return@withContext null
                }

                // Reset socket timeout for data transfer
                socket.soTimeout = 0

                if (verboseLogging) Log.i(TAG, "[$streamId] SOCKS5: Connected to ${dstAddr.hostAddress}:$dstPort via slipstream")
                socket

            } catch (e: Exception) {
                Log.e(TAG, "[$streamId] SOCKS5 handshake error: ${e.message}")
                try { socket.close() } catch (ex: Exception) { }
                null
            }
        }
    }

    /**
     * Read exactly buffer.size bytes from the input stream.
     * Returns the number of bytes read, or less if EOF reached.
     */
    private fun readFully(input: java.io.InputStream, buffer: ByteArray): Int {
        var offset = 0
        while (offset < buffer.size) {
            val read = input.read(buffer, offset, buffer.size - offset)
            if (read == -1) return offset
            offset += read
        }
        return offset
    }

}
