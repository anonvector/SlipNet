package app.slipnet.tunnel

import android.util.Log
import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Proxy
import com.jcraft.jsch.Session
import com.jcraft.jsch.SocketFactory
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

/**
 * SSH tunnel bridge that creates a local SOCKS5 proxy through an SSH connection.
 *
 * Traffic flow:
 * App -> hev-socks5-tunnel -> [SSH SOCKS5 :listenPort] -> SSH direct-tcpip -> [DNSTT :sshPort] -> Server
 */
object SshTunnelBridge {
    private const val TAG = "SshTunnelBridge"
    private const val BUFFER_SIZE = 32768
    private const val CONNECT_TIMEOUT_MS = 30000
    private const val KEEPALIVE_INTERVAL_MS = 15000

    private var session: Session? = null
    private var serverSocket: ServerSocket? = null
    private var acceptorThread: Thread? = null
    private val running = AtomicBoolean(false)
    private val connectionThreads = CopyOnWriteArrayList<Thread>()

    /**
     * Start the SSH SOCKS5 proxy.
     *
     * The SSH connection is routed through the DNSTT SOCKS5 proxy to reach
     * the SSH server on the remote end. DNSTT tunnels the SSH traffic
     * through DNS to the server.
     *
     * @param socksHost Local SOCKS5 proxy host (DNS tunnel proxy)
     * @param socksPort Local SOCKS5 proxy port (DNS tunnel proxy)
     * @param sshHost SSH server destination host (through SOCKS5, typically 127.0.0.1 on remote)
     * @param sshPort SSH server destination port (through SOCKS5, typically 22)
     * @param sshUsername SSH username
     * @param sshPassword SSH password
     * @param listenPort Local port for the SSH SOCKS5 proxy
     * @param listenHost Local host for the SSH SOCKS5 proxy
     * @return Result indicating success or failure
     */
    /**
     * Start in direct mode: JSch connects directly to the tunnel port.
     * Used for DNSTT which forwards raw TCP through the DNS tunnel.
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
        listenHost: String = "127.0.0.1"
    ): Result<Unit> {
        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting SSH tunnel (direct mode)")
        Log.i(TAG, "  Tunnel: $tunnelHost:$tunnelPort")
        Log.i(TAG, "  SSH User: $sshUsername")
        Log.i(TAG, "  SOCKS5 Listen: $listenHost:$listenPort")
        Log.i(TAG, "========================================")

        stop()

        return try {
            // Connect SSH directly through the tunnel port
            // DNSTT forwards raw TCP to the remote SSH server
            val jsch = JSch()
            val newSession = jsch.getSession(sshUsername, tunnelHost, tunnelPort)
            newSession.setPassword(sshPassword)

            newSession.setConfig("StrictHostKeyChecking", "no")
            newSession.setServerAliveInterval(KEEPALIVE_INTERVAL_MS)
            newSession.setServerAliveCountMax(3)
            newSession.connect(CONNECT_TIMEOUT_MS)

            if (!newSession.isConnected) {
                return Result.failure(RuntimeException("SSH session failed to connect"))
            }

            session = newSession
            Log.i(TAG, "SSH session connected (direct mode)")

            // Start SOCKS5 server
            val ss = ServerSocket()
            ss.reuseAddress = true
            ss.bind(InetSocketAddress(listenHost, listenPort))
            serverSocket = ss
            running.set(true)

            // Start acceptor thread
            acceptorThread = Thread({
                Log.d(TAG, "Acceptor thread started")
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
                Log.d(TAG, "Acceptor thread exited")
            }, "ssh-socks5-acceptor").also { it.isDaemon = true; it.start() }

            Log.i(TAG, "SSH SOCKS5 proxy started on $listenHost:$listenPort")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start SSH tunnel", e)
            stop()
            Result.failure(e)
        }
    }

    fun start(
        socksHost: String,
        socksPort: Int,
        sshHost: String,
        sshPort: Int,
        sshUsername: String,
        sshPassword: String,
        listenPort: Int,
        listenHost: String = "127.0.0.1"
    ): Result<Unit> {
        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting SSH tunnel (SOCKS5 mode)")
        Log.i(TAG, "  SOCKS5 Proxy: $socksHost:$socksPort")
        Log.i(TAG, "  SSH Destination: $sshUsername@$sshHost:$sshPort")
        Log.i(TAG, "  SOCKS5 Listen: $listenHost:$listenPort")
        Log.i(TAG, "========================================")

        stop()

        return try {
            // Connect SSH session through the SOCKS5 proxy
            val jsch = JSch()
            val newSession = jsch.getSession(sshUsername, sshHost, sshPort)
            newSession.setPassword(sshPassword)

            // Route SSH through the SOCKS5 proxy using custom implementation
            val proxy = Socks5Proxy(socksHost, socksPort)
            newSession.setProxy(proxy)

            newSession.setConfig("StrictHostKeyChecking", "no")
            newSession.setServerAliveInterval(KEEPALIVE_INTERVAL_MS)
            newSession.setServerAliveCountMax(3)
            newSession.connect(CONNECT_TIMEOUT_MS)

            if (!newSession.isConnected) {
                return Result.failure(RuntimeException("SSH session failed to connect"))
            }

            session = newSession
            Log.i(TAG, "SSH session connected")

            // Start SOCKS5 server
            val ss = ServerSocket()
            ss.reuseAddress = true
            ss.bind(InetSocketAddress(listenHost, listenPort))
            serverSocket = ss
            running.set(true)

            // Start acceptor thread
            acceptorThread = Thread({
                Log.d(TAG, "Acceptor thread started")
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
                Log.d(TAG, "Acceptor thread exited")
            }, "ssh-socks5-acceptor").also { it.isDaemon = true; it.start() }

            Log.i(TAG, "SSH SOCKS5 proxy started on $listenHost:$listenPort")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start SSH tunnel", e)
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
        Log.d(TAG, "Stopping SSH tunnel...")

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

        // Close all connection threads
        for (thread in connectionThreads) {
            thread.interrupt()
        }
        connectionThreads.clear()

        // Disconnect SSH session
        try {
            session?.disconnect()
        } catch (e: Exception) {
            Log.w(TAG, "Error disconnecting SSH: ${e.message}")
        }
        session = null

        Log.d(TAG, "SSH tunnel stopped")
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

    private fun handleConnection(clientSocket: Socket) {
        val thread = Thread({
            try {
                clientSocket.use { socket ->
                    socket.soTimeout = 60000
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

                    // SOCKS5 CONNECT request
                    val ver = input.read() // version
                    val cmd = input.read() // command
                    input.read() // reserved

                    if (ver != 0x05 || cmd != 0x01) {
                        // Send failure response
                        output.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                        output.flush()
                        return@Thread
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
                            return@Thread
                        }
                    }

                    val portHigh = input.read()
                    val portLow = input.read()
                    destPort = (portHigh shl 8) or portLow

                    // Open SSH direct-tcpip channel
                    val currentSession = session
                    if (currentSession == null || !currentSession.isConnected) {
                        output.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                        output.flush()
                        return@Thread
                    }

                    val channel: ChannelDirectTCPIP
                    try {
                        channel = currentSession.openChannel("direct-tcpip") as ChannelDirectTCPIP
                        channel.setHost(destHost)
                        channel.setPort(destPort)
                        channel.connect(CONNECT_TIMEOUT_MS)
                    } catch (e: Exception) {
                        Log.d(TAG, "SSH channel failed for $destHost:$destPort: ${e.message}")
                        output.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                        output.flush()
                        return@Thread
                    }

                    // Send success response
                    output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    output.flush()

                    // Bridge data bidirectionally
                    val channelInput = channel.inputStream
                    val channelOutput = channel.outputStream

                    val t1 = Thread({
                        try {
                            copyStream(input, channelOutput)
                        } catch (_: Exception) {
                        } finally {
                            try { channelOutput.close() } catch (_: Exception) {}
                        }
                    }, "ssh-bridge-c2s")
                    t1.isDaemon = true
                    t1.start()

                    try {
                        copyStream(channelInput, output)
                    } catch (_: Exception) {
                    } finally {
                        try { channel.disconnect() } catch (_: Exception) {}
                        t1.interrupt()
                    }
                }
            } catch (e: Exception) {
                if (running.get()) {
                    Log.d(TAG, "Connection handler error: ${e.message}")
                }
            }
        }, "ssh-socks5-handler")
        thread.isDaemon = true
        connectionThreads.add(thread)
        thread.start()

        // Clean up finished threads periodically
        connectionThreads.removeAll { !it.isAlive }
    }

    private fun copyStream(input: InputStream, output: OutputStream) {
        val buffer = ByteArray(BUFFER_SIZE)
        while (!Thread.currentThread().isInterrupted) {
            val bytesRead = input.read(buffer)
            if (bytesRead == -1) break
            output.write(buffer, 0, bytesRead)
            output.flush()
        }
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

/**
 * Custom SOCKS5 proxy implementation for JSch.
 *
 * This replaces JSch's built-in ProxySOCKS5 which sends both no-auth (0x00) and
 * username/password (0x02) auth methods. This implementation only sends no-auth
 * for better compatibility and includes detailed logging for diagnostics.
 */
private class Socks5Proxy(
    private val proxyHost: String,
    private val proxyPort: Int
) : Proxy {
    companion object {
        private const val TAG = "Socks5Proxy"
        private const val SOCKS5_TIMEOUT_MS = 30000
    }

    private var socket: Socket? = null
    private var inputStream: InputStream? = null
    private var outputStream: OutputStream? = null

    override fun connect(socketFactory: SocketFactory?, host: String, port: Int, timeout: Int) {
        val connectTimeout = if (timeout > 0) timeout else SOCKS5_TIMEOUT_MS
        Log.i(TAG, "Connecting to SOCKS5 proxy $proxyHost:$proxyPort -> $host:$port (timeout=${connectTimeout}ms)")

        // Step 1: TCP connect to the SOCKS5 proxy
        val sock = if (socketFactory != null) {
            socketFactory.createSocket(proxyHost, proxyPort)
        } else {
            Socket()
        }

        if (!sock.isConnected) {
            sock.connect(InetSocketAddress(proxyHost, proxyPort), connectTimeout)
        }
        sock.soTimeout = connectTimeout
        sock.tcpNoDelay = true

        val out = sock.getOutputStream()
        val inp = sock.getInputStream()

        Log.d(TAG, "TCP connected to proxy")

        // Step 2: SOCKS5 greeting - only no-auth method (0x00)
        val greeting = byteArrayOf(0x05, 0x01, 0x00)
        out.write(greeting)
        out.flush()
        Log.d(TAG, "Sent SOCKS5 greeting (no-auth only)")

        // Step 3: Read greeting response
        val greetResp = readExact(inp, 2, "greeting response")
        val sVer = greetResp[0].toInt() and 0xFF
        val sMethod = greetResp[1].toInt() and 0xFF
        Log.d(TAG, "Greeting response: version=$sVer, method=$sMethod")

        if (sVer != 0x05) {
            sock.close()
            throw java.io.IOException("SOCKS5: invalid version $sVer")
        }
        if (sMethod == 0xFF) {
            sock.close()
            throw java.io.IOException("SOCKS5: no acceptable auth methods")
        }

        // Step 4: Send CONNECT request
        // Format: VER CMD RSV ATYP DST.ADDR DST.PORT
        // Detect if host is IPv4 to use correct address type
        val ipv4Parts = host.split(".").mapNotNull { it.toIntOrNull() }
        val isIPv4 = ipv4Parts.size == 4 && ipv4Parts.all { it in 0..255 }

        val request: ByteArray
        if (isIPv4) {
            // ATYP 0x01: IPv4 address (4 bytes)
            request = ByteArray(4 + 4 + 2)
            request[0] = 0x05 // VER
            request[1] = 0x01 // CMD: CONNECT
            request[2] = 0x00 // RSV
            request[3] = 0x01 // ATYP: IPv4
            for (i in 0..3) {
                request[4 + i] = ipv4Parts[i].toByte()
            }
            request[8] = ((port shr 8) and 0xFF).toByte()
            request[9] = (port and 0xFF).toByte()
        } else {
            // ATYP 0x03: Domain name
            val hostBytes = host.toByteArray(Charsets.US_ASCII)
            request = ByteArray(4 + 1 + hostBytes.size + 2)
            request[0] = 0x05 // VER
            request[1] = 0x01 // CMD: CONNECT
            request[2] = 0x00 // RSV
            request[3] = 0x03 // ATYP: domain name
            request[4] = hostBytes.size.toByte()
            System.arraycopy(hostBytes, 0, request, 5, hostBytes.size)
            request[5 + hostBytes.size] = ((port shr 8) and 0xFF).toByte()
            request[5 + hostBytes.size + 1] = (port and 0xFF).toByte()
        }

        out.write(request)
        out.flush()
        Log.d(TAG, "Sent CONNECT request for $host:$port (atyp=${if (isIPv4) "IPv4" else "domain"})")

        // Step 5: Read CONNECT response header (4 bytes: VER REP RSV ATYP)
        val connResp = readExact(inp, 4, "CONNECT response header")
        val cVer = connResp[0].toInt() and 0xFF
        val cRep = connResp[1].toInt() and 0xFF
        val cAtyp = connResp[3].toInt() and 0xFF
        Log.d(TAG, "CONNECT response: version=$cVer, reply=$cRep, addrType=$cAtyp")

        if (cVer != 0x05) {
            sock.close()
            throw java.io.IOException("SOCKS5 CONNECT: invalid version $cVer")
        }
        if (cRep != 0x00) {
            sock.close()
            val errorMsg = when (cRep) {
                0x01 -> "general failure"
                0x02 -> "connection not allowed"
                0x03 -> "network unreachable"
                0x04 -> "host unreachable"
                0x05 -> "connection refused"
                0x06 -> "TTL expired"
                0x07 -> "command not supported"
                0x08 -> "address type not supported"
                else -> "unknown error ($cRep)"
            }
            throw java.io.IOException("SOCKS5 CONNECT failed: $errorMsg")
        }

        // Step 6: Read the rest of the CONNECT response (bound address + port)
        when (cAtyp) {
            0x01 -> readExact(inp, 4 + 2, "bound IPv4 address") // IPv4 + port
            0x03 -> { // Domain
                val domainLen = inp.read()
                if (domainLen == -1) throw java.io.IOException("SOCKS5: unexpected end of stream")
                readExact(inp, domainLen + 2, "bound domain address") // domain + port
            }
            0x04 -> readExact(inp, 16 + 2, "bound IPv6 address") // IPv6 + port
            else -> {
                // Read a reasonable amount to clear the buffer
                readExact(inp, 4 + 2, "bound address (unknown type)")
            }
        }

        Log.i(TAG, "SOCKS5 CONNECT successful to $host:$port through $proxyHost:$proxyPort")

        // Clear socket timeout for the SSH session (it will manage its own timeouts)
        sock.soTimeout = 0

        // Store references
        socket = sock
        inputStream = inp
        outputStream = out
    }

    override fun getInputStream(): InputStream {
        return inputStream ?: throw java.io.IOException("Not connected")
    }

    override fun getOutputStream(): OutputStream {
        return outputStream ?: throw java.io.IOException("Not connected")
    }

    override fun getSocket(): Socket {
        return socket ?: throw java.io.IOException("Not connected")
    }

    override fun close() {
        try {
            socket?.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error closing proxy socket: ${e.message}")
        }
        socket = null
        inputStream = null
        outputStream = null
    }

    private fun readExact(input: InputStream, count: Int, label: String): ByteArray {
        val buf = ByteArray(count)
        var offset = 0
        while (offset < count) {
            val n = input.read(buf, offset, count - offset)
            if (n == -1) throw java.io.IOException("SOCKS5: unexpected end of stream while reading $label")
            offset += n
        }
        return buf
    }
}
