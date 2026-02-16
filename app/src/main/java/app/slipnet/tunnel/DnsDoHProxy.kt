package app.slipnet.tunnel

import app.slipnet.util.AppLog as Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ExecutorService
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import okhttp3.ConnectionPool
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * Lightweight UDP-to-DoH DNS proxy.
 *
 * Listens on a local UDP port and forwards DNS queries to a DoH server
 * via HTTPS, then returns the responses back over UDP.
 *
 * Note: DNSTT's Go library supports DoH natively (via https:// prefix),
 * so this proxy is typically not needed for DNSTT+DoH. It remains available
 * as a fallback or for other use cases.
 *
 * Lifecycle: start before consumer, stop after consumer.
 */
object DnsDoHProxy {
    private const val TAG = "DnsDoHProxy"
    private const val MAX_DNS_PACKET = 4096

    private var socket: DatagramSocket? = null
    private var thread: Thread? = null
    private var executor: ExecutorService? = null
    private val running = AtomicBoolean(false)
    @Volatile
    private var httpClient: OkHttpClient? = null
    private var dohUrl: String = ""

    /** Pre-resolved IP map from [DOH_SERVERS] — shared with DohBridge. */
    private val serverIpMap: Map<String, List<String>> by lazy {
        DOH_SERVERS
            .filter { it.ips.isNotEmpty() }
            .associate { server ->
                try { java.net.URL(server.url).host } catch (_: Exception) { "" } to server.ips
            }
            .filterKeys { it.isNotEmpty() }
    }

    /**
     * Start the UDP-to-DoH proxy.
     * @return the local UDP port the proxy is listening on, or -1 on failure.
     */
    fun start(dohUrl: String): Int {
        stop()

        this.dohUrl = dohUrl

        httpClient = OkHttpClient.Builder()
            .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .writeTimeout(5, TimeUnit.SECONDS)
            .connectionPool(ConnectionPool(8, 30, TimeUnit.SECONDS))
            .dns(object : Dns {
                override fun lookup(hostname: String): List<InetAddress> {
                    val preResolved = serverIpMap[hostname]?.mapNotNull { ip ->
                        try { InetAddress.getByName(ip) } catch (_: Exception) { null }
                    } ?: emptyList()
                    val systemResolved = try {
                        Dns.SYSTEM.lookup(hostname)
                    } catch (_: Exception) { emptyList() }
                    val combined = (preResolved + systemResolved).distinctBy { it.hostAddress }
                    if (combined.isNotEmpty()) return combined
                    throw java.net.UnknownHostException("No addresses for $hostname")
                }
            })
            .build()

        val pool = ThreadPoolExecutor(
            4, 32, 30L, TimeUnit.SECONDS,
            LinkedBlockingQueue(256)
        )
        pool.allowCoreThreadTimeOut(true)
        executor = pool

        return try {
            val ds = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
            socket = ds
            val port = ds.localPort
            running.set(true)

            thread = Thread({
                Log.i(TAG, "UDP-to-DoH proxy started on 127.0.0.1:$port -> $dohUrl")
                val buf = ByteArray(MAX_DNS_PACKET)
                while (running.get()) {
                    try {
                        val packet = DatagramPacket(buf, buf.size)
                        ds.receive(packet)
                        val query = buf.copyOfRange(0, packet.length)
                        val clientAddr = packet.address
                        val clientPort = packet.port

                        executor?.execute {
                            try {
                                val response = forwardViaDoH(query)
                                if (response != null) {
                                    val resp = DatagramPacket(response, response.size, clientAddr, clientPort)
                                    ds.send(resp)
                                }
                            } catch (e: Exception) {
                                if (running.get()) {
                                    Log.w(TAG, "DoH forward error: ${e.message}")
                                }
                            }
                        }
                    } catch (e: Exception) {
                        if (running.get()) {
                            Log.w(TAG, "Receive error: ${e.message}")
                        }
                    }
                }
            }, "DnsDoHProxy").apply {
                isDaemon = true
                start()
            }

            Log.i(TAG, "Started on port $port for $dohUrl")
            port
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start: ${e.message}")
            stop()
            -1
        }
    }

    fun stop() {
        running.set(false)
        try { socket?.close() } catch (_: Exception) {}
        socket = null
        thread?.interrupt()
        thread = null
        try { executor?.shutdownNow() } catch (_: Exception) {}
        executor = null
        try {
            httpClient?.connectionPool?.evictAll()
            httpClient?.dispatcher?.executorService?.shutdown()
        } catch (_: Exception) {}
        httpClient = null
        Log.d(TAG, "Stopped")
    }

    fun isRunning(): Boolean = running.get()

    private fun forwardViaDoH(query: ByteArray): ByteArray? {
        val client = httpClient ?: return null
        val body = query.toRequestBody("application/dns-message".toMediaType())
        val request = Request.Builder()
            .url(dohUrl)
            .post(body)
            .header("Accept", "application/dns-message")
            .build()

        client.newCall(request).execute().use { response ->
            if (response.isSuccessful) {
                return response.body?.bytes()
            } else {
                Log.w(TAG, "DoH HTTP ${response.code}")
                return null
            }
        }
    }
}
