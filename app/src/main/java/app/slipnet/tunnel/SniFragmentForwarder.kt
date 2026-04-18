package app.slipnet.tunnel

import app.slipnet.util.AppLog as Log
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Local TCP forwarder with TLS ClientHello fragmentation for DPI bypass.
 *
 * Listens locally, connects to a CDN IP, and fragments the first TLS ClientHello
 * packet across multiple TCP segments so DPI cannot reassemble and read the SNI.
 *
 * Traffic flow:
 *   Client -> localhost:listenPort -> [fragment ClientHello] -> cdnIp:cdnPort
 *
 * Fragmentation strategies:
 * - "sni_split": find the SNI extension and split through the middle of the hostname
 * - "half": split the entire ClientHello in half
 * - "multi": split into ~24-byte chunks
 */
class SniFragmentForwarder(private val instanceId: String = "default") {
    private val TAG = "SniFragment[$instanceId]"
    var debugLogging = false
    private fun logd(msg: String) { if (debugLogging) Log.d(TAG, msg) }

    companion object {
        private const val BIND_MAX_RETRIES = 10
        private const val BIND_RETRY_DELAY_MS = 200L
        private const val BUFFER_SIZE = 65536
        private const val TCP_CONNECT_TIMEOUT_MS = 30000
        private const val MULTI_CHUNK_MIN = 16
        private const val MULTI_CHUNK_MAX = 40
        // ByeDPI-style low TTL for the decoy packet in `fake` / `disorder` modes.
        // 8 is the commonly effective value: high enough to reach typical
        // ISP-edge DPI, low enough to die before the foreign server.
        private const val DEFAULT_LOW_TTL = 8
        private const val DEFAULT_NORMAL_TTL = 64
        // Decoy hostname used inside the fake ClientHello in `fake` mode when
        // no user-supplied decoy is configured.
        private const val DEFAULT_FAKE_DECOY = "www.google.com"
        // Default TCP MSS cap when TCP_MAXSEG enforcement is on. 70 is below
        // the typical 80-byte SNI-carrying segment, so the kernel is forced
        // to chop the ClientHello across many TCP segments regardless of
        // TLS-record boundaries — effective against DPI that parses by
        // segment rather than reassembling records.
        private const val DEFAULT_TCP_MAXSEG = 70
        // Per-record jitter bounds for `micro` mode. The effective jitter
        // scales with the user's `fragmentDelayMs` (jitter ≈ delay/10) so the
        // same knob tunes both strategies — clamped to this range so
        // handshake time stays bounded even at extreme delay settings.
        // DPI evasion in micro mode comes from TLS record count + TCP segment
        // boundaries (TCP_MAXSEG=70), not from timing — so we only need
        // enough jitter to prevent kernel write coalescing and keep the
        // gap distribution unpredictable. 1–30 ms covers that; anything
        // larger just makes per-site handshakes painfully slow without
        // improving DPI bypass.
        private const val MICRO_JITTER_MIN_MS = 1
        private const val MICRO_JITTER_MAX_MS = 30
    }

    private val random = SecureRandom()

    var connectIp: String = ""
    var connectPort: Int = 443
    var fragmentStrategy: String = "sni_split"
    var fragmentDelayMs: Int = 100
    var chPaddingEnabled: Boolean = false
    var fakeDecoyHost: String = DEFAULT_FAKE_DECOY
    var lowTtl: Int = DEFAULT_LOW_TTL
    var normalTtl: Int = DEFAULT_NORMAL_TTL
    // When > 0, cap the CDN socket's outgoing TCP MSS via TCP_MAXSEG so the
    // kernel fragments every write into small segments. Forces sub-record TCP
    // fragmentation on top of whatever TLS-record splitting the strategy does.
    // 0 = auto: apply DEFAULT_TCP_MAXSEG only when strategy is `micro` (the
    // explicitly-aggressive strategy, where throughput was already traded
    // away). Non-zero = explicit override. Set < 0 to force-disable.
    var tcpMaxSeg: Int = 0

    private var serverSocket: ServerSocket? = null
    private var acceptorThread: Thread? = null
    private val running = AtomicBoolean(false)
    private val connectionThreads = CopyOnWriteArrayList<Thread>()
    private val txBytes = AtomicLong(0)
    private val rxBytes = AtomicLong(0)

    fun start(listenPort: Int, listenHost: String = "127.0.0.1"): Result<Unit> {
        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting SNI Fragment Forwarder")
        Log.i(TAG, "  Connect: $connectIp:$connectPort")
        Log.i(TAG, "  Listen: $listenHost:$listenPort")
        Log.i(TAG, "  Strategy: $fragmentStrategy")
        Log.i(TAG, "  Delay: ${fragmentDelayMs}ms")
        Log.i(TAG, "========================================")

        stop()
        return try {
            val ss = bindServerSocket(listenHost, listenPort)
            serverSocket = ss
            running.set(true)

            acceptorThread = Thread({
                logd("Acceptor thread started")
                while (running.get() && !Thread.currentThread().isInterrupted) {
                    try {
                        val client = ss.accept()
                        val t = Thread({
                            handleConnection(client)
                        }, "snifrag-conn-$instanceId-${System.nanoTime()}")
                        t.isDaemon = true
                        connectionThreads.add(t)
                        t.start()
                    } catch (e: Exception) {
                        if (running.get()) Log.w(TAG, "Accept error: ${e.message}")
                    }
                }
                logd("Acceptor thread exited")
            }, "snifrag-acceptor-$instanceId")
            acceptorThread!!.isDaemon = true
            acceptorThread!!.start()

            Log.i(TAG, "SNI Fragment Forwarder started on $listenHost:$listenPort")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start: ${e.message}", e)
            Result.failure(e)
        }
    }

    fun stop() {
        if (!running.getAndSet(false)) return
        Log.i(TAG, "Stopping SNI Fragment Forwarder")
        try { serverSocket?.close() } catch (_: Exception) {}
        acceptorThread?.interrupt()
        connectionThreads.forEach { it.interrupt() }
        connectionThreads.clear()
        serverSocket = null
        acceptorThread = null
    }

    fun isRunning(): Boolean = running.get() && serverSocket?.isClosed == false
    fun getTxBytes(): Long = txBytes.get()
    fun getRxBytes(): Long = rxBytes.get()

    private fun handleConnection(client: Socket) {
        try {
            client.tcpNoDelay = true
            client.soTimeout = 60_000

            // Connect to CDN
            val remote = Socket()
            remote.connect(InetSocketAddress(connectIp, connectPort), TCP_CONNECT_TIMEOUT_MS)
            remote.tcpNoDelay = true
            remote.soTimeout = 60_000

            // Force sub-record TCP fragmentation: cap the kernel's outgoing
            // MSS so every write lands in many small segments, regardless of
            // the TLS record sizes we build. Auto-enable only for the
            // explicitly-aggressive `micro` strategy — other strategies keep
            // the path's native MSS so post-handshake throughput isn't hurt.
            // If the native helper isn't available (e.g., SELinux blocks
            // setsockopt), silently continue.
            val effectiveMss = when {
                tcpMaxSeg < 0 -> 0 // force-disabled
                tcpMaxSeg in 40..1400 -> tcpMaxSeg // explicit override
                fragmentStrategy == "micro" || chPaddingEnabled -> DEFAULT_TCP_MAXSEG
                else -> 0
            }
            if (effectiveMss > 0) {
                val fd = NativeSocket.socketFd(remote)
                if (fd >= 0) {
                    val rc = NativeSocket.setTcpMaxSeg(fd, effectiveMss)
                    if (rc == 0) logd("TCP_MAXSEG set to $effectiveMss on CDN socket")
                    else logd("TCP_MAXSEG failed (rc=$rc), continuing with default MSS")
                }
            }

            // Read first data from client (expected: TLS ClientHello)
            val buf = ByteArray(BUFFER_SIZE)
            val n = client.getInputStream().read(buf)
            if (n <= 0) {
                client.close(); remote.close(); return
            }
            val firstData = buf.copyOf(n)

            // If it looks like a TLS ClientHello, fragment it
            if (isTlsClientHello(firstData)) {
                // When CH padding is enabled, use micro-fragmentation (1-byte chunks) to
                // expand the wire size ~6x (each byte gets its own 5-byte TLS record header).
                // We cannot inject a padding extension because the forwarder sits between
                // SSLSocket and the server — modifying the ClientHello changes the TLS
                // transcript hash and breaks the Finished message verification.
                val effectiveStrategy = if (chPaddingEnabled) "micro" else fragmentStrategy
                logd("Fragmenting ClientHello (${firstData.size} bytes, strategy=$effectiveStrategy)")
                when (effectiveStrategy) {
                    "fake" -> sendFakeMode(remote, firstData)
                    "disorder" -> sendDisorderMode(remote, firstData)
                    else -> sendFragmented(remote.getOutputStream(), firstData, effectiveStrategy)
                }
            } else {
                remote.getOutputStream().write(firstData)
                remote.getOutputStream().flush()
            }

            // Bidirectional relay
            relay(client, remote)
        } catch (e: Exception) {
            logd("Connection error: ${e.message}")
        } finally {
            connectionThreads.remove(Thread.currentThread())
        }
    }

    private fun isTlsClientHello(data: ByteArray): Boolean {
        // TLS record: ContentType=0x16 (Handshake), Version, Length
        // Handshake: Type=0x01 (ClientHello)
        return data.size > 5 &&
                data[0] == 0x16.toByte() &&
                data[5] == 0x01.toByte()
    }

    /**
     * Fragment the TLS ClientHello using TLS record splitting.
     *
     * Instead of just splitting TCP segments (which DPI can reassemble),
     * we split the handshake payload across multiple valid TLS records.
     * Each record has its own 5-byte TLS header, making it a legitimate
     * multi-record handshake per RFC 8446. DPI that doesn't reassemble
     * at the TLS record level will see incomplete SNI in each record.
     *
     * Additionally, each TLS record is sent as a separate TCP segment
     * with a randomized delay to defeat timing-based correlation.
     */
    private fun sendFragmented(out: OutputStream, data: ByteArray, strategy: String = fragmentStrategy) {
        // Parse the TLS record header
        if (data.size < 5) { out.write(data); out.flush(); return }
        val contentType = data[0]
        val tlsVersionMajor = data[1]
        val tlsVersionMinor = data[2]
        val recordPayload = data.copyOfRange(5, data.size)

        // Determine split points on the handshake payload
        val splitPoints = when (strategy) {
            "sni_split" -> getSniSplitPoints(recordPayload)
            "half" -> getHalfSplitPoints(recordPayload)
            "multi" -> getMultiSplitPoints(recordPayload)
            "micro" -> getMicroSplitPoints(recordPayload)
            else -> getSniSplitPoints(recordPayload)
        }

        // Build separate TLS records for each fragment
        val fragments = mutableListOf<ByteArray>()
        var pos = 0
        for (splitAt in splitPoints) {
            if (splitAt > pos && splitAt <= recordPayload.size) {
                fragments.add(buildTlsRecord(contentType, tlsVersionMajor, tlsVersionMinor, recordPayload, pos, splitAt - pos))
                pos = splitAt
            }
        }
        if (pos < recordPayload.size) {
            fragments.add(buildTlsRecord(contentType, tlsVersionMajor, tlsVersionMinor, recordPayload, pos, recordPayload.size - pos))
        }

        logd("Sending ${fragments.size} TLS record fragments (strategy=$strategy)")

        // Send each TLS record as a separate TCP segment with randomized delay.
        // Micro uses a small per-record jitter derived from the user's
        // `fragmentDelayMs` (≈ delay/4, clamped). The point isn't to be slow,
        // it's to force DPI reassembly state to be held across many records
        // until stateful middleboxes time out and drop tracking.
        val isMicro = strategy == "micro"
        val useDelay = if (isMicro) true else fragmentDelayMs > 0
        val microJitterMax = (fragmentDelayMs / 10).coerceIn(MICRO_JITTER_MIN_MS, MICRO_JITTER_MAX_MS)
        for ((i, fragment) in fragments.withIndex()) {
            out.write(fragment)
            out.flush()
            if (i < fragments.size - 1 && useDelay) {
                val delay = if (isMicro) {
                    MICRO_JITTER_MIN_MS + random.nextInt(microJitterMax - MICRO_JITTER_MIN_MS + 1)
                } else {
                    val jitter = random.nextInt((fragmentDelayMs / 2).coerceAtLeast(1))
                    (fragmentDelayMs / 2) + jitter
                }
                Thread.sleep(delay.toLong())
            }
        }
    }

    /**
     * ByeDPI-style `fake` mode: emit a decoy ClientHello first with a low IP
     * TTL so it dies before reaching the server, then swap the kernel's send
     * queue so the TCP retransmit (triggered by the missing ACK) carries the
     * real ClientHello. DPI boxes located between the client and the TTL-drop
     * point see the decoy SNI and make their allow/block decision on it.
     *
     * If the native helper or fd extraction fails, fall back to plain send.
     */
    private fun sendFakeMode(remote: Socket, real: ByteArray) {
        val fd = NativeSocket.socketFd(remote)
        if (fd < 0) {
            logd("fake: socket fd unavailable, falling back to plain send")
            remote.getOutputStream().write(real); remote.getOutputStream().flush()
            return
        }
        val decoy = fakeDecoyHost.ifBlank { DEFAULT_FAKE_DECOY }
        val fake = buildFakeClientHello(real, decoy)
        if (fake == null || fake.size != real.size) {
            logd("fake: could not build decoy, falling back to plain send")
            remote.getOutputStream().write(real); remote.getOutputStream().flush()
            return
        }
        val rc = NativeSocket.sendFakeThenSwap(fd, fake, real, lowTtl, normalTtl)
        if (rc == real.size) {
            logd("fake: sent decoy with TTL=$lowTtl, swapped to real (${real.size} bytes)")
        } else {
            logd("fake: native send returned $rc (expected ${real.size}), falling back")
            // Best-effort fallback: send the real hello so the handshake can still proceed.
            try { remote.getOutputStream().write(real); remote.getOutputStream().flush() } catch (_: Exception) {}
        }
    }

    /**
     * ByeDPI-style `disorder` mode: split the ClientHello and send the first
     * half with TTL=1 (so it's dropped one hop out) and the second half with
     * normal TTL. The kernel will retransmit the first half after its RTO
     * fires (with TTL already restored), reaching the server after the second.
     * DPI that reassembles in arrival order sees the halves reversed.
     */
    private fun sendDisorderMode(remote: Socket, real: ByteArray) {
        if (real.size < 10) {
            remote.getOutputStream().write(real); remote.getOutputStream().flush()
            return
        }
        val fd = NativeSocket.socketFd(remote)
        if (fd < 0) {
            logd("disorder: socket fd unavailable, falling back to split")
            sendFragmented(remote.getOutputStream(), real, "half")
            return
        }
        // Split at the SNI hostname if we can find it; otherwise halve.
        val payload = if (real.size > 5) real.copyOfRange(5, real.size) else ByteArray(0)
        val sniOff = findSniHostnameOffset(payload)
        val splitAt = if (sniOff in 1 until payload.size - 1) {
            // Map back to absolute offset (add TLS record header = 5)
            5 + sniOff + payload.size.coerceAtMost(4) / 2 // mid-SNI-ish
        } else {
            real.size / 2
        }.coerceIn(1, real.size - 1)

        val first = real.copyOfRange(0, splitAt)
        val second = real.copyOfRange(splitAt, real.size)

        val out = remote.getOutputStream()
        // Send first half with TTL=1 so it's dropped at the first hop.
        if (NativeSocket.setIpTtl(fd, 1) != 0) {
            logd("disorder: setIpTtl(1) failed, falling back to split")
            sendFragmented(out, real, "half")
            return
        }
        out.write(first); out.flush()
        // Small pause so the TTL=1 packet leaves before we restore TTL.
        try { Thread.sleep(2) } catch (_: InterruptedException) {}
        NativeSocket.setIpTtl(fd, normalTtl)
        out.write(second); out.flush()
        logd("disorder: first=${first.size}B TTL=1, second=${second.size}B TTL=$normalTtl (split@$splitAt)")
    }

    /**
     * Build a decoy ClientHello by cloning [real] and replacing the SNI host
     * name in-place with [decoy] (truncated or space-padded to the original
     * length so the record's byte-offsets stay identical). Returns null if
     * the SNI extension cannot be located.
     */
    private fun buildFakeClientHello(real: ByteArray, decoy: String): ByteArray? {
        if (real.size < 6) return null
        val payload = real.copyOfRange(5, real.size)
        val sniHostOff = findSniHostnameOffset(payload)
        if (sniHostOff < 0) return null
        val hostLen = if (sniHostOff >= 2) {
            ((payload[sniHostOff - 2].toInt() and 0xFF) shl 8) or (payload[sniHostOff - 1].toInt() and 0xFF)
        } else 0
        if (hostLen <= 0 || sniHostOff + hostLen > payload.size) return null

        val decoyBytes = decoy.toByteArray(Charsets.US_ASCII)
        val replacement = ByteArray(hostLen) { ' '.code.toByte() }
        val copyLen = minOf(decoyBytes.size, hostLen)
        System.arraycopy(decoyBytes, 0, replacement, 0, copyLen)

        val fake = real.copyOf()
        // sniHostOff is the offset inside `payload`; in `fake` that's + 5.
        System.arraycopy(replacement, 0, fake, 5 + sniHostOff, hostLen)
        return fake
    }

    /**
     * Build a valid TLS record wrapping a fragment of the handshake payload.
     */
    private fun buildTlsRecord(contentType: Byte, versionMajor: Byte, versionMinor: Byte,
                                payload: ByteArray, offset: Int, length: Int): ByteArray {
        val record = ByteArray(5 + length)
        record[0] = contentType
        record[1] = versionMajor
        record[2] = versionMinor
        record[3] = (length shr 8 and 0xFF).toByte()
        record[4] = (length and 0xFF).toByte()
        System.arraycopy(payload, offset, record, 5, length)
        return record
    }

    // ── Split point calculators (offsets within handshake payload, excluding TLS header) ──

    /**
     * Split through the middle of the SNI hostname with a random offset.
     * Also prepends a 1-byte first fragment to defeat DPI that only checks the first packet.
     */
    private fun getSniSplitPoints(payload: ByteArray): List<Int> {
        val sniOffset = findSniHostnameOffset(payload)
        if (sniOffset > 0 && sniOffset < payload.size - 1) {
            val hostnameLen = if (sniOffset >= 2) {
                ((payload[sniOffset - 2].toInt() and 0xFF) shl 8) or (payload[sniOffset - 1].toInt() and 0xFF)
            } else 0
            // Split at a random point within the hostname (not exactly the middle)
            val mid = if (hostnameLen > 2) {
                sniOffset + 1 + random.nextInt(hostnameLen - 1)
            } else {
                sniOffset + (payload.size - sniOffset) / 2
            }
            val splitPoint = mid.coerceIn(2, payload.size - 1)
            logd("SNI split: 1-byte lead + split at $splitPoint (hostname at $sniOffset, len=$hostnameLen)")
            // 1-byte first fragment + split at SNI
            return listOf(1, splitPoint)
        }
        return getHalfSplitPoints(payload)
    }

    /**
     * 1-byte first fragment + split the rest in half.
     */
    private fun getHalfSplitPoints(payload: ByteArray): List<Int> {
        val mid = 1 + (payload.size - 1) / 2
        return listOf(1, mid)
    }

    /**
     * Split into random-sized chunks (16-40 bytes) for maximum fragmentation.
     */
    private fun getMultiSplitPoints(payload: ByteArray): List<Int> {
        val points = mutableListOf<Int>()
        // Always start with a 1-byte fragment
        var pos = 1
        points.add(pos)
        while (pos < payload.size) {
            val chunkSize = MULTI_CHUNK_MIN + random.nextInt(MULTI_CHUNK_MAX - MULTI_CHUNK_MIN + 1)
            pos += chunkSize
            if (pos < payload.size) {
                points.add(pos)
            }
        }
        return points
    }

    /**
     * Micro-fragmentation: split into 1-byte chunks for maximum wire overhead.
     * Each byte gets its own 5-byte TLS record header, expanding wire size ~6x.
     * This makes every individual packet useless to DPI without reassembly.
     */
    private fun getMicroSplitPoints(payload: ByteArray): List<Int> {
        return (1 until payload.size).toList()
    }

    /**
     * Find the offset where the SNI hostname data begins in the handshake payload
     * (payload excludes the 5-byte TLS record header).
     */
    private fun findSniHostnameOffset(payload: ByteArray): Int {
        // Handshake header (4) + ClientHello fixed (2+32=34) + SessionID(1+)
        if (payload.size < 39) return -1

        var pos = 4 // Skip handshake header
        pos += 2 // client version
        pos += 32 // random

        if (pos >= payload.size) return -1
        val sessionIdLen = payload[pos].toInt() and 0xFF
        pos += 1 + sessionIdLen

        if (pos + 2 > payload.size) return -1
        val cipherSuitesLen = ((payload[pos].toInt() and 0xFF) shl 8) or (payload[pos + 1].toInt() and 0xFF)
        pos += 2 + cipherSuitesLen

        if (pos + 1 > payload.size) return -1
        val compMethodsLen = payload[pos].toInt() and 0xFF
        pos += 1 + compMethodsLen

        if (pos + 2 > payload.size) return -1
        val extensionsLen = ((payload[pos].toInt() and 0xFF) shl 8) or (payload[pos + 1].toInt() and 0xFF)
        pos += 2
        val extensionsEnd = pos + extensionsLen

        while (pos + 4 <= extensionsEnd && pos + 4 <= payload.size) {
            val extType = ((payload[pos].toInt() and 0xFF) shl 8) or (payload[pos + 1].toInt() and 0xFF)
            val extLen = ((payload[pos + 2].toInt() and 0xFF) shl 8) or (payload[pos + 3].toInt() and 0xFF)
            pos += 4

            if (extType == 0x0000 && extLen > 0) {
                if (pos + 5 <= payload.size) {
                    val hostnameStart = pos + 5
                    if (hostnameStart < payload.size) return hostnameStart
                }
            }
            pos += extLen
        }
        return -1
    }

    private fun relay(client: Socket, remote: Socket) {
        val executor = Executors.newFixedThreadPool(2)
        val clientIn = client.getInputStream()
        val clientOut = client.getOutputStream()
        val remoteIn = remote.getInputStream()
        val remoteOut = remote.getOutputStream()

        // client -> remote
        val f1 = executor.submit {
            try {
                val buf = ByteArray(BUFFER_SIZE)
                while (!Thread.currentThread().isInterrupted) {
                    val n = clientIn.read(buf)
                    if (n <= 0) break
                    remoteOut.write(buf, 0, n)
                    remoteOut.flush()
                    txBytes.addAndGet(n.toLong())
                }
            } catch (_: Exception) {}
            try { remote.shutdownOutput() } catch (_: Exception) {}
        }

        // remote -> client
        val f2 = executor.submit {
            try {
                val buf = ByteArray(BUFFER_SIZE)
                while (!Thread.currentThread().isInterrupted) {
                    val n = remoteIn.read(buf)
                    if (n <= 0) break
                    clientOut.write(buf, 0, n)
                    clientOut.flush()
                    rxBytes.addAndGet(n.toLong())
                }
            } catch (_: Exception) {}
            try { client.shutdownOutput() } catch (_: Exception) {}
        }

        try { f1.get() } catch (_: Exception) {}
        try { f2.get() } catch (_: Exception) {}
        executor.shutdownNow()

        try { client.close() } catch (_: Exception) {}
        try { remote.close() } catch (_: Exception) {}
    }

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
