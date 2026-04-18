package app.slipnet.tunnel

import app.slipnet.util.AppLog as Log
import java.io.FileDescriptor
import java.net.Socket

/**
 * Native socket primitives used by the DPI-bypass strategies in
 * [SniFragmentForwarder].
 *
 * - [setIpTtl]: sets IP_TTL / IPV6_UNICAST_HOPS on an already-connected socket.
 * - [sendFakeThenSwap]: ByeDPI-style fake ClientHello — sends `fake` with a
 *   low TTL (so it dies mid-path), then swaps the kernel's send-buffer pages
 *   to hold `real`, so any TCP retransmit carries real data.
 *
 * Getting the raw fd out of a [Socket] relies on the hidden
 * `getFileDescriptor$()` method; if that's unavailable (future Android
 * tightens access), the helpers return failure and the caller should fall
 * back to a plain `send()`.
 */
object NativeSocket {

    private const val TAG = "NativeSocket"

    @Volatile private var libraryLoaded: Boolean = false
    @Volatile private var libraryErrorLogged: Boolean = false

    private fun ensureLibrary(): Boolean {
        if (libraryLoaded) return true
        return try {
            System.loadLibrary("slipnet-sockops")
            libraryLoaded = true
            true
        } catch (t: Throwable) {
            if (!libraryErrorLogged) {
                Log.w(TAG, "slipnet-sockops not loaded: ${t.message}")
                libraryErrorLogged = true
            }
            false
        }
    }

    /** Extract the raw OS fd from a connected [Socket]. Returns -1 on failure. */
    fun socketFd(socket: Socket): Int {
        return try {
            val m = Socket::class.java.getDeclaredMethod("getFileDescriptor\$")
            m.isAccessible = true
            val fd = m.invoke(socket) as? FileDescriptor ?: return -1
            val intM = FileDescriptor::class.java.getDeclaredMethod("getInt\$")
            intM.isAccessible = true
            intM.invoke(fd) as Int
        } catch (t: Throwable) {
            Log.w(TAG, "socketFd reflection failed: ${t.message}")
            -1
        }
    }

    /** Set IP_TTL (or IPV6_UNICAST_HOPS) on [fd]. Returns 0 on success, -errno on failure. */
    fun setIpTtl(fd: Int, ttl: Int): Int {
        if (fd < 0 || !ensureLibrary()) return -1
        return try {
            nativeSetIpTtl(fd, ttl)
        } catch (t: Throwable) {
            Log.w(TAG, "nativeSetIpTtl threw: ${t.message}")
            -1
        }
    }

    /**
     * Cap the outgoing TCP MSS on [fd] via `TCP_MAXSEG`. Must be called after
     * `connect()`. Returns 0 on success, -errno on failure.
     *
     * Useful for DPI evasion: a small MSS (e.g. 70–90 bytes) forces the kernel
     * to chop every write into many tiny TCP segments, so middleboxes that
     * parse by TCP segment — rather than reassembling TLS records — never see
     * the SNI hostname contiguously.
     */
    fun setTcpMaxSeg(fd: Int, mss: Int): Int {
        if (fd < 0 || !ensureLibrary()) return -1
        return try {
            nativeSetTcpMaxSeg(fd, mss)
        } catch (t: Throwable) {
            Log.w(TAG, "nativeSetTcpMaxSeg threw: ${t.message}")
            -1
        }
    }

    /**
     * Send [fake] with TTL = [lowTtl] then swap kernel send-buffer contents to
     * [real], so any TCP retransmit sends [real] instead. [fake].size must
     * equal [real].size.
     *
     * Returns bytes spliced (should equal fake.size) or negative errno.
     */
    fun sendFakeThenSwap(fd: Int, fake: ByteArray, real: ByteArray, lowTtl: Int, normalTtl: Int): Int {
        if (fd < 0 || !ensureLibrary()) return -1
        if (fake.isEmpty() || fake.size != real.size) return -22  // EINVAL
        return try {
            nativeSendFakeThenSwap(fd, fake, real, lowTtl, normalTtl)
        } catch (t: Throwable) {
            Log.w(TAG, "nativeSendFakeThenSwap threw: ${t.message}")
            -1
        }
    }

    @JvmStatic private external fun nativeSetIpTtl(fd: Int, ttl: Int): Int
    @JvmStatic private external fun nativeSetTcpMaxSeg(fd: Int, mss: Int): Int
    @JvmStatic private external fun nativeSendFakeThenSwap(
        fd: Int, fake: ByteArray, real: ByteArray, lowTtl: Int, normalTtl: Int
    ): Int
}
