package app.slipnet.tunnel

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * TCP connection state
 */
enum class TcpState {
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT,
    CLOSED
}

/**
 * NAT entry for tracking a connection
 */
data class NatEntry(
    val key: ConnectionKey,
    val streamId: Long,
    var tcpState: TcpState = TcpState.SYN_RECEIVED,
    var ourSeqNum: Long = 0,
    var ourAckNum: Long = 0,
    var clientSeqNum: Long = 0,
    var lastActivity: Long = System.currentTimeMillis()
) {
    fun touch() {
        lastActivity = System.currentTimeMillis()
    }

    fun isExpired(timeoutMs: Long): Boolean {
        return System.currentTimeMillis() - lastActivity > timeoutMs
    }
}

/**
 * NAT table for connection tracking
 */
class NatTable(private val timeoutMs: Long = 300_000L) {
    private val entries = ConcurrentHashMap<ConnectionKey, NatEntry>()
    private val streamIdToKey = ConcurrentHashMap<Long, ConnectionKey>()
    private val nextStreamId = AtomicLong(1)

    /**
     * Get or create a NAT entry for a connection.
     * Returns pair of (entry, isNew)
     */
    fun getOrCreate(key: ConnectionKey): Pair<NatEntry, Boolean> {
        val existing = entries[key]
        if (existing != null) {
            existing.touch()
            return existing to false
        }

        val streamId = nextStreamId.getAndIncrement()
        val entry = NatEntry(key = key, streamId = streamId)
        entries[key] = entry
        streamIdToKey[streamId] = key
        return entry to true
    }

    /**
     * Get entry by connection key
     */
    fun get(key: ConnectionKey): NatEntry? {
        return entries[key]?.also { it.touch() }
    }

    /**
     * Get entry by stream ID
     */
    fun getByStreamId(streamId: Long): NatEntry? {
        val key = streamIdToKey[streamId] ?: return null
        return entries[key]?.also { it.touch() }
    }

    /**
     * Update entry state
     */
    fun update(key: ConnectionKey, block: (NatEntry) -> Unit) {
        entries[key]?.let {
            block(it)
            it.touch()
        }
    }

    /**
     * Update entry by stream ID
     */
    fun updateByStreamId(streamId: Long, block: (NatEntry) -> Unit) {
        val key = streamIdToKey[streamId] ?: return
        entries[key]?.let {
            block(it)
            it.touch()
        }
    }

    /**
     * Remove entry by key
     */
    fun remove(key: ConnectionKey) {
        entries.remove(key)?.let { entry ->
            streamIdToKey.remove(entry.streamId)
        }
    }

    /**
     * Remove entry by stream ID
     */
    fun removeByStreamId(streamId: Long) {
        streamIdToKey.remove(streamId)?.let { key ->
            entries.remove(key)
        }
    }

    /**
     * Clean up expired entries
     */
    fun cleanupExpired(): Int {
        val now = System.currentTimeMillis()
        var removed = 0

        entries.entries.removeIf { (key, entry) ->
            val expired = entry.isExpired(timeoutMs)
            if (expired) {
                streamIdToKey.remove(entry.streamId)
                removed++
            }
            expired
        }

        return removed
    }

    /**
     * Get current connection count
     */
    fun connectionCount(): Int = entries.size

    /**
     * Clear all entries
     */
    fun clear() {
        entries.clear()
        streamIdToKey.clear()
    }
}
