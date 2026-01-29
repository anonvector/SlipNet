package app.slipnet.data.native

import app.slipnet.domain.model.TrafficStats

/**
 * Traffic statistics from the native tunnel.
 */
data class NativeStats(
    val bytesSent: Long = 0,
    val bytesReceived: Long = 0,
    val packetsSent: Long = 0,
    val packetsReceived: Long = 0,
    val activeConnections: Long = 0,
    val rttMs: Long = 0
) {
    companion object {
        val EMPTY = NativeStats()
    }

    /**
     * Convert to domain TrafficStats.
     */
    fun toTrafficStats() = TrafficStats(
        bytesSent = bytesSent,
        bytesReceived = bytesReceived,
        packetsSent = packetsSent,
        packetsReceived = packetsReceived,
        rttMs = rttMs
    )

    /**
     * Format bytes as human-readable string.
     */
    fun formatBytesSent(): String = formatBytes(bytesSent)
    fun formatBytesReceived(): String = formatBytes(bytesReceived)

    /**
     * Get total bytes transferred.
     */
    val totalBytes: Long get() = bytesSent + bytesReceived

    /**
     * Format total bytes as human-readable string.
     */
    fun formatTotalBytes(): String = formatBytes(totalBytes)

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> "%.1f KB".format(bytes / 1024.0)
            bytes < 1024 * 1024 * 1024 -> "%.1f MB".format(bytes / (1024.0 * 1024.0))
            else -> "%.2f GB".format(bytes / (1024.0 * 1024.0 * 1024.0))
        }
    }
}
