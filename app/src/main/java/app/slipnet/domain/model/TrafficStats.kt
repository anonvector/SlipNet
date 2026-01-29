package app.slipnet.domain.model

data class TrafficStats(
    val bytesSent: Long = 0,
    val bytesReceived: Long = 0,
    val packetsSent: Long = 0,
    val packetsReceived: Long = 0,
    val rttMs: Long = 0
) {
    val totalBytes: Long
        get() = bytesSent + bytesReceived

    val totalPackets: Long
        get() = packetsSent + packetsReceived

    fun formatBytesSent(): String = formatBytes(bytesSent)
    fun formatBytesReceived(): String = formatBytes(bytesReceived)
    fun formatTotalBytes(): String = formatBytes(totalBytes)

    companion object {
        val EMPTY = TrafficStats()

        fun formatBytes(bytes: Long): String {
            return when {
                bytes < 1024 -> "$bytes B"
                bytes < 1024 * 1024 -> String.format("%.1f KB", bytes / 1024.0)
                bytes < 1024 * 1024 * 1024 -> String.format("%.1f MB", bytes / (1024.0 * 1024.0))
                else -> String.format("%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
            }
        }
    }
}
