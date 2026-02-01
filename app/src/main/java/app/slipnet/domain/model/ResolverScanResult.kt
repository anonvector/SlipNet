package app.slipnet.domain.model

/**
 * Status of a DNS resolver scan result
 */
enum class ResolverStatus {
    PENDING,
    SCANNING,
    WORKING,      // Resolver responds correctly
    CENSORED,     // Resolver hijacks to 10.x.x.x or similar
    TIMEOUT,      // Resolver did not respond in time
    ERROR         // Resolver had an error
}

/**
 * Result of scanning a single DNS resolver
 */
data class ResolverScanResult(
    val host: String,
    val port: Int = 53,
    val status: ResolverStatus = ResolverStatus.PENDING,
    val responseTimeMs: Long? = null,
    val errorMessage: String? = null
)

/**
 * Overall state of the scanner
 */
data class ScannerState(
    val isScanning: Boolean = false,
    val totalCount: Int = 0,
    val scannedCount: Int = 0,
    val workingCount: Int = 0,
    val results: List<ResolverScanResult> = emptyList()
) {
    val progress: Float
        get() = if (totalCount > 0) scannedCount.toFloat() / totalCount else 0f
}
