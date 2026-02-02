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
 * DNS scanning mode
 */
enum class ScanMode {
    SIMPLE,       // Basic ping - just check if resolver responds to A record query
    DNS_TUNNEL    // Advanced - test NS, TXT records and random subdomain support for DNS tunneling
}

/**
 * Detailed results from DNS tunnel compatibility testing
 */
data class DnsTunnelTestResult(
    val nsSupport: Boolean = false,
    val txtSupport: Boolean = false,
    val randomSubdomain1: Boolean = false,
    val randomSubdomain2: Boolean = false
) {
    val score: Int
        get() = listOf(nsSupport, txtSupport, randomSubdomain1, randomSubdomain2).count { it }

    val maxScore: Int = 4

    val isCompatible: Boolean
        get() = score == maxScore

    val details: String
        get() = buildString {
            append(if (nsSupport) "NS✓" else "NS✗")
            append(" ")
            append(if (txtSupport) "TXT✓" else "TXT✗")
            append(" ")
            append(if (randomSubdomain1) "RND1✓" else "RND1✗")
            append(" ")
            append(if (randomSubdomain2) "RND2✓" else "RND2✗")
        }
}

/**
 * Result of scanning a single DNS resolver
 */
data class ResolverScanResult(
    val host: String,
    val port: Int = 53,
    val status: ResolverStatus = ResolverStatus.PENDING,
    val responseTimeMs: Long? = null,
    val errorMessage: String? = null,
    val tunnelTestResult: DnsTunnelTestResult? = null
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
