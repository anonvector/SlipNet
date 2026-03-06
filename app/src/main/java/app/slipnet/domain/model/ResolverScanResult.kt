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
 * Detailed results from DNS tunnel compatibility testing
 */
data class DnsTunnelTestResult(
    val nsSupport: Boolean = false,
    val txtSupport: Boolean = false,
    val randomSubdomain: Boolean = false,
    /** True when a dnstt-style long base32 TXT query survives DPI (tunnel realism test). */
    val tunnelRealism: Boolean = false,
    /** True when resolver handles EDNS0 large responses (>512 bytes). */
    val edns0Support: Boolean = false,
    /** Maximum EDNS payload size that works (512, 900, or 1232). 0 = not tested or failed. */
    val ednsMaxPayload: Int = 0,
    /** True when resolver returns proper NXDOMAIN for non-existent domains (no hijacking). */
    val nxdomainCorrect: Boolean = false
) {
    val score: Int
        get() = listOf(nsSupport, txtSupport, randomSubdomain, tunnelRealism, edns0Support, nxdomainCorrect).count { it }

    val maxScore: Int = 6

    val isCompatible: Boolean
        get() = score == maxScore

    val details: String
        get() = buildString {
            append(if (nsSupport) "NS→A✓" else "NS→A✗")
            append(" ")
            append(if (txtSupport) "TXT✓" else "TXT✗")
            append(" ")
            append(if (randomSubdomain) "RND✓" else "RND✗")
            append(" ")
            append(if (tunnelRealism) "DPI✓" else "DPI✗")
            append(" ")
            if (edns0Support) {
                append("EDNS✓")
                if (ednsMaxPayload > 0) append("($ednsMaxPayload)")
            } else {
                append("EDNS✗")
            }
            append(" ")
            append(if (nxdomainCorrect) "NXD✓" else "NXD✗")
        }
}

/**
 * Phase of the end-to-end tunnel test
 */
enum class E2eTestPhase { TUNNEL_SETUP, QUIC_HANDSHAKE, HTTP_REQUEST, COMPLETED }

/**
 * Result of an end-to-end tunnel test through a single resolver
 */
data class E2eTestResult(
    val tunnelSetupMs: Long = 0,
    val httpLatencyMs: Long = 0,
    val totalMs: Long = 0,
    val httpStatusCode: Int = 0,
    val success: Boolean = false,
    val errorMessage: String? = null,
    val phase: E2eTestPhase = E2eTestPhase.COMPLETED
)

/**
 * State of the simple-mode E2E pipeline (DNS scan + E2E in one step)
 */
data class SimpleModeE2eState(
    val isRunning: Boolean = false,
    val queuedCount: Int = 0,
    val testedCount: Int = 0,
    val passedCount: Int = 0,
    val currentResolver: String? = null,
    val currentPhase: String = ""
)

/**
 * Overall state of the E2E tunnel scanner
 */
data class E2eScannerState(
    val isRunning: Boolean = false,
    val totalCount: Int = 0,
    val testedCount: Int = 0,
    val passedCount: Int = 0,
    val currentResolver: String? = null,
    val currentPhase: String = ""
)

/**
 * Result of scanning a single DNS resolver
 */
data class ResolverScanResult(
    val host: String,
    val port: Int = 53,
    val status: ResolverStatus = ResolverStatus.PENDING,
    val responseTimeMs: Long? = null,
    val errorMessage: String? = null,
    val tunnelTestResult: DnsTunnelTestResult? = null,
    val e2eTestResult: E2eTestResult? = null
)

/**
 * Overall state of the scanner
 */
data class ScannerState(
    val isScanning: Boolean = false,
    val totalCount: Int = 0,
    val scannedCount: Int = 0,
    val workingCount: Int = 0,
    val timeoutCount: Int = 0,
    val errorCount: Int = 0,
    val focusRangeCount: Int = 0,
    /** Only WORKING results are kept in memory to avoid OOM on large scans. */
    val results: List<ResolverScanResult> = emptyList()
) {
    val progress: Float
        get() = if (totalCount + focusRangeCount > 0) scannedCount.toFloat() / (totalCount + focusRangeCount) else 0f
}
