package app.slipnet.service

import app.slipnet.domain.model.ResolverScanResult

data class ScanServiceState(
    val isScanning: Boolean = false,
    val isE2eRunning: Boolean = false,
    val scannedCount: Int = 0,
    val totalCount: Int = 0,
    val workingCount: Int = 0,
    val stopRequested: Boolean = false,
    /** Working scan results preserved across activity recreation. */
    val results: List<ResolverScanResult> = emptyList(),
    /** Profile ID for restoring E2E test context after activity recreation. */
    val profileId: Long? = null,
    // E2E progress (standalone advanced-mode E2E)
    val e2eTotalCount: Int = 0,
    val e2eTestedCount: Int = 0,
    val e2ePassedCount: Int = 0,
    // Simple-mode E2E progress
    val simpleE2eQueuedCount: Int = 0,
    val simpleE2eTestedCount: Int = 0,
    val simpleE2ePassedCount: Int = 0,
    // Active E2E resolvers: host → current phase (e.g. "Connecting...", "Testing HTTP")
    val e2eActiveResolvers: Map<String, String> = emptyMap()
)
