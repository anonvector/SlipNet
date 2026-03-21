package app.slipnet.service

data class ScanServiceState(
    val isScanning: Boolean = false,
    val isE2eRunning: Boolean = false,
    val scannedCount: Int = 0,
    val totalCount: Int = 0,
    val workingCount: Int = 0,
    val stopRequested: Boolean = false
)
