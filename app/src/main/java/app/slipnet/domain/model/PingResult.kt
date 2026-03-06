package app.slipnet.domain.model

sealed class PingResult {
    data object Pending : PingResult()
    /** E2E test in progress — shows current phase (e.g. "QUIC handshake...") */
    data class Testing(val phase: String) : PingResult()
    data class Success(val latencyMs: Long) : PingResult()
    data class Error(val message: String) : PingResult()
    data object Skipped : PingResult()
}
