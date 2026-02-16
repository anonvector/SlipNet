package app.slipnet.domain.model

sealed class PingResult {
    data object Pending : PingResult()
    data class Success(val latencyMs: Long) : PingResult()
    data class Error(val message: String) : PingResult()
    data object Skipped : PingResult()
}
