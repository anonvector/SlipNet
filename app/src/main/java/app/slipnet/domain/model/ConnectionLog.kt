package app.slipnet.domain.model

data class ConnectionLog(
    val id: Long = 0,
    val profileId: Long,
    val profileName: String,
    val timestamp: Long = System.currentTimeMillis(),
    val eventType: LogEventType,
    val message: String,
    val details: String? = null
)

enum class LogEventType(val displayName: String) {
    CONNECT_START("Connection Started"),
    CONNECT_SUCCESS("Connected"),
    CONNECT_FAILED("Connection Failed"),
    DISCONNECT("Disconnected"),
    DISCONNECT_ERROR("Disconnect Error"),
    TRAFFIC_UPDATE("Traffic Update"),
    ERROR("Error"),
    INFO("Info"),
    WARNING("Warning")
}
