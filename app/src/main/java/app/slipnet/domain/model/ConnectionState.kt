package app.slipnet.domain.model

sealed class ConnectionState {
    data object Disconnected : ConnectionState()
    data object Connecting : ConnectionState()
    data class Connected(
        val profile: ServerProfile,
        val connectedAt: Long = System.currentTimeMillis()
    ) : ConnectionState()
    data object Disconnecting : ConnectionState()
    data class Error(val message: String, val cause: Throwable? = null) : ConnectionState()

    val isConnected: Boolean
        get() = this is Connected

    val isConnecting: Boolean
        get() = this is Connecting

    val isDisconnected: Boolean
        get() = this is Disconnected || this is Error

    val displayName: String
        get() = when (this) {
            is Disconnected -> "Disconnected"
            is Connecting -> "Connecting"
            is Connected -> "Connected"
            is Disconnecting -> "Disconnecting"
            is Error -> "Error"
        }
}
