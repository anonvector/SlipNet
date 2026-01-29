package app.slipnet.data.native

interface NativeCallback {
    fun onStateChanged(state: Int)
    fun onStatsUpdated(stats: NativeStats)
    fun onError(errorCode: Int, message: String)

    companion object {
        const val STATE_DISCONNECTED = 0
        const val STATE_CONNECTING = 1
        const val STATE_CONNECTED = 2
        const val STATE_DISCONNECTING = 3
        const val STATE_ERROR = 4
    }
}
