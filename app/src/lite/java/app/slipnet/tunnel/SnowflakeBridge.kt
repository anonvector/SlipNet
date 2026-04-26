package app.slipnet.tunnel

import android.content.Context
import java.net.InetSocketAddress

/**
 * Stub SnowflakeBridge for the lite flavor.
 * Tor/Snowflake is not available in the lite build.
 */
object SnowflakeBridge {
    @Volatile var isTorReady = false
    @Volatile var torBootstrapProgress = 0

    fun startClient(
        context: Context,
        snowflakePort: Int,
        torSocksPort: Int,
        listenHost: String = "127.0.0.1",
        bridgeLines: String = "",
        upstreamSocksAddr: InetSocketAddress? = null
    ): Result<Unit> {
        return Result.failure(UnsupportedOperationException("Tor/Snowflake is not available in SlipNet Lite"))
    }

    fun stopClient() {}

    fun isRunning(): Boolean = false

    fun isClientHealthy(): Boolean = false
}
