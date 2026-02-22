package app.slipnet.tunnel

import android.content.Context
import app.slipnet.util.AppLog as Log
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.ServerSocket

/**
 * Bridge to the NaiveProxy binary (Chromium-based HTTPS tunnel).
 *
 * NaiveProxy provides a local SOCKS5 proxy that tunnels traffic through
 * an HTTPS CONNECT proxy (Caddy + forwardproxy) with authentic Chrome
 * TLS fingerprinting. This makes traffic indistinguishable from normal
 * Chrome HTTPS browsing to deep packet inspection.
 *
 * Used by NAIVE_SSH tunnel type: JSch connects through NaiveProxy's
 * local SOCKS5 to reach the SSH server behind Caddy.
 */
object NaiveBridge {
    private const val TAG = "NaiveBridge"
    private const val BINARY_NAME = "libnaive.so"

    private var process: Process? = null
    @Volatile var isReady = false

    /**
     * Start the NaiveProxy process.
     *
     * @param context Android context for accessing native library dir
     * @param listenPort Local SOCKS5 port for NaiveProxy to listen on
     * @param listenHost Local listen address (default: 127.0.0.1)
     * @param serverHost Caddy server hostname (domain field)
     * @param serverPort Caddy HTTPS port (naivePort, default 443)
     * @param username HTTP proxy auth username
     * @param password HTTP proxy auth password
     */
    fun start(
        context: Context,
        listenPort: Int,
        listenHost: String = "127.0.0.1",
        serverHost: String,
        serverPort: Int,
        username: String,
        password: String
    ): Result<Unit> {
        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting NaiveProxy")
        Log.i(TAG, "  Listen: socks://$listenHost:$listenPort")
        Log.i(TAG, "  Server: $serverHost:$serverPort")
        Log.i(TAG, "========================================")

        stop()
        isReady = false

        // Wait for port to be available
        if (!waitForPortAvailable(listenPort)) {
            return Result.failure(RuntimeException("Port $listenPort is in use"))
        }

        val binaryPath = context.applicationInfo.nativeLibraryDir + "/$BINARY_NAME"
        if (!File(binaryPath).exists()) {
            return Result.failure(RuntimeException("NaiveProxy binary not found at $binaryPath"))
        }

        return try {
            val args = mutableListOf(
                binaryPath,
                "--listen=socks://$listenHost:$listenPort",
                "--log"
            )

            // Pre-resolve server IP to avoid ISP DNS poisoning.
            // NaiveProxy (Chromium) would otherwise use its own DNS resolver,
            // which goes through ISP DNS since the app is excluded from VPN.
            val resolvedIp = try {
                InetAddress.getByName(serverHost).hostAddress
            } catch (e: Exception) {
                Log.w(TAG, "Failed to resolve $serverHost: ${e.message}")
                return Result.failure(RuntimeException("Cannot resolve server hostname '$serverHost'"))
            }

            args.add("--proxy=https://$username:$password@$serverHost:$serverPort")
            args.add("--host-resolver-rules=MAP $serverHost $resolvedIp")
            Log.i(TAG, "Pre-resolved: $serverHost -> $resolvedIp")

            val pb = ProcessBuilder(args)
            pb.redirectErrorStream(true)
            val proc = pb.start()
            process = proc

            // Monitor output in daemon thread
            Thread({
                try {
                    val reader = BufferedReader(InputStreamReader(proc.inputStream))
                    var line: String?
                    while (reader.readLine().also { line = it } != null) {
                        Log.d(TAG, "naive: $line")
                        // NaiveProxy logs "Listening on socks://..." when ready
                        if (line?.contains("Listening on") == true) {
                            isReady = true
                        }
                    }
                } catch (e: Exception) {
                    if (process != null) {
                        Log.w(TAG, "NaiveProxy output reader error: ${e.message}")
                    }
                }
            }, "naive-output-reader").also { it.isDaemon = true; it.start() }

            Log.i(TAG, "NaiveProxy process started")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start NaiveProxy", e)
            stop()
            Result.failure(e)
        }
    }

    /**
     * Stop the NaiveProxy process.
     */
    fun stop() {
        process?.let { p ->
            try {
                Log.d(TAG, "Stopping NaiveProxy process...")
                p.destroy()
                Thread.sleep(500)
                if (p.isAlive) {
                    p.destroyForcibly()
                }
                Log.d(TAG, "NaiveProxy process stopped")
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping NaiveProxy", e)
            }
        }
        process = null
        isReady = false
    }

    fun isRunning(): Boolean {
        return process?.isAlive == true
    }

    fun isClientHealthy(): Boolean {
        return isRunning() && isReady
    }

    private fun waitForPortAvailable(port: Int, maxWaitMs: Long = 5000): Boolean {
        val startTime = System.currentTimeMillis()
        while (System.currentTimeMillis() - startTime < maxWaitMs) {
            if (!isPortInUse(port)) return true
            Log.d(TAG, "Waiting for port $port to be released...")
            Thread.sleep(200)
        }
        return !isPortInUse(port)
    }

    private fun isPortInUse(port: Int): Boolean {
        return try {
            ServerSocket(port).use { false }
        } catch (e: Exception) {
            true
        }
    }
}
