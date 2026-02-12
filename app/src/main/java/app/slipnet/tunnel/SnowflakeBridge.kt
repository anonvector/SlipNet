package app.slipnet.tunnel

import android.content.Context
import android.util.Log
import snowflake.Snowflake
import snowflake.SnowflakeClient
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.ServerSocket

/**
 * Bridge to the Snowflake pluggable transport (Go library) + Tor binary.
 *
 * Snowflake provides WebRTC-based transport for Tor. This bridge manages:
 * 1. Snowflake PT (Go library) — local SOCKS5 for Tor to connect through
 * 2. Tor process — connects through Snowflake PT, provides SOCKS5 for app traffic
 *
 * Port allocation:
 * - snowflakePort (proxyPort+2): Snowflake PT SOCKS5 (Tor connects through this)
 * - torSocksPort (proxyPort+1): Tor SOCKS5 (TorSocksBridge chains to this)
 */
object SnowflakeBridge {
    private const val TAG = "SnowflakeBridge"

    // CDN77 broker (matches latest Tor Browser defaults, optimized for Iran)
    // www.phpmyadmin.net removed — CDN77's TLS cert doesn't cover it
    private const val BROKER_URL = "https://1098762253.rsc.cdn77.org/"
    private const val FRONT_DOMAINS = "www.cdn77.com"
    // Diverse non-Google STUN servers (Google STUN blocked in Iran).
    // Includes port 443 and 10000 variants (harder to block than 3478).
    private const val STUN_URLS = "stun:stun.antisip.com:3478," +
        "stun:stun.epygi.com:3478," +
        "stun:stun.uls.co.za:3478," +
        "stun:stun.voipgate.com:3478," +
        "stun:stun.mixvoip.com:3478," +
        "stun:stun.nextcloud.com:3478," +
        "stun:stun.bethesda.net:3478," +
        "stun:stun.nextcloud.com:443," +
        "stun:stun.sipgate.net:3478," +
        "stun:stun.sipgate.net:10000," +
        "stun:stun.sonetel.com:3478," +
        "stun:stun.voipia.net:3478," +
        "stun:stun.ucsb.edu:3478," +
        "stun:stun.schlund.de:3478"
    // Randomized TLS fingerprint to evade DPI
    private const val UTLS_CLIENT_ID = "hellorandomizedalpn"
    private const val BRIDGE_FINGERPRINT = "2B280B23E1107BB62ABFC40DDCC8824814F80A72"

    // AMP cache rendezvous config (for Snowflake AMP mode)
    private const val AMP_BROKER_URL = "https://snowflake-broker.torproject.net/"
    private const val AMP_FRONT_DOMAIN = "www.google.com"
    private const val AMP_CACHE_URL = "https://cdn.ampproject.org/"

    private var client: SnowflakeClient? = null
    private var torProcess: Process? = null
    @Volatile var isTorReady = false
    @Volatile var torBootstrapProgress = 0

    /**
     * Start the Tor process with the appropriate pluggable transport.
     *
     * Transport is auto-detected from bridge lines:
     * - Empty bridgeLines → built-in Snowflake (zero-config)
     * - Lines starting with "obfs4", "webtunnel", "meek_lite" → lyrebird (obfs4proxy) exec PT
     * - Lines starting with "snowflake" → Snowflake Go library PT
     *
     * @param context Android context for accessing native libs and files dir
     * @param snowflakePort Port for Snowflake PT SOCKS5 listener (only used for Snowflake transport)
     * @param torSocksPort Port for Tor SOCKS5 listener
     * @param listenHost Local host (default: 127.0.0.1)
     * @param bridgeLines Custom bridge lines (one per line). Empty = use built-in Snowflake.
     */
    fun startClient(
        context: Context,
        snowflakePort: Int,
        torSocksPort: Int,
        listenHost: String = "127.0.0.1",
        bridgeLines: String = ""
    ): Result<Unit> {
        val isDirect = bridgeLines.trim() == "DIRECT"
        val isAmp = bridgeLines.trim() == "SNOWFLAKE_AMP"
        val isSmart = bridgeLines.trim() == "SMART"
        // Use built-in Snowflake for: empty lines, AMP mode, or SMART fallback
        val useSnowflakePt = bridgeLines.isBlank() || isAmp || isSmart
        val detectedTransport = when {
            isDirect -> "direct"
            useSnowflakePt -> "snowflake"
            else -> detectTransport(bridgeLines)
        }

        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting Tor with $detectedTransport transport")
        if (useSnowflakePt) {
            Log.i(TAG, "  Snowflake PT: $listenHost:$snowflakePort")
            if (isAmp) Log.i(TAG, "  AMP cache rendezvous enabled")
        }
        if (isDirect) Log.i(TAG, "  Direct connection (no bridges)")
        Log.i(TAG, "  Tor SOCKS5: $listenHost:$torSocksPort")
        Log.i(TAG, "========================================")

        stopClient()
        isTorReady = false
        torBootstrapProgress = 0

        // Wait for ports to be available
        if (useSnowflakePt && !waitForPortAvailable(snowflakePort)) {
            return Result.failure(RuntimeException("Port $snowflakePort is in use"))
        }
        if (!waitForPortAvailable(torSocksPort)) {
            return Result.failure(RuntimeException("Port $torSocksPort is in use"))
        }

        return try {
            if (useSnowflakePt) {
                // Start Snowflake PT (Go library)
                val sfListenAddr = "$listenHost:$snowflakePort"
                val newClient = if (isAmp) {
                    Snowflake.newClient(sfListenAddr, AMP_BROKER_URL, AMP_FRONT_DOMAIN, STUN_URLS, UTLS_CLIENT_ID, AMP_CACHE_URL)
                } else {
                    Snowflake.newClient(sfListenAddr, BROKER_URL, FRONT_DOMAINS, STUN_URLS, UTLS_CLIENT_ID, "")
                }
                client = newClient
                newClient.start()

                Thread.sleep(200)

                if (!newClient.isRunning) {
                    client = null
                    return Result.failure(RuntimeException("Snowflake PT failed to start"))
                }

                if (!verifyTcpListening(listenHost, snowflakePort)) {
                    Log.w(TAG, "Snowflake PT not listening, but client reports running")
                }
                Log.i(TAG, "Snowflake PT started on $sfListenAddr")
            } else if (!isDirect && detectedTransport != "snowflake") {
                // For obfs4/webtunnel/meek_lite: verify the PT binary exists
                val ptBinaryPath = getObfs4proxyPath(context)
                    ?: return Result.failure(RuntimeException(
                        "obfs4proxy (lyrebird) binary not found. " +
                        "It needs to be compiled and bundled as libobfs4proxy.so in the app's native libraries."
                    ))
                Log.i(TAG, "PT binary found: $ptBinaryPath")
            }

            // Setup Tor data directory and config
            val torDataDir = File(context.filesDir, "tor_data")
            torDataDir.mkdirs()

            extractGeoIpFiles(context, torDataDir)
            val torrcPath = writeTorrc(
                context = context,
                torDataDir = torDataDir,
                listenHost = listenHost,
                torSocksPort = torSocksPort,
                snowflakePort = snowflakePort,
                bridgeLines = bridgeLines
            )

            // Start Tor process
            val torBinary = context.applicationInfo.nativeLibraryDir + "/libtor.so"
            if (!File(torBinary).exists()) {
                stopSnowflakePt()
                return Result.failure(RuntimeException("Tor binary not found at $torBinary"))
            }

            val pb = ProcessBuilder(torBinary, "-f", torrcPath)
            pb.redirectErrorStream(true)
            pb.environment()["HOME"] = torDataDir.absolutePath
            val process = pb.start()
            torProcess = process

            // Monitor Tor output for bootstrap progress
            Thread({
                try {
                    val reader = BufferedReader(InputStreamReader(process.inputStream))
                    var line: String?
                    while (reader.readLine().also { line = it } != null) {
                        Log.d(TAG, "Tor: $line")
                        val match = Regex("Bootstrapped (\\d+)%").find(line!!)
                        if (match != null) {
                            torBootstrapProgress = match.groupValues[1].toInt()
                            Log.i(TAG, "Tor bootstrap: $torBootstrapProgress%")
                            if (torBootstrapProgress >= 100) {
                                isTorReady = true
                            }
                        }
                    }
                } catch (e: Exception) {
                    if (torProcess != null) {
                        Log.w(TAG, "Tor output reader error: ${e.message}")
                    }
                }
            }, "tor-output-reader").also { it.isDaemon = true; it.start() }

            Log.i(TAG, "Tor process started, waiting for bootstrap...")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start Tor with $detectedTransport", e)
            stopClient()
            Result.failure(e)
        }
    }

    /**
     * Detect the pluggable transport type from the first bridge line's prefix.
     * Returns the transport name (e.g., "obfs4", "webtunnel", "meek_lite", "snowflake").
     */
    private fun detectTransport(bridgeLines: String): String {
        val firstLine = bridgeLines.lines().firstOrNull { it.isNotBlank() }?.trim() ?: return "snowflake"
        val firstWord = firstLine.split("\\s+".toRegex()).firstOrNull()?.lowercase() ?: return "snowflake"
        return when {
            firstWord == "obfs4" -> "obfs4"
            firstWord == "webtunnel" -> "webtunnel"
            firstWord == "meek_lite" -> "meek_lite"
            firstWord == "snowflake" -> "snowflake"
            else -> "obfs4" // Default to obfs4 if prefix is unrecognized (could be IP:PORT format)
        }
    }

    /**
     * Stop the Tor process and Snowflake PT.
     */
    fun stopClient() {
        // Stop Tor first
        torProcess?.let { p ->
            try {
                Log.d(TAG, "Stopping Tor process...")
                p.destroy()
                Thread.sleep(500)
                if (p.isAlive) {
                    p.destroyForcibly()
                }
                Log.d(TAG, "Tor process stopped")
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping Tor", e)
            }
        }
        torProcess = null
        isTorReady = false
        torBootstrapProgress = 0

        // Stop Snowflake PT
        stopSnowflakePt()
    }

    private fun stopSnowflakePt() {
        client?.let { c ->
            try {
                Log.d(TAG, "Stopping Snowflake PT...")
                c.stop()
                Log.d(TAG, "Snowflake PT stopped")
                Thread.sleep(500)
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping Snowflake PT", e)
            }
        }
        client = null
    }

    fun isRunning(): Boolean {
        // For non-Snowflake transports, client is null — only Tor needs to be alive
        return (client == null || client?.isRunning == true) && isTorProcessAlive()
    }

    fun isClientHealthy(): Boolean {
        return isRunning() && isTorReady
    }

    private fun isTorProcessAlive(): Boolean {
        return torProcess?.isAlive == true
    }

    /**
     * Check if the obfs4proxy (lyrebird) binary exists in the app's native library dir.
     * obfs4proxy handles obfs4, webtunnel, and meek_lite transports.
     *
     * @return absolute path to the binary, or null if not found
     */
    private fun getObfs4proxyPath(context: Context): String? {
        val nativeLibDir = context.applicationInfo.nativeLibraryDir
        val binaryPath = "$nativeLibDir/libobfs4proxy.so"
        return if (File(binaryPath).exists()) binaryPath else null
    }

    /**
     * Write torrc config file.
     * If bridgeLines is empty, uses built-in Snowflake. Otherwise, auto-detects
     * transport from bridge line prefixes and generates appropriate ClientTransportPlugin directives.
     */
    private fun writeTorrc(
        context: Context,
        torDataDir: File,
        listenHost: String,
        torSocksPort: Int,
        snowflakePort: Int,
        bridgeLines: String = ""
    ): String {
        val torrcFile = File(torDataDir, "torrc")
        val isDirect = bridgeLines.trim() == "DIRECT"

        // Common torrc settings (UseBridges omitted for direct mode)
        val common = buildString {
            appendLine("SocksPort $listenHost:$torSocksPort")
            appendLine("DataDirectory ${torDataDir.absolutePath}")
            if (!isDirect) appendLine("UseBridges 1")
            appendLine("GeoIPFile ${torDataDir.absolutePath}/geoip")
            appendLine("GeoIPv6File ${torDataDir.absolutePath}/geoip6")
            appendLine("Log notice stdout")
            appendLine("CircuitBuildTimeout 60")
            appendLine("LearnCircuitBuildTimeout 0")
            appendLine("KeepalivePeriod 60")
            appendLine("NumEntryGuards 4")
            appendLine("ClientUseIPv4 1")
            appendLine("ClientUseIPv6 0")
            appendLine("ClientPreferIPv6ORPort 0")
        }.trim()

        // Transport-specific lines
        val transportLines = when {
            // Direct mode: no bridges, no transport plugins
            isDirect -> ""

            // Built-in Snowflake or AMP or SMART fallback (zero-config)
            bridgeLines.isBlank() || bridgeLines.trim() == "SNOWFLAKE_AMP" || bridgeLines.trim() == "SMART" -> {
                // Our Go PT already has broker/fronts/STUN/uTLS built in, so the bridge
                // line only needs the address and fingerprint.
                """
                    ClientTransportPlugin snowflake socks5 $listenHost:$snowflakePort
                    Bridge snowflake 192.0.2.3:80 $BRIDGE_FINGERPRINT
                """.trimIndent()
            }

            else -> {
                // Auto-detect transports from bridge lines and generate config
                val lines = bridgeLines.lines().filter { it.isNotBlank() }.map { it.trim() }
                val transportsNeeded = mutableSetOf<String>()
                val bridgeDirectives = StringBuilder()

                for (line in lines) {
                    val transport = line.split("\\s+".toRegex()).firstOrNull()?.lowercase() ?: continue
                    transportsNeeded.add(transport)
                    bridgeDirectives.appendLine("Bridge $line")
                }

                val pluginDirectives = StringBuilder()
                val ptBinary = getObfs4proxyPath(context)

                for (transport in transportsNeeded) {
                    when (transport) {
                        "snowflake" -> {
                            // Custom snowflake bridge line (user-provided, not built-in)
                            pluginDirectives.appendLine("ClientTransportPlugin snowflake socks5 $listenHost:$snowflakePort")
                        }
                        "obfs4", "webtunnel", "meek_lite" -> {
                            // All handled by lyrebird (obfs4proxy)
                            if (ptBinary != null) {
                                pluginDirectives.appendLine("ClientTransportPlugin $transport exec $ptBinary")
                            }
                        }
                    }
                }

                "${pluginDirectives.toString().trim()}\n${bridgeDirectives.toString().trim()}"
            }
        }

        torrcFile.writeText("$common\n$transportLines\n")
        return torrcFile.absolutePath
    }

    private fun extractGeoIpFiles(context: Context, torDataDir: File) {
        for (name in listOf("geoip", "geoip6")) {
            val destFile = File(torDataDir, name)
            if (destFile.exists()) continue
            try {
                context.assets.open(name).use { input ->
                    destFile.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }
                Log.d(TAG, "Extracted $name to ${destFile.absolutePath}")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to extract $name (may not be bundled yet): ${e.message}")
            }
        }
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

    private fun verifyTcpListening(host: String, port: Int): Boolean {
        return try {
            java.net.Socket().use { socket ->
                socket.connect(java.net.InetSocketAddress(host, port), 2000)
                true
            }
        } catch (e: Exception) {
            false
        }
    }
}
