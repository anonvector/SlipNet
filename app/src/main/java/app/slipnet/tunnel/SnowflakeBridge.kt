package app.slipnet.tunnel

import android.content.Context
import app.slipnet.util.AppLog as Log
import snowflake.Snowflake
import snowflake.SnowflakeClient
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.ServerSocket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

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
    private var lyrebirdProcess: Process? = null
    private var torProcess: Process? = null
    @Volatile var isTorReady = false
    @Volatile var torBootstrapProgress = 0

    /**
     * Start the Tor process with the appropriate pluggable transport.
     *
     * Transport is auto-detected from bridge lines:
     * - Empty bridgeLines → built-in Snowflake (zero-config)
     * - Lines starting with "obfs4", "webtunnel", "meek_lite" → lyrebird (obfs4proxy) managed PT
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
            // Determine which lyrebird transports are needed
            val lyrebirdTransports = mutableListOf<String>()
            if (!isDirect && !useSnowflakePt) {
                val lines = bridgeLines.lines().filter { it.isNotBlank() }.map { it.trim() }
                    .map { if (it.lowercase().startsWith("bridge ")) it.substring(7).trim() else it }
                for (line in lines) {
                    val transport = line.split("\\s+".toRegex()).firstOrNull()?.lowercase() ?: continue
                    if (transport in listOf("obfs4", "webtunnel", "meek_lite") && transport !in lyrebirdTransports) {
                        lyrebirdTransports.add(transport)
                    }
                }
            }

            // Map of transport name -> SOCKS5 address (filled by PT startup)
            val lyrebirdMethods = mutableMapOf<String, String>()

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
            } else if (lyrebirdTransports.isNotEmpty()) {
                // Launch lyrebird ourselves using the managed transport protocol.
                // This avoids relying on Tor's exec() which can fail on Android
                // due to SELinux restrictions or permission issues.
                val ptBinaryPath = getObfs4proxyPath(context)
                    ?: return Result.failure(RuntimeException(
                        "obfs4proxy (lyrebird) binary not found. " +
                        "It needs to be compiled and bundled as libobfs4proxy.so in the app's native libraries."
                    ))
                Log.i(TAG, "PT binary: $ptBinaryPath (size=${File(ptBinaryPath).length()})")

                val result = startLyrebird(context, ptBinaryPath, lyrebirdTransports)
                if (result.isFailure) {
                    return result
                }
                lyrebirdMethods.putAll(lyrebirdCmethods)
                Log.i(TAG, "Lyrebird PT started with transports: $lyrebirdMethods")
            }

            // Setup Tor data directory and config
            val torDataDir = File(context.filesDir, "tor_data")
            torDataDir.mkdirs()

            // Clear guard state and lock (not descriptor caches — those help Tor
            // reconnect faster if the bridge connection drops mid-bootstrap)
            listOf("state", "lock").forEach { name ->
                val f = File(torDataDir, name)
                if (f.exists()) {
                    f.delete()
                    Log.d(TAG, "Cleared Tor state: $name")
                }
            }

            extractGeoIpFiles(context, torDataDir)
            val torrcPath = writeTorrc(
                context = context,
                torDataDir = torDataDir,
                listenHost = listenHost,
                torSocksPort = torSocksPort,
                snowflakePort = snowflakePort,
                bridgeLines = bridgeLines,
                lyrebirdMethods = lyrebirdMethods
            )

            // Start Tor process
            val torBinary = context.applicationInfo.nativeLibraryDir + "/libtor.so"
            if (!File(torBinary).exists()) {
                stopSnowflakePt()
                stopLyrebird()
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

    // --- Lyrebird managed transport ---

    /** CMETHOD results from lyrebird: transport name -> "host:port" */
    private val lyrebirdCmethods = mutableMapOf<String, String>()

    /**
     * Launch lyrebird as a managed transport process.
     * Sets up the PT protocol environment, launches the binary, and parses
     * CMETHOD lines to discover which SOCKS5 ports it's listening on.
     */
    private fun startLyrebird(
        context: Context,
        ptBinaryPath: String,
        transports: List<String>
    ): Result<Unit> {
        lyrebirdCmethods.clear()

        val torDataDir = File(context.filesDir, "tor_data")
        val ptStateDir = File(torDataDir, "pt_state")
        ptStateDir.mkdirs()

        val transportList = transports.joinToString(",")
        Log.i(TAG, "Launching lyrebird for transports: $transportList")

        val pb = ProcessBuilder(ptBinaryPath)
        pb.redirectErrorStream(false) // We need separate stdout/stderr
        pb.environment().apply {
            put("TOR_PT_MANAGED_TRANSPORT_VER", "1")
            put("TOR_PT_CLIENT_TRANSPORTS", transportList)
            put("TOR_PT_STATE_LOCATION", ptStateDir.absolutePath + "/")
            // Exit when stdin is closed (parent dies)
            put("TOR_PT_EXIT_ON_STDIN_CLOSE", "1")
        }

        val process: Process
        try {
            process = pb.start()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to launch lyrebird: ${e.message}")
            return Result.failure(RuntimeException(
                "Failed to launch obfs4proxy (lyrebird): ${e.message}"
            ))
        }
        lyrebirdProcess = process

        // Read stderr in background for diagnostics
        Thread({
            try {
                val reader = BufferedReader(InputStreamReader(process.errorStream))
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    Log.d(TAG, "Lyrebird stderr: $line")
                }
            } catch (_: Exception) {}
        }, "lyrebird-stderr").also { it.isDaemon = true; it.start() }

        // Parse stdout for PT protocol messages (CMETHOD, VERSION, etc.)
        val cmethodsDone = CountDownLatch(1)
        var protocolError: String? = null

        Thread({
            try {
                val reader = BufferedReader(InputStreamReader(process.inputStream))
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val l = line!!.trim()
                    Log.d(TAG, "Lyrebird PT: $l")

                    when {
                        l.startsWith("VERSION ") -> {
                            Log.i(TAG, "Lyrebird protocol: $l")
                        }
                        l.startsWith("CMETHOD ") -> {
                            // Format: CMETHOD <transport> socks5 <host:port>
                            val parts = l.split("\\s+".toRegex())
                            if (parts.size >= 4) {
                                val name = parts[1]
                                val addr = parts[3]
                                lyrebirdCmethods[name] = addr
                                Log.i(TAG, "Lyrebird registered: $name at $addr")
                            }
                        }
                        l.startsWith("CMETHOD-ERROR ") -> {
                            Log.e(TAG, "Lyrebird transport error: $l")
                        }
                        l == "CMETHODS DONE" -> {
                            Log.i(TAG, "Lyrebird: all transports registered")
                            cmethodsDone.countDown()
                        }
                        l.startsWith("ENV-ERROR ") -> {
                            protocolError = l
                            Log.e(TAG, "Lyrebird env error: $l")
                            cmethodsDone.countDown()
                        }
                        l.startsWith("VERSION-ERROR ") -> {
                            protocolError = l
                            Log.e(TAG, "Lyrebird version error: $l")
                            cmethodsDone.countDown()
                        }
                    }
                }
            } catch (e: Exception) {
                if (lyrebirdProcess != null) {
                    Log.w(TAG, "Lyrebird stdout reader error: ${e.message}")
                }
            }
            // If process exits without CMETHODS DONE, unblock the latch
            cmethodsDone.countDown()
        }, "lyrebird-stdout").also { it.isDaemon = true; it.start() }

        // Wait for CMETHODS DONE (up to 10 seconds)
        val success = cmethodsDone.await(10, TimeUnit.SECONDS)
        if (!success) {
            Log.e(TAG, "Lyrebird timed out waiting for CMETHODS DONE")
            stopLyrebird()
            return Result.failure(RuntimeException(
                "obfs4proxy (lyrebird) timed out during PT protocol setup"
            ))
        }

        if (protocolError != null) {
            stopLyrebird()
            return Result.failure(RuntimeException(
                "obfs4proxy (lyrebird) protocol error: $protocolError"
            ))
        }

        if (!process.isAlive) {
            val exitCode = process.exitValue()
            Log.e(TAG, "Lyrebird exited prematurely with code $exitCode")
            lyrebirdProcess = null
            return Result.failure(RuntimeException(
                "obfs4proxy (lyrebird) exited with code $exitCode"
            ))
        }

        // Verify all requested transports were registered
        val missing = transports.filter { it !in lyrebirdCmethods }
        if (missing.isNotEmpty()) {
            Log.w(TAG, "Lyrebird did not register transports: $missing")
        }

        return Result.success(Unit)
    }

    private fun stopLyrebird() {
        lyrebirdProcess?.let { p ->
            try {
                Log.d(TAG, "Stopping lyrebird process...")
                // Close stdin to signal graceful shutdown
                try { p.outputStream.close() } catch (_: Exception) {}
                Thread.sleep(500)
                if (p.isAlive) {
                    p.destroy()
                    Thread.sleep(300)
                }
                if (p.isAlive) {
                    p.destroyForcibly()
                }
                Log.d(TAG, "Lyrebird process stopped")
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping lyrebird", e)
            }
        }
        lyrebirdProcess = null
        lyrebirdCmethods.clear()
    }

    // --- Transport detection ---

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

    // --- Stop / status ---

    /**
     * Stop the Tor process, lyrebird, and Snowflake PT.
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

        // Stop PTs
        stopSnowflakePt()
        stopLyrebird()
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
        // Lyrebird also needs to be alive if it was started
        val lyrebirdOk = lyrebirdProcess == null || lyrebirdProcess?.isAlive == true
        return (client == null || client?.isRunning == true) && lyrebirdOk && isTorProcessAlive()
    }

    fun isClientHealthy(): Boolean {
        return isRunning() && isTorReady
    }

    private fun isTorProcessAlive(): Boolean {
        return torProcess?.isAlive == true
    }

    // --- Helper functions ---

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
     *
     * @param lyrebirdMethods Map of transport name -> "host:port" from pre-started lyrebird.
     *                        When non-empty, uses `socks5` instead of `exec` directives.
     */
    private fun writeTorrc(
        context: Context,
        torDataDir: File,
        listenHost: String,
        torSocksPort: Int,
        snowflakePort: Int,
        bridgeLines: String = "",
        lyrebirdMethods: Map<String, String> = emptyMap()
    ): String {
        val torrcFile = File(torDataDir, "torrc")
        val isDirect = bridgeLines.trim() == "DIRECT"

        // Detect if webtunnel or meek is involved (these have higher latency)
        val hasSlowTransport = !isDirect && bridgeLines.lines().any { line ->
            val cleaned = if (line.trim().lowercase().startsWith("bridge ")) line.trim().substring(7).trim() else line.trim()
            val transport = cleaned.split("\\s+".toRegex()).firstOrNull()?.lowercase() ?: ""
            transport in listOf("webtunnel", "meek_lite")
        }

        // Common torrc settings (UseBridges omitted for direct mode)
        val common = buildString {
            appendLine("SocksPort $listenHost:$torSocksPort")
            appendLine("DataDirectory ${torDataDir.absolutePath}")
            if (!isDirect) appendLine("UseBridges 1")
            // Only reference GeoIP files if they exist
            val geoipFile = File(torDataDir, "geoip")
            val geoip6File = File(torDataDir, "geoip6")
            if (geoipFile.exists()) appendLine("GeoIPFile ${geoipFile.absolutePath}")
            if (geoip6File.exists()) appendLine("GeoIPv6File ${geoip6File.absolutePath}")
            appendLine("Log info stdout")
            // Webtunnel/meek add HTTP overhead per round trip — need generous
            // timeout for the multi-hop CREATE→EXTEND→EXTEND circuit handshake.
            // Other transports use the default 60s.
            val circuitTimeout = if (hasSlowTransport) 120 else 60
            appendLine("CircuitBuildTimeout $circuitTimeout")
            appendLine("LearnCircuitBuildTimeout 0")
            // Shorter keepalive to prevent HTTP-based transport idle timeouts
            // from closing the bridge connection between keepalive cells
            appendLine("KeepalivePeriod 30")
            appendLine("NumEntryGuards 1")
            appendLine("ClientUseIPv4 1")
            // Must allow IPv6: webtunnel bridges use 2001:db8:: placeholder
            // addresses (PT connects via URL, not the IP, but Tor checks this
            // when selecting bridges for circuit building)
            appendLine("ClientUseIPv6 1")
            appendLine("ClientPreferIPv6ORPort auto")
            appendLine("SafeLogging 0")
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
                // Strip "Bridge" prefix if users copy-pasted from BridgeDB
                val lines = bridgeLines.lines().filter { it.isNotBlank() }.map { it.trim() }
                    .map { if (it.lowercase().startsWith("bridge ")) it.substring(7).trim() else it }
                val transportsNeeded = mutableSetOf<String>()
                val bridgeDirectives = StringBuilder()

                for (line in lines) {
                    val transport = line.split("\\s+".toRegex()).firstOrNull()?.lowercase() ?: continue
                    transportsNeeded.add(transport)
                    bridgeDirectives.appendLine("Bridge $line")
                }

                val pluginDirectives = StringBuilder()

                for (transport in transportsNeeded) {
                    when (transport) {
                        "snowflake" -> {
                            // Custom snowflake bridge line (user-provided, not built-in)
                            pluginDirectives.appendLine("ClientTransportPlugin snowflake socks5 $listenHost:$snowflakePort")
                        }
                        "obfs4", "webtunnel", "meek_lite" -> {
                            // Use pre-started lyrebird SOCKS5 (launched by us, not by Tor)
                            val addr = lyrebirdMethods[transport]
                            if (addr != null) {
                                pluginDirectives.appendLine("ClientTransportPlugin $transport socks5 $addr")
                            } else {
                                Log.w(TAG, "No lyrebird CMETHOD for transport: $transport")
                            }
                        }
                    }
                }

                "${pluginDirectives.toString().trim()}\n${bridgeDirectives.toString().trim()}"
            }
        }

        val torrcContent = "$common\n$transportLines\n"
        torrcFile.writeText(torrcContent)

        // Log torrc for debugging PT issues
        Log.d(TAG, "--- Generated torrc ---")
        torrcContent.lines().forEach { line ->
            if (line.isNotBlank()) Log.d(TAG, "torrc: $line")
        }
        Log.d(TAG, "--- End torrc ---")

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
