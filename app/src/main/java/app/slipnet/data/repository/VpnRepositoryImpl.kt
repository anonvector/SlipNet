package app.slipnet.data.repository

import android.os.ParcelFileDescriptor
import app.slipnet.util.AppLog as Log
import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TrafficStats
import app.slipnet.domain.model.DnsResolver
import app.slipnet.domain.model.DnsTransport
import app.slipnet.domain.model.TunnelType
import app.slipnet.domain.repository.VpnRepository
import app.slipnet.tunnel.DnsDoHProxy
import app.slipnet.tunnel.DnsttBridge
import app.slipnet.tunnel.VaydnsBridge
import app.slipnet.tunnel.DohBridge
import app.slipnet.tunnel.HevSocks5Tunnel
import app.slipnet.tunnel.ResolverConfig
import app.slipnet.tunnel.SlipstreamBridge
import app.slipnet.tunnel.DnsttSocksBridge
import app.slipnet.tunnel.SlipstreamSocksBridge
import app.slipnet.tunnel.NaiveBridge
import app.slipnet.tunnel.NaiveSocksBridge
import app.slipnet.tunnel.SnowflakeBridge
import app.slipnet.tunnel.Socks5ProxyBridge
import app.slipnet.tunnel.SshTunnelBridge
import app.slipnet.tunnel.TorSocksBridge
import app.slipnet.tunnel.VlessBridge
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class VpnRepositoryImpl @Inject constructor(
    @dagger.hilt.android.qualifiers.ApplicationContext private val context: android.content.Context,
    private val preferencesDataStore: PreferencesDataStore
) : VpnRepository {
    companion object {
        private const val TAG = "VpnRepositoryImpl"

        /**
         * Per-resolver TCP-connect budget for the preflight that filters dead
         * TCP/DoT resolvers before they reach the native bridge. Probes run in
         * parallel so this also caps total preflight time. Tuned for heavily
         * throttled networks (Iran cellular): SYN retransmit + DPI inspection
         * + lossy 4G can stack to several seconds even when the resolver is
         * actually live. 8 s leaves enough headroom to avoid false-dropping
         * working resolvers, while still bounding worst-case connect overhead.
         */
        private const val PREFLIGHT_TIMEOUT_MS = 8000

        /**
         * Resolve a hostname to a numeric IP. Go on Android cannot resolve
         * hostnames internally, so we must do it on the JVM side before
         * passing addresses to the Go bridge.
         * Returns the original [host] if it's already a numeric IP.
         *
         * @param customDnsServer If non-null, use this DNS server IP for resolution
         *   instead of the system resolver. Useful when the ISP's DNS is filtered.
         */
        private val PUBLIC_DNS_SERVERS = listOf("8.8.8.8", "1.1.1.1", "9.9.9.9")

        fun resolveHost(host: String, customDnsServer: String? = null): String {
            if (host.isBlank()) return host
            // Already numeric IPv4/IPv6 — pass through
            if (app.slipnet.tunnel.DomainRouter.isIpAddress(host)) return host

            // Try custom DNS server first (bypasses ISP DNS filtering)
            if (!customDnsServer.isNullOrBlank()) {
                try {
                    val resolved = resolveViaUdp(host, customDnsServer)
                    if (resolved != null) {
                        Log.i(TAG, "Resolved '$host' → $resolved via custom DNS $customDnsServer")
                        return resolved
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Custom DNS resolution failed for '$host' via $customDnsServer", e)
                }
            }

            // Try well-known public DNS servers (bypasses censored ISP DNS)
            for (dns in PUBLIC_DNS_SERVERS) {
                if (dns == customDnsServer) continue
                try {
                    val resolved = resolveViaUdp(host, dns)
                    if (resolved != null) {
                        Log.i(TAG, "Resolved '$host' → $resolved via public DNS $dns")
                        return resolved
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Public DNS resolution failed for '$host' via $dns", e)
                }
            }

            // Fall back to system resolver
            return try {
                java.net.InetAddress.getByName(host).hostAddress ?: host
            } catch (e: Exception) {
                Log.w(TAG, "Failed to resolve '$host' to IP, passing through", e)
                host
            }
        }

        /**
         * Resolve a hostname by sending a UDP DNS query directly to [dnsServer].
         * Returns the first A record IP, or null on failure.
         */
        private fun resolveViaUdp(hostname: String, dnsServer: String, timeoutMs: Int = 5000): String? {
            val id = (Math.random() * 65535).toInt().toShort()
            val query = buildDnsQuery(id, hostname)
            val serverAddr = java.net.InetAddress.getByName(dnsServer)
            val socket = java.net.DatagramSocket()
            try {
                socket.soTimeout = timeoutMs
                val request = java.net.DatagramPacket(query, query.size, serverAddr, 53)
                socket.send(request)
                val responseBuf = ByteArray(512)
                val response = java.net.DatagramPacket(responseBuf, responseBuf.size)
                socket.receive(response)
                return parseDnsResponse(responseBuf, response.length)
            } finally {
                socket.close()
            }
        }

        /** Build a minimal DNS A-record query packet. */
        private fun buildDnsQuery(id: Short, hostname: String): ByteArray {
            val buf = java.io.ByteArrayOutputStream()
            // Header: ID, flags (standard query, RD=1), QDCOUNT=1
            buf.write(id.toInt() shr 8 and 0xFF)
            buf.write(id.toInt() and 0xFF)
            buf.write(0x01); buf.write(0x00) // flags: RD=1
            buf.write(0x00); buf.write(0x01) // QDCOUNT=1
            buf.write(0x00); buf.write(0x00) // ANCOUNT=0
            buf.write(0x00); buf.write(0x00) // NSCOUNT=0
            buf.write(0x00); buf.write(0x00) // ARCOUNT=0
            // QNAME
            for (label in hostname.split(".")) {
                buf.write(label.length)
                buf.write(label.toByteArray(Charsets.US_ASCII))
            }
            buf.write(0x00) // root label
            // QTYPE=A (1), QCLASS=IN (1)
            buf.write(0x00); buf.write(0x01)
            buf.write(0x00); buf.write(0x01)
            return buf.toByteArray()
        }

        /** Parse a DNS response and return the first A record IP, or null. */
        private fun parseDnsResponse(data: ByteArray, length: Int): String? {
            if (length < 12) return null
            val anCount = (data[6].toInt() and 0xFF shl 8) or (data[7].toInt() and 0xFF)
            if (anCount == 0) return null
            // Skip header (12 bytes) and question section
            var offset = 12
            // Skip QNAME
            while (offset < length && data[offset].toInt() != 0) {
                if (data[offset].toInt() and 0xC0 == 0xC0) { offset += 2; break }
                offset += (data[offset].toInt() and 0xFF) + 1
            }
            if (offset < length && data[offset].toInt() == 0) offset++ // null terminator
            offset += 4 // skip QTYPE + QCLASS
            // Parse answer records
            for (i in 0 until anCount) {
                if (offset >= length) break
                // Skip NAME (may be pointer)
                if (data[offset].toInt() and 0xC0 == 0xC0) offset += 2
                else { while (offset < length && data[offset].toInt() != 0) offset += (data[offset].toInt() and 0xFF) + 1; offset++ }
                if (offset + 10 > length) break
                val rType = (data[offset].toInt() and 0xFF shl 8) or (data[offset + 1].toInt() and 0xFF)
                val rdLength = (data[offset + 8].toInt() and 0xFF shl 8) or (data[offset + 9].toInt() and 0xFF)
                offset += 10
                if (rType == 1 && rdLength == 4 && offset + 4 <= length) {
                    // A record
                    return "${data[offset].toInt() and 0xFF}.${data[offset+1].toInt() and 0xFF}.${data[offset+2].toInt() and 0xFF}.${data[offset+3].toInt() and 0xFF}"
                }
                offset += rdLength
            }
            return null
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    private val _connectionState = MutableStateFlow<ConnectionState>(ConnectionState.Disconnected)
    override val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    private val _trafficStats = MutableStateFlow(TrafficStats.EMPTY)
    override val trafficStats: StateFlow<TrafficStats> = _trafficStats.asStateFlow()

    private var prevBytesSent = 0L
    private var prevBytesReceived = 0L
    private var prevTimestamp = 0L

    private var connectedProfile: ServerProfile? = null
    private var currentTunFd: ParcelFileDescriptor? = null
    private var tunnelStartException: Exception? = null
    private var currentTunnelType: TunnelType? = null

    /**
     * Override the current tunnel type. Used by VPN service for chained startup
     * (e.g., DNSTT+SSH starts as DNSTT first, then switches to DNSTT_SSH).
     */
    fun setCurrentTunnelType(type: TunnelType) {
        currentTunnelType = type
    }

    override suspend fun connect(profile: ServerProfile): Result<Unit> {
        if (_connectionState.value is ConnectionState.Connected ||
            _connectionState.value is ConnectionState.Connecting) {
            return Result.failure(IllegalStateException("Already connected or connecting"))
        }

        _connectionState.value = ConnectionState.Connecting
        connectedProfile = profile

        return Result.success(Unit)
    }

    /**
     * Start the Slipstream SOCKS5 proxy. Call this BEFORE establishing the VPN interface.
     * This ensures the proxy is ready to handle traffic when the VPN starts routing.
     */
    suspend fun startSlipstreamProxy(
        profile: ServerProfile,
        portOverride: Int? = null,
        hostOverride: String? = null,
        resolverOverride: List<DnsResolver>? = null
    ): Result<Unit> = withContext(Dispatchers.IO) {
        connectedProfile = profile
        val debugLogging = preferencesDataStore.debugLogging.first()

        // Convert profile (or global override) to resolver config.
        // Deduplicate by host:port to avoid "Duplicate resolver address" from native code.
        val effectiveResolvers = resolverOverride ?: profile.resolvers
        val resolvers = effectiveResolvers.map { resolver ->
            ResolverConfig(
                host = resolver.host,
                port = resolver.port,
                authoritative = resolver.authoritative
            )
        }.distinctBy { "${it.host}:${it.port}" }

        val listenPort = portOverride ?: preferencesDataStore.proxyListenPort.first()
        val listenHost = hostOverride ?: preferencesDataStore.proxyListenAddress.first()
        val success = startSlipstreamClient(profile.domain, resolvers, profile, debugLogging, listenPort, listenHost)

        if (success) {
            Log.i(TAG, "Slipstream SOCKS5 proxy started successfully")
            currentTunnelType = TunnelType.SLIPSTREAM
            // Note: Caller should verify proxy is ready by checking the port
            Result.success(Unit)
        } else {
            val error = tunnelStartException?.message ?: "Failed to start Slipstream proxy"
            connectedProfile = null
            Log.e(TAG, "Failed to start Slipstream proxy: $error")
            Result.failure(Exception(error))
        }
    }

    /**
     * Start the DNSTT SOCKS5 proxy. Call this AFTER establishing the VPN interface.
     * The VPN must be established first with addDisallowedApplication so DNSTT's
     * DNS queries bypass the VPN.
     */
    suspend fun startDnsttProxy(
        profile: ServerProfile,
        portOverride: Int? = null,
        hostOverride: String? = null,
        socksProxyAddr: String? = null,
        socksProxyUser: String? = null,
        socksProxyPass: String? = null,
        resolverOverride: List<DnsResolver>? = null
    ): Result<Unit> = withContext(Dispatchers.IO) {
        connectedProfile = profile

        // Format DNS server address based on transport type.
        // Resolve domain names to IPs — Go on Android cannot resolve hostnames.
        val dnsServer = formatDnsServerAddress(profile, resolverOverride)

        val proxyPort = portOverride ?: preferencesDataStore.proxyListenPort.first()
        val proxyHost = hostOverride ?: preferencesDataStore.proxyListenAddress.first()

        val result = DnsttBridge.startClient(
            dnsServer = dnsServer,
            tunnelDomain = profile.domain,
            publicKey = profile.dnsttPublicKey,
            listenPort = proxyPort,
            listenHost = proxyHost,
            authoritativeMode = profile.dnsttAuthoritative,
            maxPayload = profile.dnsPayloadSize,
            socksProxyAddr = socksProxyAddr,
            socksProxyUser = socksProxyUser,
            socksProxyPass = socksProxyPass,
            resolverMode = profile.resolverMode.value,
            rrSpreadCount = profile.rrSpreadCount
        )

        if (result.isSuccess) {
            Log.i(TAG, "DNSTT SOCKS5 proxy started successfully")
            currentTunnelType = TunnelType.DNSTT
            Result.success(Unit)
        } else {
            val error = result.exceptionOrNull()?.message ?: "Failed to start DNSTT proxy"
            connectedProfile = null
            Log.e(TAG, "Failed to start DNSTT proxy: $error")
            Result.failure(Exception(error))
        }
    }

    /**
     * Start the NoizDNS SOCKS5 proxy. Same as DNSTT but with NoizMode enabled
     * for DPI evasion (hex encoding, shorter labels, record type mixing, jitter,
     * cover traffic).
     */
    suspend fun startNoizdnsProxy(
        profile: ServerProfile,
        portOverride: Int? = null,
        hostOverride: String? = null,
        socksProxyAddr: String? = null,
        socksProxyUser: String? = null,
        socksProxyPass: String? = null,
        resolverOverride: List<DnsResolver>? = null
    ): Result<Unit> = withContext(Dispatchers.IO) {
        connectedProfile = profile

        // Resolve domain names to IPs — Go on Android cannot resolve hostnames.
        val dnsServer = formatDnsServerAddress(profile, resolverOverride)

        val proxyPort = portOverride ?: preferencesDataStore.proxyListenPort.first()
        val proxyHost = hostOverride ?: preferencesDataStore.proxyListenAddress.first()

        val result = DnsttBridge.startClient(
            dnsServer = dnsServer,
            tunnelDomain = profile.domain,
            publicKey = profile.dnsttPublicKey,
            listenPort = proxyPort,
            listenHost = proxyHost,
            authoritativeMode = profile.dnsttAuthoritative,
            noizMode = true,
            stealthMode = profile.noizdnsStealth,
            maxPayload = profile.dnsPayloadSize,
            socksProxyAddr = socksProxyAddr,
            socksProxyUser = socksProxyUser,
            socksProxyPass = socksProxyPass,
            resolverMode = profile.resolverMode.value,
            rrSpreadCount = profile.rrSpreadCount
        )

        if (result.isSuccess) {
            Log.i(TAG, "NoizDNS SOCKS5 proxy started successfully")
            currentTunnelType = TunnelType.NOIZDNS
            Result.success(Unit)
        } else {
            val error = result.exceptionOrNull()?.message ?: "Failed to start NoizDNS proxy"
            connectedProfile = null
            Log.e(TAG, "Failed to start NoizDNS proxy: $error")
            Result.failure(Exception(error))
        }
    }

    /**
     * Start the VayDNS SOCKS5 proxy. Similar to DNSTT but uses the VayDNS
     * tunnel implementation for DNS tunnelling.
     */
    suspend fun startVaydnsProxy(
        profile: ServerProfile,
        portOverride: Int? = null,
        hostOverride: String? = null,
        resolverOverride: List<DnsResolver>? = null
    ): Result<Unit> = withContext(Dispatchers.IO) {
        connectedProfile = profile

        // Resolve domain names to IPs — Go on Android cannot resolve hostnames.
        val dnsServer = formatDnsServerAddress(profile, resolverOverride)

        val proxyPort = portOverride ?: preferencesDataStore.proxyListenPort.first()
        val proxyHost = hostOverride ?: preferencesDataStore.proxyListenAddress.first()

        val result = VaydnsBridge.startClient(
            dnsServer = dnsServer,
            tunnelDomain = profile.domain,
            publicKey = profile.dnsttPublicKey,
            listenPort = proxyPort,
            listenHost = proxyHost,
            dnsttCompat = profile.vaydnsDnsttCompat,
            maxPayload = 0,
            recordType = profile.vaydnsRecordType,
            maxQnameLen = profile.vaydnsMaxQnameLen,
            rps = profile.vaydnsRps,
            idleTimeout = profile.vaydnsIdleTimeout,
            keepalive = profile.vaydnsKeepalive,
            udpTimeout = profile.vaydnsUdpTimeout,
            maxNumLabels = profile.vaydnsMaxNumLabels,
            clientIdSize = profile.vaydnsClientIdSize,
            resolverMode = profile.resolverMode.value,
            rrSpreadCount = profile.rrSpreadCount
        )

        if (result.isSuccess) {
            Log.i(TAG, "VayDNS SOCKS5 proxy started successfully")
            currentTunnelType = TunnelType.VAYDNS
            Result.success(Unit)
        } else {
            val error = result.exceptionOrNull()?.message ?: "Failed to start VayDNS proxy"
            connectedProfile = null
            Log.e(TAG, "Failed to start VayDNS proxy: $error")
            Result.failure(Exception(error))
        }
    }

    /**
     * Start the DoH SOCKS5 proxy. Call this AFTER establishing the VPN interface.
     * DNS queries are encrypted via HTTPS; all other traffic flows directly.
     */
    /**
     * Format the DNS server address string for the Go bridge, resolving any
     * domain names to numeric IPs (Go on Android cannot resolve hostnames).
     *
     * For TCP and DoT transports, runs a fast parallel TCP-connect preflight
     * and drops unresponsive resolvers before they reach the native bridge —
     * a single dead resolver in the list would otherwise stall connection
     * setup while the bridge times out on it.
     */
    private suspend fun formatDnsServerAddress(profile: ServerProfile, resolverOverride: List<DnsResolver>? = null): String {
        val resolvers = resolverOverride ?: profile.resolvers
        return when (profile.dnsTransport) {
            DnsTransport.UDP -> {
                resolvers.joinToString(",") { "${resolveHost(it.host)}:${it.port}" }
                    .ifBlank { "8.8.8.8:53" }
            }
            DnsTransport.DOH -> {
                profile.dohUrl.ifBlank { "https://dns.google/dns-query" }
            }
            DnsTransport.TCP -> {
                val resolved = resolvers.map { it to resolveHost(it.host) }
                val live = preflightTcp(resolved, portOf = { it.port }, timeoutMs = PREFLIGHT_TIMEOUT_MS)
                live.joinToString(",") { (resolver, ip) -> "tcp://$ip:${resolver.port}" }
                    .ifBlank { "tcp://8.8.8.8:53" }
            }
            DnsTransport.DOT -> {
                // DoT uses port 853, not 53. When global resolver override provides
                // only an IP (defaulting to port 53), use 853 instead.
                val resolved = resolvers.map { it to resolveHost(it.host) }
                val live = preflightTcp(resolved, portOf = { if (it.port == 53) 853 else it.port }, timeoutMs = PREFLIGHT_TIMEOUT_MS)
                live.joinToString(",") { (resolver, ip) ->
                    val port = if (resolver.port == 53) 853 else resolver.port
                    "tls://$ip:$port"
                }.ifBlank { "tls://8.8.8.8:853" }
            }
        }
    }

    private data class ResolverProbe(val resolver: DnsResolver, val ip: String, val ok: Boolean)

    /**
     * Probe each (resolver, resolvedIp) in parallel with a TCP connect. Returns
     * the subset that responded within [timeoutMs]. If every probe fails, returns
     * the input unchanged so the bridge can surface the real error instead of
     * silently dropping the user's entire resolver list.
     */
    private suspend fun preflightTcp(
        resolved: List<Pair<DnsResolver, String>>,
        portOf: (DnsResolver) -> Int,
        timeoutMs: Int
    ): List<Pair<DnsResolver, String>> {
        if (resolved.size <= 1) return resolved
        val probes: List<ResolverProbe> = coroutineScope {
            resolved.map { (resolver, ip) ->
                async {
                    ResolverProbe(resolver, ip, tryTcpConnect(ip, portOf(resolver), timeoutMs))
                }
            }.awaitAll()
        }
        val live = probes.filter { it.ok }.map { it.resolver to it.ip }
        if (live.isEmpty()) {
            Log.w(TAG, "Resolver preflight: none of ${resolved.size} resolvers responded within ${timeoutMs}ms — passing full list to bridge")
            return resolved
        }
        if (live.size != resolved.size) {
            val dead = probes.filter { !it.ok }
                .joinToString(",") { "${it.resolver.host}:${it.resolver.port}" }
            Log.w(TAG, "Resolver preflight: dropped unresponsive resolver(s): $dead")
        }
        return live
    }

    private fun tryTcpConnect(host: String, port: Int, timeoutMs: Int): Boolean {
        var socket: java.net.Socket? = null
        return try {
            socket = java.net.Socket()
            socket.connect(java.net.InetSocketAddress(host, port), timeoutMs)
            true
        } catch (_: Exception) {
            false
        } finally {
            try { socket?.close() } catch (_: Exception) {}
        }
    }

    suspend fun startDohProxy(
        profile: ServerProfile,
        portOverride: Int? = null,
        hostOverride: String? = null,
        upstreamSocksAddr: java.net.InetSocketAddress? = null
    ): Result<Unit> = withContext(Dispatchers.IO) {
        connectedProfile = profile

        val proxyPort = portOverride ?: preferencesDataStore.proxyListenPort.first()
        val proxyHost = hostOverride ?: preferencesDataStore.proxyListenAddress.first()
        val localAuthUser = if (preferencesDataStore.proxyAuthEnabled.first()) preferencesDataStore.proxyAuthUsername.first().ifEmpty { null } else null
        val localAuthPass = if (preferencesDataStore.proxyAuthEnabled.first()) preferencesDataStore.proxyAuthPassword.first().ifEmpty { null } else null

        val result = DohBridge.start(
            dohUrl = profile.dohUrl,
            listenPort = proxyPort,
            listenHost = proxyHost,
            localAuthUsername = localAuthUser,
            localAuthPassword = localAuthPass,
            upstreamSocksAddr = upstreamSocksAddr
        )

        if (result.isSuccess) {
            Log.i(TAG, "DoH SOCKS5 proxy started successfully")
            currentTunnelType = TunnelType.DOH
            Result.success(Unit)
        } else {
            val error = result.exceptionOrNull()?.message ?: "Failed to start DoH proxy"
            connectedProfile = null
            Log.e(TAG, "Failed to start DoH proxy: $error")
            Result.failure(Exception(error))
        }
    }

    /**
     * Start SlipstreamSocksBridge — a middleman SOCKS5 proxy for Slipstream non-SSH.
     * Chains CONNECT to Slipstream's SOCKS5 and handles FWD_UDP (DNS/UDP) directly.
     */
    suspend fun startSlipstreamSocksBridge(
        slipstreamPort: Int,
        slipstreamHost: String,
        bridgePort: Int,
        bridgeHost: String,
        socksUsername: String? = null,
        socksPassword: String? = null,
        dnsServer: String? = null,
        dnsFallback: String? = null
    ): Result<Unit> = withContext(Dispatchers.IO) {
        val localAuthUser = if (preferencesDataStore.proxyAuthEnabled.first()) preferencesDataStore.proxyAuthUsername.first().ifEmpty { null } else null
        val localAuthPass = if (preferencesDataStore.proxyAuthEnabled.first()) preferencesDataStore.proxyAuthPassword.first().ifEmpty { null } else null
        val result = SlipstreamSocksBridge.start(
            slipstreamPort = slipstreamPort,
            slipstreamHost = slipstreamHost,
            listenPort = bridgePort,
            listenHost = bridgeHost,
            socksUsername = socksUsername,
            socksPassword = socksPassword,
            dnsServer = dnsServer,
            dnsFallback = dnsFallback,
            localAuthUsername = localAuthUser,
            localAuthPassword = localAuthPass
        )
        if (result.isSuccess) {
            Log.i(TAG, "SlipstreamSocksBridge started on $bridgeHost:$bridgePort -> $slipstreamHost:$slipstreamPort")
        } else {
            Log.e(TAG, "Failed to start SlipstreamSocksBridge: ${result.exceptionOrNull()?.message}")
        }
        result
    }

    /**
     * Start DnsttSocksBridge — a middleman SOCKS5 proxy for DNSTT standalone.
     * Chains CONNECT to DNSTT's raw tunnel (→ Dante) and handles FWD_UDP (DNS) via worker pool.
     */
    suspend fun startDnsttSocksBridge(
        dnsttPort: Int,
        dnsttHost: String,
        bridgePort: Int,
        bridgeHost: String,
        socksUsername: String? = null,
        socksPassword: String? = null,
        dnsServer: String? = null,
        dnsFallback: String? = null
    ): Result<Unit> = withContext(Dispatchers.IO) {
        val localAuthUser = if (preferencesDataStore.proxyAuthEnabled.first()) preferencesDataStore.proxyAuthUsername.first().ifEmpty { null } else null
        val localAuthPass = if (preferencesDataStore.proxyAuthEnabled.first()) preferencesDataStore.proxyAuthPassword.first().ifEmpty { null } else null
        val result = DnsttSocksBridge.start(
            dnsttPort = dnsttPort,
            dnsttHost = dnsttHost,
            listenPort = bridgePort,
            listenHost = bridgeHost,
            socksUsername = socksUsername,
            socksPassword = socksPassword,
            dnsServer = dnsServer,
            dnsFallback = dnsFallback,
            localAuthUsername = localAuthUser,
            localAuthPassword = localAuthPass
        )
        if (result.isSuccess) {
            Log.i(TAG, "DnsttSocksBridge started on $bridgeHost:$bridgePort -> $dnsttHost:$dnsttPort")
        } else {
            Log.e(TAG, "Failed to start DnsttSocksBridge: ${result.exceptionOrNull()?.message}")
        }
        result
    }

    /**
     * Start NaiveSocksBridge — a middleman SOCKS5 proxy for standalone NaiveProxy.
     * Chains CONNECT to NaiveProxy's SOCKS5 (NO_AUTH) and handles FWD_UDP (DNS) via worker pool.
     */
    suspend fun startNaiveSocksBridge(
        naivePort: Int,
        naiveHost: String,
        bridgePort: Int,
        bridgeHost: String,
        dnsServer: String? = null,
        dnsFallback: String? = null
    ): Result<Unit> = withContext(Dispatchers.IO) {
        val localAuthUser = if (preferencesDataStore.proxyAuthEnabled.first()) preferencesDataStore.proxyAuthUsername.first().ifEmpty { null } else null
        val localAuthPass = if (preferencesDataStore.proxyAuthEnabled.first()) preferencesDataStore.proxyAuthPassword.first().ifEmpty { null } else null
        val result = NaiveSocksBridge.start(
            naivePort = naivePort,
            naiveHost = naiveHost,
            listenPort = bridgePort,
            listenHost = bridgeHost,
            dnsServer = dnsServer,
            dnsFallback = dnsFallback,
            localAuthUsername = localAuthUser,
            localAuthPassword = localAuthPass
        )
        if (result.isSuccess) {
            Log.i(TAG, "NaiveSocksBridge started on $bridgeHost:$bridgePort -> $naiveHost:$naivePort")
        } else {
            Log.e(TAG, "Failed to start NaiveSocksBridge: ${result.exceptionOrNull()?.message}")
        }
        result
    }

    /**
     * Start the Snowflake proxy stack: Snowflake PT + Tor + TorSocksBridge.
     * Call this AFTER establishing the VPN interface.
     *
     * Port allocation:
     * - bridgePort (proxyPort): TorSocksBridge (what hev-socks5-tunnel connects to)
     * - torSocksPort (proxyPort+1): Tor SOCKS5 (what bridge chains CONNECT to)
     * - snowflakePtPort (proxyPort+2): Snowflake PT SOCKS5 (what Tor connects through)
     */
    suspend fun startSnowflakeProxy(
        profile: ServerProfile,
        snowflakePtPort: Int,
        torSocksPort: Int,
        bridgePort: Int,
        upstreamSocksAddr: java.net.InetSocketAddress? = null
    ): Result<Unit> = withContext(Dispatchers.IO) {
        connectedProfile = profile
        val proxyHost = preferencesDataStore.proxyListenAddress.first()

        // Step 1: Start Snowflake PT + Tor (or other PT based on bridge lines)
        val sfResult = SnowflakeBridge.startClient(
            context = context,
            snowflakePort = snowflakePtPort,
            torSocksPort = torSocksPort,
            listenHost = proxyHost,
            bridgeLines = profile.torBridgeLines,
            upstreamSocksAddr = upstreamSocksAddr
        )

        if (sfResult.isFailure) {
            connectedProfile = null
            Log.e(TAG, "Failed to start Snowflake + Tor: ${sfResult.exceptionOrNull()?.message}")
            return@withContext Result.failure(sfResult.exceptionOrNull() ?: Exception("Failed to start Snowflake"))
        }

        // Step 2: Start TorSocksBridge
        // Tor SOCKS5 is always local — use 127.0.0.1 for upstream, proxyHost for listen
        val localAuthUser = if (preferencesDataStore.proxyAuthEnabled.first()) preferencesDataStore.proxyAuthUsername.first().ifEmpty { null } else null
        val localAuthPass = if (preferencesDataStore.proxyAuthEnabled.first()) preferencesDataStore.proxyAuthPassword.first().ifEmpty { null } else null
        val bridgeResult = TorSocksBridge.start(
            torSocksPort = torSocksPort,
            torHost = "127.0.0.1",
            listenPort = bridgePort,
            listenHost = proxyHost,
            localAuthUsername = localAuthUser,
            localAuthPassword = localAuthPass
        )

        if (bridgeResult.isFailure) {
            SnowflakeBridge.stopClient()
            connectedProfile = null
            Log.e(TAG, "Failed to start TorSocksBridge: ${bridgeResult.exceptionOrNull()?.message}")
            return@withContext Result.failure(bridgeResult.exceptionOrNull() ?: Exception("Failed to start TorSocksBridge"))
        }

        currentTunnelType = TunnelType.SNOWFLAKE
        Log.i(TAG, "Snowflake proxy stack started successfully")
        Result.success(Unit)
    }

    /**
     * Start hev-socks5-tunnel after the VPN interface is established.
     * Call this AFTER startSlipstreamProxy() succeeds and VPN interface is established.
     *
     * DNS resolution works through the VPN's configured DNS servers (via VpnService.addDnsServer())
     * combined with hev-socks5-tunnel's UDP-over-TCP mode that tunnels DNS queries through SOCKS5.
     */
    suspend fun startTun2Socks(
        profile: ServerProfile,
        pfd: ParcelFileDescriptor,
        socksPortOverride: Int? = null
    ): Result<Unit> {
        currentTunFd = pfd

        val socksPort = socksPortOverride ?: preferencesDataStore.proxyListenPort.first()
        val disableQuic = preferencesDataStore.disableQuic.first()
        // Local proxy auth: hev-socks5-tunnel authenticates with the bridge
        val proxyAuthEnabled = preferencesDataStore.proxyAuthEnabled.first()
        val enableUdpTunneling = true
        val socksUsername = if (proxyAuthEnabled) preferencesDataStore.proxyAuthUsername.first().ifEmpty { null } else null
        val socksPassword = if (proxyAuthEnabled) preferencesDataStore.proxyAuthPassword.first().ifEmpty { null } else null

        val mtu = try { preferencesDataStore.vpnMtu.first() } catch (_: Exception) { PreferencesDataStore.DEFAULT_MTU }

        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting hev-socks5-tunnel")
        Log.i(TAG, "  SOCKS5 proxy: 127.0.0.1:$socksPort")
        Log.i(TAG, "  SOCKS auth: ${if (!socksUsername.isNullOrBlank()) "enabled" else "disabled"}")
        Log.i(TAG, "  Tunnel type: ${profile.tunnelType}")
        Log.i(TAG, "  UDP tunneling: $enableUdpTunneling")
        Log.i(TAG, "  MTU: $mtu")
        Log.i(TAG, "========================================")

        // Reject non-DNS UDP at TUN level with ICMP Port Unreachable so apps
        // (e.g. WhatsApp) fall back to TCP instantly instead of waiting for
        // silent-drop timeouts. DOH is excluded because DohBridge forwards
        // non-DNS UDP directly via DatagramSocket.
        val rejectNonDnsUdp = profile.tunnelType != TunnelType.DOH

        val hevResult = HevSocks5Tunnel.start(
            tunFd = pfd,
            socksAddress = "127.0.0.1",
            socksPort = socksPort,
            socksUsername = socksUsername,
            socksPassword = socksPassword,
            enableUdpTunneling = enableUdpTunneling,
            mtu = mtu,
            ipv4Address = "10.255.255.1",
            ipv6Address = "fd00::1",
            disableQuic = disableQuic,
            rejectNonDnsUdp = rejectNonDnsUdp
        )

        return if (hevResult.isSuccess) {
            _connectionState.value = ConnectionState.Connected(profile)
            Log.i(TAG, "Tunnel started successfully")
            Result.success(Unit)
        } else {
            val error = hevResult.exceptionOrNull()?.message ?: "Failed to start tun2socks"
            _connectionState.value = ConnectionState.Error(error)
            connectedProfile = null
            // Stop the SOCKS5 proxy since tun2socks failed
            stopCurrentProxy()
            Log.e(TAG, "Failed to start tun2socks: $error")
            Result.failure(Exception(error))
        }
    }

    /**
     * Stop the currently running proxy (Slipstream, DNSTT, or SSH).
     */
    private fun stopCurrentProxy() {
        when (currentTunnelType) {
            TunnelType.SLIPSTREAM -> {
                Log.d(TAG, "Stopping Slipstream proxy and bridge")
                SlipstreamSocksBridge.stop()
                SlipstreamBridge.stopClient()
            }
            TunnelType.DNSTT -> {
                Log.d(TAG, "Stopping DNSTT proxy")
                DnsttBridge.stopClient()
                DnsDoHProxy.stop()
            }
            TunnelType.NOIZDNS -> {
                Log.d(TAG, "Stopping NoizDNS proxy")
                DnsttBridge.stopClient()
                DnsDoHProxy.stop()
            }
            TunnelType.VAYDNS -> {
                Log.d(TAG, "Stopping VayDNS proxy")
                VaydnsBridge.stopClient()
                DnsDoHProxy.stop()
            }
            TunnelType.SSH -> {
                Log.d(TAG, "Stopping SSH proxy")
                SshTunnelBridge.stop()
            }
            TunnelType.DNSTT_SSH -> {
                Log.d(TAG, "Stopping DNSTT+SSH: SSH first, then DNSTT")
                SshTunnelBridge.stop()
                DnsttBridge.stopClient()
                DnsDoHProxy.stop()
            }
            TunnelType.NOIZDNS_SSH -> {
                Log.d(TAG, "Stopping NoizDNS+SSH: SSH first, then NoizDNS")
                SshTunnelBridge.stop()
                DnsttBridge.stopClient()
                DnsDoHProxy.stop()
            }
            TunnelType.VAYDNS_SSH -> {
                Log.d(TAG, "Stopping VayDNS+SSH: SSH first, then VayDNS")
                SshTunnelBridge.stop()
                VaydnsBridge.stopClient()
                DnsDoHProxy.stop()
            }
            TunnelType.SLIPSTREAM_SSH -> {
                Log.d(TAG, "Stopping Slipstream+SSH: SSH first, then Slipstream")
                SshTunnelBridge.stop()
                SlipstreamBridge.stopClient()
            }
            TunnelType.DOH -> {
                Log.d(TAG, "Stopping DoH proxy")
                DohBridge.stop()
            }
            TunnelType.SNOWFLAKE -> {
                Log.d(TAG, "Stopping Snowflake: TorSocksBridge first, then Snowflake+Tor")
                TorSocksBridge.stop()
                SnowflakeBridge.stopClient()
            }
            TunnelType.NAIVE_SSH -> {
                Log.d(TAG, "Stopping NaiveProxy+SSH: SSH first, then NaiveProxy")
                SshTunnelBridge.stop()
                NaiveBridge.stop()
            }
            TunnelType.NAIVE -> {
                Log.d(TAG, "Stopping standalone NaiveProxy: bridge first, then NaiveProxy")
                NaiveSocksBridge.stop()
                NaiveBridge.stop()
            }
            TunnelType.SOCKS5 -> {
                Log.d(TAG, "Stopping SOCKS5 proxy bridge")
                Socks5ProxyBridge.stop()
            }
            TunnelType.VLESS -> {
                Log.d(TAG, "Stopping VLESS proxy bridge")
                VlessBridge.stop()
            }
            null -> {
                // Try to stop all just in case
                Log.d(TAG, "No tunnel type set, stopping all proxies")
                SlipstreamSocksBridge.stop()
                SlipstreamBridge.stopClient()
                DnsttBridge.stopClient()
                VaydnsBridge.stopClient()
                SshTunnelBridge.stop()
                DnsDoHProxy.stop()
                TorSocksBridge.stop()
                SnowflakeBridge.stopClient()
                NaiveSocksBridge.stop()
                NaiveBridge.stop()
            }
        }
        currentTunnelType = null
    }

    @Deprecated("Use startSlipstreamProxy() and startTun2Socks() instead for proper startup ordering")
    fun startWithFd(
        profile: ServerProfile,
        pfd: ParcelFileDescriptor,
        vpnProtect: ((java.net.DatagramSocket) -> Boolean)? = null
    ): Result<Unit> {
        connectedProfile = profile
        currentTunFd = pfd

        val debugLogging = runBlocking { preferencesDataStore.debugLogging.first() }

        // Convert profile to resolver config
        val resolvers = profile.resolvers.map { resolver ->
            ResolverConfig(
                host = resolver.host,
                port = resolver.port,
                authoritative = resolver.authoritative
            )
        }

        // Start the tunnel in a background coroutine
        scope.launch(Dispatchers.IO) {
            try {
                // Step 1: Start the Slipstream DNS tunnel (SOCKS5 proxy)
                val proxyPort = runBlocking { preferencesDataStore.proxyListenPort.first() }
                val proxyHost = runBlocking { preferencesDataStore.proxyListenAddress.first() }
                val success = startSlipstreamClient(profile.domain, resolvers, profile, debugLogging, proxyPort, proxyHost)

                if (!success) {
                    val error = tunnelStartException?.message ?: "Failed to start tunnel"
                    _connectionState.value = ConnectionState.Error(error)
                    connectedProfile = null
                    Log.e(TAG, "Failed to start tunnel: $error")
                    return@launch
                }

                // Give the SOCKS5 proxy time to start
                Thread.sleep(500)

                // Step 2: Start hev-socks5-tunnel (tun2socks)
                // This routes TUN traffic through the SOCKS5 proxy
                val mtu2 = try { preferencesDataStore.vpnMtu.first() } catch (_: Exception) { PreferencesDataStore.DEFAULT_MTU }

                Log.i(TAG, "========================================")
                Log.i(TAG, "Starting hev-socks5-tunnel")
                val localAuthEnabled = runBlocking { preferencesDataStore.proxyAuthEnabled.first() }
                val localAuthUser = if (localAuthEnabled) runBlocking { preferencesDataStore.proxyAuthUsername.first().ifEmpty { null } } else null
                val localAuthPass = if (localAuthEnabled) runBlocking { preferencesDataStore.proxyAuthPassword.first().ifEmpty { null } } else null

                Log.i(TAG, "  SOCKS5 proxy: 127.0.0.1:$proxyPort")
                Log.i(TAG, "  SOCKS auth: ${if (localAuthEnabled) "enabled" else "disabled"}")
                Log.i(TAG, "  MTU: $mtu2")
                Log.i(TAG, "========================================")

                val hevResult = HevSocks5Tunnel.start(
                    tunFd = pfd,
                    socksAddress = "127.0.0.1",
                    socksPort = proxyPort,
                    socksUsername = localAuthUser,
                    socksPassword = localAuthPass,
                    mtu = mtu2,
                    ipv4Address = "10.255.255.1",
                    ipv6Address = "fd00::1"
                )

                if (hevResult.isSuccess) {
                    _connectionState.value = ConnectionState.Connected(profile)
                    Log.i(TAG, "Tunnel started successfully")
                } else {
                    val error = hevResult.exceptionOrNull()?.message ?: "Failed to start tun2socks"
                    _connectionState.value = ConnectionState.Error(error)
                    connectedProfile = null
                    // Stop the SOCKS5 proxy since tun2socks failed
                    SlipstreamBridge.stopClient()
                    Log.e(TAG, "Failed to start tunnel: $error")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Exception starting tunnel", e)
                _connectionState.value = ConnectionState.Error(e.message ?: "Unknown error")
                connectedProfile = null
            }
        }

        return Result.success(Unit)
    }

    private fun startSlipstreamClient(
        domain: String,
        resolvers: List<ResolverConfig>,
        profile: ServerProfile,
        debugLogging: Boolean,
        listenPort: Int,
        listenHost: String
    ): Boolean {
        tunnelStartException = null
        val result = SlipstreamBridge.startClient(
            domain = domain,
            resolvers = resolvers,
            congestionControl = profile.congestionControl.value,
            keepAliveInterval = profile.keepAliveInterval,
            tcpListenPort = listenPort,
            tcpListenHost = listenHost,
            gsoEnabled = profile.gsoEnabled,
            debugPoll = debugLogging,
            debugStreams = debugLogging,
            idlePollIntervalMs = 10000,
            idleTimeoutMs = 120000
        )
        if (result.isFailure) {
            val exception = result.exceptionOrNull()
            tunnelStartException = Exception("DNS tunnel failed: ${exception?.message ?: "Unknown error"}", exception)
            Log.e(TAG, "Failed to start Slipstream client", exception)
        }
        return result.isSuccess
    }

    override suspend fun disconnect(): Result<Unit> {
        if (_connectionState.value is ConnectionState.Disconnected) {
            return Result.success(Unit)
        }

        _connectionState.value = ConnectionState.Disconnecting

        try {
            // Stop hev-socks5-tunnel first
            HevSocks5Tunnel.stop()

            // Then stop the current proxy (Slipstream or DNSTT)
            stopCurrentProxy()

            currentTunFd = null
            _connectionState.value = ConnectionState.Disconnected
            connectedProfile = null
            Log.i(TAG, "Tunnel stopped successfully")
            return Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping tunnel", e)
            _connectionState.value = ConnectionState.Error(e.message ?: "Unknown error")
            return Result.failure(e)
        }
    }

    override fun isConnected(): Boolean {
        return _connectionState.value is ConnectionState.Connected
    }

    override fun getConnectedProfile(): ServerProfile? {
        return if (_connectionState.value is ConnectionState.Connected) connectedProfile else null
    }

    fun setProxyConnected(profile: ServerProfile) {
        _connectionState.value = ConnectionState.Connected(profile)
    }

    fun updateConnectionState(state: ConnectionState) {
        _connectionState.value = state
    }

    fun updateTrafficStats(stats: TrafficStats) {
        _trafficStats.value = stats
    }

    fun resetSpeedTracking() {
        prevBytesSent = 0L
        prevBytesReceived = 0L
        prevTimestamp = 0L
        _trafficStats.value = TrafficStats.EMPTY
    }

    fun refreshTrafficStats() {
        // For SOCKS-bridged tunnel types, use tunnel-level byte counters
        // instead of TUN-level stats (which include local retries/health checks)
        var sent = 0L
        var received = 0L
        var pktSent = 0L
        var pktReceived = 0L

        when (currentTunnelType) {
            TunnelType.SLIPSTREAM -> {
                sent = SlipstreamSocksBridge.getTunnelTxBytes()
                received = SlipstreamSocksBridge.getTunnelRxBytes()
            }
            TunnelType.DNSTT, TunnelType.NOIZDNS, TunnelType.VAYDNS -> {
                // VAYDNS in proxy-only mode relays through DnsttSocksBridge on the
                // SOCKS5 listen port, same as DNSTT/NOIZDNS — so its byte counters
                // are authoritative in both proxy-only and VPN mode.
                sent = DnsttSocksBridge.getTunnelTxBytes()
                received = DnsttSocksBridge.getTunnelRxBytes()
            }
            TunnelType.SSH, TunnelType.DNSTT_SSH, TunnelType.NOIZDNS_SSH,
            TunnelType.SLIPSTREAM_SSH, TunnelType.NAIVE_SSH, TunnelType.VAYDNS_SSH -> {
                sent = SshTunnelBridge.getTunnelTxBytes()
                received = SshTunnelBridge.getTunnelRxBytes()
            }
            TunnelType.SOCKS5 -> {
                sent = Socks5ProxyBridge.getTunnelTxBytes()
                received = Socks5ProxyBridge.getTunnelRxBytes()
            }
            TunnelType.VLESS -> {
                sent = VlessBridge.getTunnelTxBytes()
                received = VlessBridge.getTunnelRxBytes()
            }
            TunnelType.NAIVE -> {
                sent = NaiveSocksBridge.getTunnelTxBytes()
                received = NaiveSocksBridge.getTunnelRxBytes()
            }
            TunnelType.DOH -> {
                sent = DohBridge.getTunnelTxBytes()
                received = DohBridge.getTunnelRxBytes()
            }
            else -> {
                // Snowflake falls through here. It's Go-backed and gomobile
                // doesn't expose byte counters, so in VPN mode we read
                // TUN-level stats via HevSocks5Tunnel; in proxy-only mode
                // Snowflake currently shows 0 bytes until Go-side counter
                // exposure is added.
                val stats = HevSocks5Tunnel.getStats() ?: return
                sent = stats.txBytes
                received = stats.rxBytes
                pktSent = stats.txPackets
                pktReceived = stats.rxPackets
            }
        }

        // Compute speed normalized by actual elapsed time
        val now = System.currentTimeMillis()
        val elapsedMs = now - prevTimestamp
        val upSpeed: Long
        val downSpeed: Long
        if (prevTimestamp == 0L || elapsedMs <= 0) {
            upSpeed = 0L
            downSpeed = 0L
        } else {
            upSpeed = ((sent - prevBytesSent).coerceAtLeast(0) * 1000 / elapsedMs)
            downSpeed = ((received - prevBytesReceived).coerceAtLeast(0) * 1000 / elapsedMs)
        }
        prevBytesSent = sent
        prevBytesReceived = received
        prevTimestamp = now

        _trafficStats.value = TrafficStats(
            bytesSent = sent,
            bytesReceived = received,
            packetsSent = pktSent,
            packetsReceived = pktReceived,
            uploadSpeed = upSpeed,
            downloadSpeed = downSpeed
        )
    }
}
