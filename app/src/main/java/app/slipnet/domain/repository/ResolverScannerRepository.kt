package app.slipnet.domain.repository

import android.content.Context
import app.slipnet.domain.model.E2eTestResult
import app.slipnet.domain.model.ResolverScanResult
import app.slipnet.domain.model.ServerProfile
import kotlinx.coroutines.flow.Flow

/**
 * Repository for DNS resolver scanning operations
 */
interface ResolverScannerRepository {
    /**
     * Get the default list of resolver IPs to scan
     */
    fun getDefaultResolvers(): List<String>

    /**
     * Tier boundaries from `# SHUFFLE_BELOW` markers in the resolver list.
     * Returns indices where each marker appeared. Items before the first marker are
     * never shuffled; items between consecutive markers form independent shuffle tiers.
     * Example: markers at [10, 50] → tier 0 (0..9, unshuffled), tier 1 (10..49, shuffled), tier 2 (50..end, shuffled)
     */
    fun getDefaultResolverTierBoundaries(): List<Int>

    /**
     * Parse a text file content into a list of IP addresses
     */
    fun parseResolverList(content: String): List<String>

    /**
     * Parse a stream of text into a list of IP addresses (memory-efficient for large files)
     */
    fun parseResolverList(reader: java.io.BufferedReader): List<String>

    /**
     * Generate random IPs from a country's CIDR ranges
     * @param context Android context to access assets
     * @param countryCode Country code (e.g. "ir", "cn", "ru")
     * @param count Number of random IPs to generate
     */
    fun generateCountryRangeIps(context: Context, countryCode: String, count: Int): List<String>

    /**
     * Load raw CIDR ranges for a country from assets
     * @param context Android context to access assets
     * @param countryCode Country code (e.g. "ir", "cn", "ru")
     * @return List of (startIpLong, endIpLong) pairs
     */
    fun loadCountryCidrRanges(context: Context, countryCode: String): List<Pair<Long, Long>>

    /**
     * Generate random IPs from provided CIDR ranges
     * @param ranges List of (startIpLong, endIpLong) pairs to sample from
     * @param count Number of random IPs to generate
     */
    fun generateFromRanges(ranges: List<Pair<Long, Long>>, count: Int): List<String>

    /**
     * Expand IP ranges into a full list of individual IP addresses
     * @param ranges List of (startIpLong, endIpLong) pairs
     * @return List of all IP address strings in the ranges
     */
    fun expandIpRanges(ranges: List<Pair<Long, Long>>): List<String>

    /**
     * Scan a single resolver for DNS tunnel compatibility
     * @param host The IP address to scan
     * @param port The DNS port (default 53)
     * @param testDomain The domain to test resolution for
     * @param timeoutMs Timeout in milliseconds
     */
    suspend fun scanResolver(
        host: String,
        port: Int = 53,
        testDomain: String,
        timeoutMs: Long = 3000,
        querySize: Int = 0
    ): ResolverScanResult

    /**
     * Scan multiple resolvers concurrently
     * Emits results as they complete
     * @param querySize Cap tunnel-realism probe size to match the user's query-size setting (0 = full capacity)
     */
    fun scanResolvers(
        hosts: List<String>,
        port: Int = 53,
        testDomain: String,
        timeoutMs: Long = 3000,
        concurrency: Int = 50,
        querySize: Int = 0
    ): Flow<ResolverScanResult>

    /**
     * Probe a single resolver using the Prism (slipgate) HMAC challenge-response protocol.
     * Sends base32(nonce || HMAC(key,nonce)[:16]).<domain> as a TXT query with EDNS0(4096),
     * then verifies the server's response encodes HMAC(key, nonce||0x01).
     * Returns true only when the resolver forwards to a server holding [pubkey].
     */
    /**
     * @return Number of probes that passed (0..probeCount).
     */
    suspend fun verifyResolver(
        host: String,
        port: Int = 53,
        testDomain: String,
        pubkey: ByteArray,
        timeoutMs: Long = 3000,
        probeCount: Int = 20,
        passThreshold: Int = 5,
        responseSize: Int = 1232
    ): Int

    /**
     * Detect transparent DNS proxy/interception by querying TEST-NET IPs (RFC 5737).
     * These IPs should never host DNS servers — any response means the ISP is intercepting.
     * @param testDomain The domain to query
     * @param timeoutMs Timeout per probe (default 2000ms)
     * @return true if interception detected
     */
    suspend fun detectTransparentProxy(testDomain: String, timeoutMs: Long = 2000): Boolean

    /**
     * Test a single resolver end-to-end by establishing a real tunnel.
     * @param resolverHost The resolver IP address
     * @param resolverPort The resolver port
     * @param profile The server profile (determines tunnel type)
     * @param testUrl The URL to request through the tunnel (only used when fullVerification=true)
     * @param timeoutMs Total timeout per resolver
     * @param fullVerification When false, stops after SOCKS5 handshake (fast scan mode).
     *        When true, also performs HTTP/SSH verification through the tunnel.
     * @param onPhaseUpdate Callback for phase progress updates
     */
    suspend fun testResolverE2e(
        resolverHost: String,
        resolverPort: Int,
        profile: ServerProfile,
        testUrl: String,
        timeoutMs: Long,
        fullVerification: Boolean = false,
        onPhaseUpdate: (String) -> Unit
    ): E2eTestResult

    /**
     * Test multiple resolvers end-to-end sequentially (bridges are singletons).
     * Emits results as each resolver completes.
     */
    fun testResolversE2e(
        resolvers: List<Pair<String, Int>>,
        profile: ServerProfile,
        testUrl: String,
        timeoutMs: Long,
        fullVerification: Boolean = false,
        onPhaseUpdate: (String, String) -> Unit
    ): Flow<Pair<String, E2eTestResult>>

    /**
     * Test a single resolver E2E using an isolated (ephemeral) tunnel instance.
     * For DNSTT/NoizDNS: creates its own Go client on a unique port (safe for parallel use).
     * For Slipstream: falls back to the singleton bridge (must be serialized externally).
     */
    suspend fun testResolverE2eIsolated(
        resolverHost: String,
        resolverPort: Int,
        profile: ServerProfile,
        testUrl: String,
        timeoutMs: Long,
        fullVerification: Boolean = false,
        onPhaseUpdate: (String) -> Unit
    ): E2eTestResult

    /**
     * Maximum parallel E2E concurrency supported for the given tunnel type.
     * Slipstream uses a native singleton so only 1 is supported.
     * DNSTT/NoizDNS create ephemeral Go clients, supporting higher concurrency.
     */
    fun maxE2eConcurrency(profile: ServerProfile): Int
}
