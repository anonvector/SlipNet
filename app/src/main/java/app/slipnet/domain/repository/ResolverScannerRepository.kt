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
     * Parse a text file content into a list of IP addresses
     */
    fun parseResolverList(content: String): List<String>

    /**
     * Generate random IPs from a country's CIDR ranges
     * @param context Android context to access assets
     * @param countryCode Country code (e.g. "ir", "cn", "ru")
     * @param count Number of random IPs to generate
     */
    fun generateCountryRangeIps(context: Context, countryCode: String, count: Int): List<String>

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
        timeoutMs: Long = 3000
    ): ResolverScanResult

    /**
     * Scan multiple resolvers concurrently
     * Emits results as they complete
     */
    fun scanResolvers(
        hosts: List<String>,
        port: Int = 53,
        testDomain: String,
        timeoutMs: Long = 3000,
        concurrency: Int = 50
    ): Flow<ResolverScanResult>

    /**
     * Detect transparent DNS proxy/interception by querying TEST-NET IPs (RFC 5737).
     * These IPs should never host DNS servers — any response means the ISP is intercepting.
     * @param testDomain The domain to query
     * @param timeoutMs Timeout per probe (default 2000ms)
     * @return true if interception detected
     */
    suspend fun detectTransparentProxy(testDomain: String, timeoutMs: Long = 2000): Boolean

    /**
     * Test a single resolver end-to-end by establishing a real tunnel and sending an HTTP request.
     * @param resolverHost The resolver IP address
     * @param resolverPort The resolver port
     * @param profile The server profile (determines tunnel type)
     * @param testUrl The URL to request through the tunnel
     * @param timeoutMs Total timeout per resolver
     * @param onPhaseUpdate Callback for phase progress updates
     */
    suspend fun testResolverE2e(
        resolverHost: String,
        resolverPort: Int,
        profile: ServerProfile,
        testUrl: String,
        timeoutMs: Long,
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
        onPhaseUpdate: (String, String) -> Unit
    ): Flow<Pair<String, E2eTestResult>>
}
