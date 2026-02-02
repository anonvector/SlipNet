package app.slipnet.domain.repository

import app.slipnet.domain.model.ResolverScanResult
import app.slipnet.domain.model.ScanMode
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
     * Scan a single resolver for DNS connectivity
     * @param host The IP address to scan
     * @param port The DNS port (default 53)
     * @param testDomain The domain to test resolution for
     * @param timeoutMs Timeout in milliseconds
     * @param scanMode The scanning mode (SIMPLE or DNS_TUNNEL)
     */
    suspend fun scanResolver(
        host: String,
        port: Int = 53,
        testDomain: String,
        timeoutMs: Long = 3000,
        scanMode: ScanMode = ScanMode.SIMPLE
    ): ResolverScanResult

    /**
     * Scan multiple resolvers concurrently
     * Emits results as they complete
     * @param scanMode The scanning mode (SIMPLE or DNS_TUNNEL)
     */
    fun scanResolvers(
        hosts: List<String>,
        port: Int = 53,
        testDomain: String,
        timeoutMs: Long = 3000,
        concurrency: Int = 50,
        scanMode: ScanMode = ScanMode.SIMPLE
    ): Flow<ResolverScanResult>
}
