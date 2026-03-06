package app.slipnet.util

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

data class AppUpdate(
    val versionName: String,
    val downloadUrl: String,
    val releaseNotes: String
)

object UpdateChecker {
    private const val TAG = "UpdateChecker"
    private const val GITHUB_API = "https://api.github.com/repos/anonvector/SlipNet/releases/latest"
    private const val TIMEOUT_MS = 10_000
    // Only check once per 12 hours
    const val CHECK_INTERVAL_MS = 12 * 60 * 60 * 1000L

    /**
     * Check GitHub for a newer release. Returns null if up-to-date or on error.
     * Safe to call from any coroutine — uses Dispatchers.IO, never throws.
     */
    suspend fun check(currentVersionName: String): AppUpdate? = withContext(Dispatchers.IO) {
        try {
            val conn = URL(GITHUB_API).openConnection() as HttpURLConnection
            conn.requestMethod = "GET"
            conn.setRequestProperty("Accept", "application/vnd.github+json")
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS

            if (conn.responseCode != 200) {
                Log.d(TAG, "GitHub API returned ${conn.responseCode}")
                conn.disconnect()
                return@withContext null
            }

            val body = conn.inputStream.bufferedReader().use { it.readText() }
            conn.disconnect()

            val json = JSONObject(body)
            val tagName = json.optString("tag_name", "").removePrefix("v")
            val htmlUrl = json.optString("html_url", "")
            val releaseBody = json.optString("body", "").take(500)

            if (tagName.isBlank() || htmlUrl.isBlank()) {
                return@withContext null
            }

            if (isNewer(tagName, currentVersionName)) {
                Log.d(TAG, "Update available: $tagName (current: $currentVersionName)")
                AppUpdate(
                    versionName = tagName,
                    downloadUrl = htmlUrl,
                    releaseNotes = releaseBody
                )
            } else {
                Log.d(TAG, "Up to date ($currentVersionName)")
                null
            }
        } catch (e: Exception) {
            Log.d(TAG, "Update check failed: ${e.message}")
            null
        }
    }

    /**
     * Compare version strings. Returns true if remote > current.
     * Handles: "2.2.1", "2.3-beta", "2.3.0-rc1"
     * Pre-release tags (beta, rc, alpha) are considered older than the
     * same version without a tag: 2.3-beta < 2.3
     */
    private fun isNewer(remote: String, current: String): Boolean {
        val (rNums, rPre) = parseVersion(remote)
        val (cNums, cPre) = parseVersion(current)
        for (i in 0 until maxOf(rNums.size, cNums.size)) {
            val rv = rNums.getOrElse(i) { 0 }
            val cv = cNums.getOrElse(i) { 0 }
            if (rv > cv) return true
            if (rv < cv) return false
        }
        // Same numeric version: release > pre-release
        // e.g., "2.3" (no pre) is newer than "2.3-beta"
        if (cPre != null && rPre == null) return true
        if (cPre == null && rPre != null) return false
        return false
    }

    /** Split "2.3.1-beta" into ([2,3,1], "beta"). */
    private fun parseVersion(version: String): Pair<List<Int>, String?> {
        val dashIndex = version.indexOf('-')
        val numPart = if (dashIndex >= 0) version.substring(0, dashIndex) else version
        val prePart = if (dashIndex >= 0) version.substring(dashIndex + 1) else null
        val nums = numPart.split(".").map { it.toIntOrNull() ?: 0 }
        return nums to prePart
    }
}
