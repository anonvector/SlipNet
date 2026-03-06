package app.slipnet.util

import android.content.Context
import android.provider.Settings
import java.security.MessageDigest

object DeviceIdUtil {

    /**
     * Returns a scrambled device identifier derived from ANDROID_ID.
     * Uses SHA-256 hash truncated to 16 hex chars so the raw ANDROID_ID
     * is never exposed or stored directly.
     */
    fun getScrambledDeviceId(context: Context): String {
        val androidId = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) ?: ""
        if (androidId.isEmpty()) return ""
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(androidId.toByteArray(Charsets.UTF_8))
        return hash.take(8).joinToString("") { "%02x".format(it) }
    }
}
