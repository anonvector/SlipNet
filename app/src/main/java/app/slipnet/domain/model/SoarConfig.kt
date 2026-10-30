package app.slipnet.domain.model

import android.util.Base64

/**
 * Shared Soar tunnel settings and validation (profile editor and config import).
 *
 * Soar (github.com/getlantern/soar) authenticates its server with an Ed25519
 * key. `soar-server pubkey` prints it as base64; hex is accepted too.
 */
object SoarConfig {
    const val TCP_AUTO = "auto"
    const val TCP_ON = "on"
    const val TCP_ONLY = "only"
    const val TCP_OFF = "off"

    /** TCP/53 path modes, in the order the editor shows them. */
    val TCP_MODES = listOf(TCP_AUTO, TCP_ON, TCP_ONLY, TCP_OFF)

    /** Countries with bundled resolver lists in Soar ("" = global list only). */
    val DISCOVERY_COUNTRIES = listOf("", "IR", "RU", "CN")

    private const val KEY_SIZE = 32

    fun normalizeTcpMode(mode: String): String =
        mode.trim().lowercase().takeIf { it in TCP_MODES } ?: TCP_AUTO

    fun normalizeCountry(country: String): String =
        country.trim().uppercase().takeIf { it.length == 2 && it.all { c -> c in 'A'..'Z' } } ?: ""

    /** Returns an error message, or null if [key] is a valid Soar server public key. */
    fun validatePublicKey(key: String): String? {
        val trimmed = key.trim()
        if (trimmed.isEmpty()) return "Soar profiles require the server public key"
        if (decodePublicKey(trimmed) == null) {
            return "Public key must be the 32-byte Ed25519 key from `soar-server pubkey` (base64 or hex)"
        }
        return null
    }

    private fun decodePublicKey(key: String): ByteArray? {
        if (key.length == KEY_SIZE * 2 && key.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
            return key.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        }
        for (flags in intArrayOf(Base64.NO_WRAP, Base64.NO_WRAP or Base64.URL_SAFE)) {
            val bytes = try {
                Base64.decode(key, flags)
            } catch (_: IllegalArgumentException) {
                null
            }
            if (bytes != null && bytes.size == KEY_SIZE) return bytes
        }
        return null
    }
}
