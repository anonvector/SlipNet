package app.slipnet.util

import java.security.MessageDigest
import java.security.SecureRandom

object LockPasswordUtil {

    fun hashPassword(password: String): String {
        val salt = ByteArray(16)
        SecureRandom().nextBytes(salt)
        val saltHex = salt.joinToString("") { "%02x".format(it) }
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(salt)
        val hash = digest.digest(password.toByteArray(Charsets.UTF_8))
        val hashHex = hash.joinToString("") { "%02x".format(it) }
        return "$saltHex:$hashHex"
    }

    fun verifyPassword(password: String, storedHash: String): Boolean {
        val parts = storedHash.split(":")
        if (parts.size != 2) return false
        val saltHex = parts[0]
        val expectedHashHex = parts[1]
        val salt = saltHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(salt)
        val hash = digest.digest(password.toByteArray(Charsets.UTF_8))
        val hashHex = hash.joinToString("") { "%02x".format(it) }
        return hashHex == expectedHashHex
    }
}
