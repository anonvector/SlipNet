package app.slipnet.util

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Password-derived AES-GCM encryption for profile bundles.
 *
 * Wire format (after base64 decoding the URI payload):
 *   [version=0x01] [salt=16B] [iv=12B] [ciphertext+tag]
 *
 * KDF: PBKDF2-HMAC-SHA256, 600_000 iterations → 256-bit AES key.
 */
object BundleCrypto {
    private const val FORMAT_VERSION: Byte = 0x01
    private const val SALT_LENGTH = 16
    private const val IV_LENGTH = 12
    private const val GCM_TAG_BITS = 128
    private const val KEY_BITS = 256
    private const val PBKDF2_ITERATIONS = 600_000

    class DecryptionException(message: String, cause: Throwable? = null) : Exception(message, cause)

    fun encrypt(plaintext: String, password: String): ByteArray {
        require(password.isNotEmpty()) { "Password must not be empty" }
        val salt = ByteArray(SALT_LENGTH).also { SecureRandom().nextBytes(it) }
        val iv = ByteArray(IV_LENGTH).also { SecureRandom().nextBytes(it) }
        val key = deriveKey(password, salt)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))

        val out = ByteArray(1 + SALT_LENGTH + IV_LENGTH + ciphertext.size)
        out[0] = FORMAT_VERSION
        System.arraycopy(salt, 0, out, 1, SALT_LENGTH)
        System.arraycopy(iv, 0, out, 1 + SALT_LENGTH, IV_LENGTH)
        System.arraycopy(ciphertext, 0, out, 1 + SALT_LENGTH + IV_LENGTH, ciphertext.size)
        return out
    }

    fun decrypt(data: ByteArray, password: String): String {
        if (data.isEmpty() || data[0] != FORMAT_VERSION) {
            throw DecryptionException("Unsupported encrypted bundle format")
        }
        val minLength = 1 + SALT_LENGTH + IV_LENGTH + GCM_TAG_BITS / 8
        if (data.size < minLength) {
            throw DecryptionException("Encrypted bundle is truncated")
        }

        val salt = data.copyOfRange(1, 1 + SALT_LENGTH)
        val iv = data.copyOfRange(1 + SALT_LENGTH, 1 + SALT_LENGTH + IV_LENGTH)
        val ciphertext = data.copyOfRange(1 + SALT_LENGTH + IV_LENGTH, data.size)
        val key = deriveKey(password, salt)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        val plainBytes = try {
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            // AEAD tag mismatch ⇒ wrong password or tampered data.
            throw DecryptionException("Wrong password or corrupted data", e)
        }
        return String(plainBytes, Charsets.UTF_8)
    }

    private fun deriveKey(password: String, salt: ByteArray): SecretKeySpec {
        val spec = PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_BITS)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val keyBytes = factory.generateSecret(spec).encoded
        return SecretKeySpec(keyBytes, "AES")
    }
}
