package fr.aegis.android.security

import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Authenticated encryption envelope for AEGIS recovery archives.
 *
 * The archive encryption key is a random 256-bit recovery secret kept separate
 * from the ciphertext. The trusted peer stores only the ciphertext. The secret
 * must be transferred out-of-band during the recovery ceremony and must never
 * be logged or persisted in ordinary app preferences.
 *
 * This codec does not transfer archives or restore application data by itself.
 */
object RecoveryBackupCodec {
    private val random = SecureRandom()
    private val magic = byteArrayOf(0x41, 0x45, 0x47, 0x52) // AEGR
    private const val VERSION: Byte = 1
    private const val NONCE_BYTES = 12
    private const val KEY_BYTES = 32
    private const val TAG_BITS = 128
    private const val HEADER_BYTES = 4 + 1 + NONCE_BYTES
    const val MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
    private const val MIN_ENVELOPE_BYTES = HEADER_BYTES + 16
    private const val MAX_ENVELOPE_BYTES = HEADER_BYTES + MAX_ARCHIVE_BYTES + 16
    private const val SECRET_PREFIX = "AEGIS-R1-"

    data class RecoverySecret internal constructor(val encoded: String) {
        override fun toString(): String = "RecoverySecret([redacted])"
    }

    /** Generates a one-time 256-bit secret. Display it only in a protected recovery flow. */
    fun createSecret(): RecoverySecret {
        val key = ByteArray(KEY_BYTES).also(random::nextBytes)
        return try {
            RecoverySecret(SECRET_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(key))
        } finally {
            key.fill(0)
        }
    }

    /** Validates a recovery code entered during restore. */
    fun parseSecret(code: String): RecoverySecret {
        require(code.length <= 64 && code.startsWith(SECRET_PREFIX)) {
            "Code de récupération AEGIS invalide."
        }
        val candidate = RecoverySecret(code.trim())
        val key = decodeSecret(candidate)
        key.fill(0)
        return candidate
    }

    /** Encrypts a serialized recovery archive. The caller retains responsibility for clearing plaintext. */
    fun encrypt(archive: ByteArray, secret: RecoverySecret): ByteArray {
        require(archive.isNotEmpty() && archive.size <= MAX_ARCHIVE_BYTES) {
            "Archive de récupération vide ou trop volumineuse."
        }
        val key = decodeSecret(secret)
        val nonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
            cipher.updateAAD(associatedData())
            val encrypted = cipher.doFinal(archive)
            return try {
                ByteBuffer.allocate(HEADER_BYTES + encrypted.size)
                    .put(magic)
                    .put(VERSION)
                    .put(nonce)
                    .put(encrypted)
                    .array()
            } finally {
                encrypted.fill(0)
            }
        } finally {
            key.fill(0)
            nonce.fill(0)
        }
    }

    /** Decrypts and authenticates an archive; tampered data or a wrong secret is rejected. */
    fun decrypt(envelope: ByteArray, secret: RecoverySecret): ByteArray {
        require(envelope.size in MIN_ENVELOPE_BYTES..MAX_ENVELOPE_BYTES) {
            "Archive de récupération invalide ou trop volumineuse."
        }
        val buffer = ByteBuffer.wrap(envelope)
        val headerMagic = ByteArray(magic.size)
        buffer.get(headerMagic)
        require(headerMagic.contentEquals(magic)) { "Format d’archive de récupération inconnu." }
        require(buffer.get() == VERSION) { "Version d’archive de récupération non prise en charge." }
        val nonce = ByteArray(NONCE_BYTES)
        buffer.get(nonce)
        val ciphertext = ByteArray(buffer.remaining())
        buffer.get(ciphertext)
        val key = decodeSecret(secret)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
            cipher.updateAAD(associatedData())
            return try {
                cipher.doFinal(ciphertext)
            } catch (failure: AEADBadTagException) {
                throw SecurityException("Authentification de l’archive échouée : secret incorrect ou données modifiées.", failure)
            }
        } finally {
            key.fill(0)
            nonce.fill(0)
            ciphertext.fill(0)
            headerMagic.fill(0)
        }
    }

    private fun decodeSecret(secret: RecoverySecret): ByteArray {
        require(secret.encoded.startsWith(SECRET_PREFIX)) { "Code de récupération AEGIS invalide." }
        val decoded = runCatching {
            Base64.getUrlDecoder().decode(secret.encoded.removePrefix(SECRET_PREFIX))
        }.getOrElse { throw IllegalArgumentException("Code de récupération AEGIS invalide.", it) }
        require(decoded.size == KEY_BYTES) {
            decoded.fill(0)
            "Longueur du code de récupération invalide."
        }
        return decoded
    }

    private fun associatedData(): ByteArray = "AEGIS|RECOVERY-ARCHIVE|v1".toByteArray(Charsets.UTF_8)
}
