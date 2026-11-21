package fr.aegis.android.security

import android.content.Context
import android.os.SystemClock
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Local PIN verifier for the prototype.
 *
 * This stores a salted PBKDF2 verifier, never the PIN itself. SharedPreferences
 * are private to the app but are not an anti-tampering hardware security boundary.
 * A production design must bind access to a Keystore key and validate a
 * hardware-backed, rollback-resistant attempt policy.
 */
class PinLockManager(context: Context) {
    private val prefs = context.getSharedPreferences("aegis_local_lock_v1", Context.MODE_PRIVATE)

    sealed interface Verification {
        data object Accepted : Verification
        data object Rejected : Verification
        data class Locked(val remainingMillis: Long) : Verification
        data object IdentityWipeRequired : Verification
    }

    fun isConfigured(): Boolean = prefs.contains(KEY_HASH) && prefs.contains(KEY_SALT)

    @Synchronized
    fun configure(pin: CharArray) {
        require(pin.size in MIN_PIN_LENGTH..MAX_PIN_LENGTH) { "Le code PIN doit contenir 6 à 12 chiffres." }
        require(pin.all { it in '0'..'9' }) { "Le code PIN doit contenir uniquement des chiffres." }

        val salt = ByteArray(SALT_BYTES).also(SecureRandom()::nextBytes)
        val hash = derive(pin, salt)
        prefs.edit()
            .putString(KEY_SALT, salt.toHex())
            .putString(KEY_HASH, hash.toHex())
            .putInt(KEY_FAILURES, 0)
            .putLong(KEY_LOCK_UNTIL, 0L)
            .commit()
    }

    @Synchronized
    fun verify(pin: CharArray): Verification {
        val salt = prefs.getString(KEY_SALT, null)?.hexToBytes() ?: return Verification.Rejected
        val expected = prefs.getString(KEY_HASH, null)?.hexToBytes() ?: return Verification.Rejected

        val lockUntil = prefs.getLong(KEY_LOCK_UNTIL, 0L)
        val now = System.currentTimeMillis()
        if (now < lockUntil) return Verification.Locked(lockUntil - now)

        val candidate = derive(pin, salt)
        if (MessageDigest.isEqual(expected, candidate)) {
            prefs.edit().putInt(KEY_FAILURES, 0).putLong(KEY_LOCK_UNTIL, 0L).commit()
            return Verification.Accepted
        }

        val failures = prefs.getInt(KEY_FAILURES, 0) + 1
        if (failures >= WIPE_AFTER_FAILURES) {
            prefs.edit().putInt(KEY_FAILURES, failures).commit()
            return Verification.IdentityWipeRequired
        }

        val delaySeconds = if (failures < 5) 0L else (30L shl (failures - 5)).coerceAtMost(MAX_LOCK_SECONDS)
        val until = if (delaySeconds == 0L) 0L else now + delaySeconds * 1_000L
        prefs.edit()
            .putInt(KEY_FAILURES, failures)
            .putLong(KEY_LOCK_UNTIL, until)
            .commit()
        return Verification.Rejected
    }

    @Synchronized
    fun resetAfterIdentityWipe() {
        prefs.edit().clear().commit()
    }

    private fun derive(pin: CharArray, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(pin, salt, PBKDF2_ITERATIONS, HASH_BITS)
        return try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun String.hexToBytes(): ByteArray {
        require(length % 2 == 0)
        return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    companion object {
        private const val KEY_SALT = "pin_salt"
        private const val KEY_HASH = "pin_hash"
        private const val KEY_FAILURES = "failed_attempts"
        private const val KEY_LOCK_UNTIL = "lock_until_epoch_ms"
        private const val MIN_PIN_LENGTH = 6
        private const val MAX_PIN_LENGTH = 12
        private const val SALT_BYTES = 16
        private const val HASH_BITS = 256
        private const val PBKDF2_ITERATIONS = 310_000
        private const val WIPE_AFTER_FAILURES = 10
        private const val MAX_LOCK_SECONDS = 15 * 60L
    }
}
