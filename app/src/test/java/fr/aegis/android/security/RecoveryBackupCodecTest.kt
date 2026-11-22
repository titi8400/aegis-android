package fr.aegis.android.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class RecoveryBackupCodecTest {
    @Test
    fun encryptDecryptRoundTrip() {
        val secret = RecoveryBackupCodec.createSecret()
        val archive = """{"format":"AEGIS-RECOVERY","version":1,"records":[]}""".toByteArray()
        val encrypted = RecoveryBackupCodec.encrypt(archive, secret)
        assertNotEquals(archive.toList(), encrypted.toList())
        assertArrayEquals(archive, RecoveryBackupCodec.decrypt(encrypted, secret))
    }

    @Test
    fun wrongSecretIsRejected() {
        val encrypted = RecoveryBackupCodec.encrypt(
            "private recovery data".toByteArray(),
            RecoveryBackupCodec.createSecret()
        )
        assertThrows(SecurityException::class.java) {
            RecoveryBackupCodec.decrypt(encrypted, RecoveryBackupCodec.createSecret())
        }
    }

    @Test
    fun modifiedCiphertextIsRejected() {
        val secret = RecoveryBackupCodec.createSecret()
        val encrypted = RecoveryBackupCodec.encrypt("private recovery data".toByteArray(), secret)
        encrypted[encrypted.lastIndex] = (encrypted.last().toInt() xor 1).toByte()
        assertThrows(SecurityException::class.java) {
            RecoveryBackupCodec.decrypt(encrypted, secret)
        }
    }

    @Test
    fun malformedEnvelopeIsRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            RecoveryBackupCodec.decrypt(byteArrayOf(1, 2, 3), RecoveryBackupCodec.createSecret())
        }
    }
}
