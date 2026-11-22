package fr.aegis.android.security

import android.content.Context

/**
 * Exports only user content. Identity keys, trusted-peer pins, PIN state and
 * transport/session state are intentionally excluded and must be re-established.
 */
class RecoveryArchiveManager(context: Context) {
    private val vault = EncryptedFileStore(context.applicationContext)

    data class EncryptedBackup(val envelope: ByteArray, val secret: RecoveryBackupCodec.RecoverySecret)

    fun createEncryptedBackup(): EncryptedBackup {
        val secret = RecoveryBackupCodec.createSecret()
        val records = vault.listRecordIds()
            .filter(RecoveryArchiveCodec::isAllowedId)
            .mapNotNull { id -> vault.get(id)?.let { RecoveryArchiveCodec.Record(id, it) } }
        val plain = try {
            RecoveryArchiveCodec.encode(records)
        } finally {
            records.forEach { it.bytes.fill(0) }
        }
        return try {
            EncryptedBackup(RecoveryBackupCodec.encrypt(plain, secret), secret)
        } finally {
            plain.fill(0)
        }
    }

    /** Restores user content into this device's own Keystore-backed vault. */
    fun restoreEncryptedBackup(envelope: ByteArray, code: String): Int {
        val secret = RecoveryBackupCodec.parseSecret(code)
        val plain = RecoveryBackupCodec.decrypt(envelope, secret)
        val records = try {
            RecoveryArchiveCodec.decode(plain)
        } finally {
            plain.fill(0)
        }
        try {
            // Validate the full archive before writing any record.
            records.forEach { record ->
                require(RecoveryArchiveCodec.isAllowedId(record.id)) { "Type de donnée non autorisé dans l’archive." }
            }
            records.forEach { record -> vault.put(record.id, record.bytes) }
            return records.size
        } finally {
            records.forEach { it.bytes.fill(0) }
        }
    }
}
