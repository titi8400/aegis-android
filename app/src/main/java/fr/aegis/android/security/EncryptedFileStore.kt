package fr.aegis.android.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypted private-file vault backed by an AES-256 key in Android Keystore.
 *
 * File format: 4-byte magic, 1-byte format version, 12-byte GCM nonce,
 * then AES-GCM ciphertext and authentication tag.
 *
 * Record identifiers are authenticated as additional data, preventing a
 * ciphertext from being silently moved to a different record identifier.
 * The key is non-exportable through this API. Hardware backing depends on
 * the Android device and is not guaranteed.
 *
 * This class is a storage primitive; it does not implement a message database,
 * synchronization, key recovery, or secure deletion of flash memory blocks.
 */
class EncryptedFileStore(context: Context) {
    private val directory = File(context.applicationContext.noBackupFilesDir, DIRECTORY_NAME)
    private val keyStore: KeyStore
        get() = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    init {
        check(directory.exists() || directory.mkdirs()) {
            "Impossible de créer le répertoire chiffré AEGIS"
        }
        check(directory.isDirectory) { "Le chemin du coffre AEGIS n'est pas un répertoire" }
    }

    @Synchronized
    fun put(recordId: String, plaintext: ByteArray) {
        validateRecordId(recordId)
        require(plaintext.size <= MAX_PLAINTEXT_BYTES) { "Contenu trop volumineux" }

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        cipher.updateAAD(associatedData(recordId))
        val ciphertext = cipher.doFinal(plaintext)
        val nonce = cipher.iv
        check(nonce.size == GCM_NONCE_BYTES) { "Nonce GCM inattendu" }

        val envelope = ByteBuffer.allocate(HEADER_BYTES + nonce.size + ciphertext.size)
            .put(MAGIC)
            .put(FORMAT_VERSION)
            .put(nonce)
            .put(ciphertext)
            .array()

        val target = recordFile(recordId)
        val temporary = File(directory, ".${recordId}.${System.nanoTime()}.tmp")
        try {
            FileOutputStream(temporary).use { output ->
                output.write(envelope)
                output.fd.sync()
            }
            if (!temporary.renameTo(target)) {
                throw IllegalStateException("Impossible de finaliser l'enregistrement chiffré")
            }
        } finally {
            if (temporary.exists()) temporary.delete()
            envelope.fill(0)
            ciphertext.fill(0)
        }
    }

    @Synchronized
    fun get(recordId: String): ByteArray? {
        validateRecordId(recordId)
        val file = recordFile(recordId)
        if (!file.exists()) return null
        require(file.isFile && file.length() in MIN_ENVELOPE_BYTES.toLong()..MAX_ENVELOPE_BYTES.toLong()) {
            "Enregistrement chiffré invalide ou trop volumineux"
        }

        val envelope = file.readBytes()
        try {
            val buffer = ByteBuffer.wrap(envelope)
            val magic = ByteArray(MAGIC.size)
            buffer.get(magic)
            require(magic.contentEquals(MAGIC)) { "Format de coffre inconnu" }
            require(buffer.get() == FORMAT_VERSION) { "Version de coffre non prise en charge" }

            val nonce = ByteArray(GCM_NONCE_BYTES)
            buffer.get(nonce)
            val ciphertext = ByteArray(buffer.remaining())
            buffer.get(ciphertext)

            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, getExistingKey(), GCMParameterSpec(GCM_TAG_BITS, nonce))
            cipher.updateAAD(associatedData(recordId))
            return try {
                cipher.doFinal(ciphertext)
            } catch (failure: AEADBadTagException) {
                throw SecurityException("Authentification du contenu chiffré échouée", failure)
            } finally {
                nonce.fill(0)
                ciphertext.fill(0)
            }
        } finally {
            envelope.fill(0)
        }
    }

    @Synchronized
    fun delete(recordId: String): Boolean {
        validateRecordId(recordId)
        val file = recordFile(recordId)
        return !file.exists() || file.delete()
    }

    @Synchronized
    fun contains(recordId: String): Boolean {
        validateRecordId(recordId)
        return recordFile(recordId).isFile
    }

    /** Deletes the vault key. All existing records then become unrecoverable. */
    @Synchronized
    fun destroyKey(): Boolean {
        val store = keyStore
        if (!store.containsAlias(KEY_ALIAS)) return false
        store.deleteEntry(KEY_ALIAS)
        return true
    }

    private fun getOrCreateKey(): SecretKey {
        val store = keyStore
        val existing = store.getKey(KEY_ALIAS, null) as? SecretKey
        if (existing != null) return existing

        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEY_STORE
        )
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(false)
                .build()
        )
        return generator.generateKey()
    }

    private fun getExistingKey(): SecretKey =
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)
            ?: throw IllegalStateException("Clé du coffre AEGIS absente ou supprimée")

    private fun recordFile(recordId: String): File = File(directory, "$recordId.aeg")

    private fun associatedData(recordId: String): ByteArray =
        "AEGIS|ENCRYPTED-FILE|v1|$recordId".toByteArray(StandardCharsets.UTF_8)

    private fun validateRecordId(recordId: String) {
        require(recordId.matches(Regex("[A-Za-z0-9_-]{1,80}"))) {
            "Identifiant d'enregistrement invalide"
        }
    }

    companion object {
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "aegis.local.vault.aes256.v1"
        private const val DIRECTORY_NAME = "aegis-vault-v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val FORMAT_VERSION: Byte = 1
        private const val GCM_NONCE_BYTES = 12
        private const val GCM_TAG_BITS = 128
        private const val HEADER_BYTES = 5
        private const val MIN_ENVELOPE_BYTES = HEADER_BYTES + GCM_NONCE_BYTES + 16
        private const val MAX_PLAINTEXT_BYTES = 32 * 1024 * 1024
        private const val MAX_ENVELOPE_BYTES = MAX_PLAINTEXT_BYTES + HEADER_BYTES + GCM_NONCE_BYTES + 16
        private val MAGIC = byteArrayOf(0x41, 0x45, 0x47, 0x31) // "AEG1"
    }
}
