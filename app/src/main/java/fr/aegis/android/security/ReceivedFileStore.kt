package fr.aegis.android.security

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/** Stores completed incoming files and their metadata in the encrypted local vault. */
class ReceivedFileStore(context: Context) {
    private val vault = EncryptedFileStore(context.applicationContext)

    data class ReceivedFile(
        val id: String,
        val fileName: String,
        val mimeType: String,
        val size: Long,
        val receivedAtEpochMs: Long
    )

    @Synchronized
    fun save(
        id: String,
        fileName: String,
        mimeType: String,
        bytes: ByteArray,
        nowEpochMs: Long = System.currentTimeMillis()
    ): ReceivedFile {
        validateId(id)
        val safeName = P2pFileTransferCodec.sanitizeFileName(fileName)
        require(safeName == fileName && safeName.length <= 100) { "Nom de fichier invalide." }
        require(mimeType.isNotBlank() && mimeType.length <= 100) { "Type MIME invalide." }
        require(bytes.isNotEmpty() && bytes.size.toLong() <= P2pFileTransferCodec.MAX_FILE_BYTES) {
            "Taille de fichier invalide."
        }
        val current = readIndex().filterNot { it.id == id }.toMutableList()
        require(current.size < MAX_FILES) { "Limite de fichiers reçus atteinte." }
        val item = ReceivedFile(id, safeName, mimeType, bytes.size.toLong(), nowEpochMs)
        vault.put(fileRecordId(id), bytes)
        try {
            current.add(item)
            writeIndex(current)
        } catch (failure: Exception) {
            vault.delete(fileRecordId(id))
            throw failure
        }
        return item
    }

    @Synchronized
    fun list(): List<ReceivedFile> = readIndex().sortedByDescending { it.receivedAtEpochMs }

    @Synchronized
    fun read(id: String): ByteArray? {
        validateId(id)
        require(readIndex().any { it.id == id }) { "Fichier reçu introuvable." }
        return vault.get(fileRecordId(id))
    }

    @Synchronized
    fun delete(id: String): Boolean {
        validateId(id)
        val files = readIndex()
        if (files.none { it.id == id }) return false
        vault.delete(fileRecordId(id))
        writeIndex(files.filterNot { it.id == id })
        return true
    }

    private fun readIndex(): List<ReceivedFile> {
        val bytes = vault.get(INDEX_RECORD) ?: return emptyList()
        return try {
            val array = JSONArray(bytes.toString(Charsets.UTF_8))
            require(array.length() <= MAX_FILES) { "Index des fichiers reçus invalide." }
            buildList {
                for (index in 0 until array.length()) {
                    val item = array.getJSONObject(index)
                    val id = item.getString("id")
                    validateId(id)
                    val name = item.getString("name")
                    require(P2pFileTransferCodec.sanitizeFileName(name) == name) { "Nom de fichier invalide." }
                    val size = item.getLong("size")
                    require(size in 1..P2pFileTransferCodec.MAX_FILE_BYTES) { "Taille de fichier invalide." }
                    add(
                        ReceivedFile(
                            id,
                            name,
                            item.getString("mime"),
                            size,
                            item.getLong("receivedAt")
                        )
                    )
                }
            }
        } catch (failure: Exception) {
            throw SecurityException("Index chiffré des fichiers reçus illisible.", failure)
        } finally {
            bytes.fill(0)
        }
    }

    private fun writeIndex(files: List<ReceivedFile>) {
        val array = JSONArray()
        files.forEach { item ->
            array.put(
                JSONObject()
                    .put("id", item.id)
                    .put("name", item.fileName)
                    .put("mime", item.mimeType)
                    .put("size", item.size)
                    .put("receivedAt", item.receivedAtEpochMs)
            )
        }
        val bytes = array.toString().toByteArray(Charsets.UTF_8)
        try {
            vault.put(INDEX_RECORD, bytes)
        } finally {
            bytes.fill(0)
        }
    }

    private fun fileRecordId(id: String) = "received_" + id.replace("-", "")

    private fun validateId(id: String) {
        require(runCatching { UUID.fromString(id).toString() == id }.getOrDefault(false)) {
            "Identifiant de fichier invalide."
        }
    }

    companion object {
        private const val INDEX_RECORD = "received_files_index_v1"
        private const val MAX_FILES = 100
    }
}
