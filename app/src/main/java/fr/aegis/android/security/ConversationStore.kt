package fr.aegis.android.security

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * Per-peer encrypted local conversation history.
 *
 * The message body is stored only inside EncryptedFileStore (AES-256-GCM).
 * This first version is a bounded local history, not a delivery queue or
 * cross-device synchronization database.
 */
class ConversationStore(context: Context) {
    private val vault = EncryptedFileStore(context.applicationContext)

    data class Message(
        val id: String,
        val peerDeviceId: String,
        val body: String,
        val outgoing: Boolean,
        val createdAtEpochMs: Long
    )

    @Synchronized
    fun append(
        peerDeviceId: String,
        body: String,
        outgoing: Boolean,
        nowEpochMs: Long = System.currentTimeMillis()
    ): Message {
        validatePeerId(peerDeviceId)
        require(body.isNotBlank() && body.length <= MAX_MESSAGE_CHARS) {
            "Message vide ou trop long."
        }
        val messages = read(peerDeviceId).toMutableList()
        val message = Message(
            id = UUID.randomUUID().toString(),
            peerDeviceId = peerDeviceId,
            body = body,
            outgoing = outgoing,
            createdAtEpochMs = nowEpochMs
        )
        messages.add(message)
        write(peerDeviceId, messages.takeLast(MAX_MESSAGES))
        return message
    }

    @Synchronized
    fun list(peerDeviceId: String): List<Message> {
        validatePeerId(peerDeviceId)
        return read(peerDeviceId)
    }

    @Synchronized
    fun clear(peerDeviceId: String): Boolean {
        validatePeerId(peerDeviceId)
        return vault.delete(recordId(peerDeviceId))
    }

    private fun read(peerDeviceId: String): List<Message> {
        val bytes = vault.get(recordId(peerDeviceId)) ?: return emptyList()
        return try {
            val array = JSONArray(bytes.toString(Charsets.UTF_8))
            require(array.length() <= MAX_MESSAGES) { "Historique de conversation trop volumineux." }
            buildList {
                for (index in 0 until array.length()) {
                    val item = array.getJSONObject(index)
                    val body = item.getString("body")
                    require(body.isNotBlank() && body.length <= MAX_MESSAGE_CHARS) {
                        "Message local invalide."
                    }
                    val message = Message(
                        id = item.getString("id"),
                        peerDeviceId = peerDeviceId,
                        body = body,
                        outgoing = item.getBoolean("outgoing"),
                        createdAtEpochMs = item.getLong("createdAt")
                    )
                    require(runCatching { UUID.fromString(message.id) }.isSuccess) {
                        "Identifiant de message invalide."
                    }
                    add(message)
                }
            }
        } catch (failure: Exception) {
            throw SecurityException("Historique chiffré illisible ; refus de l'utiliser.", failure)
        } finally {
            bytes.fill(0)
        }
    }

    private fun write(peerDeviceId: String, messages: List<Message>) {
        val array = JSONArray()
        messages.forEach { message ->
            array.put(
                JSONObject()
                    .put("id", message.id)
                    .put("body", message.body)
                    .put("outgoing", message.outgoing)
                    .put("createdAt", message.createdAtEpochMs)
            )
        }
        val bytes = array.toString().toByteArray(Charsets.UTF_8)
        try {
            vault.put(recordId(peerDeviceId), bytes)
        } finally {
            bytes.fill(0)
        }
    }

    private fun recordId(peerDeviceId: String) = "chat_" + peerDeviceId.replace("-", "")

    private fun validatePeerId(peerDeviceId: String) {
        val uuid = runCatching { UUID.fromString(peerDeviceId) }.getOrNull()
        require(uuid != null && uuid.toString() == peerDeviceId) { "Identifiant de pair invalide." }
    }

    companion object {
        const val MAX_MESSAGE_CHARS = 4_096
        private const val MAX_MESSAGES = 500
    }
}
