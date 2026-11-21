package fr.aegis.android.security

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * Durable encrypted outbox for messages waiting for a direct P2P connection.
 *
 * Queue entries are encrypted at rest by EncryptedFileStore. Delivery is
 * at-least-once: a message is removed only after sendFrame returns. Receivers
 * must therefore deduplicate by message UUID (ConversationStore already does).
 * No background delivery is attempted; the queue drains when a peer reconnects.
 */
class OutboxStore(context: Context) {
    private val vault = EncryptedFileStore(context.applicationContext)

    data class PendingMessage(
        val id: String,
        val peerDeviceId: String,
        val body: String,
        val createdAtEpochMs: Long,
        val expiresAtEpochMs: Long?
    )

    @Synchronized
    fun enqueue(
        peerDeviceId: String,
        body: String,
        createdAtEpochMs: Long = System.currentTimeMillis(),
        expiresAtEpochMs: Long? = null,
        messageId: String = UUID.randomUUID().toString(),
        nowEpochMs: Long = System.currentTimeMillis()
    ): PendingMessage {
        validatePeerId(peerDeviceId)
        require(body.isNotBlank() && body.length <= ConversationStore.MAX_MESSAGE_CHARS) {
            "Message vide ou trop long."
        }
        require(createdAtEpochMs in 1L..(nowEpochMs + CLOCK_SKEW_MS)) {
            "Date de message invalide."
        }
        require(expiresAtEpochMs == null || expiresAtEpochMs > nowEpochMs) {
            "Ce message a déjà expiré."
        }
        require(expiresAtEpochMs == null || expiresAtEpochMs > createdAtEpochMs) {
            "Expiration de message invalide."
        }
        validateMessageId(messageId)

        val queue = read(peerDeviceId).filter { it.expiresAtEpochMs == null || it.expiresAtEpochMs > nowEpochMs }
            .toMutableList()
        queue.firstOrNull { it.id == messageId }?.let { return it }
        require(queue.size < MAX_PENDING_MESSAGES) { "File d'attente pleine (200 messages maximum)." }

        val pending = PendingMessage(messageId, peerDeviceId, body, createdAtEpochMs, expiresAtEpochMs)
        queue.add(pending)
        write(peerDeviceId, queue)
        return pending
    }

    @Synchronized
    fun list(peerDeviceId: String, nowEpochMs: Long = System.currentTimeMillis()): List<PendingMessage> {
        validatePeerId(peerDeviceId)
        val all = read(peerDeviceId)
        val active = all.filter { it.expiresAtEpochMs == null || it.expiresAtEpochMs > nowEpochMs }
        if (active.size != all.size) write(peerDeviceId, active)
        return active
    }

    /** Removes a message only after the transport has accepted its frame. */
    @Synchronized
    fun markSent(peerDeviceId: String, messageId: String): Boolean {
        validatePeerId(peerDeviceId)
        validateMessageId(messageId)
        val queue = read(peerDeviceId)
        val remaining = queue.filterNot { it.id == messageId }
        if (remaining.size == queue.size) return false
        if (remaining.isEmpty()) vault.delete(recordId(peerDeviceId))
        else write(peerDeviceId, remaining)
        return true
    }

    @Synchronized
    fun clear(peerDeviceId: String): Boolean {
        validatePeerId(peerDeviceId)
        return vault.delete(recordId(peerDeviceId))
    }

    private fun read(peerDeviceId: String): List<PendingMessage> {
        val bytes = vault.get(recordId(peerDeviceId)) ?: return emptyList()
        return try {
            val array = JSONArray(bytes.toString(Charsets.UTF_8))
            require(array.length() <= MAX_PENDING_MESSAGES) { "File d'attente chiffrée invalide." }
            buildList {
                for (index in 0 until array.length()) {
                    val item = array.getJSONObject(index)
                    val id = item.getString("id")
                    val body = item.getString("body")
                    val createdAt = item.getLong("createdAt")
                    val expiresAt = if (item.isNull("expiresAt")) null else item.getLong("expiresAt")
                    validateMessageId(id)
                    require(body.isNotBlank() && body.length <= ConversationStore.MAX_MESSAGE_CHARS)
                    require(createdAt > 0L && (expiresAt == null || expiresAt > createdAt))
                    add(PendingMessage(id, peerDeviceId, body, createdAt, expiresAt))
                }
            }
        } catch (failure: Exception) {
            throw SecurityException("File d'attente chiffrée illisible ; refus de l'utiliser.", failure)
        } finally {
            bytes.fill(0)
        }
    }

    private fun write(peerDeviceId: String, messages: List<PendingMessage>) {
        require(messages.size <= MAX_PENDING_MESSAGES)
        val array = JSONArray()
        messages.forEach { message ->
            array.put(
                JSONObject()
                    .put("id", message.id)
                    .put("body", message.body)
                    .put("createdAt", message.createdAtEpochMs)
                    .put("expiresAt", message.expiresAtEpochMs ?: JSONObject.NULL)
            )
        }
        val bytes = array.toString().toByteArray(Charsets.UTF_8)
        try {
            vault.put(recordId(peerDeviceId), bytes)
        } finally {
            bytes.fill(0)
        }
    }

    private fun recordId(peerDeviceId: String) = "outbox_" + peerDeviceId.replace("-", "")

    private fun validatePeerId(peerDeviceId: String) {
        require(runCatching { UUID.fromString(peerDeviceId).toString() == peerDeviceId }.getOrDefault(false)) {
            "Identifiant de pair invalide."
        }
    }

    private fun validateMessageId(messageId: String) {
        require(runCatching { UUID.fromString(messageId).toString() == messageId }.getOrDefault(false)) {
            "Identifiant de message invalide."
        }
    }

    companion object {
        const val MAX_PENDING_MESSAGES = 200
        private const val CLOCK_SKEW_MS = 30_000L
    }
}
