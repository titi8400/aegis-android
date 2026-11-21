package fr.aegis.android.security

import org.json.JSONObject
import java.util.UUID

/** Versioned application-message envelope carried inside the authenticated TLS stream. */
object P2pWireCodec {
    data class TextMessage(
        val id: String,
        val body: String,
        val createdAtEpochMs: Long,
        val expiresAtEpochMs: Long?
    )

    fun encodeText(
        body: String,
        createdAtEpochMs: Long = System.currentTimeMillis(),
        expiresAtEpochMs: Long? = null,
        id: String = UUID.randomUUID().toString()
    ): ByteArray {
        validateBody(body)
        validateUuid(id)
        require(createdAtEpochMs > 0L) { "Date de message invalide." }
        require(expiresAtEpochMs == null || expiresAtEpochMs > createdAtEpochMs) {
            "Expiration de message invalide."
        }
        return JSONObject()
            .put("magic", MAGIC)
            .put("version", VERSION)
            .put("type", TYPE_TEXT)
            .put("id", id)
            .put("createdAt", createdAtEpochMs)
            .put("expiresAt", expiresAtEpochMs ?: JSONObject.NULL)
            .put("body", body)
            .toString()
            .toByteArray(Charsets.UTF_8)
    }

    fun decodeText(frame: ByteArray, nowEpochMs: Long = System.currentTimeMillis()): TextMessage? {
        require(frame.isNotEmpty() && frame.size <= MAX_FRAME_BYTES) { "Trame AEGIS invalide." }
        val json = JSONObject(frame.toString(Charsets.UTF_8))
        require(json.getString("magic") == MAGIC && json.getInt("version") == VERSION) {
            "Version de message AEGIS non prise en charge."
        }
        require(json.getString("type") == TYPE_TEXT) { "Type de message non pris en charge." }
        val id = json.getString("id")
        validateUuid(id)
        val createdAt = json.getLong("createdAt")
        require(createdAt in 1L..(nowEpochMs + CLOCK_SKEW_MS)) { "Date de message invalide." }
        val expiresAt = if (json.isNull("expiresAt")) null else json.getLong("expiresAt")
        require(expiresAt == null || expiresAt > createdAt) { "Expiration de message invalide." }
        if (expiresAt != null) {
            require(expiresAt - createdAt <= MAX_TTL_MS) { "Durée de conservation excessive." }
            if (expiresAt <= nowEpochMs) return null
        }
        val body = json.getString("body")
        validateBody(body)
        return TextMessage(id, body, createdAt, expiresAt)
    }

    private fun validateBody(body: String) {
        require(body.isNotBlank() && body.length <= MAX_BODY_CHARS) {
            "Message vide ou trop long."
        }
    }

    private fun validateUuid(id: String) {
        require(runCatching { UUID.fromString(id).toString() == id }.getOrDefault(false)) {
            "Identifiant de message invalide."
        }
    }

    private const val MAGIC = "AEGIS"
    private const val VERSION = 1
    private const val TYPE_TEXT = "text"
    private const val MAX_BODY_CHARS = 4_096
    private const val MAX_FRAME_BYTES = 32 * 1024
    private const val CLOCK_SKEW_MS = 30_000L
    private const val MAX_TTL_MS = 30L * 24L * 60L * 60L * 1000L
}
