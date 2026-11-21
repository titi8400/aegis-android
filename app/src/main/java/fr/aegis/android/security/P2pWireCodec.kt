package fr.aegis.android.security

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Base64
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
        val encodedBody = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(body.toByteArray(StandardCharsets.UTF_8))
        val expires = expiresAtEpochMs?.toString() ?: "-"
        return "$PREFIX|$VERSION|$id|$createdAtEpochMs|$expires|$encodedBody"
            .toByteArray(StandardCharsets.US_ASCII)
    }

    /** Returns null for an expired ephemeral message; malformed frames are rejected. */
    fun decodeText(frame: ByteArray, nowEpochMs: Long = System.currentTimeMillis()): TextMessage? {
        require(frame.isNotEmpty() && frame.size <= MAX_FRAME_BYTES) { "Trame AEGIS invalide." }
        val raw = String(frame, StandardCharsets.US_ASCII)
        val fields = raw.split('|', limit = 6)
        require(fields.size == 6 && fields[0] == PREFIX && fields[1] == VERSION) {
            "Version ou format de message AEGIS non pris en charge."
        }
        val id = fields[2]
        validateUuid(id)
        val createdAt = fields[3].toLongOrNull()
            ?: throw IllegalArgumentException("Date de message invalide.")
        require(createdAt in 1L..(nowEpochMs + CLOCK_SKEW_MS)) { "Date de message invalide." }
        val expiresAt = if (fields[4] == "-") null else fields[4].toLongOrNull()
            ?: throw IllegalArgumentException("Expiration de message invalide.")
        require(expiresAt == null || expiresAt > createdAt) { "Expiration de message invalide." }
        if (expiresAt != null) {
            require(expiresAt - createdAt <= MAX_TTL_MS) { "Durée de conservation excessive." }
            if (expiresAt <= nowEpochMs) return null
        }
        val bodyBytes = Base64.getUrlDecoder().decode(fields[5])
        require(bodyBytes.isNotEmpty() && bodyBytes.size <= MAX_BODY_BYTES) {
            "Contenu de message trop volumineux."
        }
        val body = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bodyBytes))
                .toString()
        } finally {
            bodyBytes.fill(0)
        }
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

    private const val PREFIX = "AEGIS-TEXT"
    private const val VERSION = "1"
    private const val MAX_BODY_CHARS = 4_096
    private const val MAX_BODY_BYTES = 16 * 1024
    private const val MAX_FRAME_BYTES = 32 * 1024
    private const val CLOCK_SKEW_MS = 30_000L
    private const val MAX_TTL_MS = 30L * 24L * 60L * 60L * 1000L
}
