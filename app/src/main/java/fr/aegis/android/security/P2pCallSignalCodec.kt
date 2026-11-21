package fr.aegis.android.security

import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.UUID

/** Bounded signaling envelope carried only inside the authenticated TLS peer session. */
object P2pCallSignalCodec {
    sealed interface Signal {
        val callId: String
        data class Offer(override val callId: String, val sdp: String) : Signal
        data class Answer(override val callId: String, val sdp: String) : Signal
        data class Candidate(
            override val callId: String,
            val sdpMid: String?,
            val sdpMLineIndex: Int,
            val candidate: String
        ) : Signal
        data class Hangup(override val callId: String) : Signal
    }

    fun isCallFrame(frame: ByteArray): Boolean =
        frame.size in 1..MAX_FRAME_BYTES &&
            frame.toString(StandardCharsets.US_ASCII).startsWith("$PREFIX|")

    fun encode(signal: Signal): ByteArray {
        validateCallId(signal.callId)
        val fields = when (signal) {
            is Signal.Offer -> listOf(PREFIX, VERSION, "OFFER", signal.callId, encodeText(signal.sdp))
            is Signal.Answer -> listOf(PREFIX, VERSION, "ANSWER", signal.callId, encodeText(signal.sdp))
            is Signal.Candidate -> listOf(
                PREFIX, VERSION, "ICE", signal.callId,
                signal.sdpMid?.let(::encodeText) ?: "-",
                signal.sdpMLineIndex.toString(),
                encodeText(signal.candidate)
            )
            is Signal.Hangup -> listOf(PREFIX, VERSION, "HANGUP", signal.callId)
        }
        return fields.joinToString("|").toByteArray(StandardCharsets.US_ASCII).also {
            require(it.size <= MAX_FRAME_BYTES) { "Signalisation d'appel trop volumineuse." }
        }
    }

    fun decode(frame: ByteArray): Signal {
        require(frame.isNotEmpty() && frame.size <= MAX_FRAME_BYTES) { "Trame d'appel invalide." }
        val fields = frame.toString(StandardCharsets.US_ASCII).split('|')
        require(fields.size >= 4 && fields[0] == PREFIX && fields[1] == VERSION) {
            "Format de signalisation AEGIS invalide."
        }
        val callId = fields[3]
        validateCallId(callId)
        return when (fields[2]) {
            "OFFER" -> {
                require(fields.size == 5) { "Offre SDP invalide." }
                Signal.Offer(callId, decodeText(fields[4]))
            }
            "ANSWER" -> {
                require(fields.size == 5) { "Réponse SDP invalide." }
                Signal.Answer(callId, decodeText(fields[4]))
            }
            "ICE" -> {
                require(fields.size == 7) { "Candidat ICE invalide." }
                val mid = if (fields[4] == "-") null else decodeText(fields[4])
                val line = fields[5].toIntOrNull()?.takeIf { it >= 0 }
                    ?: throw IllegalArgumentException("Index ICE invalide.")
                Signal.Candidate(callId, mid, line, decodeText(fields[6]))
            }
            "HANGUP" -> {
                require(fields.size == 4) { "Fin d'appel invalide." }
                Signal.Hangup(callId)
            }
            else -> throw IllegalArgumentException("Signal d'appel inconnu.")
        }
    }

    private fun encodeText(value: String): String {
        require(value.isNotEmpty() && value.length <= MAX_SDP_CHARS) { "Donnée de signalisation invalide." }
        return Base64.getUrlEncoder().withoutPadding()
            .encodeToString(value.toByteArray(StandardCharsets.UTF_8))
    }

    private fun decodeText(value: String): String {
        val bytes = Base64.getUrlDecoder().decode(value)
        require(bytes.isNotEmpty() && bytes.size <= MAX_SDP_BYTES) { "Donnée SDP trop volumineuse." }
        return try {
            String(bytes, StandardCharsets.UTF_8)
        } finally {
            bytes.fill(0)
        }
    }

    private fun validateCallId(value: String) {
        require(runCatching { UUID.fromString(value).toString() == value }.getOrDefault(false)) {
            "Identifiant d'appel invalide."
        }
    }

    private const val PREFIX = "AEGIS-CALL"
    private const val VERSION = "1"
    private const val MAX_SDP_CHARS = 180_000
    private const val MAX_SDP_BYTES = 180 * 1024
    const val MAX_FRAME_BYTES = 256 * 1024
}
