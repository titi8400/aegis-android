package fr.aegis.android.security

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.UUID

/** Binary, bounded file-transfer packets carried inside the authenticated TLS session. */
object P2pFileTransferCodec {
    sealed interface Packet {
        val transferId: String
        data class Start(
            override val transferId: String,
            val fileName: String,
            val mimeType: String,
            val size: Long
        ) : Packet
        data class Chunk(
            override val transferId: String,
            val index: Int,
            val data: ByteArray
        ) : Packet
        data class Finish(
            override val transferId: String,
            val sha256: ByteArray
        ) : Packet
    }

    fun encodeStart(packet: Packet.Start): ByteArray {
        validateUuid(packet.transferId)
        val name = sanitizeFileName(packet.fileName).toByteArray(StandardCharsets.UTF_8)
        val mime = packet.mimeType.take(MAX_MIME_CHARS).toByteArray(StandardCharsets.US_ASCII)
        require(packet.size in 1..MAX_FILE_BYTES) { "Taille de fichier non autorisée." }
        require(name.isNotEmpty() && name.size <= MAX_NAME_BYTES) { "Nom de fichier invalide." }
        require(mime.isNotEmpty() && mime.size <= MAX_MIME_BYTES && mime.all { it.toInt() in 0x21..0x7E }) {
            "Type MIME invalide."
        }
        return header(TYPE_START, packet.transferId, 8 + 2 + 2 + name.size + mime.size)
            .putLong(packet.size)
            .putShort(name.size.toShort())
            .putShort(mime.size.toShort())
            .put(name)
            .put(mime)
            .array()
    }

    fun encodeChunk(transferId: String, index: Int, data: ByteArray): ByteArray {
        validateUuid(transferId)
        require(index >= 0) { "Index de bloc invalide." }
        require(data.isNotEmpty() && data.size <= CHUNK_BYTES) { "Taille de bloc invalide." }
        return header(TYPE_CHUNK, transferId, 4 + 4 + data.size)
            .putInt(index)
            .putInt(data.size)
            .put(data)
            .array()
    }

    fun encodeFinish(transferId: String, sha256: ByteArray): ByteArray {
        validateUuid(transferId)
        require(sha256.size == SHA256_BYTES) { "Empreinte de fichier invalide." }
        return header(TYPE_FINISH, transferId, SHA256_BYTES).put(sha256).array()
    }

    fun isFilePacket(frame: ByteArray): Boolean =
        frame.size >= HEADER_BYTES &&
            frame.copyOfRange(0, MAGIC.size).contentEquals(MAGIC) &&
            frame[5] == VERSION &&
            frame[6].toInt() in TYPE_START..TYPE_FINISH

    fun decode(frame: ByteArray): Packet {
        require(frame.size in HEADER_BYTES..MAX_PACKET_BYTES && isFilePacket(frame)) {
            "Trame de transfert AEGIS invalide."
        }
        val buffer = ByteBuffer.wrap(frame).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(MAGIC.size)
        buffer.get(magic)
        require(magic.contentEquals(MAGIC) && buffer.get() == VERSION) { "Version de transfert inconnue." }
        val type = buffer.get().toInt()
        val transferId = ByteArray(UUID_BYTES).also(buffer::get).toUuid()
        return when (type) {
            TYPE_START -> {
                require(buffer.remaining() >= 12) { "Métadonnées de fichier incomplètes." }
                val size = buffer.long
                val nameLength = buffer.short.toInt() and 0xFFFF
                val mimeLength = buffer.short.toInt() and 0xFFFF
                require(size in 1..MAX_FILE_BYTES && nameLength in 1..MAX_NAME_BYTES && mimeLength in 1..MAX_MIME_BYTES) {
                    "Métadonnées de fichier invalides."
                }
                require(buffer.remaining() == nameLength + mimeLength) { "Longueur de métadonnées incohérente." }
                val nameBytes = ByteArray(nameLength).also(buffer::get)
                val mimeBytes = ByteArray(mimeLength).also(buffer::get)
                val name = strictUtf8(nameBytes)
                val mime = String(mimeBytes, StandardCharsets.US_ASCII)
                require(sanitizeFileName(name) == name) { "Nom de fichier non autorisé." }
                require(mime.all { it.code in 0x21..0x7E }) { "Type MIME invalide." }
                Packet.Start(transferId, name, mime, size)
            }
            TYPE_CHUNK -> {
                require(buffer.remaining() >= 8) { "Bloc de fichier incomplet." }
                val index = buffer.int
                val length = buffer.int
                require(index >= 0 && length in 1..CHUNK_BYTES && buffer.remaining() == length) {
                    "Bloc de fichier invalide."
                }
                Packet.Chunk(transferId, index, ByteArray(length).also(buffer::get))
            }
            TYPE_FINISH -> {
                require(buffer.remaining() == SHA256_BYTES) { "Fin de transfert invalide." }
                Packet.Finish(transferId, ByteArray(SHA256_BYTES).also(buffer::get))
            }
            else -> throw IllegalArgumentException("Type de transfert inconnu.")
        }
    }

    fun sanitizeFileName(value: String): String {
        val leaf = value.substringAfterLast('/').substringAfterLast('\\')
            .replace(Regex("[\\u0000-\\u001F\\u007F]"), "")
            .replace(Regex("[<>:\"/\\\\|?*]"), "_")
            .trim()
            .take(MAX_NAME_CHARS)
        return leaf.ifBlank { "fichier-aegis" }
    }

    private fun header(type: Byte, transferId: String, payloadLength: Int): ByteBuffer {
        validateUuid(transferId)
        require(payloadLength in 0..MAX_PACKET_BYTES) { "Trame trop volumineuse." }
        val id = UUID.fromString(transferId)
        return ByteBuffer.allocate(HEADER_BYTES + UUID_BYTES + payloadLength)
            .order(ByteOrder.BIG_ENDIAN)
            .put(MAGIC)
            .put(VERSION)
            .put(type)
            .putLong(id.mostSignificantBits)
            .putLong(id.leastSignificantBits)
    }

    private fun ByteArray.toUuid(): String {
        val buffer = ByteBuffer.wrap(this).order(ByteOrder.BIG_ENDIAN)
        return UUID(buffer.long, buffer.long).toString()
    }

    private fun strictUtf8(bytes: ByteArray): String =
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()

    private fun validateUuid(value: String) {
        require(runCatching { UUID.fromString(value).toString() == value }.getOrDefault(false)) {
            "Identifiant de transfert invalide."
        }
    }

    private const val VERSION: Byte = 1
    private const val TYPE_START = 1
    private const val TYPE_CHUNK = 2
    private const val TYPE_FINISH = 3
    private const val UUID_BYTES = 16
    private const val HEADER_BYTES = 7
    const val CHUNK_BYTES = 512 * 1024
    const val MAX_FILE_BYTES = 20L * 1024L * 1024L
    const val MAX_PACKET_BYTES = 1_048_576
    private const val MAX_NAME_CHARS = 100
    private const val MAX_NAME_BYTES = 255
    private const val MAX_MIME_CHARS = 100
    private const val MAX_MIME_BYTES = 127
    private const val SHA256_BYTES = 32
    private val MAGIC = "AEGIS".toByteArray(StandardCharsets.US_ASCII)
}
