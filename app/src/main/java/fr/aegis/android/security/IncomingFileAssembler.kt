package fr.aegis.android.security

import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * Assembles strictly ordered bounded file chunks in memory.
 * Plaintext is not written to disk before the complete SHA-256 check succeeds.
 */
class IncomingFileAssembler {
    data class CompletedFile(
        val transferId: String,
        val fileName: String,
        val mimeType: String,
        val bytes: ByteArray,
        val sha256: ByteArray
    )

    private data class ActiveTransfer(
        val start: P2pFileTransferCodec.Packet.Start,
        val output: ByteArrayOutputStream,
        var nextChunkIndex: Int = 0
    )

    private var active: ActiveTransfer? = null

    @Synchronized
    fun accept(packet: P2pFileTransferCodec.Packet): CompletedFile? {
        return when (packet) {
            is P2pFileTransferCodec.Packet.Start -> {
                require(active == null) { "Un autre transfert de fichier est déjà en cours." }
                require(packet.size in 1..P2pFileTransferCodec.MAX_FILE_BYTES) {
                    "Taille de fichier non autorisée."
                }
                active = ActiveTransfer(packet, ByteArrayOutputStream())
                null
            }
            is P2pFileTransferCodec.Packet.Chunk -> {
                val current = active ?: throw IllegalStateException("Aucun transfert de fichier actif.")
                require(packet.transferId == current.start.transferId) { "Bloc lié à un autre transfert." }
                require(packet.index == current.nextChunkIndex) { "Bloc manquant, dupliqué ou désordonné." }
                require(current.output.size().toLong() + packet.data.size <= current.start.size) {
                    "Le fichier reçu dépasse la taille annoncée."
                }
                current.output.write(packet.data)
                packet.data.fill(0)
                current.nextChunkIndex += 1
                null
            }
            is P2pFileTransferCodec.Packet.Finish -> {
                val current = active ?: throw IllegalStateException("Aucun transfert de fichier actif.")
                require(packet.transferId == current.start.transferId) { "Fin liée à un autre transfert." }
                val bytes = current.output.toByteArray()
                val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
                val valid = bytes.size.toLong() == current.start.size &&
                    MessageDigest.isEqual(digest, packet.sha256)
                active = null
                current.output.reset()
                require(valid) { bytes.fill(0); digest.fill(0); "Fichier incomplet ou empreinte SHA-256 incorrecte." }
                CompletedFile(
                    current.start.transferId,
                    current.start.fileName,
                    current.start.mimeType,
                    bytes,
                    digest
                )
            }
        }
    }

    @Synchronized
    fun cancel() {
        active?.output?.reset()
        active = null
    }

    @Synchronized
    fun isReceiving(): Boolean = active != null
}
