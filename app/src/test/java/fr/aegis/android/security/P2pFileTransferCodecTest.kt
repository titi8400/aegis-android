package fr.aegis.android.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import java.security.MessageDigest
import java.util.UUID

class P2pFileTransferCodecTest {
    private val transferId = UUID.fromString("9e7c7c4a-0b7a-49b2-9f40-2b57b5f48f12").toString()

    @Test
    fun roundTripsStartMetadata() {
        val start = P2pFileTransferCodec.Packet.Start(
            transferId,
            "photo été.jpg",
            "image/jpeg",
            1234L
        )
        val decoded = P2pFileTransferCodec.decode(P2pFileTransferCodec.encodeStart(start))
        require(decoded is P2pFileTransferCodec.Packet.Start)
        assertEquals(start.transferId, decoded.transferId)
        assertEquals(start.fileName, decoded.fileName)
        assertEquals(start.mimeType, decoded.mimeType)
        assertEquals(start.size, decoded.size)
    }

    @Test
    fun assemblesChunksAndVerifiesSha256() {
        val bytes = "AEGIS file transfer test".toByteArray()
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        val assembler = IncomingFileAssembler()
        assertNull(assembler.accept(P2pFileTransferCodec.decode(
            P2pFileTransferCodec.encodeStart(
                P2pFileTransferCodec.Packet.Start(transferId, "test.txt", "text/plain", bytes.size.toLong())
            )
        )))
        val chunk = P2pFileTransferCodec.decode(P2pFileTransferCodec.encodeChunk(transferId, 0, bytes))
        assertNull(assembler.accept(chunk))
        val completed = assembler.accept(
            P2pFileTransferCodec.decode(P2pFileTransferCodec.encodeFinish(transferId, digest))
        )
        requireNotNull(completed)
        assertArrayEquals(bytes, completed.bytes)
        assertArrayEquals(digest, completed.sha256)
    }

    @Test
    fun rejectsOutOfOrderChunks() {
        val assembler = IncomingFileAssembler()
        assembler.accept(P2pFileTransferCodec.Packet.Start(transferId, "x.bin", "application/octet-stream", 2))
        assertThrows(IllegalArgumentException::class.java) {
            assembler.accept(P2pFileTransferCodec.Packet.Chunk(transferId, 1, byteArrayOf(1)))
        }
    }

    @Test
    fun rejectsFileWithIncorrectDigest() {
        val assembler = IncomingFileAssembler()
        assembler.accept(P2pFileTransferCodec.Packet.Start(transferId, "x.bin", "application/octet-stream", 1))
        assembler.accept(P2pFileTransferCodec.Packet.Chunk(transferId, 0, byteArrayOf(1)))
        assertThrows(IllegalArgumentException::class.java) {
            assembler.accept(P2pFileTransferCodec.Packet.Finish(transferId, ByteArray(32)))
        }
    }

    @Test
    fun stripsPathComponentsFromFileNames() {
        assertEquals("photo.jpg", P2pFileTransferCodec.sanitizeFileName("../../photo.jpg"))
    }
}
