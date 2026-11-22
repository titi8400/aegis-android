package fr.aegis.android.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class RecoveryArchiveCodecTest {
    @Test fun roundTripPreservesAllowedRecords() {
        val records = listOf(
            RecoveryArchiveCodec.Record("chat_0123456789abcdef", byteArrayOf(1, 2, 3)),
            RecoveryArchiveCodec.Record("received_0123456789abcdef", byteArrayOf(4, 5, 6, 7))
        )
        val decoded = RecoveryArchiveCodec.decode(RecoveryArchiveCodec.encode(records))
        assertEquals(records.map { it.id }, decoded.map { it.id })
        records.indices.forEach { assertArrayEquals(records[it].bytes, decoded[it].bytes) }
    }

    @Test fun rejectsIdentityAndTrustRecords() {
        assertThrows(IllegalArgumentException::class.java) {
            RecoveryArchiveCodec.encode(listOf(RecoveryArchiveCodec.Record("trusted_peers_v1", byteArrayOf(1))))
        }
    }

    @Test fun rejectsDuplicateRecords() {
        assertThrows(IllegalArgumentException::class.java) {
            RecoveryArchiveCodec.encode(listOf(
                RecoveryArchiveCodec.Record("chat_a", byteArrayOf(1)),
                RecoveryArchiveCodec.Record("chat_a", byteArrayOf(2))
            ))
        }
    }

    @Test fun rejectsTrailingData() {
        val encoded = RecoveryArchiveCodec.encode(listOf(RecoveryArchiveCodec.Record("chat_a", byteArrayOf(1))))
        assertThrows(IllegalArgumentException::class.java) {
            RecoveryArchiveCodec.decode(encoded + byteArrayOf(9))
        }
    }
}
