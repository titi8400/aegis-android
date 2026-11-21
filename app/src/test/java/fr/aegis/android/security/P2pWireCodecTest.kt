package fr.aegis.android.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.UUID

class P2pWireCodecTest {
    private val id = UUID.fromString("d9f90a2d-12b5-4f17-8e10-7c1f6d8a3b20").toString()
    private val now = 1_000_000L

    @Test
    fun roundTripsPermanentUnicodeText() {
        val encoded = P2pWireCodec.encodeText("Bonjour, été !", now, null, id)
        val decoded = P2pWireCodec.decodeText(encoded, now)
        requireNotNull(decoded)
        assertEquals(id, decoded.id)
        assertEquals("Bonjour, été !", decoded.body)
        assertNull(decoded.expiresAtEpochMs)
    }

    @Test
    fun roundTripsEphemeralMessage() {
        val encoded = P2pWireCodec.encodeText("secret temporaire", now, now + 60_000L, id)
        val decoded = P2pWireCodec.decodeText(encoded, now + 1_000L)
        requireNotNull(decoded)
        assertEquals(now + 60_000L, decoded.expiresAtEpochMs)
    }

    @Test
    fun silentlyDiscardsExpiredMessage() {
        val encoded = P2pWireCodec.encodeText("expiré", now, now + 1_000L, id)
        assertNull(P2pWireCodec.decodeText(encoded, now + 1_000L))
    }

    @Test
    fun deliveryAcknowledgementRoundTrips() {
        val decoded = P2pWireCodec.decodeAck(P2pWireCodec.encodeAck(id))
        assertEquals(id, decoded)
    }

    @Test
    fun rejectsMalformedDeliveryAcknowledgement() {
        assertThrows(IllegalArgumentException::class.java) {
            P2pWireCodec.decodeAck("AEGIS-ACK|1|not-a-uuid".toByteArray(Charsets.US_ASCII))
        }
    }

    @Test
    fun rejectsUnsupportedVersion() {
        val encoded = P2pWireCodec.encodeText("test", now, null, id)
            .toString(Charsets.US_ASCII)
            .replace("|1|", "|99|")
            .toByteArray(Charsets.US_ASCII)
        assertThrows(IllegalArgumentException::class.java) {
            P2pWireCodec.decodeText(encoded, now)
        }
    }

    @Test
    fun rejectsExcessiveExpiryWindow() {
        val encoded = P2pWireCodec.encodeText("test", now, now + 31L * 24L * 60L * 60L * 1000L, id)
        assertThrows(IllegalArgumentException::class.java) {
            P2pWireCodec.decodeText(encoded, now)
        }
    }
}
