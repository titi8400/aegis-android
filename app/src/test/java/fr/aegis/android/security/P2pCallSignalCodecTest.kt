package fr.aegis.android.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class P2pCallSignalCodecTest {
    private val callId = UUID.fromString("28d21f51-5f28-4a54-8a82-b4a73e1f8b9e").toString()

    @Test
    fun roundTripsOfferAndAnswer() {
        val offer = P2pCallSignalCodec.Signal.Offer(callId, "v=0\r\no=- 123 2 IN IP4 127.0.0.1")
        val decodedOffer = P2pCallSignalCodec.decode(P2pCallSignalCodec.encode(offer))
        assertTrue(decodedOffer is P2pCallSignalCodec.Signal.Offer)
        assertEquals(offer, decodedOffer)

        val answer = P2pCallSignalCodec.Signal.Answer(callId, "v=0\r\no=- 456 2 IN IP4 127.0.0.1")
        val decodedAnswer = P2pCallSignalCodec.decode(P2pCallSignalCodec.encode(answer))
        assertEquals(answer, decodedAnswer)
    }

    @Test
    fun roundTripsIceCandidateAndHangup() {
        val candidate = P2pCallSignalCodec.Signal.Candidate(
            callId,
            "video",
            0,
            "candidate:1 1 UDP 2122260223 192.168.1.10 50000 typ host"
        )
        assertEquals(candidate, P2pCallSignalCodec.decode(P2pCallSignalCodec.encode(candidate)))
        val hangup = P2pCallSignalCodec.Signal.Hangup(callId)
        assertEquals(hangup, P2pCallSignalCodec.decode(P2pCallSignalCodec.encode(hangup)))
    }
}
