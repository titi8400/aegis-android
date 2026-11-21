package fr.aegis.android.security

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PairingHandshakeCodecTest {
    @Test
    fun completesMutualSignedChallengeResponse() {
        val now = System.currentTimeMillis()
        val inviter = TestSigningIdentity()
        val challenger = TestSigningIdentity()
        val inviteText = PairingInviteCodec.create(inviter, nowEpochMs = now)
        val invite = PairingInviteCodec.verify(inviteText, nowEpochMs = now)

        val challengeText = PairingHandshakeCodec.createChallenge(
            invite, challenger, nowEpochMs = now
        )
        val challenge = PairingHandshakeCodec.verifyChallenge(
            challengeText, invite, nowEpochMs = now
        )
        val response = PairingHandshakeCodec.createResponsePackage(
            challenge, invite, inviter
        )
        val verified = PairingHandshakeCodec.verifyResponse(
            response.encoded, challenge, invite, nowEpochMs = now
        )

        assertArrayEquals(challenger.publicKeyEncoded(), verified.challengerPublicKey)
        assertArrayEquals(inviter.publicKeyEncoded(), verified.responderPublicKey)
        assertEquals(PairingInviteCodec.fingerprint(inviter.publicKeyEncoded()), verified.responderFingerprint)
        assertEquals(64, verified.transcriptSha256.length)
        assertEquals(verified.transcriptSha256, response.proof.transcriptSha256)
    }

    @Test
    fun rejectsModifiedChallenge() {
        val now = System.currentTimeMillis()
        val inviter = TestSigningIdentity()
        val challenger = TestSigningIdentity()
        val invite = PairingInviteCodec.verify(
            PairingInviteCodec.create(inviter, nowEpochMs = now), nowEpochMs = now
        )
        val challenge = PairingHandshakeCodec.createChallenge(invite, challenger, nowEpochMs = now)
        val modified = challenge.replaceFirst("AEGIS-CHALLENGE", "AEGIS-CHALLENGX")
        assertThrows(IllegalArgumentException::class.java) {
            PairingHandshakeCodec.verifyChallenge(modified, invite, nowEpochMs = now)
        }
    }

    @Test
    fun rejectsModifiedResponseSignature() {
        val now = System.currentTimeMillis()
        val inviter = TestSigningIdentity()
        val challenger = TestSigningIdentity()
        val invite = PairingInviteCodec.verify(
            PairingInviteCodec.create(inviter, nowEpochMs = now), nowEpochMs = now
        )
        val challenge = PairingHandshakeCodec.verifyChallenge(
            PairingHandshakeCodec.createChallenge(invite, challenger, nowEpochMs = now),
            invite,
            nowEpochMs = now
        )
        val response = PairingHandshakeCodec.createResponse(challenge, invite, inviter)
        val fields = response.split('|').toMutableList()
        val signature = fields.last()
        fields[fields.lastIndex] = if (signature[0] == 'A') "B" + signature.drop(1)
            else "A" + signature.drop(1)
        assertThrows(IllegalArgumentException::class.java) {
            PairingHandshakeCodec.verifyResponse(fields.joinToString("|"), challenge, invite, nowEpochMs = now)
        }
    }

    private class TestSigningIdentity : SigningIdentity {
        private val pair: KeyPair = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }

        override fun exists() = true
        override fun publicKeyEncoded() = pair.public.encoded
        override fun sign(data: ByteArray): ByteArray =
            Signature.getInstance("SHA256withECDSA").run {
                initSign(pair.private)
                update(data)
                sign()
            }
    }
}
