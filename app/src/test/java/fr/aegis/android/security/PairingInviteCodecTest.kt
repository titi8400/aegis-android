package fr.aegis.android.security

import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PairingInviteCodecTest {
    @Test
    fun verifiesValidP256Invitation() {
        val encoded = signedInvite("secp256r1", 10_000L, 310_000L)
        val verified = PairingInviteCodec.verify(encoded, nowEpochMs = 10_000L)
        assertEquals(64, verified.fingerprintSha256.length)
        assertEquals(32, verified.nonce.size)
    }

    @Test
    fun rejectsTamperedInvitation() {
        val encoded = signedInvite("secp256r1", 10_000L, 310_000L)
        val fields = encoded.split('|').toMutableList()
        fields[5] = if (fields[5][0] == 'A') "B" + fields[5].drop(1)
            else "A" + fields[5].drop(1)
        assertThrows(IllegalArgumentException::class.java) {
            PairingInviteCodec.verify(fields.joinToString("|"), nowEpochMs = 10_000L)
        }
    }

    @Test
    fun rejectsNonP256IdentityKey() {
        val encoded = signedInvite("secp384r1", 10_000L, 310_000L)
        assertThrows(IllegalArgumentException::class.java) {
            PairingInviteCodec.verify(encoded, nowEpochMs = 10_000L)
        }
    }

    @Test
    fun rejectsExpiredInvitation() {
        val encoded = signedInvite("secp256r1", 10_000L, 310_000L)
        assertThrows(IllegalArgumentException::class.java) {
            PairingInviteCodec.verify(encoded, nowEpochMs = 310_001L)
        }
    }

    @Test
    fun deviceIdIsStableForTheSamePublicIdentity() {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val publicKey = generator.generateKeyPair().public.encoded
        assertEquals(
            PairingInviteCodec.deviceIdForPublicKey(publicKey),
            PairingInviteCodec.deviceIdForPublicKey(publicKey)
        )
    }

    @Test
    fun rejectsInvitationWithExcessiveLifetime() {
        val encoded = signedInvite("secp256r1", 10_000L, 400_000L)
        assertThrows(IllegalArgumentException::class.java) {
            PairingInviteCodec.verify(encoded, nowEpochMs = 10_000L)
        }
    }

    private fun signedInvite(curve: String, createdAt: Long, expiresAt: Long): String {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec(curve))
        val keyPair = generator.generateKeyPair()
        val deviceId = UUID.randomUUID().toString()
        val nonce = ByteArray(32) { 7 }
        val encoder = Base64.getUrlEncoder().withoutPadding()
        val nonceText = encoder.encodeToString(nonce)
        val publicKeyText = encoder.encodeToString(keyPair.public.encoded)
        val unsigned = listOf(
            "AEGIS-PAIR", "1", deviceId, createdAt.toString(),
            expiresAt.toString(), nonceText, publicKeyText
        ).joinToString("|").toByteArray(StandardCharsets.UTF_8)
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(keyPair.private)
            update(unsigned)
            sign()
        }
        return listOf(
            "AEGIS-PAIR", "1", deviceId, createdAt.toString(),
            expiresAt.toString(), nonceText, publicKeyText,
            encoder.encodeToString(signature)
        ).joinToString("|")
    }
}
