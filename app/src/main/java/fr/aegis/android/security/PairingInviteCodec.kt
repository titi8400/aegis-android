package fr.aegis.android.security

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.UUID

/**
 * Signed, short-lived device invitation intended to be encoded in a QR code.
 *
 * The QR contains only public identity material and a signed one-time invitation
 * nonce. It never contains a private key or secret. The receiver must verify the
 * signature and the user must compare the full SHA-256 fingerprint through a
 * trusted independent channel before trusting the identity.
 *
 * This is an invitation format, not yet a complete mutual-authentication,
 * replay-protected pairing protocol. A nonce must be consumed and the peer must
 * prove possession of its private key in a subsequent challenge-response step.
 */
object PairingInviteCodec {
    private const val PREFIX = "AEGIS-PAIR"
    private const val VERSION = "1"
    private const val MAX_LIFETIME_MS = 5 * 60 * 1000L
    private const val CLOCK_SKEW_MS = 30_000L
    private const val NONCE_BYTES = 32
    private const val MAX_PUBLIC_KEY_BYTES = 1024
    private const val MAX_SIGNATURE_BYTES = 256

    data class Invite(
        val deviceId: String,
        val createdAtEpochMs: Long,
        val expiresAtEpochMs: Long,
        val nonce: ByteArray,
        val publicKeyEncoded: ByteArray,
        val signature: ByteArray
    )

    data class VerifiedInvite(
        val deviceId: String,
        val createdAtEpochMs: Long,
        val expiresAtEpochMs: Long,
        val nonce: ByteArray,
        val publicKeyEncoded: ByteArray,
        val fingerprintSha256: String
    )

    fun create(
        identity: SigningIdentity,
        nowEpochMs: Long = System.currentTimeMillis(),
        nonce: ByteArray = randomNonce()
    ): String {
        require(identity.exists()) { "Identité AEGIS non initialisée" }
        require(nonce.size == NONCE_BYTES) { "Nonce invalide" }

        val deviceId = deviceIdForPublicKey(publicKey)
        val expiresAt = Math.addExact(nowEpochMs, MAX_LIFETIME_MS)
        val publicKey = identity.publicKeyEncoded()
        val unsigned = canonical(deviceId, nowEpochMs, expiresAt, nonce, publicKey)
        val signature = identity.sign(unsigned)
        return listOf(
            PREFIX,
            VERSION,
            deviceId,
            nowEpochMs.toString(),
            expiresAt.toString(),
            encode(nonce),
            encode(publicKey),
            encode(signature)
        ).joinToString("|")
    }

    fun verify(
        encodedInvite: String,
        nowEpochMs: Long = System.currentTimeMillis()
    ): VerifiedInvite {
        require(encodedInvite.length <= 4096) { "Invitation trop volumineuse" }
        val fields = encodedInvite.split('|')
        require(fields.size == 8 && fields[0] == PREFIX && fields[1] == VERSION) {
            "Format d'invitation AEGIS invalide"
        }

        val deviceId = fields[2]
        require(runCatching { UUID.fromString(deviceId).toString() == deviceId }.getOrDefault(false)) {
            "Identifiant d'appareil invalide"
        }
        val createdAt = fields[3].toLongOrNull() ?: error("Date d'invitation invalide")
        val expiresAt = fields[4].toLongOrNull() ?: error("Expiration invalide")
        require(expiresAt > createdAt && expiresAt - createdAt <= MAX_LIFETIME_MS) {
            "Durée de validité de l'invitation invalide"
        }
        require(createdAt <= nowEpochMs + CLOCK_SKEW_MS) { "Invitation datée dans le futur" }
        require(nowEpochMs <= expiresAt) { "Invitation expirée" }

        val nonce = decode(fields[5], NONCE_BYTES)
        val publicKey = decode(fields[6], MAX_PUBLIC_KEY_BYTES)
        val signature = decode(fields[7], MAX_SIGNATURE_BYTES)
        val unsigned = canonical(deviceId, createdAt, expiresAt, nonce, publicKey)

        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(publicKey))
        require(key is ECPublicKey) { "La clé d’identité doit être une clé EC" }
        require(key.params.curve.field.fieldSize == 256 && key.params.order.bitLength() == 256) { "La clé d’identité doit utiliser la courbe NIST P-256" }
        require(signature.size in 8..MAX_SIGNATURE_BYTES) { "Signature invalide" }
        val valid = Signature.getInstance("SHA256withECDSA").run {
            initVerify(key)
            update(unsigned)
            verify(signature)
        }
        require(valid) { "Signature de l'invitation invalide" }

        return VerifiedInvite(
            deviceId = deviceId,
            createdAtEpochMs = createdAt,
            expiresAtEpochMs = expiresAt,
            nonce = nonce,
            publicKeyEncoded = publicKey,
            fingerprintSha256 = fingerprint(publicKey)
        )
    }

    /** Stable device identifier derived from the public identity key (UUIDv8 layout). */
    fun deviceIdForPublicKey(publicKeyEncoded: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(publicKeyEncoded)
        val buffer = ByteBuffer.wrap(digest)
        val most = (buffer.long and 0xffffffffffff0fffUL.toLong()) or 0x0000000000008000L
        val least = (buffer.long and 0x3fffffffffffffffL) or Long.MIN_VALUE
        digest.fill(0)
        return UUID(most, least).toString()
    }

    fun fingerprint(publicKeyEncoded: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(publicKeyEncoded)
            .joinToString("") { "%02X".format(it) }

    private fun canonical(
        deviceId: String,
        createdAt: Long,
        expiresAt: Long,
        nonce: ByteArray,
        publicKey: ByteArray
    ): ByteArray = listOf(
        PREFIX,
        VERSION,
        deviceId,
        createdAt.toString(),
        expiresAt.toString(),
        encode(nonce),
        encode(publicKey)
    ).joinToString("|").toByteArray(StandardCharsets.UTF_8)

    private fun encode(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private fun decode(value: String, maxBytes: Int): ByteArray {
        require(value.length <= maxBytes * 2) { "Champ d'invitation trop volumineux" }
        val decoded = Base64.getUrlDecoder().decode(value)
        require(decoded.isNotEmpty() && decoded.size <= maxBytes) { "Champ d'invitation invalide" }
        return decoded
    }

    private fun randomNonce(): ByteArray =
        ByteArray(NONCE_BYTES).also { java.security.SecureRandom().nextBytes(it) }
}
