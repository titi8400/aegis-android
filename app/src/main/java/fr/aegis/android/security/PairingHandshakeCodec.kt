package fr.aegis.android.security

import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.UUID

/**
 * Signed challenge/response primitives for QR pairing.
 *
 * The caller must compare BOTH public-key fingerprints through an independent
 * trusted channel before accepting the resulting proof. This codec does not
 * establish trust, persist peers, transport messages, or prevent replay by
 * itself; PairingReplayGuard must consume the challenge nonce durably.
 */
object PairingHandshakeCodec {
    private const val PREFIX_CHALLENGE = "AEGIS-CHALLENGE"
    private const val PREFIX_RESPONSE = "AEGIS-RESPONSE"
    private const val VERSION = "1"
    private const val VALIDITY_MS = 90_000L
    private const val CLOCK_SKEW_MS = 30_000L
    private const val NONCE_BYTES = 32
    private const val MAX_KEY_BYTES = 1024
    private const val MAX_SIGNATURE_BYTES = 256

    data class VerifiedChallenge(
        val inviteDeviceId: String,
        val inviteNonce: ByteArray,
        val challengerDeviceId: String,
        val createdAtEpochMs: Long,
        val challengeNonce: ByteArray,
        val challengerPublicKey: ByteArray,
        val challengerFingerprint: String
    )

    data class VerifiedHandshake internal constructor(
        val inviteDeviceId: String,
        val challengerDeviceId: String,
        val challengerPublicKey: ByteArray,
        val responderPublicKey: ByteArray,
        val responderNonce: ByteArray,
        val responderFingerprint: String,
        val transcriptSha256: String
    )

    data class ResponsePackage(
        val encoded: String,
        val proof: VerifiedHandshake
    )

    fun createChallenge(
        invite: PairingInviteCodec.VerifiedInvite,
        challengerIdentity: SigningIdentity,
        challengerDeviceId: String? = null,
        nowEpochMs: Long = System.currentTimeMillis()
    ): String {
        require(challengerIdentity.exists()) { "Identité locale absente" }
        require(nowEpochMs <= invite.expiresAtEpochMs) { "Invitation expirée" }
        val stableChallengerId = challengerDeviceId ?: PairingInviteCodec.deviceIdForPublicKey(challengerIdentity.publicKeyEncoded())
        require(isCanonicalUuid(stableChallengerId)) { "Identifiant local invalide" }
        val nonce = randomNonce()
        val publicKey = challengerIdentity.publicKeyEncoded()
        validateP256(publicKey)
        val unsigned = challengeCanonical(
            invite.deviceId, invite.nonce, stableChallengerId, nowEpochMs, nonce, publicKey
        )
        val signature = challengerIdentity.sign(unsigned)
        return listOf(
            PREFIX_CHALLENGE, VERSION, invite.deviceId, encode(invite.nonce),
            stableChallengerId, nowEpochMs.toString(), encode(nonce),
            encode(publicKey), encode(signature)
        ).joinToString("|")
    }

    fun verifyChallenge(
        encoded: String,
        expectedInvite: PairingInviteCodec.VerifiedInvite,
        nowEpochMs: Long = System.currentTimeMillis()
    ): VerifiedChallenge {
        require(encoded.length <= 4096) { "Défi trop volumineux" }
        val f = encoded.split('|')
        require(f.size == 9 && f[0] == PREFIX_CHALLENGE && f[1] == VERSION) {
            "Format de défi AEGIS invalide"
        }
        require(f[2] == expectedInvite.deviceId) { "Défi destiné à un autre appareil" }
        require(nowEpochMs <= expectedInvite.expiresAtEpochMs) { "Invitation initiale expirée" }
        val inviteNonce = decode(f[3], NONCE_BYTES)
        require(MessageDigest.isEqual(inviteNonce, expectedInvite.nonce)) { "Invitation non correspondante" }
        val challengerId = f[4]
        require(isCanonicalUuid(challengerId)) { "Identifiant du pair invalide" }
        val createdAt = f[5].toLongOrNull() ?: error("Date du défi invalide")
        require(createdAt <= nowEpochMs + CLOCK_SKEW_MS && nowEpochMs <= createdAt + VALIDITY_MS) {
            "Défi expiré ou daté dans le futur"
        }
        val challengeNonce = decode(f[6], NONCE_BYTES)
        val publicKey = decode(f[7], MAX_KEY_BYTES)
        val signature = decode(f[8], MAX_SIGNATURE_BYTES)
        validateP256(publicKey)
        val unsigned = challengeCanonical(
            expectedInvite.deviceId, inviteNonce, challengerId, createdAt, challengeNonce, publicKey
        )
        verifySignature(publicKey, unsigned, signature)
        return VerifiedChallenge(
            inviteDeviceId = expectedInvite.deviceId,
            inviteNonce = inviteNonce,
            challengerDeviceId = challengerId,
            createdAtEpochMs = createdAt,
            challengeNonce = challengeNonce,
            challengerPublicKey = publicKey,
            challengerFingerprint = PairingInviteCodec.fingerprint(publicKey)
        )
    }

    fun createResponse(
        challenge: VerifiedChallenge,
        responderInvite: PairingInviteCodec.VerifiedInvite,
        responderIdentity: SigningIdentity
    ): String = createResponsePackage(challenge, responderInvite, responderIdentity).encoded

    fun createResponsePackage(
        challenge: VerifiedChallenge,
        responderInvite: PairingInviteCodec.VerifiedInvite,
        responderIdentity: SigningIdentity
    ): ResponsePackage {
        require(challenge.inviteDeviceId == responderInvite.deviceId) { "Défi destiné à une autre identité" }
        require(System.currentTimeMillis() <= challenge.createdAtEpochMs + VALIDITY_MS) { "Défi expiré" }
        require(MessageDigest.isEqual(challenge.inviteNonce, responderInvite.nonce)) { "Nonce d’invitation incorrect" }
        val publicKey = responderIdentity.publicKeyEncoded()
        require(MessageDigest.isEqual(publicKey, responderInvite.publicKeyEncoded)) {
            "La clé locale ne correspond pas à l’invitation"
        }
        val responderNonce = randomNonce()
        val unsigned = responseCanonical(
            challenge.inviteDeviceId, challenge.inviteNonce, challenge.challengerDeviceId,
            challenge.challengeNonce, responderNonce, publicKey
        )
        val signature = responderIdentity.sign(unsigned)
        val encoded = listOf(
            PREFIX_RESPONSE, VERSION, challenge.inviteDeviceId, encode(challenge.inviteNonce),
            challenge.challengerDeviceId, encode(challenge.challengeNonce),
            encode(responderNonce), encode(publicKey), encode(signature)
        ).joinToString("|")
        val transcript = unsigned + signature
        val proof = VerifiedHandshake(
            inviteDeviceId = challenge.inviteDeviceId,
            challengerDeviceId = challenge.challengerDeviceId,
            challengerPublicKey = challenge.challengerPublicKey,
            responderPublicKey = publicKey,
            responderNonce = responderNonce,
            responderFingerprint = PairingInviteCodec.fingerprint(publicKey),
            transcriptSha256 = MessageDigest.getInstance("SHA-256").digest(transcript).toHex()
        )
        return ResponsePackage(encoded, proof)
    }

    fun verifyResponse(
        encoded: String,
        challenge: VerifiedChallenge,
        expectedResponder: PairingInviteCodec.VerifiedInvite,
        nowEpochMs: Long = System.currentTimeMillis()
    ): VerifiedHandshake {
        require(nowEpochMs <= challenge.createdAtEpochMs + VALIDITY_MS) { "Défi expiré" }
        require(encoded.length <= 4096) { "Réponse trop volumineuse" }
        val f = encoded.split('|')
        require(f.size == 9 && f[0] == PREFIX_RESPONSE && f[1] == VERSION) {
            "Format de réponse AEGIS invalide"
        }
        require(f[2] == challenge.inviteDeviceId && f[4] == challenge.challengerDeviceId) {
            "Réponse liée à un autre échange"
        }
        val inviteNonce = decode(f[3], NONCE_BYTES)
        val challengeNonce = decode(f[5], NONCE_BYTES)
        require(MessageDigest.isEqual(inviteNonce, challenge.inviteNonce)) { "Nonce d’invitation incorrect" }
        require(MessageDigest.isEqual(challengeNonce, challenge.challengeNonce)) { "Défi incorrect ou rejoué" }
        val responderNonce = decode(f[6], NONCE_BYTES)
        val responderKey = decode(f[7], MAX_KEY_BYTES)
        val signature = decode(f[8], MAX_SIGNATURE_BYTES)
        require(MessageDigest.isEqual(responderKey, expectedResponder.publicKeyEncoded)) {
            "La réponse ne provient pas de l’identité invitante"
        }
        val unsigned = responseCanonical(
            challenge.inviteDeviceId, inviteNonce, challenge.challengerDeviceId,
            challengeNonce, decode(f[6], NONCE_BYTES), responderKey
        )
        verifySignature(responderKey, unsigned, signature)
        val transcript = unsigned + signature
        return VerifiedHandshake(
            inviteDeviceId = challenge.inviteDeviceId,
            challengerDeviceId = challenge.challengerDeviceId,
            challengerPublicKey = challenge.challengerPublicKey,
            responderPublicKey = responderKey,
            responderNonce = responderNonce,
            responderFingerprint = PairingInviteCodec.fingerprint(responderKey),
            transcriptSha256 = MessageDigest.getInstance("SHA-256").digest(transcript).toHex()
        )
    }

    private fun challengeCanonical(
        inviteId: String, inviteNonce: ByteArray, challengerId: String,
        createdAt: Long, challengeNonce: ByteArray, publicKey: ByteArray
    ) = listOf(
        PREFIX_CHALLENGE, VERSION, inviteId, encode(inviteNonce), challengerId,
        createdAt.toString(), encode(challengeNonce), encode(publicKey)
    ).joinToString("|").toByteArray(StandardCharsets.UTF_8)

    private fun responseCanonical(
        inviteId: String, inviteNonce: ByteArray, challengerId: String,
        challengeNonce: ByteArray, responderNonce: ByteArray, publicKey: ByteArray
    ) = listOf(
        PREFIX_RESPONSE, VERSION, inviteId, encode(inviteNonce), challengerId,
        encode(challengeNonce), encode(responderNonce), encode(publicKey)
    ).joinToString("|").toByteArray(StandardCharsets.UTF_8)

    private fun verifySignature(publicKey: ByteArray, data: ByteArray, signature: ByteArray) {
        require(signature.size in 8..MAX_SIGNATURE_BYTES) { "Signature invalide" }
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(publicKey))
        require(key is ECPublicKey) { "Clé EC requise" }
        val valid = Signature.getInstance("SHA256withECDSA").run {
            initVerify(key)
            update(data)
            verify(signature)
        }
        require(valid) { "Signature cryptographique invalide" }
    }

    private fun validateP256(encoded: ByteArray) {
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(encoded))
        require(key is ECPublicKey) { "Clé EC requise" }
        require(key.params.curve.field.fieldSize == 256 && key.params.order.bitLength() == 256) {
            "Courbe NIST P-256 obligatoire"
        }
    }

    private fun isCanonicalUuid(value: String): Boolean =
        runCatching { UUID.fromString(value).toString() == value }.getOrDefault(false)

    private fun randomNonce() = ByteArray(NONCE_BYTES).also { java.security.SecureRandom().nextBytes(it) }
    private fun encode(bytes: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    private fun decode(value: String, max: Int): ByteArray {
        require(value.length <= max * 2) { "Champ trop volumineux" }
        return Base64.getUrlDecoder().decode(value).also {
            require(it.isNotEmpty() && it.size <= max) { "Champ invalide" }
        }
    }
    private fun ByteArray.toHex() = joinToString("") { "%02X".format(it) }
}
