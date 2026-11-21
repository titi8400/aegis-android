package fr.aegis.android.security

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Local trusted-device directory. A peer can only be stored when the caller
 * explicitly confirms that BOTH device fingerprints were compared out of band
 * and supplies a verified mutual-handshake proof.
 *
 * Records are stored inside EncryptedFileStore; this is local trust metadata,
 * not a network directory or synchronization service.
 */
class TrustedPeerStore(context: Context) {
    private val vault = EncryptedFileStore(context.applicationContext)

    data class Peer(
        val deviceId: String,
        val fingerprintSha256: String,
        val publicKeyEncoded: ByteArray,
        val displayName: String,
        val pairedAtEpochMs: Long,
        val transcriptSha256: String
    )

    @Synchronized
    fun trustPeer(
        proof: PairingHandshakeCodec.VerifiedHandshake,
        peerDeviceId: String,
        peerPublicKeyEncoded: ByteArray,
        displayName: String,
        bothFingerprintsComparedOutOfBand: Boolean,
        nowEpochMs: Long = System.currentTimeMillis()
    ) {
        require(bothFingerprintsComparedOutOfBand) {
            "La comparaison indépendante des deux empreintes est obligatoire."
        }
        require(peerDeviceId == proof.challengerDeviceId || peerDeviceId == proof.inviteDeviceId) {
            "L’appareil ne fait pas partie de la preuve d’appairage."
        }
        val keyMatchesProof =
            (peerDeviceId == proof.challengerDeviceId &&
                MessageDigest.isEqual(peerPublicKeyEncoded, proof.challengerPublicKey)) ||
            (peerDeviceId == proof.inviteDeviceId &&
                MessageDigest.isEqual(peerPublicKeyEncoded, proof.responderPublicKey))
        require(keyMatchesProof) { "Clé publique absente de la preuve d’appairage." }
        validateP256(peerPublicKeyEncoded)
        require(displayName.isNotBlank() && displayName.length <= 40) { "Nom d’appareil invalide." }

        val fingerprint = PairingInviteCodec.fingerprint(peerPublicKeyEncoded)
        val peers = readPeers().filterNot { it.deviceId == peerDeviceId }.toMutableList()
        peers.add(
            Peer(
                deviceId = peerDeviceId,
                fingerprintSha256 = fingerprint,
                publicKeyEncoded = peerPublicKeyEncoded.copyOf(),
                displayName = displayName.trim(),
                pairedAtEpochMs = nowEpochMs,
                transcriptSha256 = proof.transcriptSha256
            )
        )
        writePeers(peers)
    }

    @Synchronized
    fun listPeers(): List<Peer> = readPeers().sortedBy { it.displayName.lowercase() }

    @Synchronized
    fun removePeer(deviceId: String): Boolean {
        val peers = readPeers()
        val filtered = peers.filterNot { it.deviceId == deviceId }
        if (filtered.size == peers.size) return false
        writePeers(filtered)
        return true
    }

    private fun readPeers(): List<Peer> {
        val bytes = vault.get(RECORD_ID) ?: return emptyList()
        return try {
            val array = JSONArray(bytes.toString(Charsets.UTF_8))
            require(array.length() <= MAX_PEERS) { "Répertoire d’appareils trop volumineux." }
            buildList {
                for (i in 0 until array.length()) {
                    val item = array.getJSONObject(i)
                    val publicKey = Base64.getDecoder().decode(item.getString("publicKey"))
                    validateP256(publicKey)
                    val fingerprint = PairingInviteCodec.fingerprint(publicKey)
                    require(fingerprint == item.getString("fingerprint")) {
                        "Empreinte d’appareil incohérente."
                    }
                    add(
                        Peer(
                            deviceId = item.getString("deviceId"),
                            fingerprintSha256 = fingerprint,
                            publicKeyEncoded = publicKey,
                            displayName = item.getString("displayName"),
                            pairedAtEpochMs = item.getLong("pairedAt"),
                            transcriptSha256 = item.getString("transcript")
                        )
                    )
                }
            }
        } catch (failure: Exception) {
            throw SecurityException("Répertoire d’appareils illisible : refus de poursuivre.", failure)
        } finally {
            bytes.fill(0)
        }
    }

    private fun writePeers(peers: List<Peer>) {
        require(peers.size <= MAX_PEERS) { "Nombre maximal d’appareils atteint." }
        val array = JSONArray()
        peers.forEach { peer ->
            array.put(
                JSONObject()
                    .put("deviceId", peer.deviceId)
                    .put("fingerprint", peer.fingerprintSha256)
                    .put("publicKey", Base64.getEncoder().encodeToString(peer.publicKeyEncoded))
                    .put("displayName", peer.displayName)
                    .put("pairedAt", peer.pairedAtEpochMs)
                    .put("transcript", peer.transcriptSha256)
            )
        }
        vault.put(RECORD_ID, array.toString().toByteArray(Charsets.UTF_8))
    }

    private fun validateP256(encoded: ByteArray) {
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(encoded))
        require(key is ECPublicKey && key.params.curve.field.fieldSize == 256 &&
            key.params.order.bitLength() == 256) { "Clé P-256 invalide." }
    }

    companion object {
        private const val RECORD_ID = "trusted_peers_v1"
        private const val MAX_PEERS = 256
    }
}
