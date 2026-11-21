package fr.aegis.android.security

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

/**
 * Persistent, encrypted one-time nonce registry.
 * Fails closed if its authenticated record cannot be read. Clearing app data or
 * rolling back the OS can reset this local history; this is not tamper-proof.
 */
class PairingReplayGuard(context: Context) {
    private val vault = EncryptedFileStore(context.applicationContext)

    @Synchronized
    fun consume(
        purpose: String,
        nonce: ByteArray,
        expiresAtEpochMs: Long,
        nowEpochMs: Long = System.currentTimeMillis()
    ) {
        require(purpose.matches(Regex("[a-z]{1,16}"))) { "Usage de nonce invalide" }
        require(nonce.size == NONCE_BYTES) { "Nonce invalide" }
        require(expiresAtEpochMs > nowEpochMs) { "Nonce déjà expiré" }

        val key = "$purpose:" + nonce.toHex()
        val active = readEntries().filter { it.second > nowEpochMs }
        require(active.none { constantTimeEquals(it.first, key) }) {
            "Invitation ou défi déjà utilisé : rejeu détecté"
        }
        require(active.size < MAX_ENTRIES) { "Historique anti-rejeu plein" }

        val updated = JSONArray()
        active.forEach { (entryKey, expiry) ->
            updated.put(JSONObject().put("key", entryKey).put("expires", expiry))
        }
        updated.put(JSONObject().put("key", key).put("expires", expiresAtEpochMs))
        vault.put(RECORD_ID, updated.toString().toByteArray(Charsets.UTF_8))
    }

    private fun readEntries(): List<Pair<String, Long>> {
        val bytes = vault.get(RECORD_ID) ?: return emptyList()
        return try {
            val array = JSONArray(bytes.toString(Charsets.UTF_8))
            require(array.length() <= MAX_ENTRIES) { "Historique anti-rejeu corrompu" }
            buildList {
                for (i in 0 until array.length()) {
                    val item = array.getJSONObject(i)
                    val key = item.getString("key")
                    val expiry = item.getLong("expires")
                    require(key.matches(Regex("[a-z]{1,16}:[0-9A-F]{64}")) && expiry > 0L) {
                        "Entrée anti-rejeu invalide"
                    }
                    add(key to expiry)
                }
            }
        } catch (failure: Exception) {
            throw SecurityException("Historique anti-rejeu illisible : refus de poursuivre", failure)
        } finally {
            bytes.fill(0)
        }
    }

    private fun constantTimeEquals(left: String, right: String): Boolean =
        MessageDigest.isEqual(left.toByteArray(Charsets.UTF_8), right.toByteArray(Charsets.UTF_8))

    private fun ByteArray.toHex() = joinToString("") { "%02X".format(it) }

    companion object {
        private const val RECORD_ID = "pairing_replay_guard_v1"
        private const val NONCE_BYTES = 32
        private const val MAX_ENTRIES = 4096
    }
}
