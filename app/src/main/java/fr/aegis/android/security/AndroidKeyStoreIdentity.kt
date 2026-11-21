package fr.aegis.android.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore

/**
 * Creates a local signing identity in Android Keystore.
 *
 * The private key is never returned by this API. Android Keystore may use
 * hardware-backed storage when the device supports it; this is not guaranteed.
 * This class is an initial primitive, not a complete identity or pairing protocol.
 */
class AndroidKeyStoreIdentity(
    private val alias: String = DEFAULT_ALIAS
) : SigningIdentity {
    fun createIfAbsent(): Boolean {
        val keyStore = loadKeyStore()
        if (keyStore.containsAlias(alias)) return false

        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEY_STORE
        )
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
            .build()

        generator.initialize(spec)
        generator.generateKeyPair()
        return true
    }

    override fun publicKeyEncoded(): ByteArray {
        val entry = loadKeyStore().getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: error("Identité AEGIS absente")
        return entry.certificate.publicKey.encoded
    }

    override fun sign(data: ByteArray): ByteArray {
        val entry = loadKeyStore().getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: error("Identité AEGIS absente")
        return java.security.Signature.getInstance("SHA256withECDSA").run {
            initSign(entry.privateKey)
            update(data)
            sign()
        }
    }

    /**
     * Returns the Android Keystore private-key handle for TLS key management.
     * The key material remains non-exportable; callers receive only the
     * platform PrivateKey handle and must never serialize it.
     */
    internal fun privateKeyForTls(): java.security.PrivateKey {
        val entry = loadKeyStore().getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: error("Identité AEGIS absente")
        return entry.privateKey
    }

    override fun exists(): Boolean = loadKeyStore().containsAlias(alias)

    fun delete(): Boolean {
        val keyStore = loadKeyStore()
        if (!keyStore.containsAlias(alias)) return false
        keyStore.deleteEntry(alias)
        return true
    }

    private fun loadKeyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    companion object {
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val DEFAULT_ALIAS = "aegis.device.identity.signing.v1"
    }
}
