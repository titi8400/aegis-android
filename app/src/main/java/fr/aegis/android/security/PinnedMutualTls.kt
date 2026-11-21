package fr.aegis.android.security

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import java.io.OutputStream
import java.math.BigInteger
import java.net.Socket
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Date
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509ExtendedTrustManager

/**
 * TLS identity adapter for AEGIS direct peer links.
 *
 * A short-lived self-signed certificate is created for each TLS context and
 * signed by the device's long-term Android Keystore identity. The private key
 * is exposed only as a non-exportable Android Keystore handle.
 *
 * Trust is based exclusively on exact public-key pins in TrustedPeerStore.
 * No CA, DNS name, cloud service, or relay is involved.
 */
internal object PinnedMutualTls {
    fun createContext(
        identity: AndroidKeyStoreIdentity,
        trustedPeers: TrustedPeerStore
    ): SSLContext {
        require(identity.exists()) { "Identité AEGIS locale absente." }
        val publicKey = identity.publicKeyEncoded()
        val deviceId = PairingInviteCodec.deviceIdForPublicKey(publicKey)
        val privateKey = identity.privateKeyForTls()
        val certificate = createIdentityCertificate(identity, deviceId)
        val keyManager = DeviceKeyManager(privateKey, certificate)
        val trustManager = PeerPinTrustManager(trustedPeers)
        return SSLContext.getInstance("TLS").apply {
            init(arrayOf<KeyManager>(keyManager), arrayOf(trustManager), SecureRandom())
        }
    }

    fun configure(socket: SSLSocket) {
        val supported = socket.supportedProtocols.toSet()
        val protocols = listOf("TLSv1.3", "TLSv1.2").filter { it in supported }
        require(protocols.isNotEmpty()) { "Aucune version TLS moderne disponible." }
        socket.enabledProtocols = protocols.toTypedArray()
        socket.useClientMode = true
    }

    fun configureServer(socket: javax.net.ssl.SSLServerSocket) {
        val supported = socket.supportedProtocols.toSet()
        val protocols = listOf("TLSv1.3", "TLSv1.2").filter { it in supported }
        require(protocols.isNotEmpty()) { "Aucune version TLS moderne disponible." }
        socket.enabledProtocols = protocols.toTypedArray()
        socket.needClientAuth = true
    }

    private fun createIdentityCertificate(
        identity: AndroidKeyStoreIdentity,
        deviceId: String
    ): X509Certificate {
        val provider = BouncyCastleProvider()
        val now = System.currentTimeMillis()
        val subject = X500Name("CN=$deviceId")
        val builder = JcaX509v3CertificateBuilder(
            subject,
            BigInteger(159, SecureRandom()).setBit(158),
            Date(now - 60_000L),
            Date(now + CERTIFICATE_LIFETIME_MS),
            subject,
            java.security.KeyFactory.getInstance("EC").generatePublic(
                java.security.spec.X509EncodedKeySpec(identity.publicKeyEncoded())
            )
        )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature))
        builder.addExtension(
            Extension.extendedKeyUsage,
            false,
            ExtendedKeyUsage(arrayOf(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth))
        )
        val signer = keystoreContentSigner(identity)
        return JcaX509CertificateConverter()
            .setProvider(provider)
            .getCertificate(builder.build(signer))
            .also {
                it.checkValidity(Date(now))
                it.verify(it.publicKey)
                require(it.publicKey.encoded.contentEquals(identity.publicKeyEncoded())) {
                    "Le certificat TLS ne correspond pas à l'identité AEGIS."
                }
            }
    }

    private fun keystoreContentSigner(identity: AndroidKeyStoreIdentity): ContentSigner {
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(identity.privateKeyForTls())
        return object : ContentSigner {
            private val algorithm = DefaultSignatureAlgorithmIdentifierFinder()
                .find("SHA256withECDSA")

            override fun getAlgorithmIdentifier() = algorithm
            override fun getOutputStream(): OutputStream = object : OutputStream() {
                override fun write(value: Int) {
                    signature.update(value.toByte())
                }

                override fun write(bytes: ByteArray, offset: Int, length: Int) {
                    signature.update(bytes, offset, length)
                }
            }

            override fun getSignature(): ByteArray = signature.sign()
        }
    }

    private class DeviceKeyManager(
        private val privateKey: java.security.PrivateKey,
        private val certificate: X509Certificate
    ) : X509ExtendedKeyManager() {
        override fun chooseServerAlias(keyType: String?, issuers: Array<out java.security.Principal>?, socket: Socket?) =
            if (keyType == null || keyType.contains("EC", ignoreCase = true)) ALIAS else null

        override fun chooseClientAlias(
            keyType: Array<out String>?,
            issuers: Array<out java.security.Principal>?,
            socket: Socket?
        ) = if (keyType?.any { it.contains("EC", ignoreCase = true) } == true) ALIAS else null

        override fun getCertificateChain(alias: String?) =
            if (alias == ALIAS) arrayOf(certificate) else null

        override fun getPrivateKey(alias: String?) =
            if (alias == ALIAS) privateKey else null

        override fun getServerAliases(keyType: String?, issuers: Array<out java.security.Principal>?) =
            if (keyType == null || keyType.contains("EC", ignoreCase = true)) arrayOf(ALIAS) else null

        override fun getClientAliases(keyType: String?, issuers: Array<out java.security.Principal>?) =
            if (keyType == null || keyType.contains("EC", ignoreCase = true)) arrayOf(ALIAS) else null

        override fun chooseEngineServerAlias(
            keyType: String?,
            issuers: Array<out java.security.Principal>?,
            engine: SSLEngine?
        ) = if (keyType == null || keyType.contains("EC", ignoreCase = true)) ALIAS else null

        override fun chooseEngineClientAlias(
            keyType: Array<out String>?,
            issuers: Array<out java.security.Principal>?,
            engine: SSLEngine?
        ) = if (keyType?.any { it.contains("EC", ignoreCase = true) } == true) ALIAS else null

        companion object { private const val ALIAS = "aegis-device-identity" }
    }

    private class PeerPinTrustManager(
        private val peers: TrustedPeerStore
    ) : X509ExtendedTrustManager() {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = checkPinned(chain)
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = checkPinned(chain)
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) = checkPinned(chain)
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) = checkPinned(chain)
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) = checkPinned(chain)
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) = checkPinned(chain)
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()

        private fun checkPinned(chain: Array<out X509Certificate>?) {
            try {
                require(!chain.isNullOrEmpty() && chain.size == 1) { "Chaîne de certificat TLS inattendue." }
                val certificate = chain[0]
                certificate.checkValidity()
                require(certificate.basicConstraints == -1) { "Un certificat CA n'est pas accepté." }
                certificate.verify(certificate.publicKey)
                val presentedKey = certificate.publicKey.encoded
                val matched = peers.listPeers().any { peer ->
                    MessageDigest.isEqual(peer.publicKeyEncoded, presentedKey)
                }
                require(matched) { "Appareil non approuvé : empreinte absente du répertoire local." }
            } catch (failure: Exception) {
                throw CertificateException("Authentification TLS du pair refusée.", failure)
            }
        }
    }

    private const val CERTIFICATE_LIFETIME_MS = 24L * 60L * 60L * 1000L
}
