package fr.aegis.android.security

/** Minimal signing-identity contract shared by Android Keystore and JVM tests. */
interface SigningIdentity {
    fun exists(): Boolean
    fun publicKeyEncoded(): ByteArray
    fun sign(data: ByteArray): ByteArray
}
