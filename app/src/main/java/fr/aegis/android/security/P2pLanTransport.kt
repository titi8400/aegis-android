package fr.aegis.android.security

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

/**
 * Direct, mutually authenticated TCP transport for peers on the same IP network.
 *
 * This transport has no rendezvous server and no relay. It deliberately does
 * not perform NAT traversal: devices on different networks, behind incompatible
 * NATs, or behind restrictive firewalls may not connect.
 *
 * All application payload bytes are protected by TLS 1.2/1.3 with certificate
 * public-key pins from the local trusted-device directory.
 */
class P2pLanTransport(
    private val identity: AndroidKeyStoreIdentity,
    private val trustedPeers: TrustedPeerStore
) : Closeable {
    private val closed = AtomicBoolean(false)
    private val workers: ExecutorService = Executors.newCachedThreadPool()
    @Volatile private var serverSocket: SSLServerSocket? = null

    data class PeerConnection(
        val remoteAddress: InetAddress,
        val session: SecureSession
    )

    fun listen(
        port: Int = DEFAULT_PORT,
        onConnection: (PeerConnection) -> Unit,
        onError: (Exception) -> Unit
    ) {
        require(port in 1024..65535) { "Port réseau invalide." }
        check(!closed.get()) { "Transport déjà fermé." }
        workers.execute {
            try {
                val context = PinnedMutualTls.createContext(identity, trustedPeers)
                val server = context.serverSocketFactory.createServerSocket(
                    port,
                    SERVER_BACKLOG,
                    InetAddress.getByName("0.0.0.0")
                ) as SSLServerSocket
                PinnedMutualTls.configureServer(server)
                serverSocket = server
                if (closed.get()) {
                    server.close()
                    return@execute
                }
                while (!closed.get() && !server.isClosed) {
                    val raw = server.accept() as SSLSocket
                    workers.execute {
                        try {
                            raw.tcpNoDelay = true
                            raw.keepAlive = true
                            raw.soTimeout = HANDSHAKE_TIMEOUT_MS
                            raw.startHandshake()
                            raw.soTimeout = 0
                            onConnection(PeerConnection(raw.inetAddress, SecureSession(raw)))
                        } catch (failure: Exception) {
                            runCatching { raw.close() }
                            onError(failure)
                        }
                    }
                }
            } catch (failure: Exception) {
                if (!closed.get()) onError(failure)
            }
        }
    }

    fun connect(
        host: String,
        port: Int = DEFAULT_PORT,
        connectTimeoutMs: Int = CONNECT_TIMEOUT_MS
    ): SecureSession {
        check(!closed.get()) { "Transport déjà fermé." }
        require(host.isNotBlank() && host.length <= 253) { "Adresse du pair invalide." }
        require(port in 1024..65535) { "Port réseau invalide." }
        require(connectTimeoutMs in 1_000..30_000) { "Délai de connexion invalide." }
        val context = PinnedMutualTls.createContext(identity, trustedPeers)
        val socket = context.socketFactory.createSocket() as SSLSocket
        try {
            socket.connect(InetSocketAddress(host, port), connectTimeoutMs)
            socket.tcpNoDelay = true
            socket.keepAlive = true
            socket.soTimeout = HANDSHAKE_TIMEOUT_MS
            PinnedMutualTls.configure(socket)
            socket.startHandshake()
            socket.soTimeout = 0
            return SecureSession(socket)
        } catch (failure: Exception) {
            runCatching { socket.close() }
            throw failure
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        runCatching { serverSocket?.close() }
        workers.shutdownNow()
    }

    class SecureSession internal constructor(
        private val socket: SSLSocket
    ) : Closeable {
        /** Stable identity derived from the TLS peer certificate already pinned by the trust manager. */
        val remoteDeviceId: String = run {
            val certificate = socket.session.peerCertificates.firstOrNull() as? java.security.cert.X509Certificate
                ?: error("Certificat d'identité du pair absent.")
            PairingInviteCodec.deviceIdForPublicKey(certificate.publicKey.encoded)
        }

        private val input = DataInputStream(BufferedInputStream(socket.inputStream))
        private val output = DataOutputStream(BufferedOutputStream(socket.outputStream))
        private val writeLock = Any()

        val isOpen: Boolean get() = !socket.isClosed && socket.isConnected

        /** Sends one bounded, length-prefixed application frame. */
        fun sendFrame(payload: ByteArray) {
            require(payload.isNotEmpty() && payload.size <= MAX_FRAME_BYTES) {
                "Taille de message réseau invalide."
            }
            check(isOpen) { "Connexion AEGIS fermée." }
            synchronized(writeLock) {
                output.writeInt(payload.size)
                output.write(payload)
                output.flush()
            }
        }

        /** Blocks until a complete frame arrives or the socket closes. */
        @Throws(EOFException::class)
        fun readFrame(): ByteArray {
            check(isOpen) { "Connexion AEGIS fermée." }
            val length = input.readInt()
            require(length in 1..MAX_FRAME_BYTES) { "Trame réseau trop volumineuse ou invalide." }
            return ByteArray(length).also { input.readFully(it) }
        }

        override fun close() {
            runCatching { socket.close() }
        }

        companion object {
            const val MAX_FRAME_BYTES = 1_048_576
        }
    }

    companion object {
        const val DEFAULT_PORT = 39_841
        private const val SERVER_BACKLOG = 8
        private const val CONNECT_TIMEOUT_MS = 8_000
        private const val HANDSHAKE_TIMEOUT_MS = 12_000
    }
}
