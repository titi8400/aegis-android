package fr.aegis.android.security

import java.io.Closeable
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.SocketException
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * LAN-only discovery beacons. Beacons are hints, never authentication.
 * A candidate is shown only when its stable device ID is already in the local
 * trusted directory; the subsequent TLS handshake still verifies the pinned
 * public key and proof of private-key possession.
 */
class P2pLanDiscovery(
    identity: AndroidKeyStoreIdentity,
    private val trustedPeers: TrustedPeerStore
) : Closeable {
    data class DiscoveredPeer(
        val deviceId: String,
        val displayName: String,
        val address: String,
        val port: Int
    )

    private val localDeviceId = PairingInviteCodec.deviceIdForPublicKey(identity.publicKeyEncoded())
    private val stopped = AtomicBoolean(false)
    private val sender: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor()
    @Volatile private var socket: DatagramSocket? = null
    @Volatile private var listener: Thread? = null

    fun start(onPeerFound: (DiscoveredPeer) -> Unit, onError: (Exception) -> Unit = {}) {
        check(!stopped.get()) { "Découverte locale arrêtée." }
        sender.scheduleAtFixedRate(
            { runCatching { announce() }.onFailure { onError(it as? Exception ?: Exception(it)) } },
            0,
            ANNOUNCE_INTERVAL_SECONDS,
            TimeUnit.SECONDS
        )
        listener = Thread({
            try {
                val datagram = DatagramSocket(null).apply {
                    reuseAddress = true
                    broadcast = true
                    soTimeout = 2_000
                    bind(java.net.InetSocketAddress(DISCOVERY_PORT))
                }
                socket = datagram
                val buffer = ByteArray(MAX_PACKET_BYTES)
                while (!stopped.get()) {
                    try {
                        val packet = DatagramPacket(buffer, buffer.size)
                        datagram.receive(packet)
                        val message = String(packet.data, packet.offset, packet.length, StandardCharsets.US_ASCII)
                        parse(message, packet.address)?.let(onPeerFound)
                    } catch (_: java.net.SocketTimeoutException) {
                        // Recheck shutdown flag.
                    }
                }
            } catch (failure: Exception) {
                if (!stopped.get()) onError(failure)
            }
        }, "aegis-lan-discovery").apply { isDaemon = true; start() }
    }

    fun announce() {
        check(!stopped.get()) { "Découverte locale arrêtée." }
        val nonce = ByteArray(NONCE_BYTES).also { SecureRandom().nextBytes(it) }
        val message = listOf(
            PREFIX,
            VERSION,
            localDeviceId,
            P2pLanTransport.DEFAULT_PORT.toString(),
            Base64.getUrlEncoder().withoutPadding().encodeToString(nonce)
        ).joinToString("|").toByteArray(StandardCharsets.US_ASCII)
        require(message.size <= MAX_PACKET_BYTES) { "Annonce de découverte trop volumineuse." }
        DatagramSocket().use { senderSocket ->
            senderSocket.broadcast = true
            broadcastAddresses().forEach { address ->
                senderSocket.send(DatagramPacket(message, message.size, address, DISCOVERY_PORT))
            }
        }
        nonce.fill(0)
        message.fill(0)
    }

    private fun parse(message: String, source: InetAddress): DiscoveredPeer? {
        if (source !is Inet4Address) return null
        val fields = message.split('|')
        if (fields.size != 5 || fields[0] != PREFIX || fields[1] != VERSION) return null
        val deviceId = fields[2]
        if (deviceId == localDeviceId || !isCanonicalUuid(deviceId)) return null
        val port = fields[3].toIntOrNull()?.takeIf { it in 1024..65535 } ?: return null
        val nonce = runCatching { Base64.getUrlDecoder().decode(fields[4]) }.getOrNull() ?: return null
        if (nonce.size != NONCE_BYTES) return null
        nonce.fill(0)
        val trusted = trustedPeers.listPeers().firstOrNull { peer ->
            peer.deviceId == deviceId &&
                PairingInviteCodec.deviceIdForPublicKey(peer.publicKeyEncoded) == deviceId
        } ?: return null
        return DiscoveredPeer(deviceId, trusted.displayName, source.hostAddress ?: return null, port)
    }

    private fun broadcastAddresses(): Set<InetAddress> = runCatching {
        NetworkInterface.getNetworkInterfaces().toList()
            .filter { it.isUp && !it.isLoopback && it.supportsMulticast() }
            .flatMap { it.interfaceAddresses }
            .mapNotNull { it.broadcast }
            .toSet()
    }.getOrDefault(setOf(InetAddress.getByName("255.255.255.255")))

    private fun isCanonicalUuid(value: String): Boolean =
        runCatching { java.util.UUID.fromString(value).toString() == value }.getOrDefault(false)

    override fun close() {
        if (!stopped.compareAndSet(false, true)) return
        sender.shutdownNow()
        runCatching { socket?.close() }
        runCatching { listener?.interrupt() }
    }

    companion object {
        const val DISCOVERY_PORT = 39_842
        private const val PREFIX = "AEGIS-DISCOVERY"
        private const val VERSION = "1"
        private const val NONCE_BYTES = 16
        private const val MAX_PACKET_BYTES = 512
        private const val ANNOUNCE_INTERVAL_SECONDS = 5L
    }
}
