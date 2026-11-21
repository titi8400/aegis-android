package fr.aegis.android.calls

import android.content.Context
import android.content.pm.PackageManager
import android.Manifest
import androidx.core.content.ContextCompat
import org.webrtc.AudioSource
import org.webrtc.AudioTrack
import org.webrtc.Camera2Enumerator
import org.webrtc.CameraVideoCapturer
import org.webrtc.DefaultVideoDecoderFactory
import org.webrtc.DefaultVideoEncoderFactory
import org.webrtc.EglBase
import org.webrtc.IceCandidate
import org.webrtc.MediaConstraints
import org.webrtc.MediaStream
import org.webrtc.PeerConnection
import org.webrtc.PeerConnectionFactory
import org.webrtc.RtpReceiver
import org.webrtc.SdpObserver
import org.webrtc.SessionDescription
import org.webrtc.SurfaceTextureHelper
import org.webrtc.SurfaceViewRenderer
import org.webrtc.VideoSource
import org.webrtc.VideoTrack
import fr.aegis.android.security.P2pCallSignalCodec
import java.io.Closeable
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Direct WebRTC call engine. No STUN, TURN, SFU or signaling server is configured.
 * It can therefore establish media only when direct host ICE candidates are reachable,
 * normally when both devices share the same LAN.
 *
 * Signaling frames are sent over the already mutually authenticated AEGIS TLS session.
 */
class P2pCallEngine(
    context: Context,
    private val sendSignalFrame: (ByteArray) -> Unit,
    private val onStateChanged: (String) -> Unit,
    private val onIncomingOffer: () -> Unit
) : Closeable {
    private val appContext = context.applicationContext
    private val egl = EglBase.create()
    private val factory: PeerConnectionFactory
    private var peerConnection: PeerConnection? = null
    private var callId: String? = null
    private var pendingOffer: P2pCallSignalCodec.Signal.Offer? = null
    private var remoteDescriptionSet = false
    private val pendingCandidates = CopyOnWriteArrayList<IceCandidate>()
    private val pendingLocalCandidates = CopyOnWriteArrayList<IceCandidate>()
    private var localDescriptionSignaled = false
    private var audioSource: AudioSource? = null
    private var audioTrack: AudioTrack? = null
    private var videoSource: VideoSource? = null
    private var videoTrack: VideoTrack? = null
    private var remoteVideoTrack: VideoTrack? = null
    private var cameraCapturer: CameraVideoCapturer? = null
    private var surfaceTextureHelper: SurfaceTextureHelper? = null
    private var localRenderer: SurfaceViewRenderer? = null
    private var remoteRenderer: SurfaceViewRenderer? = null
    @Volatile private var closed = false

    init {
        ensureWebRtcInitialized(appContext)
        factory = PeerConnectionFactory.builder()
            .setVideoEncoderFactory(DefaultVideoEncoderFactory(egl.eglBaseContext, true, true))
            .setVideoDecoderFactory(DefaultVideoDecoderFactory(egl.eglBaseContext))
            .createPeerConnectionFactory()
    }

    fun attachRenderers(local: SurfaceViewRenderer, remote: SurfaceViewRenderer) {
        check(!closed) { "Moteur d'appel fermé." }
        localRenderer = local
        remoteRenderer = remote
        local.init(egl.eglBaseContext, null)
        remote.init(egl.eglBaseContext, null)
        local.setEnableHardwareScaler(true)
        remote.setEnableHardwareScaler(true)
        local.setMirror(true)
        remote.setMirror(false)
        videoTrack?.addSink(local)
        remoteVideoTrack?.addSink(remote)
    }

    val hasPendingIncomingOffer: Boolean get() = pendingOffer != null
    val hasActiveCall: Boolean get() = callId != null

    fun startOutgoingCall() {
        check(!closed) { "Moteur d'appel fermé." }
        check(hasPermission(Manifest.permission.RECORD_AUDIO)) {
            "L'autorisation microphone est nécessaire pour appeler."
        }
        val id = UUID.randomUUID().toString()
        callId = id
        ensurePeerConnection()
        addLocalMedia()
        onStateChanged("Préparation de l'appel direct…")
        peerConnection?.createOffer(object : SdpObserverAdapter() {
            override fun onCreateSuccess(description: SessionDescription?) {
                if (description == null) return fail("Offre WebRTC vide.")
                peerConnection?.setLocalDescription(object : SdpObserverAdapter() {
                    override fun onSetSuccess() {
                        sendSignal(P2pCallSignalCodec.Signal.Offer(id, description.description))
                        localDescriptionSignaled = true
                        flushLocalCandidates()
                    }
                    override fun onSetFailure(error: String?) = fail("Impossible d'appliquer l'offre : $error")
                }, description)
            }
            override fun onCreateFailure(error: String?) = fail("Création de l'offre impossible : $error")
        }, MediaConstraints())
    }

    fun handleSignal(signal: P2pCallSignalCodec.Signal) {
        if (closed) return
        when (signal) {
            is P2pCallSignalCodec.Signal.Offer -> {
                if (callId != null && callId != signal.callId) {
                    fail("Un autre appel est déjà actif.")
                    return
                }
                callId = signal.callId
                pendingOffer = signal
                onIncomingOffer()
                onStateChanged("Appel entrant : accepte ou refuse l'appel.")
            }
            is P2pCallSignalCodec.Signal.Answer -> {
                if (signal.callId != callId) return
                val description = SessionDescription(SessionDescription.Type.ANSWER, signal.sdp)
                peerConnection?.setRemoteDescription(object : SdpObserverAdapter() {
                    override fun onSetSuccess() {
                        remoteDescriptionSet = true
                        flushPendingCandidates()
                        onStateChanged("Réponse reçue ; établissement du média…")
                    }
                    override fun onSetFailure(error: String?) = fail("Réponse distante refusée : $error")
                }, description)
            }
            is P2pCallSignalCodec.Signal.Candidate -> {
                if (signal.callId != callId) return
                val candidate = IceCandidate(signal.sdpMid, signal.sdpMLineIndex, signal.candidate)
                if (remoteDescriptionSet) peerConnection?.addIceCandidate(candidate)
                else pendingCandidates.add(candidate)
            }
            is P2pCallSignalCodec.Signal.Hangup -> {
                if (signal.callId == callId) {
                    closePeerConnection()
                    onStateChanged("Appel terminé par le correspondant.")
                }
            }
        }
    }

    val hasPendingIncomingOffer: Boolean
        get() = pendingOffer != null

    fun acceptPendingOffer() {
        val offer = pendingOffer ?: throw IllegalStateException("Aucun appel entrant en attente.")
        check(hasPermission(Manifest.permission.RECORD_AUDIO)) {
            "L'autorisation microphone est nécessaire pour accepter l'appel."
        }
        pendingOffer = null
        ensurePeerConnection()
        addLocalMedia()
        val description = SessionDescription(SessionDescription.Type.OFFER, offer.sdp)
        peerConnection?.setRemoteDescription(object : SdpObserverAdapter() {
            override fun onSetSuccess() {
                remoteDescriptionSet = true
                flushPendingCandidates()
                createAnswer(offer.callId)
            }
            override fun onSetFailure(error: String?) = fail("Offre distante refusée : $error")
        }, description)
    }

    fun rejectPendingOffer() {
        pendingOffer?.let { sendSignal(P2pCallSignalCodec.Signal.Hangup(it.callId)) }
        closePeerConnection()
        onStateChanged("Appel entrant refusé.")
    }

    fun hangUp() {
        val id = callId
        if (id != null) runCatching { sendSignal(P2pCallSignalCodec.Signal.Hangup(id)) }
        closePeerConnection()
        onStateChanged("Appel terminé.")
    }

    private fun createAnswer(id: String) {
        peerConnection?.createAnswer(object : SdpObserverAdapter() {
            override fun onCreateSuccess(description: SessionDescription?) {
                if (description == null) return fail("Réponse WebRTC vide.")
                peerConnection?.setLocalDescription(object : SdpObserverAdapter() {
                    override fun onSetSuccess() {
                        sendSignal(P2pCallSignalCodec.Signal.Answer(id, description.description))
                        localDescriptionSignaled = true
                        flushLocalCandidates()
                    }
                    override fun onSetFailure(error: String?) = fail("Impossible d'appliquer la réponse : $error")
                }, description)
            }
            override fun onCreateFailure(error: String?) = fail("Création de la réponse impossible : $error")
        }, MediaConstraints())
    }

    private fun ensurePeerConnection() {
        if (peerConnection != null) return
        val config = PeerConnection.RTCConfiguration(emptyList()).apply {
            sdpSemantics = PeerConnection.SdpSemantics.UNIFIED_PLAN
            iceTransportsType = PeerConnection.IceTransportsType.ALL
            bundlePolicy = PeerConnection.BundlePolicy.MAXBUNDLE
            rtcpMuxPolicy = PeerConnection.RtcpMuxPolicy.REQUIRE
            continualGatheringPolicy = PeerConnection.ContinualGatheringPolicy.GATHER_CONTINUALLY
            iceCandidatePoolSize = 0
        }
        peerConnection = factory.createPeerConnection(config, object : PeerConnection.Observer {
            override fun onSignalingChange(state: PeerConnection.SignalingState?) = Unit
            override fun onIceConnectionChange(state: PeerConnection.IceConnectionState?) {
                when (state) {
                    PeerConnection.IceConnectionState.CONNECTED,
                    PeerConnection.IceConnectionState.COMPLETED -> onStateChanged("Appel P2P connecté.")
                    PeerConnection.IceConnectionState.DISCONNECTED -> onStateChanged("Connexion média interrompue.")
                    PeerConnection.IceConnectionState.FAILED -> fail("Connexion média directe impossible sur ce réseau.")
                    PeerConnection.IceConnectionState.CLOSED -> onStateChanged("Appel fermé.")
                    else -> Unit
                }
            }
            override fun onIceConnectionReceivingChange(receiving: Boolean) = Unit
            override fun onIceGatheringChange(state: PeerConnection.IceGatheringState?) = Unit
            override fun onIceCandidate(candidate: IceCandidate?) {
                val id = callId ?: return
                if (candidate != null) {
                    if (localDescriptionSignaled) sendIceCandidate(id, candidate)
                    else pendingLocalCandidates.add(candidate)
                }
            }
            override fun onIceCandidatesRemoved(candidates: Array<out IceCandidate>?) = Unit
            override fun onAddStream(stream: MediaStream?) {
                stream?.videoTracks?.firstOrNull()?.let(::attachRemoteVideo)
            }
            override fun onRemoveStream(stream: MediaStream?) = Unit
            override fun onDataChannel(channel: org.webrtc.DataChannel?) = Unit
            override fun onRenegotiationNeeded() = Unit
            override fun onAddTrack(receiver: RtpReceiver?, streams: Array<out MediaStream>?) {
                (receiver?.track() as? VideoTrack)?.let(::attachRemoteVideo)
            }
        })
        check(peerConnection != null) { "Création du pair WebRTC impossible." }
    }

    private fun addLocalMedia() {
        if (audioTrack == null) {
            val source = factory.createAudioSource(MediaConstraints())
            val track = factory.createAudioTrack("aegis-audio", source)
            audioSource = source
            audioTrack = track
            peerConnection?.addTrack(track, listOf("aegis-stream"))
        }
        if (videoTrack == null && hasPermission(Manifest.permission.CAMERA)) {
            val enumerator = Camera2Enumerator(appContext)
            val cameraName = enumerator.deviceNames.firstOrNull { enumerator.isFrontFacing(it) }
                ?: enumerator.deviceNames.firstOrNull()
            if (cameraName != null) {
                val capturer = enumerator.createCapturer(cameraName, null)
                if (capturer != null) {
                    cameraCapturer = capturer
                    val source = factory.createVideoSource(false)
                    val textureHelper = SurfaceTextureHelper.create("AegisCamera", egl.eglBaseContext)
                    videoSource = source
                    surfaceTextureHelper = textureHelper
                    capturer.initialize(textureHelper, appContext, source.capturerObserver)
                    capturer.startCapture(VIDEO_WIDTH, VIDEO_HEIGHT, VIDEO_FPS)
                    val track = factory.createVideoTrack("aegis-video", source)
                    videoTrack = track
                    localRenderer?.let(track::addSink)
                    peerConnection?.addTrack(track, listOf("aegis-stream"))
                }
            }
        }
    }

    private fun attachRemoteVideo(track: VideoTrack) {
        remoteVideoTrack?.let { old -> remoteRenderer?.let(old::removeSink) }
        remoteVideoTrack = track
        remoteRenderer?.let(track::addSink)
    }

    private fun flushPendingCandidates() {
        pendingCandidates.forEach { peerConnection?.addIceCandidate(it) }
        pendingCandidates.clear()
    }

    private fun flushLocalCandidates() {
        val id = callId ?: return
        pendingLocalCandidates.forEach { sendIceCandidate(id, it) }
        pendingLocalCandidates.clear()
    }

    private fun sendIceCandidate(id: String, candidate: IceCandidate) {
        sendSignal(
            P2pCallSignalCodec.Signal.Candidate(
                id, candidate.sdpMid, candidate.sdpMLineIndex, candidate.sdp
            )
        )
    }

    private fun sendSignal(signal: P2pCallSignalCodec.Signal) {
        try {
            sendSignalFrame(P2pCallSignalCodec.encode(signal))
        } catch (failure: Exception) {
            fail(failure.message ?: "Envoi de signalisation impossible.")
        }
    }

    private fun fail(message: String) {
        onStateChanged(message)
    }

    private fun hasPermission(permission: String) =
        ContextCompat.checkSelfPermission(appContext, permission) == PackageManager.PERMISSION_GRANTED

    private fun closePeerConnection() {
        runCatching { cameraCapturer?.stopCapture() }
        runCatching { cameraCapturer?.dispose() }
        cameraCapturer = null
        runCatching { videoTrack?.let { track -> localRenderer?.let(track::removeSink) } }
        runCatching { remoteVideoTrack?.let { track -> remoteRenderer?.let(track::removeSink) } }
        videoTrack?.dispose()
        videoTrack = null
        remoteVideoTrack = null
        videoSource?.dispose()
        videoSource = null
        surfaceTextureHelper?.dispose()
        surfaceTextureHelper = null
        audioTrack?.dispose()
        audioTrack = null
        audioSource?.dispose()
        audioSource = null
        peerConnection?.close()
        peerConnection?.dispose()
        peerConnection = null
        pendingCandidates.clear()
        pendingLocalCandidates.clear()
        localDescriptionSignaled = false
        remoteDescriptionSet = false
        callId = null
    }

    override fun close() {
        if (closed) return
        closed = true
        closePeerConnection()
        runCatching { localRenderer?.release() }
        runCatching { remoteRenderer?.release() }
        localRenderer = null
        remoteRenderer = null
        factory.dispose()
        egl.release()
    }

    private open class SdpObserverAdapter : SdpObserver {
        override fun onCreateSuccess(description: SessionDescription?) = Unit
        override fun onSetSuccess() = Unit
        override fun onCreateFailure(error: String?) = Unit
        override fun onSetFailure(error: String?) = Unit
    }

    companion object {
        private const val VIDEO_WIDTH = 640
        private const val VIDEO_HEIGHT = 480
        private const val VIDEO_FPS = 24
        @Volatile private var initialized = false
        private val initLock = Any()

        private fun ensureWebRtcInitialized(context: Context) {
            if (initialized) return
            synchronized(initLock) {
                if (!initialized) {
                    PeerConnectionFactory.initialize(
                        PeerConnectionFactory.InitializationOptions.builder(context).createInitializationOptions()
                    )
                    initialized = true
                }
            }
        }
    }
}
