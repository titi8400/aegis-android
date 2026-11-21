package fr.aegis.android.ui

import android.provider.OpenableColumns
import android.Manifest
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaRecorder
import android.os.SystemClock
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Looper
import android.os.Bundle
import android.os.Handler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import fr.aegis.android.security.AndroidKeyStoreIdentity
import fr.aegis.android.security.ConversationStore
import fr.aegis.android.security.IncomingFileAssembler
import fr.aegis.android.security.P2pFileTransferCodec
import fr.aegis.android.security.ReceivedFileStore
import fr.aegis.android.security.P2pLanDiscovery
import fr.aegis.android.security.P2pLanTransport
import fr.aegis.android.security.P2pWireCodec
import fr.aegis.android.security.TrustedPeerStore
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.net.Inet4Address
import java.net.NetworkInterface
import java.nio.charset.StandardCharsets
import kotlin.concurrent.thread
import kotlinx.coroutines.delay
import java.util.UUID
import java.util.Locale
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.atomic.AtomicBoolean

private data class ChatLine(val outgoing: Boolean, val body: String, val ephemeral: Boolean = false)

@Composable
fun P2pChatScreen(
    identity: AndroidKeyStoreIdentity,
    onClose: () -> Unit
) {
    val context = LocalContext.current
    val peerStore = remember { TrustedPeerStore(context.applicationContext) }
    val conversationStore = remember { ConversationStore(context.applicationContext) }
    val receivedFileStore = remember { ReceivedFileStore(context.applicationContext) }
    val receivedFiles = remember { mutableStateListOf<ReceivedFileStore.ReceivedFile>() }
    var pendingExportId by remember { mutableStateOf<String?>(null) }
    val transport = remember { P2pLanTransport(identity, peerStore) }
    val discovery = remember { P2pLanDiscovery(identity, peerStore) }
    val discoveredPeers = remember { mutableStateListOf<P2pLanDiscovery.DiscoveredPeer>() }
    val mainHandler = remember { Handler(Looper.getMainLooper()) }
    val history = remember { mutableStateListOf<ChatLine>() }
    var host by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("Hors connexion — aucun pair connecté.") }
    var error by remember { mutableStateOf<String?>(null) }
    var session by remember { mutableStateOf<P2pLanTransport.SecureSession?>(null) }
    var activePeerId by remember { mutableStateOf<String?>(null) }
    var listening by remember { mutableStateOf(false) }
    var ephemeralMinutes by remember { mutableStateOf(0) }
    var isSendingFile by remember { mutableStateOf(false) }
    var isRecordingVoice by remember { mutableStateOf(false) }
    var audioRecorder by remember { mutableStateOf<AudioRecord?>(null) }
    var recordingStopFlag by remember { mutableStateOf<AtomicBoolean?>(null) }
    var locationPermissionGranted by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED ||
                ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED
        )
    }
    fun startVoiceRecording() {
        val current = session
        if (current == null) {
            error = "Aucun pair connecté."
            return
        }
        try {
            val sampleRate = 16_000
            val channelMask = AudioFormat.CHANNEL_IN_MONO
            val encoding = AudioFormat.ENCODING_PCM_16BIT
            val minBuffer = AudioRecord.getMinBufferSize(sampleRate, channelMask, encoding)
            require(minBuffer > 0) { "Enregistrement audio non pris en charge." }
            val recorder = AudioRecord.Builder()
                .setAudioSource(MediaRecorder.AudioSource.VOICE_RECOGNITION)
                .setAudioFormat(
                    AudioFormat.Builder()
                        .setSampleRate(sampleRate)
                        .setChannelMask(channelMask)
                        .setEncoding(encoding)
                        .build()
                )
                .setBufferSizeInBytes(maxOf(minBuffer * 2, 8_192))
                .build()
            check(recorder.state == AudioRecord.STATE_INITIALIZED) {
                "Microphone indisponible sur cet appareil."
            }
            val stopFlag = AtomicBoolean(true)
            recorder.startRecording()
            audioRecorder = recorder
            recordingStopFlag = stopFlag
            isRecordingVoice = true
            status = "Enregistrement vocal — maximum 30 secondes."
            thread(name = "aegis-voice-note", isDaemon = true) {
                val pcmOutput = ByteArrayOutputStream()
                val buffer = ByteArray(8_192)
                try {
                    val startedAt = SystemClock.elapsedRealtime()
                    while (stopFlag.get() && SystemClock.elapsedRealtime() - startedAt < 30_000L) {
                        val count = recorder.read(buffer, 0, buffer.size)
                        if (count > 0) pcmOutput.write(buffer, 0, count)
                        else if (count < 0) throw IllegalStateException("Erreur de lecture du microphone.")
                    }
                    if (recorder.recordingState == AudioRecord.RECORDSTATE_RECORDING) recorder.stop()
                    val pcm = pcmOutput.toByteArray()
                    require(pcm.isNotEmpty()) { "Aucun son enregistré." }
                    val wav = createWavBytes(pcm, sampleRate)
                    pcm.fill(0)
                    sendFileBytes(
                        current,
                        "note-vocale-${System.currentTimeMillis()}.wav",
                        "audio/wav",
                        wav
                    )
                    mainHandler.post {
                        status = "Note vocale transmise."
                        error = null
                    }
                } catch (failure: Exception) {
                    mainHandler.post { error = failure.message ?: "Enregistrement ou envoi vocal impossible." }
                } finally {
                    buffer.fill(0)
                    pcmOutput.reset()
                    runCatching {
                        if (recorder.recordingState == AudioRecord.RECORDSTATE_RECORDING) recorder.stop()
                    }
                    recorder.release()
                    mainHandler.post {
                        audioRecorder = null
                        recordingStopFlag = null
                        isRecordingVoice = false
                    }
                }
            }
        } catch (failure: Exception) {
            audioRecorder?.let { runCatching { it.release() } }
            audioRecorder = null
            recordingStopFlag = null
            isRecordingVoice = false
            error = failure.message ?: "Impossible de démarrer l’enregistrement."
        }
    }

    val audioPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) startVoiceRecording()
        else error = "Autorisation microphone refusée."
    }

    fun shareCurrentLocation() {
        val current = session
        val peerId = activePeerId
        if (current == null || peerId == null) {
            error = "Aucun pair connecté."
            return
        }
        val manager = context.getSystemService(android.content.Context.LOCATION_SERVICE) as LocationManager
        val hasFinePermission = ContextCompat.checkSelfPermission(
            context, Manifest.permission.ACCESS_FINE_LOCATION
        ) == PackageManager.PERMISSION_GRANTED
        val provider = when {
            hasFinePermission && manager.isProviderEnabled(LocationManager.GPS_PROVIDER) -> LocationManager.GPS_PROVIDER
            manager.isProviderEnabled(LocationManager.NETWORK_PROVIDER) -> LocationManager.NETWORK_PROVIDER
            else -> {
                error = "Aucun fournisseur de localisation activé."
                return
            }
        }
        var listener: LocationListener? = null
        status = "Recherche d’une position actuelle…"
        val timeout = Runnable {
            listener?.let { runCatching { manager.removeUpdates(it) } }
            if (status == "Recherche d’une position actuelle…") {
                status = "Position indisponible (délai dépassé)."
            }
        }
        listener = object : LocationListener {
            override fun onStatusChanged(provider: String?, status: Int, extras: Bundle?) = Unit
            override fun onProviderEnabled(provider: String) = Unit
            override fun onProviderDisabled(provider: String) = Unit

            override fun onLocationChanged(location: Location) {
                manager.removeUpdates(this)
                mainHandler.removeCallbacks(timeout)
                try {
                    val latitude = String.format(Locale.US, "%.6f", location.latitude)
                    val longitude = String.format(Locale.US, "%.6f", location.longitude)
                    val body = "Ma position : https://maps.google.com/?q=$latitude,$longitude (précision ±${location.accuracy.toInt()} m)"
                    val createdAt = System.currentTimeMillis()
                    val expiresAt = if (ephemeralMinutes == 0) null else createdAt + ephemeralMinutes * 60_000L
                    val messageId = UUID.randomUUID().toString()
                    val frame = P2pWireCodec.encodeText(body, createdAt, expiresAt, messageId)
                    current.sendFrame(frame)
                    frame.fill(0)
                    conversationStore.append(
                        peerId, body, outgoing = true, nowEpochMs = createdAt,
                        expiresAtEpochMs = expiresAt, messageId = messageId, createdAtEpochMs = createdAt
                    )
                    history.add(ChatLine(true, body, expiresAt != null))
                    status = "Position partagée avec le pair connecté."
                    error = null
                } catch (failure: Exception) {
                    error = failure.message ?: "Partage de position impossible."
                }
            }
        }
        try {
            manager.requestSingleUpdate(provider, listener!!, Looper.getMainLooper())
            mainHandler.postDelayed(timeout, 20_000L)
        } catch (failure: SecurityException) {
            error = "Autorisation de localisation refusée."
        } catch (failure: Exception) {
            error = failure.message ?: "Impossible d'obtenir la position."
        }
    }

    val locationPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        locationPermissionGranted = grants[Manifest.permission.ACCESS_FINE_LOCATION] == true ||
            grants[Manifest.permission.ACCESS_COARSE_LOCATION] == true
        if (locationPermissionGranted) shareCurrentLocation()
        else error = "Autorisation de localisation refusée."
    }
    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val fileId = pendingExportId
        pendingExportId = null
        if (uri != null && fileId != null) {
            thread(name = "aegis-file-export", isDaemon = true) {
                try {
                    val bytes = receivedFileStore.read(fileId) ?: throw IllegalStateException("Fichier reçu introuvable.")
                    try {
                        context.contentResolver.openOutputStream(uri, "w")?.use { output -> output.write(bytes) }
                            ?: throw IllegalStateException("Impossible d’écrire le fichier exporté.")
                    } finally {
                        bytes.fill(0)
                    }
                    mainHandler.post { status = "Fichier exporté dans l’emplacement choisi." }
                } catch (failure: Exception) {
                    mainHandler.post { error = failure.message ?: "Export du fichier impossible." }
                }
            }
        }
    }
    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val current = session
        if (uri != null && current != null && !isSendingFile) {
            isSendingFile = true
            thread(name = "aegis-file-send", isDaemon = true) {
                var fileBytes: ByteArray? = null
                var fileDigest: ByteArray? = null
                try {
                    var name = "fichier-aegis"
                    var reportedSize = -1L
                    context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { cursor ->
                        if (cursor.moveToFirst()) {
                            val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                            val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                            if (nameIndex >= 0) name = cursor.getString(nameIndex) ?: name
                            if (sizeIndex >= 0 && !cursor.isNull(sizeIndex)) reportedSize = cursor.getLong(sizeIndex)
                        }
                    }
                    val safeName = P2pFileTransferCodec.sanitizeFileName(name)
                    val mime = context.contentResolver.getType(uri) ?: "application/octet-stream"
                    if (reportedSize > P2pFileTransferCodec.MAX_FILE_BYTES) throw IllegalArgumentException("Fichier supérieur à 20 Mio.")
                    val bytes = context.contentResolver.openInputStream(uri)?.use { input ->
                        val output = ByteArrayOutputStream()
                        val buffer = ByteArray(64 * 1024)
                        var total = 0L
                        while (true) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            total += count
                            require(total <= P2pFileTransferCodec.MAX_FILE_BYTES) { "Fichier supérieur à 20 Mio." }
                            output.write(buffer, 0, count)
                        }
                        buffer.fill(0)
                        output.toByteArray()
                    } ?: throw IllegalStateException("Impossible de lire le fichier sélectionné.")
                    fileBytes = bytes
                    require(bytes.isNotEmpty()) { "Fichier vide." }
                    sendFileBytes(current, safeName, mime, bytes)
                    mainHandler.post { status = "Fichier transmis : $safeName"; error = null }
                } catch (failure: Exception) {
                    mainHandler.post { error = failure.message ?: "Transfert de fichier impossible." }
                } finally {
                    fileBytes?.fill(0)
                    fileDigest?.fill(0)
                    mainHandler.post { isSendingFile = false }
                }
            }
        }
    }

    fun attachSession(connected: P2pLanTransport.SecureSession, label: String) {
        session?.close()
        session = connected
        activePeerId = connected.remoteDeviceId
        receivedFiles.clear()
        runCatching { receivedFileStore.list() }.onSuccess { receivedFiles.addAll(it) }
        history.clear()
        try {
            conversationStore.list(connected.remoteDeviceId).forEach { saved ->
                history.add(ChatLine(saved.outgoing, saved.body, saved.expiresAtEpochMs != null))
            }
        } catch (failure: Exception) {
            error = failure.message ?: "Impossible de lire l’historique chiffré."
        }
        status = "Connexion TLS mutuellement authentifiée : $label"
        val fileAssembler = IncomingFileAssembler()
        thread(name = "aegis-p2p-reader", isDaemon = true) {
            try {
                while (connected.isOpen) {
                    val frame = connected.readFrame()
                    if (P2pFileTransferCodec.isFilePacket(frame)) {
                        val packet = P2pFileTransferCodec.decode(frame)
                        frame.fill(0)
                        val completed = fileAssembler.accept(packet)
                        if (completed != null) {
                            try {
                                receivedFileStore.save(completed.transferId, completed.fileName, completed.mimeType, completed.bytes)
                            } finally {
                                completed.bytes.fill(0)
                                completed.sha256.fill(0)
                            }
                            mainHandler.post {
                                receivedFiles.clear()
                                receivedFiles.addAll(receivedFileStore.list())
                                status = "Fichier reçu et conservé dans le coffre chiffré."
                            }
                        }
                        continue
                    }
                    val decoded = P2pWireCodec.decodeText(frame)
                    frame.fill(0)
                    if (decoded != null) {
                        conversationStore.append(
                            connected.remoteDeviceId,
                            decoded.body,
                            outgoing = false,
                            expiresAtEpochMs = decoded.expiresAtEpochMs,
                            messageId = decoded.id,
                            createdAtEpochMs = decoded.createdAtEpochMs
                        )
                        mainHandler.post { history.add(ChatLine(false, decoded.body, decoded.expiresAtEpochMs != null)) }
                    }
                }
            } catch (failure: Exception) {
                fileAssembler.cancel()
                mainHandler.post {
                    if (session === connected) {
                        session = null
                        status = "Connexion interrompue."
                        error = failure.message
                    }
                }
            }
        }
    }

    LaunchedEffect(activePeerId) {
        val peerId = activePeerId
        if (peerId != null) {
            while (true) {
                delay(5_000)
                runCatching { conversationStore.list(peerId) }
                    .onSuccess { saved ->
                        history.clear()
                        saved.forEach { history.add(ChatLine(it.outgoing, it.body, it.expiresAtEpochMs != null)) }
                    }
                    .onFailure { error = it.message ?: "Impossible de nettoyer l’historique." }
            }
        }
    }

    DisposableEffect(Unit) {
        try {
            discovery.start(
                onPeerFound = { peer ->
                    mainHandler.post {
                        val index = discoveredPeers.indexOfFirst { it.deviceId == peer.deviceId }
                        if (index >= 0) discoveredPeers[index] = peer else discoveredPeers.add(peer)
                    }
                },
                onError = { failure -> mainHandler.post { error = failure.message } }
            )
        } catch (failure: Exception) {
            error = failure.message ?: "Découverte locale indisponible."
        }
        onDispose {
            recordingStopFlag?.set(false)
            discovery.close()
            transport.close()
            session?.close()
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(18.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Text("AEGIS / LIAISON DIRECTE", color = Color.White, fontWeight = FontWeight.Black, fontSize = 18.sp)
        Text("TCP local • TLS 1.2/1.3 • authentification mutuelle par clés approuvées", color = Color(0xFF8292A3), fontSize = 10.sp)
        Text(status, color = if (session != null) Color(0xFF39D98A) else Color(0xFF00BFFF), fontSize = 11.sp)
        error?.let { Text(it, color = Color(0xFFFF7070), fontSize = 10.sp) }
        Text("IP locales : ${localIpv4Addresses().ifEmpty { listOf("indisponible") }.joinToString(" • ")}", color = Color(0xFF8292A3), fontSize = 10.sp)
        Text("Port : ${P2pLanTransport.DEFAULT_PORT}", color = Color(0xFF8292A3), fontSize = 10.sp)
        Text("APPAREILS DE CONFIANCE DÉTECTÉS", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 10.sp)
        if (discoveredPeers.isEmpty()) {
            Text("Recherche des appareils approuvés sur le même réseau local…", color = Color(0xFF8292A3), fontSize = 10.sp)
        } else {
            discoveredPeers.forEach { peer ->
                Button(
                    onClick = { host = peer.address },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10233B), contentColor = Color(0xFF00BFFF))
                ) { Text("${peer.displayName} • ${peer.address} • PORT ${peer.port}") }
            }
        }

        Button(
            onClick = {
                if (!listening) {
                    listening = true
                    status = "En attente d’un appareil approuvé sur le réseau local…"
                    try {
                        transport.listen(
                            onConnection = { connection ->
                                mainHandler.post { attachSession(connection.session, connection.remoteAddress.hostAddress ?: "pair local") }
                            },
                            onError = { failure ->
                                mainHandler.post {
                                    error = failure.message ?: "Erreur du serveur local."
                                    listening = false
                                }
                            }
                        )
                    } catch (failure: Exception) {
                        listening = false
                        error = failure.message ?: "Impossible d’ouvrir le port local."
                    }
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = !listening && session == null,
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10233B), contentColor = Color(0xFF00BFFF))
        ) { Text(if (listening) "ÉCOUTE ACTIVE" else "ATTENDRE UN PAIR") }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = host,
                onValueChange = { host = it.take(253) },
                modifier = Modifier.weight(1f),
                singleLine = true,
                label = { Text("Adresse IP du pair") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri)
            )
            Button(
                onClick = {
                    error = null
                    status = "Connexion directe en cours…"
                    thread(name = "aegis-p2p-connect", isDaemon = true) {
                        try {
                            val connected = transport.connect(host.trim())
                            mainHandler.post { attachSession(connected, host.trim()) }
                        } catch (failure: Exception) {
                            mainHandler.post {
                                status = "Connexion refusée."
                                error = failure.message ?: "Échec de connexion directe."
                            }
                        }
                    }
                },
                enabled = host.isNotBlank() && session == null,
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF00BFFF), contentColor = Color(0xFF00131D))
            ) { Text("CONNECTER") }
        }

        LazyColumn(
            modifier = Modifier.weight(1f).fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(7.dp)
        ) {
            items(history) { line ->
                Text(
                    text = (if (line.outgoing) "MOI  •  " else "PAIR  •  ") + line.body + if (line.ephemeral) "  •  ÉPHÉMÈRE" else "",
                    color = if (line.outgoing) Color(0xFF00BFFF) else Color.White,
                    fontSize = 12.sp
                )
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(5.dp)) {
            FilterChip(selected = ephemeralMinutes == 0, onClick = { ephemeralMinutes = 0 }, label = { Text("DURABLE") })
            FilterChip(selected = ephemeralMinutes == 1, onClick = { ephemeralMinutes = 1 }, label = { Text("1 MIN") })
            FilterChip(selected = ephemeralMinutes == 60, onClick = { ephemeralMinutes = 60 }, label = { Text("1 H") })
            FilterChip(selected = ephemeralMinutes == 1440, onClick = { ephemeralMinutes = 1440 }, label = { Text("24 H") })
        }
        OutlinedTextField(
            value = message,
            onValueChange = { message = it.take(4096) },
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Message") },
            enabled = session != null
        )
        Button(
            onClick = {
                if (locationPermissionGranted) shareCurrentLocation()
                else locationPermissionLauncher.launch(arrayOf(
                    Manifest.permission.ACCESS_FINE_LOCATION,
                    Manifest.permission.ACCESS_COARSE_LOCATION
                ))
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = session != null,
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10233B), contentColor = Color(0xFF00BFFF))
        ) { Text("PARTAGER MA POSITION ACTUELLE") }

        Button(
            onClick = {
                if (isRecordingVoice) {
                    recordingStopFlag?.set(false)
                    status = "Finalisation de la note vocale…"
                } else if (ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) {
                    startVoiceRecording()
                } else {
                    audioPermissionLauncher.launch(Manifest.permission.RECORD_AUDIO)
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = session != null,
            colors = ButtonDefaults.buttonColors(
                containerColor = if (isRecordingVoice) Color(0xFF7A2630) else Color(0xFF10233B),
                contentColor = Color.White
            )
        ) { Text(if (isRecordingVoice) "ARRÊTER ET ENVOYER LA NOTE VOCALE" else "ENREGISTRER UNE NOTE VOCALE (30 S)") }

        Button(
            onClick = { importLauncher.launch(arrayOf("*/*")) },
            modifier = Modifier.fillMaxWidth(),
            enabled = session != null && !isSendingFile,
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10233B), contentColor = Color(0xFF00BFFF))
        ) { Text(if (isSendingFile) "TRANSFERT EN COURS…" else "ENVOYER UN FICHIER (20 MIO MAX.)") }

        if (receivedFiles.isNotEmpty()) {
            Text("FICHIERS REÇUS — COFFRE CHIFFRÉ", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 10.sp)
            receivedFiles.forEach { file ->
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    if (file.mimeType == "audio/wav") {
                        Button(
                            onClick = {
                                thread(name = "aegis-voice-playback", isDaemon = true) {
                                    try {
                                        val bytes = receivedFileStore.read(file.id) ?: throw IllegalStateException("Note vocale introuvable.")
                                        try {
                                            playWavBytes(bytes)
                                            mainHandler.post { status = "Lecture terminée." }
                                        } finally {
                                            bytes.fill(0)
                                        }
                                    } catch (failure: Exception) {
                                        mainHandler.post { error = failure.message ?: "Lecture audio impossible." }
                                    }
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10233B), contentColor = Color(0xFF39D98A))
                        ) { Text("ÉCOUTER") }
                    }
                    Button(
                        onClick = {
                            pendingExportId = file.id
                            exportLauncher.launch(file.fileName)
                        },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10233B), contentColor = Color(0xFF00BFFF))
                    ) { Text("EXPORTER • ${file.fileName} • ${file.size / 1024} Kio") }
                    Button(
                        onClick = {
                            runCatching { receivedFileStore.delete(file.id) }
                                .onSuccess { receivedFiles.remove(file) }
                                .onFailure { error = it.message ?: "Suppression impossible." }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF26313E), contentColor = Color(0xFFFF7070))
                    ) { Text("SUPPRIMER") }
                }
            }
        }

        Button(
            onClick = {
                val current = session ?: return@Button
                val body = message.trim()
                if (body.isNotEmpty()) {
                    try {
                        val peerId = activePeerId ?: throw IllegalStateException("Identité du pair non disponible.")
                        val createdAt = System.currentTimeMillis()
                        val expiresAt = if (ephemeralMinutes == 0) null else createdAt + ephemeralMinutes * 60_000L
                        val messageId = UUID.randomUUID().toString()
                        val frame = P2pWireCodec.encodeText(body, createdAt, expiresAt, messageId)
                        current.sendFrame(frame)
                        frame.fill(0)
                        conversationStore.append(
                            peerId,
                            body,
                            outgoing = true,
                            nowEpochMs = createdAt,
                            expiresAtEpochMs = expiresAt,
                            messageId = messageId,
                            createdAtEpochMs = createdAt
                        )
                        history.add(ChatLine(true, body, expiresAt != null))
                        message = ""
                        error = null
                    } catch (failure: Exception) {
                        error = failure.message ?: "Envoi impossible."
                        current.close()
                        session = null
                    }
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = session != null && message.isNotBlank(),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF39D98A), contentColor = Color(0xFF00150B))
        ) { Text("ENVOYER") }

        Button(
            onClick = onClose,
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF26313E), contentColor = Color.White),
            shape = RoundedCornerShape(10.dp)
        ) { Text("RETOUR") }
    }
}


private fun playWavBytes(bytes: ByteArray) {
    require(bytes.size >= 44) { "Fichier WAV incomplet." }
    val header = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    val riff = String(bytes, 0, 4, Charsets.US_ASCII)
    val wave = String(bytes, 8, 4, Charsets.US_ASCII)
    require(riff == "RIFF" && wave == "WAVE") { "Format WAV invalide." }
    val channels = header.getShort(22).toInt()
    val sampleRate = header.getInt(24)
    val bitsPerSample = header.getShort(34).toInt()
    val dataSize = header.getInt(40)
    require(channels == 1 && bitsPerSample == 16 && sampleRate in 8_000..48_000) {
        "Format audio non pris en charge."
    }
    require(dataSize > 0 && dataSize <= bytes.size - 44 && dataSize % 2 == 0) {
        "Données audio WAV invalides."
    }
    val audioFormat = AudioFormat.Builder()
        .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
        .setSampleRate(sampleRate)
        .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
        .build()
    val attributes = AudioAttributes.Builder()
        .setUsage(AudioAttributes.USAGE_MEDIA)
        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
        .build()
    val track = AudioTrack.Builder()
        .setAudioAttributes(attributes)
        .setAudioFormat(audioFormat)
        .setTransferMode(AudioTrack.MODE_STATIC)
        .setBufferSizeInBytes(dataSize)
        .build()
    try {
        var offset = 0
        while (offset < dataSize) {
            val written = track.write(bytes, 44 + offset, dataSize - offset, AudioTrack.WRITE_BLOCKING)
            require(written > 0) { "Écriture audio interrompue." }
            offset += written
        }
        track.play()
        val expectedFrames = dataSize / 2
        while (track.playbackHeadPosition < expectedFrames && track.playState == AudioTrack.PLAYSTATE_PLAYING) {
            Thread.sleep(20)
        }
    } finally {
        runCatching {
            if (track.playState == AudioTrack.PLAYSTATE_PLAYING) track.stop()
        }
        track.release()
    }
}

private fun createWavBytes(pcm: ByteArray, sampleRate: Int): ByteArray {
    require(pcm.isNotEmpty() && pcm.size <= 20 * 1024 * 1024 - 44) { "Note vocale trop volumineuse." }
    val header = ByteBuffer.allocate(44).order(ByteOrder.LITTLE_ENDIAN)
    header.put("RIFF".toByteArray(Charsets.US_ASCII))
    header.putInt(36 + pcm.size)
    header.put("WAVE".toByteArray(Charsets.US_ASCII))
    header.put("fmt ".toByteArray(Charsets.US_ASCII))
    header.putInt(16)
    header.putShort(1.toShort())
    header.putShort(1.toShort())
    header.putInt(sampleRate)
    header.putInt(sampleRate * 2)
    header.putShort(2.toShort())
    header.putShort(16.toShort())
    header.put("data".toByteArray(Charsets.US_ASCII))
    header.putInt(pcm.size)
    return ByteArray(44 + pcm.size).also {
        header.array().copyInto(it, 0)
        pcm.copyInto(it, 44)
    }
}

private fun sendFileBytes(
    session: P2pLanTransport.SecureSession,
    fileName: String,
    mimeType: String,
    bytes: ByteArray
) {
    require(bytes.isNotEmpty() && bytes.size.toLong() <= P2pFileTransferCodec.MAX_FILE_BYTES) {
        "Fichier vide ou supérieur à 20 Mio."
    }
    var digest: ByteArray? = null
    try {
        val transferId = UUID.randomUUID().toString()
        session.sendFrame(
            P2pFileTransferCodec.encodeStart(
                P2pFileTransferCodec.Packet.Start(transferId, fileName, mimeType, bytes.size.toLong())
            )
        )
        var index = 0
        var offset = 0
        while (offset < bytes.size) {
            val end = minOf(offset + P2pFileTransferCodec.CHUNK_BYTES, bytes.size)
            val chunk = bytes.copyOfRange(offset, end)
            val frame = P2pFileTransferCodec.encodeChunk(transferId, index, chunk)
            try {
                session.sendFrame(frame)
            } finally {
                chunk.fill(0)
                frame.fill(0)
            }
            offset = end
            index++
        }
        digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        session.sendFrame(P2pFileTransferCodec.encodeFinish(transferId, digest))
    } finally {
        digest?.fill(0)
        bytes.fill(0)
    }
}

private fun localIpv4Addresses(): List<String> = runCatching {
    NetworkInterface.getNetworkInterfaces().toList()
        .filter { it.isUp && !it.isLoopback }
        .flatMap { it.inetAddresses.toList() }
        .filterIsInstance<Inet4Address>()
        .filterNot { it.isLoopbackAddress || it.isLinkLocalAddress }
        .mapNotNull { it.hostAddress }
        .distinct()
}.getOrDefault(emptyList())
