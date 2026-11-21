package fr.aegis.android.ui

import android.os.Handler
import android.os.Looper
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
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import fr.aegis.android.security.AndroidKeyStoreIdentity
import fr.aegis.android.security.P2pLanTransport
import fr.aegis.android.security.TrustedPeerStore
import java.net.Inet4Address
import java.net.NetworkInterface
import java.nio.charset.StandardCharsets
import kotlin.concurrent.thread

private data class ChatLine(val outgoing: Boolean, val body: String)

@Composable
fun P2pChatScreen(
    identity: AndroidKeyStoreIdentity,
    onClose: () -> Unit
) {
    val transport = remember {
        P2pLanTransport(identity, TrustedPeerStore(
            androidx.compose.ui.platform.LocalContext.current.applicationContext
        ))
    }
    val mainHandler = remember { Handler(Looper.getMainLooper()) }
    val history = remember { mutableStateListOf<ChatLine>() }
    var host by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("Hors connexion — aucun pair connecté.") }
    var error by remember { mutableStateOf<String?>(null) }
    var session by remember { mutableStateOf<P2pLanTransport.SecureSession?>(null) }
    var listening by remember { mutableStateOf(false) }

    fun attachSession(connected: P2pLanTransport.SecureSession, label: String) {
        session?.close()
        session = connected
        status = "Connexion TLS mutuellement authentifiée : $label"
        error = null
        thread(name = "aegis-p2p-reader", isDaemon = true) {
            try {
                while (connected.isOpen) {
                    val frame = connected.readFrame()
                    val text = frame.toString(StandardCharsets.UTF_8)
                    frame.fill(0)
                    mainHandler.post { history.add(ChatLine(false, text)) }
                }
            } catch (failure: Exception) {
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

    DisposableEffect(Unit) {
        onDispose { transport.close(); session?.close() }
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
                    text = (if (line.outgoing) "MOI  •  " else "PAIR  •  ") + line.body,
                    color = if (line.outgoing) Color(0xFF00BFFF) else Color.White,
                    fontSize = 12.sp
                )
            }
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
                val current = session ?: return@Button
                val body = message.trim()
                if (body.isNotEmpty()) {
                    try {
                        current.sendFrame(body.toByteArray(StandardCharsets.UTF_8))
                        history.add(ChatLine(true, body))
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

private fun localIpv4Addresses(): List<String> = runCatching {
    NetworkInterface.getNetworkInterfaces().toList()
        .filter { it.isUp && !it.isLoopback }
        .flatMap { it.inetAddresses.toList() }
        .filterIsInstance<Inet4Address>()
        .filterNot { it.isLoopbackAddress || it.isLinkLocalAddress }
        .mapNotNull { it.hostAddress }
        .distinct()
}.getOrDefault(emptyList())
