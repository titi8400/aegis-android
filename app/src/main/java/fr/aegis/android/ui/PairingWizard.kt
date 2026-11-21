package fr.aegis.android.ui

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.OutlinedTextField
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import fr.aegis.android.security.AndroidKeyStoreIdentity
import fr.aegis.android.security.PairingHandshakeCodec
import fr.aegis.android.security.PairingInviteCodec
import fr.aegis.android.security.PairingQrGenerator
import fr.aegis.android.security.PairingReplayGuard
import fr.aegis.android.security.TrustedPeerStore
import java.security.MessageDigest

private enum class PairingScanMode { INVITE, CHALLENGE, RESPONSE }

@Composable
fun PairingWizard(identity: AndroidKeyStoreIdentity, onClose: () -> Unit) {
    val context = LocalContext.current
    val replayGuard = remember { PairingReplayGuard(context.applicationContext) }
    val peerStore = remember { TrustedPeerStore(context.applicationContext) }
    var scanMode by remember { mutableStateOf<PairingScanMode?>(null) }
    var localInvite by remember { mutableStateOf<PairingInviteCodec.VerifiedInvite?>(null) }
    var remoteInvite by remember { mutableStateOf<PairingInviteCodec.VerifiedInvite?>(null) }
    var verifiedChallenge by remember { mutableStateOf<PairingHandshakeCodec.VerifiedChallenge?>(null) }
    var proof by remember { mutableStateOf<PairingHandshakeCodec.VerifiedHandshake?>(null) }
    var inviteQr by remember { mutableStateOf<Bitmap?>(null) }
    var challengeQr by remember { mutableStateOf<Bitmap?>(null) }
    var responseQr by remember { mutableStateOf<Bitmap?>(null) }
    var remoteFingerprint by remember { mutableStateOf<String?>(null) }
    var peerName by remember { mutableStateOf("Appareil de confiance") }
    var fingerprintsCompared by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("Aucun appairage en cours.") }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var peers by remember { mutableStateOf(peerStore.listPeers()) }

    fun handleScan(payload: String) {
        try {
            when (scanMode) {
                PairingScanMode.INVITE -> {
                    val invite = PairingInviteCodec.verify(payload)
                    replayGuard.consume("invite", invite.nonce, invite.expiresAtEpochMs)
                    remoteInvite = invite
                    remoteFingerprint = invite.fingerprintSha256
                    verifiedChallenge = null
                    proof = null
                    challengeQr = null
                    responseQr = null
                    fingerprintsCompared = false
                    status = "Invitation vérifiée. Compare l’empreinte affichée avec l’autre appareil."
                }
                PairingScanMode.CHALLENGE -> {
                    val expected = localInvite ?: error("Crée d’abord ton invitation locale.")
                    val challenge = PairingHandshakeCodec.verifyChallenge(payload, expected)
                    replayGuard.consume("inviteuse", expected.nonce, expected.expiresAtEpochMs)
                    replayGuard.consume("challenge", challenge.challengeNonce, challenge.createdAtEpochMs + 90_000L)
                    verifiedChallenge = challenge
                    remoteFingerprint = challenge.challengerFingerprint
                    proof = null
                    responseQr = null
                    fingerprintsCompared = false
                    status = "Défi authentifié. Compare l’empreinte du pair, puis génère la réponse."
                }
                PairingScanMode.RESPONSE -> {
                    val challenge = verifiedChallenge ?: error("Aucun défi local en attente.")
                    val expected = remoteInvite ?: error("Invitation distante absente.")
                    val verified = PairingHandshakeCodec.verifyResponse(payload, challenge, expected)
                    replayGuard.consume("response", verified.responderNonce, challenge.createdAtEpochMs + 90_000L)
                    proof = verified
                    remoteFingerprint = verified.responderFingerprint
                    fingerprintsCompared = false
                    status = "Réponse signée vérifiée. Compare les deux empreintes avant d’approuver."
                }
                null -> error("Aucun mode de scan actif.")
            }
            errorMessage = null
        } catch (failure: Exception) {
            errorMessage = failure.message ?: "Échec de vérification de l’appairage."
        } finally {
            scanMode = null
        }
    }

    if (scanMode != null) {
        PairingQrScanner(onInviteScanned = ::handleScan, onClose = { scanMode = null })
        return
    }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Text("AEGIS / APPARIEMENT", color = Color.White, fontWeight = FontWeight.Black, fontSize = 18.sp)
        Text("Échange entièrement hors ligne par QR : invitation → défi signé → réponse signée.", color = Color(0xFF8292A3), fontSize = 11.sp)
        Text(status, color = Color(0xFF39D98A), fontSize = 12.sp)
        errorMessage?.let { Text(it, color = Color(0xFFFF7070), fontSize = 11.sp) }

        Button(
            onClick = {
                try {
                    check(identity.exists()) { "Initialise d’abord ton identité AEGIS." }
                    val encoded = PairingInviteCodec.create(identity)
                    val invite = PairingInviteCodec.verify(encoded)
                    replayGuard.consume("invite", invite.nonce, invite.expiresAtEpochMs)
                    localInvite = invite
                    inviteQr = PairingQrGenerator.generate(encoded)
                    remoteInvite = null
                    verifiedChallenge = null
                    proof = null
                    challengeQr = null
                    responseQr = null
                    remoteFingerprint = null
                    fingerprintsCompared = false
                    status = "Invitation créée. Fais scanner ce QR par l’autre appareil."
                    errorMessage = null
                } catch (failure: Exception) {
                    errorMessage = failure.message ?: "Impossible de créer l’invitation."
                }
            },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF00BFFF), contentColor = Color(0xFF00131D))
        ) { Text("1. CRÉER MON INVITATION") }
        inviteQr?.let { QrPanel("INVITATION — 5 MINUTES", it) }

        Button(
            onClick = { scanMode = PairingScanMode.INVITE },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10233B), contentColor = Color(0xFF00BFFF))
        ) { Text("2. SCANNER L’INVITATION DE L’AUTRE APPAREIL") }

        if (remoteInvite != null) {
            Text("Empreinte de l’appareil invitant :\n$remoteFingerprint", color = Color.White, fontSize = 10.sp)
            Button(
                onClick = {
                    try {
                        val invite = remoteInvite ?: error("Invitation absente.")
                        val encoded = PairingHandshakeCodec.createChallenge(invite, identity)
                        val challenge = PairingHandshakeCodec.verifyChallenge(encoded, invite)
                        replayGuard.consume("inviteuse", invite.nonce, invite.expiresAtEpochMs)
                        replayGuard.consume("challenge", challenge.challengeNonce, challenge.createdAtEpochMs + 90_000L)
                        verifiedChallenge = challenge
                        challengeQr = PairingQrGenerator.generate(encoded)
                        remoteFingerprint = invite.fingerprintSha256
                        fingerprintsCompared = false
                        status = "Défi créé. Fais scanner ce QR par l’appareil qui a généré l’invitation."
                        errorMessage = null
                    } catch (failure: Exception) {
                        errorMessage = failure.message ?: "Impossible de créer le défi."
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10233B), contentColor = Color(0xFF00BFFF))
            ) { Text("3. CRÉER LE DÉFI SIGNÉ") }
            challengeQr?.let { QrPanel("DÉFI — 90 SECONDES", it) }
        }

        if (localInvite != null) {
            Button(
                onClick = { scanMode = PairingScanMode.CHALLENGE },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10233B), contentColor = Color(0xFF00BFFF))
            ) { Text("4. SCANNER LE DÉFI DE L’AUTRE APPAREIL") }
        }

        if (verifiedChallenge != null && localInvite != null) {
            Text("Empreinte du pair ayant signé le défi :\n$remoteFingerprint", color = Color.White, fontSize = 10.sp)
            Button(
                onClick = {
                    try {
                        val challenge = verifiedChallenge ?: error("Défi absent.")
                        val invite = localInvite ?: error("Invitation locale absente.")
                        val packageData = PairingHandshakeCodec.createResponsePackage(challenge, invite, identity)
                        replayGuard.consume("response", packageData.proof.responderNonce, challenge.createdAtEpochMs + 90_000L)
                        proof = packageData.proof
                        responseQr = PairingQrGenerator.generate(packageData.encoded)
                        fingerprintsCompared = false
                        status = "Réponse créée. Fais scanner ce QR par l’appareil qui a créé le défi."
                        errorMessage = null
                    } catch (failure: Exception) {
                        errorMessage = failure.message ?: "Impossible de créer la réponse."
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF00BFFF), contentColor = Color(0xFF00131D))
            ) { Text("5. GÉNÉRER LA RÉPONSE SIGNÉE") }
            responseQr?.let { QrPanel("RÉPONSE — 90 SECONDES", it) }
        }

        if (verifiedChallenge != null && remoteInvite != null) {
            Button(
                onClick = { scanMode = PairingScanMode.RESPONSE },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10233B), contentColor = Color(0xFF00BFFF))
            ) { Text("6. SCANNER LA RÉPONSE DE L’AUTRE APPAREIL") }
        }

        proof?.let { verified ->
            Spacer(Modifier.height(6.dp))
            Text("PREUVE MUTUELLE VÉRIFIÉE", color = Color(0xFF39D98A), fontWeight = FontWeight.Bold)
            Text("Ton empreinte : ${PairingInviteCodec.fingerprint(identity.publicKeyEncoded())}", color = Color.White, fontSize = 10.sp)
            Text("Empreinte du pair : $remoteFingerprint", color = Color.White, fontSize = 10.sp)
            Text("Transcript SHA-256 : ${verified.transcriptSha256}", color = Color(0xFF8292A3), fontSize = 9.sp)
            OutlinedTextField(
                value = peerName,
                onValueChange = { peerName = it.take(40) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Nom de l’appareil") }
            )
            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                Checkbox(checked = fingerprintsCompared, onCheckedChange = { fingerprintsCompared = it })
                Text("J’ai comparé les deux empreintes complètes avec l’autre personne par un canal indépendant.", color = Color.White, fontSize = 10.sp)
            }
            Button(
                onClick = {
                    try {
                        check(fingerprintsCompared) { "Compare les deux empreintes par un canal indépendant avant d’approuver." }
                        val localPublic = identity.publicKeyEncoded()
                        val peer = if (MessageDigest.isEqual(localPublic, verified.responderPublicKey)) {
                            verified.challengerDeviceId to verified.challengerPublicKey
                        } else {
                            verified.inviteDeviceId to verified.responderPublicKey
                        }
                        peerStore.trustPeer(
                            proof = verified,
                            peerDeviceId = peer.first,
                            peerPublicKeyEncoded = peer.second,
                            displayName = peerName,
                            bothFingerprintsComparedOutOfBand = true
                        )
                        peers = peerStore.listPeers()
                        status = "Appareil enregistré localement comme appareil de confiance."
                        errorMessage = null
                    } catch (failure: Exception) {
                        errorMessage = failure.message ?: "Enregistrement impossible."
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF39D98A), contentColor = Color(0xFF00150B))
            ) { Text("7. APPROUVER ET ENREGISTRER L’APPAREIL") }
        }

        if (peers.isNotEmpty()) {
            Text("APPAREILS DE CONFIANCE ENREGISTRÉS", color = Color.White, fontWeight = FontWeight.Bold)
            peers.forEach { peer ->
                Text("${peer.displayName} • ${peer.fingerprintSha256}", color = Color(0xFF8292A3), fontSize = 9.sp)
            }
        }

        Button(
            onClick = onClose,
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF26313E), contentColor = Color.White)
        ) { Text("RETOUR") }
    }
}

@Composable
private fun QrPanel(label: String, bitmap: Bitmap) {
    Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
        Text(label, color = Color(0xFF00BFFF), fontWeight = FontWeight.Bold, fontSize = 11.sp)
        Image(
            bitmap = bitmap.asImageBitmap(),
            contentDescription = label,
            modifier = Modifier.fillMaxWidth().height(220.dp),
            contentScale = ContentScale.Fit
        )
    }
}
