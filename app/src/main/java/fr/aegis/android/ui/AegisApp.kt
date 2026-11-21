package fr.aegis.android.ui

import android.graphics.Bitmap
import android.os.SystemClock
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import fr.aegis.android.security.AndroidKeyStoreIdentity
import fr.aegis.android.security.PinLockManager
import fr.aegis.android.security.PairingInviteCodec
import fr.aegis.android.security.PairingQrGenerator
import fr.aegis.android.security.PairingReplayGuard
import kotlinx.coroutines.delay

private val Background = Color(0xFF080C12)
private val Panel = Color(0xFF101A27)
private val Cyan = Color(0xFF00BFFF)
private val Muted = Color(0xFF8292A3)
private val Green = Color(0xFF39D98A)
private val Danger = Color(0xFFFF7070)
private const val AUTO_LOCK_MILLIS = 60_000L

@Composable
fun AegisApp() {
    val context = LocalContext.current
    val activity = context as FragmentActivity
    val lifecycleOwner = LocalLifecycleOwner.current
    val identity = remember { AndroidKeyStoreIdentity() }
    val pinLock = remember { PinLockManager(context.applicationContext) }
    val replayGuard = remember { PairingReplayGuard(context.applicationContext) }

    var pinConfigured by remember { mutableStateOf(pinLock.isConfigured()) }
    var unlocked by remember { mutableStateOf(false) }
    var confirmPin by remember { mutableStateOf(false) }
    var pinInput by remember { mutableStateOf("") }
    var firstPin by remember { mutableStateOf("") }
    var pinError by remember { mutableStateOf<String?>(null) }
    var identityStatus by remember {
        mutableStateOf(if (identity.exists()) "CRÉÉE" else "NON CRÉÉE")
    }
    var identityError by remember { mutableStateOf<String?>(null) }
    var scannerOpen by remember { mutableStateOf(false) }
    var scannedFingerprint by remember { mutableStateOf<String?>(null) }
    var pairingError by remember { mutableStateOf<String?>(null) }
    var invitationBitmap by remember { mutableStateOf<Bitmap?>(null) }
    var lastInteraction by remember { mutableStateOf(SystemClock.elapsedRealtime()) }

    DisposableEffect(lifecycleOwner, pinConfigured) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP && pinConfigured) {
                unlocked = false
                pinInput = ""
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    LaunchedEffect(unlocked, lastInteraction) {
        if (unlocked && pinConfigured) {
            delay(AUTO_LOCK_MILLIS)
            if (SystemClock.elapsedRealtime() - lastInteraction >= AUTO_LOCK_MILLIS) {
                unlocked = false
                pinInput = ""
            }
        }
    }

    val biometricAvailable = remember {
        BiometricManager.from(context).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        ) == BiometricManager.BIOMETRIC_SUCCESS
    }

    fun authenticateBiometric() {
        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(context),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    unlocked = true
                    pinInput = ""
                    pinError = null
                    lastInteraction = SystemClock.elapsedRealtime()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    pinError = errString.toString()
                }

                override fun onAuthenticationFailed() {
                    pinError = "Empreinte ou donnée biométrique non reconnue."
                }
            }
        )
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Déverrouiller AEGIS")
            .setSubtitle("Authentification biométrique de l'appareil")
            .setNegativeButtonText("Utiliser le PIN")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()
        prompt.authenticate(promptInfo)
    }

    fun submitPin() {
        pinError = null
        if (pinInput.length !in 6..12 || pinInput.any { !it.isDigit() }) {
            pinError = "Saisis un code de 6 à 12 chiffres."
            return
        }

        if (!pinConfigured) {
            if (!confirmPin) {
                firstPin = pinInput
                pinInput = ""
                confirmPin = true
                return
            }
            if (pinInput != firstPin) {
                firstPin = ""
                pinInput = ""
                confirmPin = false
                pinError = "Les deux codes ne correspondent pas. Recommence."
                return
            }
            pinLock.configure(pinInput.toCharArray())
            pinConfigured = true
            unlocked = true
            pinInput = ""
            firstPin = ""
            confirmPin = false
            lastInteraction = SystemClock.elapsedRealtime()
            return
        }

        when (val result = pinLock.verify(pinInput.toCharArray())) {
            PinLockManager.Verification.Accepted -> {
                unlocked = true
                pinInput = ""
                lastInteraction = SystemClock.elapsedRealtime()
            }
            PinLockManager.Verification.Rejected -> {
                pinInput = ""
                pinError = "Code incorrect. Après 10 échecs, l'identité cryptographique sera supprimée."
            }
            is PinLockManager.Verification.Locked -> {
                pinInput = ""
                val seconds = (result.remainingMillis + 999) / 1000
                pinError = "Verrouillage temporaire : $seconds seconde(s)."
            }
            PinLockManager.Verification.IdentityWipeRequired -> {
                identity.delete()
                pinLock.resetAfterIdentityWipe()
                identityStatus = "SUPPRIMÉE"
                pinConfigured = false
                unlocked = false
                pinInput = ""
                firstPin = ""
                confirmPin = false
                pinError = "10 échecs : identité cryptographique locale supprimée. Configure un nouveau PIN."
            }
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Background)
            .pointerInput(Unit) {
                awaitPointerEventScope {
                    while (true) {
                        awaitPointerEvent()
                        lastInteraction = SystemClock.elapsedRealtime()
                    }
                }
            }
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 24.dp, vertical = 30.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Top
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "AEGIS",
                    color = Color.White,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Black,
                    letterSpacing = 4.sp
                )
                Text(
                    text = if (unlocked) "●  SESSION OUVERTE" else "●  SESSION VERROUILLÉE",
                    color = if (unlocked) Green else Cyan,
                    fontSize = 9.sp,
                    letterSpacing = 1.sp
                )
            }

            Spacer(Modifier.height(34.dp))
            Icon(
                imageVector = if (unlocked) Icons.Outlined.Security else Icons.Outlined.Lock,
                contentDescription = null,
                tint = Cyan,
                modifier = Modifier.height(82.dp)
            )
            Spacer(Modifier.height(18.dp))

            if (!unlocked) {
                Text(
                    text = if (!pinConfigured) "CONFIGURATION DU PIN" else "ACCÈS SÉCURISÉ",
                    color = Color.White,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.5.sp
                )
                Spacer(Modifier.height(10.dp))
                Text(
                    text = when {
                        !pinConfigured && !confirmPin -> "Crée un code PIN indépendant de 6 à 12 chiffres."
                        !pinConfigured -> "Confirme ton nouveau code PIN."
                        else -> "Saisis ton PIN pour ouvrir ta session."
                    },
                    color = Muted,
                    fontSize = 12.sp
                )
                Spacer(Modifier.height(22.dp))
                OutlinedTextField(
                    value = pinInput,
                    onValueChange = { value ->
                        if (value.length <= 12 && value.all { it.isDigit() }) {
                            pinInput = value
                            pinError = null
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    label = { Text("Code PIN", color = Muted) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = Color.White,
                        unfocusedTextColor = Color.White,
                        focusedBorderColor = Cyan,
                        unfocusedBorderColor = Color(0xFF38516A),
                        cursorColor = Cyan
                    )
                )
                Spacer(Modifier.height(16.dp))
                Button(
                    onClick = { submitPin() },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Cyan,
                        contentColor = Color(0xFF00131D)
                    ),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Text(
                        text = if (!pinConfigured) {
                            if (confirmPin) "CONFIRMER LE PIN" else "CONTINUER"
                        } else "DÉVERROUILLER",
                        fontWeight = FontWeight.Bold
                    )
                }
                if (pinConfigured && biometricAvailable) {
                    Spacer(Modifier.height(10.dp))
                    Button(
                        onClick = { authenticateBiometric() },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Panel,
                            contentColor = Cyan
                        ),
                        shape = RoundedCornerShape(10.dp)
                    ) {
                        Text("UTILISER LA BIOMÉTRIE")
                    }
                }
                pinError?.let {
                    Spacer(Modifier.height(14.dp))
                    Text(it, color = Danger, fontSize = 11.sp)
                }
            } else if (scannerOpen) {
                PairingQrScanner(
                    onInviteScanned = { payload ->
                        try {
                            val verified = PairingInviteCodec.verify(payload)
                            replayGuard.consume("invite", verified.nonce, verified.expiresAtEpochMs)
                            scannedFingerprint = verified.fingerprintSha256
                            pairingError = null
                        } catch (error: Exception) {
                            scannedFingerprint = null
                            pairingError = error.message ?: "Invitation invalide."
                        }
                        scannerOpen = false
                    },
                    onClose = { scannerOpen = false }
                )
            } else {
                Text(
                    text = "COMMUNICATION PRIVÉE",
                    color = Color.White,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.5.sp
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = "Session locale protégée.",
                    color = Muted,
                    fontSize = 12.sp
                )
                Spacer(Modifier.height(28.dp))
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    color = Panel,
                    shape = RoundedCornerShape(16.dp),
                    border = BorderStroke(1.dp, Color(0xFF20364C))
                ) {
                    Column(modifier = Modifier.padding(18.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Outlined.Lock,
                                contentDescription = null,
                                tint = Cyan
                            )
                            Text(
                                text = "  PROTECTIONS LOCALES",
                                color = Color.White,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                letterSpacing = 1.sp
                            )
                        }
                        Spacer(Modifier.height(14.dp))
                        StatusLine("Verrouillage PIN", "ACTIF")
                        StatusLine("Verrouillage biométrique", if (biometricAvailable) "DISPONIBLE" else "INDISPONIBLE")
                        StatusLine("Verrouillage après inactivité", "60 SECONDES")
                        StatusLine("Identité cryptographique", identityStatus)

                        Spacer(Modifier.height(18.dp))
                        Button(
                            onClick = {
                                identityError = null
                                try {
                                    identity.createIfAbsent()
                                    identityStatus = "CRÉÉE"
                                } catch (_: Exception) {
                                    identityStatus = "ÉCHEC"
                                    identityError = "Impossible de créer l'identité sur cet appareil."
                                }
                            },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Cyan,
                                contentColor = Color(0xFF00131D)
                            ),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Text(
                                text = if (identityStatus == "CRÉÉE") "IDENTITÉ LOCALE CRÉÉE" else "INITIALISER MON IDENTITÉ",
                                fontWeight = FontWeight.Bold
                            )
                        }
                        identityError?.let {
                            Spacer(Modifier.height(8.dp))
                            Text(it, color = Danger, fontSize = 11.sp)
                        }
                        Spacer(Modifier.height(12.dp))
                        Button(
                            onClick = {
                                try {
                                    check(identity.exists()) { "Initialise d’abord ton identité locale." }
                                    val invite = PairingInviteCodec.create(identity)
                                    invitationBitmap = PairingQrGenerator.generate(invite)
                                    identityError = null
                                } catch (error: Exception) {
                                    invitationBitmap = null
                                    identityError = error.message ?: "Impossible de générer l’invitation."
                                }
                            },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(containerColor = Cyan, contentColor = Color(0xFF00131D)),
                            shape = RoundedCornerShape(10.dp)
                        ) { Text("GÉNÉRER MON QR D’INVITATION") }
                        invitationBitmap?.let { qr ->
                            Spacer(Modifier.height(12.dp))
                            Image(
                                bitmap = qr.asImageBitmap(),
                                contentDescription = "QR code d’invitation AEGIS valable cinq minutes",
                                modifier = Modifier.fillMaxWidth().height(240.dp),
                                contentScale = ContentScale.Fit
                            )
                            Text("QR temporaire : expiration après 5 minutes. Ne le partage qu’avec la personne concernée.", color = Muted, fontSize = 10.sp)
                        }
                        Spacer(Modifier.height(12.dp))
                        Button(
                            onClick = {
                                scannerOpen = true
                                scannedFingerprint = null
                                pairingError = null
                            },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(containerColor = Panel, contentColor = Cyan),
                            shape = RoundedCornerShape(10.dp)
                        ) { Text("SCANNER UN QR D’APPAREIL") }
                        scannedFingerprint?.let {
                            Spacer(Modifier.height(12.dp))
                            Text("INVITATION SIGNÉE VÉRIFIÉE", color = Green, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            Text("Empreinte SHA-256 : $it", color = Color.White, fontSize = 10.sp)
                            Text("Compare cette empreinte par un canal indépendant. L’appareil n’est pas encore approuvé.", color = Muted, fontSize = 10.sp)
                        }
                        pairingError?.let {
                            Spacer(Modifier.height(8.dp))
                            Text("QR REFUSÉ : $it", color = Danger, fontSize = 11.sp)
                        }
                    }
                }
                Spacer(Modifier.height(16.dp))
                Button(
                    onClick = {
                        unlocked = false
                        pinInput = ""
                    },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Panel,
                        contentColor = Cyan
                    ),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Text("VERROUILLER MAINTENANT")
                }
            }

            Spacer(Modifier.height(28.dp))
            Text(
                text = "VERSION 0.7.0 • PROTOTYPE",
                color = Muted,
                fontSize = 10.sp,
                letterSpacing = 1.5.sp
            )
            Spacer(Modifier.height(8.dp))
            Text(
                text = "Le scan vérifie une invitation, sans encore approuver l’appareil.",
                color = Muted,
                fontSize = 10.sp
            )
        }
    }
}

@Composable
private fun StatusLine(label: String, status: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, color = Muted, fontSize = 11.sp)
        Text(
            text = status,
            color = when (status) {
                "ACTIF", "DISPONIBLE", "CRÉÉE", "60 SECONDES" -> Green
                "ÉCHEC", "SUPPRIMÉE" -> Danger
                else -> Cyan
            },
            fontSize = 9.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 0.5.sp
        )
    }
}
