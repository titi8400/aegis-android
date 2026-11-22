package fr.aegis.android.ui

import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.platform.LocalContext
import fr.aegis.android.security.RecoveryArchiveManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream

private const val MAX_RECOVERY_ENVELOPE = 64 * 1024 * 1024 + 64

@Composable
fun RecoveryCenterScreen(onClose: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val manager = remember { RecoveryArchiveManager(context.applicationContext) }
    var recoveryCode by remember { mutableStateOf("") }
    var codeToDisplay by remember { mutableStateOf<String?>(null) }
    var status by remember { mutableStateOf("Sauvegarde chiffrée locale. Aucun serveur AEGIS n'est utilisé.") }
    var busy by remember { mutableStateOf(false) }

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri: Uri? ->
        if (uri != null && !busy) {
            busy = true
            status = "Création de l'archive chiffrée…"
            scope.launch {
                val result = withContext(Dispatchers.IO) {
                    runCatching {
                        val backup = manager.createEncryptedBackup()
                        try {
                            context.contentResolver.openOutputStream(uri, "wt")?.use { output ->
                                output.write(backup.envelope)
                                output.flush()
                            } ?: error("Impossible d'écrire le fichier choisi.")
                            backup.secret.encoded
                        } finally {
                            backup.envelope.fill(0)
                        }
                    }
                }
                result.onSuccess { secret ->
                    codeToDisplay = secret
                    status = "Sauvegarde créée. Note le code ci-dessous et conserve-le séparément du fichier."
                }.onFailure {
                    status = it.message ?: "Échec de la création de la sauvegarde."
                }
                busy = false
            }
        }
    }

    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null && !busy) {
            busy = true
            status = "Vérification et restauration de l'archive…"
            scope.launch {
                val result = withContext(Dispatchers.IO) {
                    runCatching {
                        val envelope = context.contentResolver.openInputStream(uri)?.use { input ->
                            val output = ByteArrayOutputStream()
                            val buffer = ByteArray(32 * 1024)
                            var total = 0
                            while (true) {
                                val count = input.read(buffer)
                                if (count < 0) break
                                total += count
                                require(total <= MAX_RECOVERY_ENVELOPE) {
                                    "Archive supérieure à la taille maximale autorisée."
                                }
                                output.write(buffer, 0, count)
                            }
                            buffer.fill(0)
                            output.toByteArray()
                        } ?: error("Impossible de lire le fichier sélectionné.")
                        try {
                            manager.restoreEncryptedBackup(envelope, recoveryCode.trim())
                        } finally {
                            envelope.fill(0)
                        }
                    }
                }
                result.onSuccess { count ->
                    status = "Restauration terminée : $count enregistrement(s) restauré(s). L'identité de cet appareil reste distincte ; les contacts doivent être appairés à nouveau."
                    recoveryCode = ""
                }.onFailure {
                    status = it.message ?: "Échec de la restauration."
                }
                busy = false
            }
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(22.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("CENTRE DE RÉCUPÉRATION", color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.Bold)
        Text(
            "L'archive contient les conversations, la file d'attente et les fichiers reçus. Elle ne contient ni clé privée, ni PIN, ni liste des appareils de confiance.",
            color = Color(0xFF9EADBD), fontSize = 12.sp
        )
        Button(
            onClick = { exportLauncher.launch("aegis-recovery.aegis") },
            enabled = !busy,
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF00BFFF), contentColor = Color(0xFF00131D))
        ) { Text("CRÉER UNE SAUVEGARDE CHIFFRÉE", fontWeight = FontWeight.Bold) }

        codeToDisplay?.let { secret ->
            Text("CODE DE RÉCUPÉRATION — À CONSERVER SÉPARÉMENT", color = Color(0xFFFFD166), fontSize = 11.sp, fontWeight = FontWeight.Bold)
            Text(secret, color = Color.White, fontSize = 12.sp)
            Text("Ce code donne accès au contenu de cette sauvegarde. Ne le partage pas avec une personne non autorisée.", color = Color(0xFFFFD166), fontSize = 11.sp)
            Button(
                onClick = { codeToDisplay = null },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF20364C), contentColor = Color.White)
            ) { Text("J'AI CONSERVÉ LE CODE — MASQUER") }
        }

        Spacer(Modifier.height(4.dp))
        Text("RESTAURER SUR UN NOUVEL APPAREIL", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 13.sp)
        OutlinedTextField(
            value = recoveryCode,
            onValueChange = { recoveryCode = it.take(64) },
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Code de récupération") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii)
        )
        Button(
            onClick = { importLauncher.launch(arrayOf("application/octet-stream", "*/*")) },
            enabled = !busy && recoveryCode.startsWith("AEGIS-R1-"),
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF20364C), contentColor = Color(0xFF00BFFF))
        ) { Text("SÉLECTIONNER L'ARCHIVE ET RESTAURER") }

        Text(status, color = Color(0xFF00BFFF), fontSize = 12.sp)
        Text(
            "Important : cette fonction exporte et importe un fichier chiffré via le sélecteur Android. Le transfert direct entre deux téléphones et la sauvegarde automatique sur un second appareil ne sont pas encore intégrés. Effectue la restauration sur un appareil neuf ou après sauvegarde préalable de ses données.",
            color = Color(0xFF9EADBD), fontSize = 11.sp
        )
        Spacer(Modifier.height(8.dp))
        Button(
            onClick = onClose,
            modifier = Modifier.fillMaxWidth(),
            enabled = !busy,
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF20364C), contentColor = Color.White)
        ) { Text("RETOUR") }
    }
}
