package fr.aegis.android.ui

import androidx.compose.foundation.BorderStroke
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import fr.aegis.android.security.AndroidKeyStoreIdentity

private val Background = Color(0xFF080C12)
private val Panel = Color(0xFF101A27)
private val Cyan = Color(0xFF00BFFF)
private val Muted = Color(0xFF8292A3)
private val Green = Color(0xFF39D98A)

@Composable
fun AegisApp() {
    val identity = remember { AndroidKeyStoreIdentity() }
    var identityStatus by remember {
        mutableStateOf(if (identity.exists()) "CRÉÉE" else "NON CRÉÉE")
    }
    var identityError by remember { mutableStateOf<String?>(null) }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = Background
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 24.dp, vertical = 36.dp),
            horizontalAlignment = Alignment.CenterHorizontally
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
                    text = "●  MODE LOCAL",
                    color = Green,
                    fontSize = 10.sp,
                    letterSpacing = 1.5.sp
                )
            }

            Spacer(Modifier.height(54.dp))

            Box(
                modifier = Modifier
                    .height(132.dp)
                    .fillMaxWidth(),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Outlined.Security,
                    contentDescription = "Bouclier AEGIS",
                    tint = Cyan,
                    modifier = Modifier.fillMaxSize(0.72f)
                )
            }

            Spacer(Modifier.height(22.dp))
            Text(
                text = "COMMUNICATION PRIVÉE",
                color = Color.White,
                fontSize = 17.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 2.sp
            )
            Spacer(Modifier.height(10.dp))
            Text(
                text = "Votre espace sécurisé commence ici.",
                color = Muted,
                fontSize = 13.sp
            )

            Spacer(Modifier.height(34.dp))

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
                            text = "  SOCLE DE SÉCURITÉ",
                            color = Color.White,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 1.sp
                        )
                    }
                    Spacer(Modifier.height(16.dp))
                    StatusLine("Application Android native", "INITIALISÉ")
                    StatusLine("Sauvegarde automatique", "DÉSACTIVÉ")
                    StatusLine("Communication P2P", "À IMPLÉMENTER")
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
                            text = if (identityStatus == "CRÉÉE") {
                                "IDENTITÉ LOCALE CRÉÉE"
                            } else {
                                "INITIALISER MON IDENTITÉ"
                            },
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 0.5.sp
                        )
                    }
                    identityError?.let {
                        Spacer(Modifier.height(8.dp))
                        Text(it, color = Color(0xFFFF7070), fontSize = 11.sp)
                    }
                }
            }

            Spacer(Modifier.weight(1f))
            Text(
                text = "VERSION 0.1.0 • PROTOTYPE",
                color = Muted,
                fontSize = 10.sp,
                letterSpacing = 1.5.sp
            )
            Spacer(Modifier.height(8.dp))
            Text(
                text = "Aucune communication n'est encore active.",
                color = Muted,
                fontSize = 11.sp
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
                "DÉSACTIVÉ", "CRÉÉE" -> Green
                "ÉCHEC" -> Color(0xFFFF7070)
                else -> Cyan
            },
            fontSize = 9.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 0.5.sp
        )
    }
}
