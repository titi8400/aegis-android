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
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val Background = Color(0xFF080C12)
private val Panel = Color(0xFF101A27)
private val Cyan = Color(0xFF00BFFF)
private val Muted = Color(0xFF8292A3)
private val Green = Color(0xFF39D98A)

@Composable
fun AegisApp() {
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
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .height(8.dp)
                            .background(Green, RoundedCornerShape(50))
                    )
                    Text(
                        text = "  MODE LOCAL",
                        color = Green,
                        fontSize = 10.sp,
                        letterSpacing = 1.5.sp
                    )
                }
            }

            Spacer(Modifier.height(72.dp))

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

            Spacer(Modifier.height(42.dp))

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
                    StatusLine("Stockage de sauvegarde automatique", "DÉSACTIVÉ")
                    StatusLine("Communication P2P", "À IMPLÉMENTER")
                    StatusLine("Identité cryptographique", "EN PRÉPARATION")
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
            color = if (status == "DÉSACTIVÉ") Green else Cyan,
            fontSize = 9.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 0.5.sp
        )
    }
}
