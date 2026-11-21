package fr.aegis.android.ui

import android.Manifest
import android.content.pm.PackageManager
import android.view.Gravity
import android.widget.FrameLayout
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import fr.aegis.android.calls.P2pCallEngine
import org.webrtc.SurfaceViewRenderer

@Composable
fun P2pCallScreen(
    engine: P2pCallEngine,
    callStatus: String,
    onClose: () -> Unit
) {
    val context = LocalContext.current
    var started by remember { mutableStateOf(false) }
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        val microphone = grants[Manifest.permission.RECORD_AUDIO] == true ||
            ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED
        if (microphone) {
            try {
                if (engine.hasPendingIncomingOffer) engine.acceptPendingOffer()
                else engine.startOutgoingCall()
                started = true
            } catch (failure: Exception) {
                // The parent displays the engine status; permission and setup failures stay visible here.
                started = false
            }
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text("AEGIS / APPEL DIRECT", color = Color.White, fontSize = 18.sp)
        Text("WebRTC • candidats réseau locaux uniquement • aucun STUN/TURN/relais", color = Color(0xFF8292A3), fontSize = 10.sp)
        Text(callStatus, color = Color(0xFF00BFFF), fontSize = 11.sp)

        AndroidView(
            factory = { viewContext ->
                val container = FrameLayout(viewContext)
                val remote = SurfaceViewRenderer(viewContext)
                val local = SurfaceViewRenderer(viewContext)
                container.addView(
                    remote,
                    FrameLayout.LayoutParams(
                        FrameLayout.LayoutParams.MATCH_PARENT,
                        FrameLayout.LayoutParams.MATCH_PARENT
                    )
                )
                val localParams = FrameLayout.LayoutParams(280, 210, Gravity.TOP or Gravity.END).apply {
                    setMargins(12, 12, 12, 12)
                }
                container.addView(local, localParams)
                engine.attachRenderers(local, remote)
                container
            },
            modifier = Modifier.weight(1f).fillMaxWidth()
        )

        if (engine.hasPendingIncomingOffer) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = {
                        val mic = ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED
                        if (mic) {
                            runCatching { engine.acceptPendingOffer(); started = true }
                        } else {
                            permissionLauncher.launch(arrayOf(Manifest.permission.RECORD_AUDIO, Manifest.permission.CAMERA))
                        }
                    },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF39D98A), contentColor = Color(0xFF00150B))
                ) { Text("ACCEPTER") }
                Button(
                    onClick = { engine.rejectPendingOffer(); onClose() },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF7A2630), contentColor = Color.White)
                ) { Text("REFUSER") }
            }
        } else if (!started) {
            Button(
                onClick = {
                    val mic = ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED
                    if (mic) {
                        runCatching { engine.startOutgoingCall(); started = true }
                    } else {
                        permissionLauncher.launch(arrayOf(Manifest.permission.RECORD_AUDIO, Manifest.permission.CAMERA))
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF00BFFF), contentColor = Color(0xFF00131D))
            ) { Text("LANCER L’APPEL AUDIO / VIDÉO") }
        } else {
            Button(
                onClick = { engine.hangUp(); onClose() },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF7A2630), contentColor = Color.White)
            ) { Text("RACCROCHER") }
        }

        Button(
            onClick = onClose,
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF26313E), contentColor = Color.White)
        ) { Text("RETOUR AU CHAT") }
    }
}
