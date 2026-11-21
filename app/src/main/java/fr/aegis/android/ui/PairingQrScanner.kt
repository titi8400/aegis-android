package fr.aegis.android.ui

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.common.InputImage
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

@Composable
fun PairingQrScanner(
    onInviteScanned: (String) -> Unit,
    onClose: () -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var hasPermission by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    var permissionDenied by remember { mutableStateOf(false) }
    var scanError by remember { mutableStateOf<String?>(null) }
    val executor = remember { Executors.newSingleThreadExecutor() }
    val barcodeScanner = remember { BarcodeScanning.getClient() }
    val providerState = remember { mutableStateOf<ProcessCameraProvider?>(null) }
    DisposableEffect(Unit) {
        onDispose {
            providerState.value?.unbindAll()
            barcodeScanner.close()
            executor.shutdown()
        }
    }
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasPermission = granted
        permissionDenied = !granted
    }

    LaunchedEffect(Unit) {
        if (!hasPermission) permissionLauncher.launch(Manifest.permission.CAMERA)
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text("SCANNER UNE INVITATION AEGIS", color = Color.White)
        if (hasPermission) {
            AndroidView(
                modifier = Modifier.fillMaxWidth().height(420.dp),
                factory = { ctx ->
                    val previewView = PreviewView(ctx)
                    val providerFuture = ProcessCameraProvider.getInstance(ctx)
                                        val delivered = AtomicBoolean(false)
                    providerFuture.addListener({
                        val provider = providerFuture.get()
                        providerState.value = provider
                        val preview = Preview.Builder().build().also {
                            it.surfaceProvider = previewView.surfaceProvider
                        }
                        val analysis = ImageAnalysis.Builder()
                            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                            .build()
                        analysis.setAnalyzer(executor) { proxy ->
                            val mediaImage = proxy.image
                            if (mediaImage == null || delivered.get()) {
                                proxy.close()
                            } else {
                                barcodeScanner.process(
                                    InputImage.fromMediaImage(mediaImage, proxy.imageInfo.rotationDegrees)
                                ).addOnSuccessListener { barcodes ->
                                    val raw = barcodes.firstNotNullOfOrNull { it.rawValue }
                                    if (raw != null && raw.startsWith("AEGIS-PAIR|") && delivered.compareAndSet(false, true)) {
                                        onInviteScanned(raw)
                                    }
                                }.addOnFailureListener {
                                    scanError = "Lecture du QR impossible."
                                }.addOnCompleteListener {
                                    proxy.close()
                                }
                            }
                        }
                        try {
                            provider.unbindAll()
                            provider.bindToLifecycle(
                                lifecycleOwner,
                                CameraSelector.DEFAULT_BACK_CAMERA,
                                preview,
                                analysis
                            )
                        } catch (_: Exception) {
                            scanError = "Caméra indisponible sur cet appareil."
                        }
                    }, ContextCompat.getMainExecutor(ctx))
                    previewView
                }
            )
            scanError?.let { Text(it, color = Color(0xFFFF7070)) }
        } else {
            Text(
                if (permissionDenied) "L’accès caméra est refusé. Autorise-le dans les paramètres Android."
                else "Autorisation caméra nécessaire pour lire le QR.",
                color = Color(0xFF8292A3)
            )
            Button(onClick = { permissionLauncher.launch(Manifest.permission.CAMERA) }) {
                Text("AUTORISER LA CAMÉRA")
            }
        }
        Button(
            onClick = onClose,
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(
                containerColor = Color(0xFF10233B),
                contentColor = Color(0xFF00BFFF)
            )
        ) { Text("RETOUR") }
    }
}
