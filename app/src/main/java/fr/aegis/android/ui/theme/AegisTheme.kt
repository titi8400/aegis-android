package fr.aegis.android.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val AegisColors = darkColorScheme(
    primary = Color(0xFF00BFFF),
    onPrimary = Color(0xFF00131D),
    secondary = Color(0xFF39D98A),
    background = Color(0xFF080C12),
    surface = Color(0xFF101A27),
    onBackground = Color(0xFFEAF2F8),
    onSurface = Color(0xFFEAF2F8)
)

@Composable
fun AegisTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = AegisColors,
        content = content
    )
}
