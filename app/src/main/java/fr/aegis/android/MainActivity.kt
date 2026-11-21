package fr.aegis.android

import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.fragment.app.FragmentActivity
import androidx.activity.compose.setContent
import fr.aegis.android.ui.AegisApp
import fr.aegis.android.ui.theme.AegisTheme

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            AegisTheme {
                AegisApp()
            }
        }
    }
}
