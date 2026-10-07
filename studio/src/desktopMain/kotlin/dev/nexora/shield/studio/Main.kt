package dev.nexora.shield.studio

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState

fun main() = application {
    Window(
        onCloseRequest = ::exitApplication,
        title = "Nexora Shield Studio",
        state = rememberWindowState(width = 1360.dp, height = 860.dp),
    ) {
        MaterialTheme(colorScheme = darkColorScheme()) {
            StudioApp()
        }
    }
}
