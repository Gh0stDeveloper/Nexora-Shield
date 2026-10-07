package dev.nexora.shield.studio

import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import dev.nexora.shield.studio.ui.NexoraShieldTheme
import dev.nexora.shield.studio.ui.StudioLayoutPolicy
import java.awt.Dimension

fun main() = application {
    Window(
        onCloseRequest = ::exitApplication,
        title = "Nexora Shield Studio",
        state = rememberWindowState(width = 1440.dp, height = 900.dp),
    ) {
        LaunchedEffect(Unit) {
            window.minimumSize = Dimension(
                StudioLayoutPolicy.minimumWindowWidthPx,
                StudioLayoutPolicy.minimumWindowHeightPx,
            )
        }
        NexoraShieldTheme {
            StudioApp()
        }
    }
}
