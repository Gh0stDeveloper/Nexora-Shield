package dev.nexora.shield.studio.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

object ShieldColors {
    val Background = Color(0xFF090B10)
    val Surface = Color(0xFF10141B)
    val SurfaceRaised = Color(0xFF151A23)
    val SurfaceMuted = Color(0xFF0D1118)
    val Border = Color(0xFF252C38)
    val BorderStrong = Color(0xFF343E4D)
    val Primary = Color(0xFF6EA8FF)
    val PrimaryStrong = Color(0xFF8CB9FF)
    val Accent = Color(0xFF5DE2C2)
    val Success = Color(0xFF63D99B)
    val Warning = Color(0xFFFFC766)
    val Danger = Color(0xFFFF7B86)
    val TextPrimary = Color(0xFFF4F7FB)
    val TextSecondary = Color(0xFFAEB8C7)
    val TextMuted = Color(0xFF788496)
    val Console = Color(0xFF05070A)
}

private val ShieldColorScheme = darkColorScheme(
    primary = ShieldColors.Primary,
    onPrimary = Color(0xFF06142B),
    primaryContainer = Color(0xFF142B4D),
    onPrimaryContainer = Color(0xFFD9E8FF),
    secondary = ShieldColors.Accent,
    onSecondary = Color(0xFF04251D),
    secondaryContainer = Color(0xFF10352F),
    onSecondaryContainer = Color(0xFFC5FFF0),
    background = ShieldColors.Background,
    onBackground = ShieldColors.TextPrimary,
    surface = ShieldColors.Surface,
    onSurface = ShieldColors.TextPrimary,
    surfaceVariant = ShieldColors.SurfaceRaised,
    onSurfaceVariant = ShieldColors.TextSecondary,
    outline = ShieldColors.Border,
    outlineVariant = ShieldColors.BorderStrong,
    error = ShieldColors.Danger,
    onError = Color(0xFF330007),
)

private val ShieldTypography = Typography(
    displaySmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Bold,
        fontSize = 30.sp,
        lineHeight = 36.sp,
        letterSpacing = (-0.5).sp,
    ),
    headlineMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 24.sp,
        lineHeight = 30.sp,
    ),
    headlineSmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 20.sp,
        lineHeight = 26.sp,
    ),
    titleLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 17.sp,
        lineHeight = 22.sp,
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Medium,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 21.sp,
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 13.sp,
        lineHeight = 19.sp,
    ),
    bodySmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 17.sp,
    ),
    labelLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 13.sp,
        lineHeight = 18.sp,
    ),
    labelMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp,
        lineHeight = 16.sp,
        letterSpacing = 0.2.sp,
    ),
)

@Composable
fun NexoraShieldTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = ShieldColorScheme,
        typography = ShieldTypography,
        content = content,
    )
}
