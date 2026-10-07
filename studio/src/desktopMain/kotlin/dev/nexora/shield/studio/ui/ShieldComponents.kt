package dev.nexora.shield.studio.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

enum class ShieldTone {
    Neutral,
    Info,
    Success,
    Warning,
    Danger,
}

@Composable
fun PageHeader(
    eyebrow: String,
    title: String,
    description: String,
    actions: @Composable RowScope.() -> Unit = {},
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Bottom,
        horizontalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                text = eyebrow.uppercase(),
                style = MaterialTheme.typography.labelMedium,
                color = ShieldColors.PrimaryStrong,
            )
            Text(
                text = title,
                modifier = Modifier.semantics { heading() },
                style = MaterialTheme.typography.headlineMedium,
                color = ShieldColors.TextPrimary,
            )
            Text(
                text = description,
                style = MaterialTheme.typography.bodyMedium,
                color = ShieldColors.TextSecondary,
            )
        }
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
            content = actions,
        )
    }
}

@Composable
fun Panel(
    modifier: Modifier = Modifier,
    title: String? = null,
    subtitle: String? = null,
    content: @Composable () -> Unit,
) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = ShieldColors.Surface),
        shape = RoundedCornerShape(18.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, ShieldColors.Border),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            if (title != null) {
                Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Text(
                        text = title,
                        style = MaterialTheme.typography.titleLarge,
                        color = ShieldColors.TextPrimary,
                    )
                    if (subtitle != null) {
                        Text(
                            text = subtitle,
                            style = MaterialTheme.typography.bodySmall,
                            color = ShieldColors.TextSecondary,
                        )
                    }
                }
            }
            content()
        }
    }
}

@Composable
fun MetricCard(
    icon: ImageVector,
    label: String,
    value: String,
    detail: String,
    tone: ShieldTone = ShieldTone.Neutral,
    modifier: Modifier = Modifier,
) {
    val accent = toneColor(tone)
    Panel(modifier = modifier) {
        Row(
            horizontalArrangement = Arrangement.spacedBy(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(42.dp)
                    .background(accent.copy(alpha = 0.12f), RoundedCornerShape(12.dp))
                    .border(1.dp, accent.copy(alpha = 0.25f), RoundedCornerShape(12.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = accent,
                    modifier = Modifier.size(21.dp),
                )
            }
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(3.dp),
            ) {
                Text(label, style = MaterialTheme.typography.labelMedium, color = ShieldColors.TextMuted)
                Text(
                    value,
                    style = MaterialTheme.typography.titleLarge,
                    color = ShieldColors.TextPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(detail, style = MaterialTheme.typography.bodySmall, color = ShieldColors.TextSecondary)
            }
        }
    }
}

@Composable
fun StatusPill(
    text: String,
    tone: ShieldTone,
) {
    val color = toneColor(tone)
    val icon = when (tone) {
        ShieldTone.Success -> Icons.Outlined.CheckCircle
        ShieldTone.Warning -> Icons.Outlined.Schedule
        ShieldTone.Danger -> Icons.Outlined.ErrorOutline
        ShieldTone.Info -> Icons.Outlined.Info
        ShieldTone.Neutral -> Icons.Outlined.Info
    }

    Row(
        modifier = Modifier
            .background(color.copy(alpha = 0.10f), RoundedCornerShape(50))
            .border(1.dp, color.copy(alpha = 0.25f), RoundedCornerShape(50))
            .padding(horizontal = 10.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(14.dp))
        Text(text, style = MaterialTheme.typography.labelMedium, color = color)
    }
}

@Composable
fun KeyValueRow(
    label: String,
    value: String,
    mono: Boolean = false,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(16.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Text(
            text = label,
            modifier = Modifier.weight(0.34f),
            style = MaterialTheme.typography.bodySmall,
            color = ShieldColors.TextMuted,
        )
        Text(
            text = value,
            modifier = Modifier.weight(0.66f),
            style = MaterialTheme.typography.bodyMedium.copy(
                fontFamily = if (mono) FontFamily.Monospace else FontFamily.SansSerif,
                fontWeight = if (mono) FontWeight.Medium else FontWeight.Normal,
            ),
            color = ShieldColors.TextPrimary,
        )
    }
}

@Composable
fun EmptyState(
    icon: ImageVector,
    title: String,
    description: String,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxWidth().padding(vertical = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Box(
            modifier = Modifier
                .size(54.dp)
                .background(ShieldColors.Primary.copy(alpha = 0.10f), CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = ShieldColors.PrimaryStrong,
                modifier = Modifier.size(26.dp),
            )
        }
        Text(title, style = MaterialTheme.typography.titleLarge, color = ShieldColors.TextPrimary)
        Text(
            description,
            style = MaterialTheme.typography.bodyMedium,
            color = ShieldColors.TextSecondary,
        )
    }
}

@Composable
fun ConsoleSurface(output: String) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(ShieldColors.Console, RoundedCornerShape(14.dp))
            .border(1.dp, ShieldColors.Border, RoundedCornerShape(14.dp))
            .padding(14.dp),
    ) {
        Text(
            text = output.ifBlank { "Command output will appear here." },
            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            color = if (output.isBlank()) ShieldColors.TextMuted else Color(0xFFD9E2EE),
        )
    }
}

private fun toneColor(tone: ShieldTone): Color = when (tone) {
    ShieldTone.Neutral -> ShieldColors.TextSecondary
    ShieldTone.Info -> ShieldColors.PrimaryStrong
    ShieldTone.Success -> ShieldColors.Success
    ShieldTone.Warning -> ShieldColors.Warning
    ShieldTone.Danger -> ShieldColors.Danger
}
