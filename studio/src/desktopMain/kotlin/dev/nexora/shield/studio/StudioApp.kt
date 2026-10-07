package dev.nexora.shield.studio

import androidx.compose.animation.Crossfade
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Assessment
import androidx.compose.material.icons.outlined.Dashboard
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.ListAlt
import androidx.compose.material.icons.outlined.Save
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Speed
import androidx.compose.material.icons.outlined.Terminal
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.nexora.shield.studio.ui.ShieldColors
import dev.nexora.shield.studio.ui.ShieldTone
import dev.nexora.shield.studio.ui.StatusPill
import dev.nexora.shield.studio.ui.chooseDirectory

internal enum class StudioSection(
    val title: String,
    val subtitle: String,
    val icon: ImageVector,
) {
    DASHBOARD("Dashboard", "Security workspace overview", Icons.Outlined.Dashboard),
    PROJECT("Project", "Import and discovery", Icons.Outlined.FolderOpen),
    CONFIGURATION("Protection", "Profile and application policy", Icons.Outlined.Settings),
    SELECTORS("Selectors", "Protection targeting rules", Icons.Outlined.ListAlt),
    REPORT("Security report", "Build evidence and output", Icons.Outlined.Assessment),
    PERFORMANCE("Performance", "Protection budgets", Icons.Outlined.Speed),
    BUILD("Build console", "Gradle and Shield CLI", Icons.Outlined.Terminal),
    VERIFY("Verification", "APK, AAB, AAR and APKS", Icons.Outlined.VerifiedUser),
    RETRACE("Retrace", "Mapping and stack traces", Icons.Outlined.History),
    SECRETS("Secret providers", "Reference-only credentials", Icons.Outlined.Key),
}

@Composable
fun StudioApp(state: StudioState = remember { StudioState() }) {
    var section by remember { mutableStateOf(StudioSection.DASHBOARD) }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = ShieldColors.Background,
    ) {
        BoxWithConstraints(Modifier.fillMaxSize()) {
            val compactNavigation = maxWidth < 1180.dp
            val compactContent = maxWidth < 1080.dp

            Row(Modifier.fillMaxSize()) {
                StudioNavigation(
                    selected = section,
                    compact = compactNavigation,
                    onSelect = { section = it },
                )
                HorizontalDivider(
                    modifier = Modifier.fillMaxHeight().width(1.dp),
                    color = ShieldColors.Border,
                )
                Column(Modifier.fillMaxSize()) {
                    StudioTopBar(
                        state = state,
                        section = section,
                        onImport = { chooseDirectory()?.let(state::importProject) },
                    )
                    HorizontalDivider(color = ShieldColors.Border)
                    Crossfade(
                        targetState = section,
                        label = "studio-section",
                        modifier = Modifier.fillMaxSize(),
                    ) { selected ->
                        StudioScreen(
                            section = selected,
                            state = state,
                            compact = compactContent,
                            onNavigate = { section = it },
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun StudioNavigation(
    selected: StudioSection,
    compact: Boolean,
    onSelect: (StudioSection) -> Unit,
) {
    val width = if (compact) 82.dp else 232.dp

    Column(
        modifier = Modifier
            .width(width)
            .fillMaxHeight()
            .background(ShieldColors.SurfaceMuted),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(
                horizontal = if (compact) 17.dp else 18.dp,
                vertical = 18.dp,
            ),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(11.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(42.dp)
                    .background(
                        ShieldColors.Primary.copy(alpha = 0.14f),
                        RoundedCornerShape(13.dp),
                    ),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Outlined.Security,
                    contentDescription = null,
                    tint = ShieldColors.PrimaryStrong,
                    modifier = Modifier.size(24.dp),
                )
            }
            if (!compact) {
                Column {
                    Text(
                        "Nexora Shield",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                        color = ShieldColors.TextPrimary,
                    )
                    Text(
                        "Studio",
                        style = MaterialTheme.typography.bodySmall,
                        color = ShieldColors.TextMuted,
                    )
                }
            }
        }

        HorizontalDivider(color = ShieldColors.Border)
        Spacer(Modifier.size(10.dp))

        NavigationGroup(
            label = "Workspace",
            items = listOf(StudioSection.DASHBOARD, StudioSection.PROJECT),
            selected = selected,
            compact = compact,
            onSelect = onSelect,
        )
        NavigationGroup(
            label = "Policy",
            items = listOf(
                StudioSection.CONFIGURATION,
                StudioSection.SELECTORS,
                StudioSection.PERFORMANCE,
            ),
            selected = selected,
            compact = compact,
            onSelect = onSelect,
        )
        NavigationGroup(
            label = "Operations",
            items = listOf(
                StudioSection.BUILD,
                StudioSection.VERIFY,
                StudioSection.REPORT,
                StudioSection.RETRACE,
            ),
            selected = selected,
            compact = compact,
            onSelect = onSelect,
        )
        NavigationGroup(
            label = "Security",
            items = listOf(StudioSection.SECRETS),
            selected = selected,
            compact = compact,
            onSelect = onSelect,
        )
    }
}

@Composable
private fun NavigationGroup(
    label: String,
    items: List<StudioSection>,
    selected: StudioSection,
    compact: Boolean,
    onSelect: (StudioSection) -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 9.dp, vertical = 4.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        if (!compact) {
            Text(
                text = label.uppercase(),
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 7.dp),
                style = MaterialTheme.typography.labelMedium,
                color = ShieldColors.TextMuted,
            )
        }

        items.forEach { item ->
            val active = item == selected
            Surface(
                onClick = { onSelect(item) },
                modifier = Modifier.fillMaxWidth(),
                color = if (active) {
                    ShieldColors.Primary.copy(alpha = 0.12f)
                } else {
                    ShieldColors.SurfaceMuted
                },
                contentColor = if (active) {
                    ShieldColors.PrimaryStrong
                } else {
                    ShieldColors.TextSecondary
                },
                shape = RoundedCornerShape(11.dp),
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(
                            horizontal = if (compact) 0.dp else 12.dp,
                            vertical = 10.dp,
                        ),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = if (compact) {
                        Arrangement.Center
                    } else {
                        Arrangement.spacedBy(11.dp)
                    },
                ) {
                    Icon(
                        imageVector = item.icon,
                        contentDescription = item.title,
                        modifier = Modifier.size(20.dp),
                    )
                    if (!compact) {
                        Text(
                            item.title,
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = if (active) FontWeight.SemiBold else FontWeight.Medium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun StudioTopBar(
    state: StudioState,
    section: StudioSection,
    onImport: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 22.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(
                section.title,
                style = MaterialTheme.typography.titleLarge,
                color = ShieldColors.TextPrimary,
            )
            Text(
                state.project?.root?.fileName?.toString() ?: section.subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = ShieldColors.TextMuted,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }

        StatusPill(
            text = when {
                state.busy -> "Operation running"
                state.project == null -> "No project"
                else -> "Project ready"
            },
            tone = when {
                state.busy -> ShieldTone.Info
                state.project == null -> ShieldTone.Neutral
                else -> ShieldTone.Success
            },
        )

        OutlinedButton(onClick = onImport) {
            Icon(Icons.Outlined.FolderOpen, contentDescription = null, modifier = Modifier.size(17.dp))
            Spacer(Modifier.width(7.dp))
            Text(if (state.project == null) "Import project" else "Change project")
        }

        Button(
            onClick = state::saveConfig,
            enabled = state.project != null && !state.busy,
        ) {
            Icon(Icons.Outlined.Save, contentDescription = null, modifier = Modifier.size(17.dp))
            Spacer(Modifier.width(7.dp))
            Text("Save")
        }
    }
}
