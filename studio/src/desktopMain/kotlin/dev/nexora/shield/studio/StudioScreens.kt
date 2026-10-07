package dev.nexora.shield.studio

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Android
import androidx.compose.material.icons.outlined.Assessment
import androidx.compose.material.icons.outlined.Build
import androidx.compose.material.icons.outlined.Code
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Layers
import androidx.compose.material.icons.outlined.PlayArrow
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Rule
import androidx.compose.material.icons.outlined.Save
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Speed
import androidx.compose.material.icons.outlined.Terminal
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.nexora.shield.studio.model.BudgetPolicy
import dev.nexora.shield.studio.model.PerformanceBudgets
import dev.nexora.shield.studio.model.SelectorGroup
import dev.nexora.shield.studio.model.ShieldProfile
import dev.nexora.shield.studio.ui.ConsoleSurface
import dev.nexora.shield.studio.ui.EmptyState
import dev.nexora.shield.studio.ui.KeyValueRow
import dev.nexora.shield.studio.ui.MetricCard
import dev.nexora.shield.studio.ui.PageHeader
import dev.nexora.shield.studio.ui.Panel
import dev.nexora.shield.studio.ui.ShieldColors
import dev.nexora.shield.studio.ui.ShieldTone
import dev.nexora.shield.studio.ui.StatusPill
import dev.nexora.shield.studio.ui.FeedbackLevel
import dev.nexora.shield.studio.ui.StudioFeedbackPolicy
import dev.nexora.shield.studio.ui.chooseFile
import kotlinx.coroutines.launch

@Composable
internal fun StudioScreen(
    section: StudioSection,
    state: StudioState,
    compact: Boolean,
    onNavigate: (StudioSection) -> Unit,
) {
    when (section) {
        StudioSection.DASHBOARD -> DashboardScreen(state, compact, onNavigate)
        StudioSection.PROJECT -> ProjectScreen(state)
        StudioSection.CONFIGURATION -> ConfigurationScreen(state)
        StudioSection.SELECTORS -> SelectorsScreen(state)
        StudioSection.REPORT -> ReportScreen(state, compact)
        StudioSection.PERFORMANCE -> PerformanceScreen(state, compact)
        StudioSection.BUILD -> BuildScreen(state)
        StudioSection.VERIFY -> VerifyScreen(state)
        StudioSection.RETRACE -> RetraceScreen(state)
        StudioSection.SECRETS -> SecretsScreen(state)
    }
}

@Composable
private fun DashboardScreen(
    state: StudioState,
    compact: Boolean,
    onNavigate: (StudioSection) -> Unit,
) {
    ScreenSurface {
        PageHeader(
            eyebrow = "Shield Studio",
            title = "Protection workspace",
            description = "Review project readiness, policy, artifacts and operational status from one place.",
            actions = {
                OutlinedButton(onClick = { onNavigate(StudioSection.VERIFY) }) {
                    Icon(Icons.Outlined.VerifiedUser, contentDescription = null)
                    Spacer(Modifier.width(7.dp))
                    Text("Verify artifact")
                }
            },
        )

        StatusBanner(state.statusMessage, state.busy)

        val project = state.project
        if (project == null) {
            Panel {
                EmptyState(
                    icon = Icons.Outlined.FolderOpen,
                    title = "No project imported",
                    description = "Import an Android Gradle project to unlock policy editing, verification and build workflows.",
                )
            }
            return@ScreenSurface
        }

        MetricGrid(compact) {
            MetricCard(
                icon = Icons.Outlined.Android,
                label = "Protection profile",
                value = state.config.profile.wireValue.replaceFirstChar(Char::uppercase),
                detail = "Schema ${state.config.schema} · minSdk ${state.config.minSdk}",
                tone = ShieldTone.Info,
                modifier = Modifier.fillMaxWidth(),
            )
            MetricCard(
                icon = Icons.Outlined.Layers,
                label = "Gradle modules",
                value = project.modules.size.toString(),
                detail = "Detected without executing Gradle",
                modifier = Modifier.fillMaxWidth(),
            )
            MetricCard(
                icon = Icons.Outlined.Rule,
                label = "Selector groups",
                value = state.config.selectors.size.toString(),
                detail = "Targeted include/exclude policy",
                tone = if (state.config.selectors.isEmpty()) ShieldTone.Neutral else ShieldTone.Success,
                modifier = Modifier.fillMaxWidth(),
            )
            MetricCard(
                icon = Icons.Outlined.VerifiedUser,
                label = "Artifacts",
                value = project.artifacts.size.toString(),
                detail = state.selectedArtifact?.fileName?.toString() ?: "No artifact selected",
                tone = if (project.artifacts.isEmpty()) ShieldTone.Warning else ShieldTone.Success,
                modifier = Modifier.fillMaxWidth(),
            )
        }

        AdaptivePair(compact) {
            Panel(
                modifier = Modifier.fillMaxWidth(),
                title = "Protection readiness",
                subtitle = "Pre-flight state for common release operations.",
            ) {
                ReadinessRow("Project imported", true)
                ReadinessRow("Configuration available", state.document != null)
                ReadinessRow("Artifact discovered", project.artifacts.isNotEmpty())
                ReadinessRow("Public report available", project.publicReports.isNotEmpty())
                ReadinessRow("R8 mapping available", project.mappings.isNotEmpty())
                ReadinessRow(
                    "Secret references configured",
                    listOf(
                        state.config.secrets.signingKeyRef,
                        state.config.secrets.buildSeedRef,
                        state.config.secrets.buildNonceRef,
                    ).any { !it.isNullOrBlank() },
                )
            }

            Panel(
                modifier = Modifier.fillMaxWidth(),
                title = "Quick actions",
                subtitle = "Go directly to the next operational task.",
            ) {
                QuickAction(
                    title = "Tune protection policy",
                    description = "Change profile, application identity and minSdk.",
                    icon = Icons.Outlined.Security,
                    onClick = { onNavigate(StudioSection.CONFIGURATION) },
                )
                QuickAction(
                    title = "Run release build",
                    description = "Execute the configured Gradle release task.",
                    icon = Icons.Outlined.Build,
                    onClick = { onNavigate(StudioSection.BUILD) },
                )
                QuickAction(
                    title = "Inspect security report",
                    description = "Review signed output and pipeline evidence.",
                    icon = Icons.Outlined.Assessment,
                    onClick = { onNavigate(StudioSection.REPORT) },
                )
            }
        }

        Panel(
            title = "Current project",
            subtitle = project.root.toString(),
        ) {
            KeyValueRow("Configuration", project.configPath.toString(), mono = true)
            KeyValueRow("Latest artifact", project.artifacts.firstOrNull()?.toString() ?: "None", mono = true)
            KeyValueRow("Latest mapping", project.mappings.firstOrNull()?.toString() ?: "None", mono = true)
        }
    }
}

@Composable
private fun ProjectScreen(state: StudioState) {
    ScreenSurface {
        PageHeader(
            eyebrow = "Workspace",
            title = "Project",
            description = "Safe project discovery without evaluating Gradle build scripts.",
        )
        StatusBanner(state.statusMessage, state.busy)

        val project = state.project
        if (project == null) {
            Panel {
                EmptyState(
                    icon = Icons.Outlined.FolderOpen,
                    title = "Import a project from the top bar",
                    description = "Shield Studio will discover Gradle modules, configuration, artifacts, reports and mappings.",
                )
            }
            return@ScreenSurface
        }

        Panel(
            title = "Project identity",
            subtitle = "Resolved paths and discovered build metadata.",
        ) {
            KeyValueRow("Root", project.root.toString(), mono = true)
            KeyValueRow("Configuration", project.configPath.toString(), mono = true)
            KeyValueRow("Application id", state.config.applicationId, mono = true)
            KeyValueRow("Profile", state.config.profile.wireValue)
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            MetricCard(
                Icons.Outlined.Layers,
                "Modules",
                project.modules.size.toString(),
                "Gradle modules discovered",
                modifier = Modifier.fillMaxWidth(),
            )
            MetricCard(
                Icons.Outlined.Android,
                "Artifacts",
                project.artifacts.size.toString(),
                "APK / AAB / AAR / APKS",
                modifier = Modifier.fillMaxWidth(),
            )
            MetricCard(
                Icons.Outlined.Description,
                "Reports",
                project.publicReports.size.toString(),
                "Public Shield reports",
                modifier = Modifier.fillMaxWidth(),
            )
            MetricCard(
                Icons.Outlined.History,
                "Mappings",
                project.mappings.size.toString(),
                "R8 mapping files",
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun ConfigurationScreen(state: StudioState) {
    val config = state.config

    ScreenSurface {
        PageHeader(
            eyebrow = "Protection policy",
            title = "Profile & application",
            description = "Configure the protection posture while preserving advanced YAML sections authored outside Studio.",
            actions = {
                Button(
                    onClick = state::saveConfig,
                    enabled = state.project != null && !state.busy,
                ) {
                    Icon(Icons.Outlined.Save, contentDescription = null)
                    Spacer(Modifier.width(7.dp))
                    Text("Validate & save")
                }
            },
        )
        StatusBanner(state.statusMessage, state.busy)

        Panel(
            title = "Application identity",
            subtitle = "Values used by the schema and protection pipeline.",
        ) {
            OutlinedTextField(
                value = config.applicationId,
                onValueChange = { value -> state.updateConfig { it.copy(applicationId = value) } },
                label = { Text("Application id") },
                supportingText = { Text("Example: com.company.application") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            OutlinedTextField(
                value = config.minSdk.toString(),
                onValueChange = { value ->
                    value.toIntOrNull()?.let { sdk -> state.updateConfig { it.copy(minSdk = sdk) } }
                },
                label = { Text("Minimum Android SDK") },
                supportingText = { Text("Nexora Shield requires minSdk 24 or newer.") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }

        Panel(
            title = "Protection profile",
            subtitle = "Choose the baseline protection posture. Advanced selectors still control targeting.",
        ) {
            ShieldProfile.entries.forEach { profile ->
                ProfileChoice(
                    profile = profile,
                    selected = config.profile == profile,
                    onClick = { state.updateConfig { it.copy(profile = profile) } },
                )
            }
        }
    }
}

@Composable
private fun SelectorsScreen(state: StudioState) {
    ScreenSurface {
        PageHeader(
            eyebrow = "Protection policy",
            title = "Selectors",
            description = "Define precise include and exclude rules for sensitive application surfaces.",
            actions = {
                Button(onClick = {
                    state.updateConfig {
                        it.copy(
                            selectors = it.selectors + SelectorGroup(
                                name = "selector-" + (it.selectors.size + 1),
                            ),
                        )
                    }
                }) {
                    Icon(Icons.Outlined.Add, contentDescription = null)
                    Spacer(Modifier.width(7.dp))
                    Text("Add selector")
                }
            },
        )
        StatusBanner(state.statusMessage, state.busy)

        if (state.config.selectors.isEmpty()) {
            Panel {
                EmptyState(
                    icon = Icons.Outlined.Rule,
                    title = "No selector groups",
                    description = "Create targeted rules for sensitive packages, classes or generated code exclusions.",
                )
            }
        }

        state.config.selectors.forEachIndexed { index, selector ->
            Panel(
                title = selector.name.ifBlank { "Unnamed selector" },
                subtitle = "Rule group ${index + 1}",
            ) {
                OutlinedTextField(
                    value = selector.name,
                    onValueChange = { value -> updateSelector(state, index, selector.copy(name = value)) },
                    label = { Text("Selector name") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                OutlinedTextField(
                    value = selector.include.joinToString("\n"),
                    onValueChange = { value ->
                        updateSelector(state, index, selector.copy(include = parseLines(value)))
                    },
                    label = { Text("Include patterns") },
                    supportingText = { Text("One pattern per line.") },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 3,
                )
                OutlinedTextField(
                    value = selector.exclude.joinToString("\n"),
                    onValueChange = { value ->
                        updateSelector(state, index, selector.copy(exclude = parseLines(value)))
                    },
                    label = { Text("Exclude patterns") },
                    supportingText = { Text("Explicit exclusions take precedence.") },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 3,
                )
                OutlinedButton(onClick = {
                    state.updateConfig {
                        it.copy(
                            selectors = it.selectors.filterIndexed { itemIndex, _ -> itemIndex != index },
                        )
                    }
                }) {
                    Icon(Icons.Outlined.Delete, contentDescription = null)
                    Spacer(Modifier.width(7.dp))
                    Text("Remove selector")
                }
            }
        }
    }
}

@Composable
private fun ReportScreen(
    state: StudioState,
    compact: Boolean,
) {
    ScreenSurface {
        PageHeader(
            eyebrow = "Build evidence",
            title = "Security report",
            description = "Review public protection output without exposing private build metadata.",
            actions = {
                OutlinedButton(onClick = {
                    chooseFile("Nexora Shield public report", "json")?.let(state::loadReport)
                }) {
                    Icon(Icons.Outlined.FolderOpen, contentDescription = null)
                    Spacer(Modifier.width(7.dp))
                    Text("Open report")
                }
                state.project?.publicReports?.firstOrNull()?.let { report ->
                    Button(onClick = { state.loadReport(report) }) {
                        Icon(Icons.Outlined.Refresh, contentDescription = null)
                        Spacer(Modifier.width(7.dp))
                        Text("Latest")
                    }
                }
            },
        )
        StatusBanner(state.statusMessage, state.busy)

        val report = state.report
        if (report == null) {
            Panel {
                EmptyState(
                    icon = Icons.Outlined.Assessment,
                    title = "No public report loaded",
                    description = "Open a Nexora Shield public build report to inspect protection and packaging evidence.",
                )
            }
            return@ScreenSurface
        }

        MetricGrid(compact) {
            MetricCard(
                Icons.Outlined.Security,
                "Profile",
                report.profile,
                "Schema ${report.schemaVersion}",
                ShieldTone.Info,
                Modifier.weight(1f),
            )
            MetricCard(
                Icons.Outlined.VerifiedUser,
                "Signature",
                if (report.signed) "Signed" else "Unsigned",
                if (report.aligned) "ZIP aligned" else "Not aligned",
                if (report.signed) ShieldTone.Success else ShieldTone.Warning,
                Modifier.weight(1f),
            )
            MetricCard(
                Icons.Outlined.Code,
                "DEX files",
                report.dexCount.toString(),
                "${report.entryCount} package entries",
                ShieldTone.Neutral,
                Modifier.weight(1f),
            )
            MetricCard(
                Icons.Outlined.Build,
                "Pipeline stages",
                report.stages.size.toString(),
                report.stages.lastOrNull() ?: "No stages",
                ShieldTone.Success,
                Modifier.weight(1f),
            )
        }

        Panel(
            title = "Artifact evidence",
            subtitle = "Public, non-secret build metadata.",
        ) {
            KeyValueRow("Build id", report.buildId, mono = true)
            KeyValueRow("Manifest format", report.manifestFormat)
            KeyValueRow("Input SHA-256", report.inputSha256, mono = true)
            KeyValueRow("Output SHA-256", report.outputSha256, mono = true)
            KeyValueRow("Input bytes", report.inputSize.toString())
            KeyValueRow("Output bytes", report.outputSize.toString())
            KeyValueRow("Removed legacy signatures", report.strippedSignatureEntries.toString())
            KeyValueRow("Pipeline", report.stages.joinToString("  →  "))
        }
    }
}

@Composable
private fun PerformanceScreen(
    state: StudioState,
    compact: Boolean,
) {
    val budgets = state.config.budgets

    ScreenSurface {
        PageHeader(
            eyebrow = "Release guardrails",
            title = "Performance budgets",
            description = "Keep hardening overhead explicit and review measurable APK growth before release.",
        )
        StatusBanner(state.statusMessage, state.busy)

        AdaptivePair(compact) {
            Panel(
                modifier = Modifier.fillMaxWidth(),
                title = "Runtime & artifact",
                subtitle = "Release budgets enforced by configuration.",
            ) {
                NumericBudgetField("APK growth %", budgets.apkGrowthPercent) { value ->
                    updateBudgets(state) { it.copy(apkGrowthPercent = value) }
                }
                NumericBudgetField("Startup P50 ms", budgets.startupMsP50) { value ->
                    updateBudgets(state) { it.copy(startupMsP50 = value) }
                }
                NumericBudgetField("Startup P95 ms", budgets.startupMsP95) { value ->
                    updateBudgets(state) { it.copy(startupMsP95 = value) }
                }
                NumericBudgetField("Memory MB", budgets.memoryMb) { value ->
                    updateBudgets(state) { it.copy(memoryMb = value) }
                }
            }

            Panel(
                modifier = Modifier.fillMaxWidth(),
                title = "Build & VM",
                subtitle = "Complexity and build-time limits.",
            ) {
                NumericBudgetField("Startup ms (legacy)", budgets.startupMs) { value ->
                    updateBudgets(state) { it.copy(startupMs = value) }
                }
                IntegerBudgetField("VM methods", budgets.vmMethods) { value ->
                    updateBudgets(state) { it.copy(vmMethods = value) }
                }
                NumericBudgetField("Build minutes", budgets.buildMinutes) { value ->
                    updateBudgets(state) { it.copy(buildMinutes = value) }
                }

                Text("Budget policy", color = ShieldColors.TextSecondary)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    BudgetPolicy.entries.forEach { policy ->
                        FilterChip(
                            selected = state.config.budgetPolicy == policy,
                            onClick = { state.updateConfig { it.copy(budgetPolicy = policy) } },
                            label = { Text(policy.wireValue) },
                        )
                    }
                }
            }
        }

        val evaluation = state.budgetEvaluation()
        val measured = evaluation.measuredApkGrowthPercent
        Panel(
            title = "Measured result",
            subtitle = "Derived from the currently loaded public build report.",
        ) {
            if (measured == null) {
                EmptyState(
                    icon = Icons.Outlined.Speed,
                    title = "No measurement available",
                    description = "Load a public security report to compare actual APK growth with the configured budget.",
                )
            } else {
                KeyValueRow("Measured APK growth", String.format("%.2f%%", measured))
                StatusPill(
                    text = when (evaluation.apkGrowthWithinBudget) {
                        true -> "Within configured budget"
                        false -> "Budget exceeded"
                        null -> "No APK growth limit configured"
                    },
                    tone = when (evaluation.apkGrowthWithinBudget) {
                        true -> ShieldTone.Success
                        false -> ShieldTone.Danger
                        null -> ShieldTone.Neutral
                    },
                )
            }
        }
    }
}

@Composable
private fun BuildScreen(state: StudioState) {
    val scope = rememberCoroutineScope()

    ScreenSurface {
        PageHeader(
            eyebrow = "Operations",
            title = "Build console",
            description = "Run controlled Gradle and Nexora Shield commands with bounded output and no shell interpolation.",
        )
        StatusBanner(state.statusMessage, state.busy)

        Panel(
            title = "Command configuration",
            subtitle = "Commands are executed as explicit argument vectors.",
        ) {
            OutlinedTextField(
                value = state.gradleTask,
                onValueChange = { state.gradleTask = it },
                label = { Text("Gradle task") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            OutlinedTextField(
                value = state.cliExecutable,
                onValueChange = { state.cliExecutable = it },
                label = { Text("Nexora Shield CLI executable") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = { scope.launch { state.runGradleTask() } },
                    enabled = !state.busy && state.project != null,
                ) {
                    Icon(Icons.Outlined.PlayArrow, contentDescription = null)
                    Spacer(Modifier.width(7.dp))
                    Text("Run Gradle task")
                }
                OutlinedButton(
                    onClick = { scope.launch { state.runCliVersion() } },
                    enabled = !state.busy && state.project != null,
                ) {
                    Icon(Icons.Outlined.Terminal, contentDescription = null)
                    Spacer(Modifier.width(7.dp))
                    Text("Check CLI")
                }
            }
        }

        Panel(
            title = "Output",
            subtitle = "Captured output is bounded to protect Studio responsiveness.",
        ) {
            SelectionContainer {
                ConsoleSurface(state.consoleOutput)
            }
        }
    }
}

@Composable
private fun VerifyScreen(state: StudioState) {
    val scope = rememberCoroutineScope()

    ScreenSurface {
        PageHeader(
            eyebrow = "Release validation",
            title = "Artifact verification",
            description = "Route APK, AAB, AAR and APKS artifacts to the authoritative Nexora Shield verifier.",
            actions = {
                Button(
                    onClick = { scope.launch { state.verifySelectedArtifact() } },
                    enabled = !state.busy && state.selectedArtifact != null && state.project != null,
                ) {
                    Icon(Icons.Outlined.VerifiedUser, contentDescription = null)
                    Spacer(Modifier.width(7.dp))
                    Text("Verify")
                }
            },
        )
        StatusBanner(state.statusMessage, state.busy)

        Panel(
            title = "Artifact",
            subtitle = "Select a release artifact or use the latest artifact discovered in the imported project.",
        ) {
            KeyValueRow(
                "Selected",
                state.selectedArtifact?.toString() ?: "No artifact selected",
                mono = true,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = {
                    chooseFile("Android artifact", "apk", "aab", "aar", "apks")?.let {
                        state.selectedArtifact = it
                    }
                }) {
                    Icon(Icons.Outlined.FolderOpen, contentDescription = null)
                    Spacer(Modifier.width(7.dp))
                    Text("Select artifact")
                }
                state.project?.artifacts?.firstOrNull()?.let { artifact ->
                    OutlinedButton(onClick = { state.selectedArtifact = artifact }) {
                        Icon(Icons.Outlined.Refresh, contentDescription = null)
                        Spacer(Modifier.width(7.dp))
                        Text("Use latest discovered")
                    }
                }
            }
        }

        Panel(title = "Verification output") {
            SelectionContainer {
                ConsoleSurface(state.consoleOutput)
            }
        }
    }
}

@Composable
private fun RetraceScreen(state: StudioState) {
    val scope = rememberCoroutineScope()

    ScreenSurface {
        PageHeader(
            eyebrow = "Diagnostics",
            title = "Mapping & retrace",
            description = "Resolve obfuscated production stack traces without copying mappings into public locations.",
            actions = {
                Button(
                    onClick = { scope.launch { state.runRetrace() } },
                    enabled = !state.busy &&
                        state.project != null &&
                        state.mappingFile != null &&
                        state.stacktraceFile != null,
                ) {
                    Icon(Icons.Outlined.History, contentDescription = null)
                    Spacer(Modifier.width(7.dp))
                    Text("Retrace")
                }
            },
        )
        StatusBanner(state.statusMessage, state.busy)

        Panel(
            title = "Inputs",
            subtitle = "Mapping and stacktrace paths remain explicit.",
        ) {
            OutlinedTextField(
                value = state.retraceExecutable,
                onValueChange = { state.retraceExecutable = it },
                label = { Text("Retrace executable") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            KeyValueRow("Mapping", state.mappingFile?.toString() ?: "None", mono = true)
            KeyValueRow("Stacktrace", state.stacktraceFile?.toString() ?: "None", mono = true)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = {
                    chooseFile("R8 mapping", "txt")?.let { state.mappingFile = it }
                }) {
                    Icon(Icons.Outlined.FolderOpen, contentDescription = null)
                    Spacer(Modifier.width(7.dp))
                    Text("Select mapping")
                }
                OutlinedButton(onClick = {
                    chooseFile("Stacktrace", "txt", "log")?.let { state.stacktraceFile = it }
                }) {
                    Icon(Icons.Outlined.Description, contentDescription = null)
                    Spacer(Modifier.width(7.dp))
                    Text("Select stacktrace")
                }
            }
        }

        Panel(title = "Retraced output") {
            SelectionContainer {
                ConsoleSurface(state.consoleOutput)
            }
        }
    }
}

@Composable
private fun SecretsScreen(state: StudioState) {
    val secrets = state.config.secrets

    ScreenSurface {
        PageHeader(
            eyebrow = "Credential boundary",
            title = "Secret providers",
            description = "Configure references only. Shield Studio intentionally never provides a raw-secret editor.",
        )
        StatusBanner(state.statusMessage, state.busy)

        Panel(
            title = "Provider configuration",
            subtitle = "References are persisted; secret values remain outside Studio.",
        ) {
            OutlinedTextField(
                value = secrets.provider.orEmpty(),
                onValueChange = { value ->
                    state.updateConfig { it.copy(secrets = it.secrets.copy(provider = value)) }
                },
                label = { Text("Provider") },
                supportingText = { Text("env, file, ci, file_descriptor, os_keychain or external_kms") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            SecretReferenceField("Signing key reference", secrets.signingKeyRef) { value ->
                state.updateConfig { it.copy(secrets = it.secrets.copy(signingKeyRef = value)) }
            }
            SecretReferenceField("Build seed reference", secrets.buildSeedRef) { value ->
                state.updateConfig { it.copy(secrets = it.secrets.copy(buildSeedRef = value)) }
            }
            SecretReferenceField("Build nonce reference", secrets.buildNonceRef) { value ->
                state.updateConfig { it.copy(secrets = it.secrets.copy(buildNonceRef = value)) }
            }
        }

        Panel(
            title = "Reference status",
            subtitle = "Studio reports availability without reading secret contents into the UI.",
        ) {
            val statuses = state.secretStatuses()
            if (statuses.isEmpty()) {
                EmptyState(
                    icon = Icons.Outlined.Key,
                    title = "No secret references configured",
                    description = "Add reference identifiers only when the protection profile requires external secret material.",
                )
            } else {
                statuses.forEach { status ->
                    KeyValueRow(status.field, status.reference, mono = true)
                    StatusPill(
                        text = status.provider + " · " + when (status.available) {
                            true -> "available"
                            false -> "unavailable"
                            null -> "delegated"
                        },
                        tone = when (status.available) {
                            true -> ShieldTone.Success
                            false -> ShieldTone.Warning
                            null -> ShieldTone.Info
                        },
                    )
                    Text(status.detail, color = ShieldColors.TextSecondary)
                    HorizontalDivider(color = ShieldColors.Border)
                }
            }
        }
    }
}

@Composable
private fun ScreenSurface(content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 28.dp, vertical = 24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        content = content,
    )
}

@Composable
private fun StatusBanner(
    message: String,
    busy: Boolean,
) {
    val tone = when (StudioFeedbackPolicy.classify(message, busy)) {
        FeedbackLevel.Working -> ShieldTone.Info
        FeedbackLevel.Error -> ShieldTone.Danger
        FeedbackLevel.Success -> ShieldTone.Success
        FeedbackLevel.Neutral -> ShieldTone.Neutral
    }

    Panel {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            StatusPill(
                text = when (tone) {
                    ShieldTone.Success -> "Ready"
                    ShieldTone.Danger -> "Attention"
                    ShieldTone.Info -> "Working"
                    else -> "Status"
                },
                tone = tone,
            )
            Text(
                text = message,
                modifier = Modifier.fillMaxWidth(),
                color = ShieldColors.TextSecondary,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun MetricGrid(
    compact: Boolean,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(if (compact) 10.dp else 12.dp),
        content = content,
    )
}

@Composable
private fun AdaptivePair(
    compact: Boolean,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(if (compact) 12.dp else 14.dp),
        content = content,
    )
}

@Composable
private fun ReadinessRow(
    label: String,
    ready: Boolean,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, color = ShieldColors.TextSecondary)
        StatusPill(
            text = if (ready) "Ready" else "Pending",
            tone = if (ready) ShieldTone.Success else ShieldTone.Warning,
        )
    }
}

@Composable
private fun QuickAction(
    title: String,
    description: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    onClick: () -> Unit,
) {
    OutlinedButton(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Icon(icon, contentDescription = null)
        Spacer(Modifier.width(10.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(title)
            Text(
                description,
                color = ShieldColors.TextMuted,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun ProfileChoice(
    profile: ShieldProfile,
    selected: Boolean,
    onClick: () -> Unit,
) {
    val description = when (profile) {
        ShieldProfile.STANDARD -> "Balanced baseline for general production applications."
        ShieldProfile.HARDENED -> "Expanded integrity, native protection and stronger runtime defenses."
        ShieldProfile.MAXIMUM -> "VM Shield, aggressive diversification and optional attestation hooks."
    }
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = {
            Column(Modifier.padding(vertical = 5.dp)) {
                Text(profile.wireValue.replaceFirstChar(Char::uppercase))
                Text(description, color = ShieldColors.TextSecondary)
            }
        },
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun NumericBudgetField(
    label: String,
    value: Double?,
    onChange: (Double?) -> Unit,
) {
    OutlinedTextField(
        value = value?.toString().orEmpty(),
        onValueChange = { text -> onChange(text.takeIf(String::isNotBlank)?.toDoubleOrNull()) },
        label = { Text(label) },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
    )
}

@Composable
private fun IntegerBudgetField(
    label: String,
    value: Int?,
    onChange: (Int?) -> Unit,
) {
    OutlinedTextField(
        value = value?.toString().orEmpty(),
        onValueChange = { text -> onChange(text.takeIf(String::isNotBlank)?.toIntOrNull()) },
        label = { Text(label) },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
    )
}

@Composable
private fun SecretReferenceField(
    label: String,
    value: String?,
    onChange: (String?) -> Unit,
) {
    OutlinedTextField(
        value = value.orEmpty(),
        onValueChange = { onChange(it.ifBlank { null }) },
        label = { Text(label) },
        supportingText = { Text("Reference only — for example env:NEXORA_BUILD_SEED.") },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
    )
}

private fun updateSelector(
    state: StudioState,
    index: Int,
    selector: SelectorGroup,
) {
    state.updateConfig { config ->
        config.copy(
            selectors = config.selectors.mapIndexed { itemIndex, existing ->
                if (itemIndex == index) selector else existing
            },
        )
    }
}

private fun updateBudgets(
    state: StudioState,
    transform: (PerformanceBudgets) -> PerformanceBudgets,
) {
    state.updateConfig { config -> config.copy(budgets = transform(config.budgets)) }
}

private fun parseLines(value: String): List<String> =
    value.lines().map(String::trim).filter(String::isNotEmpty).distinct()
