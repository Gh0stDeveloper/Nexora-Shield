package dev.nexora.shield.studio

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.nexora.shield.studio.model.BudgetPolicy
import dev.nexora.shield.studio.model.PerformanceBudgets
import dev.nexora.shield.studio.model.SecretSettings
import dev.nexora.shield.studio.model.SelectorGroup
import dev.nexora.shield.studio.model.ShieldProfile
import kotlinx.coroutines.launch
import java.nio.file.Path
import javax.swing.JFileChooser

private enum class StudioSection(val title: String) {
    PROJECT("Project"),
    CONFIGURATION("Configuration"),
    SELECTORS("Selectors"),
    REPORT("Security report"),
    PERFORMANCE("Performance"),
    BUILD("Build console"),
    VERIFY("Artifact verification"),
    RETRACE("Mapping / retrace"),
    SECRETS("Secret providers"),
}

@Composable
fun StudioApp(state: StudioState = remember { StudioState() }) {
    var section by remember { mutableStateOf(StudioSection.PROJECT) }

    Surface(Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize()) {
            StudioHeader(state)
            HorizontalDivider()
            Row(Modifier.fillMaxSize()) {
                StudioSidebar(section) { section = it }
                HorizontalDivider(Modifier.fillMaxHeight().width(1.dp))
                Box(Modifier.weight(1f).fillMaxHeight().padding(24.dp)) {
                    when (section) {
                        StudioSection.PROJECT -> ProjectScreen(state)
                        StudioSection.CONFIGURATION -> ConfigurationScreen(state)
                        StudioSection.SELECTORS -> SelectorsScreen(state)
                        StudioSection.REPORT -> ReportScreen(state)
                        StudioSection.PERFORMANCE -> PerformanceScreen(state)
                        StudioSection.BUILD -> BuildScreen(state)
                        StudioSection.VERIFY -> VerifyScreen(state)
                        StudioSection.RETRACE -> RetraceScreen(state)
                        StudioSection.SECRETS -> SecretsScreen(state)
                    }
                }
            }
        }
    }
}

@Composable
private fun StudioHeader(state: StudioState) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Column(Modifier.weight(1f)) {
            Text("Nexora Shield Studio", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
            Text(
                state.project?.root?.toString() ?: "No project imported",
                style = MaterialTheme.typography.bodySmall,
            )
        }
        Button(onClick = {
            chooseDirectory()?.let(state::importProject)
        }) {
            Text("Import project")
        }
        Button(onClick = state::saveConfig, enabled = state.project != null) {
            Text("Save configuration")
        }
    }
}

@Composable
private fun StudioSidebar(
    selected: StudioSection,
    onSelect: (StudioSection) -> Unit,
) {
    Column(
        modifier = Modifier.width(220.dp).fillMaxHeight().padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        StudioSection.entries.forEach { section ->
            if (section == selected) {
                Button(onClick = { onSelect(section) }, modifier = Modifier.fillMaxWidth()) {
                    Text(section.title)
                }
            } else {
                TextButton(onClick = { onSelect(section) }, modifier = Modifier.fillMaxWidth()) {
                    Text(section.title)
                }
            }
        }
    }
}

@Composable
private fun ProjectScreen(state: StudioState) {
    ScreenColumn("Project import", state.statusMessage) {
        val project = state.project
        if (project == null) {
            Text("Import an Android Gradle project. Studio only inspects files; import never executes Gradle scripts.")
            return@ScreenColumn
        }

        InfoCard("Root", project.root.toString())
        InfoCard("Configuration", project.configPath.toString())
        InfoCard("Gradle modules", project.modules.size.toString())
        InfoCard("Discovered artifacts", project.artifacts.size.toString())
        InfoCard("Public reports", project.publicReports.size.toString())
        InfoCard("Mappings", project.mappings.size.toString())
    }
}

@Composable
private fun ConfigurationScreen(state: StudioState) {
    val config = state.config
    ScreenColumn("Profile editor", state.statusMessage) {
        OutlinedTextField(
            value = config.applicationId,
            onValueChange = { value -> state.updateConfig { it.copy(applicationId = value) } },
            label = { Text("Application id") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )
        OutlinedTextField(
            value = config.minSdk.toString(),
            onValueChange = { value ->
                value.toIntOrNull()?.let { sdk -> state.updateConfig { it.copy(minSdk = sdk) } }
            },
            label = { Text("minSdk") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )

        Text("Protection profile", style = MaterialTheme.typography.titleMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ShieldProfile.entries.forEach { profile ->
                FilterChip(
                    selected = config.profile == profile,
                    onClick = { state.updateConfig { it.copy(profile = profile) } },
                    label = { Text(profile.wireValue) },
                )
            }
        }

        Text(
            "Studio writes schema-1 application/profile fields and preserves unrelated advanced YAML sections.",
            style = MaterialTheme.typography.bodySmall,
        )
        Button(onClick = state::saveConfig, enabled = state.project != null) {
            Text("Validate and save")
        }
    }
}

@Composable
private fun SelectorsScreen(state: StudioState) {
    ScreenColumn("Selector editor", state.statusMessage) {
        state.config.selectors.forEachIndexed { index, selector ->
            Card(Modifier.fillMaxWidth()) {
                Column(
                    Modifier.fillMaxWidth().padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
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
                        label = { Text("Include patterns — one per line") },
                        modifier = Modifier.fillMaxWidth(),
                        minLines = 3,
                    )
                    OutlinedTextField(
                        value = selector.exclude.joinToString("\n"),
                        onValueChange = { value ->
                            updateSelector(state, index, selector.copy(exclude = parseLines(value)))
                        },
                        label = { Text("Exclude patterns — one per line") },
                        modifier = Modifier.fillMaxWidth(),
                        minLines = 3,
                    )
                    OutlinedButton(onClick = {
                        state.updateConfig {
                            it.copy(selectors = it.selectors.filterIndexed { itemIndex, _ -> itemIndex != index })
                        }
                    }) {
                        Text("Remove selector")
                    }
                }
            }
        }

        Button(onClick = {
            state.updateConfig {
                it.copy(selectors = it.selectors + SelectorGroup(name = "selector-" + (it.selectors.size + 1)))
            }
        }) {
            Text("Add selector")
        }
    }
}

@Composable
private fun ReportScreen(state: StudioState) {
    ScreenColumn("Security report", state.statusMessage) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = {
                chooseFile("JSON report", "json")?.let(state::loadReport)
            }) {
                Text("Open public report")
            }

            state.project?.publicReports?.firstOrNull()?.let { report ->
                OutlinedButton(onClick = { state.loadReport(report) }) {
                    Text("Open latest discovered report")
                }
            }
        }

        val report = state.report
        if (report == null) {
            Text("No public build report loaded.")
        } else {
            InfoCard("Build id", report.buildId)
            InfoCard("Profile", report.profile)
            InfoCard("Signed / aligned", report.signed.toString() + " / " + report.aligned)
            InfoCard("DEX files", report.dexCount.toString())
            InfoCard("Input SHA-256", report.inputSha256)
            InfoCard("Output SHA-256", report.outputSha256)
            InfoCard("Input / output bytes", report.inputSize.toString() + " / " + report.outputSize)
            InfoCard("Pipeline", report.stages.joinToString(" → "))
        }
    }
}

@Composable
private fun PerformanceScreen(state: StudioState) {
    val budgets = state.config.budgets
    ScreenColumn("Performance budgets", state.statusMessage) {
        NumericBudgetField("APK growth %", budgets.apkGrowthPercent) { value ->
            updateBudgets(state) { it.copy(apkGrowthPercent = value) }
        }
        NumericBudgetField("Startup ms", budgets.startupMs) { value ->
            updateBudgets(state) { it.copy(startupMs = value) }
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
        IntegerBudgetField("VM methods", budgets.vmMethods) { value ->
            updateBudgets(state) { it.copy(vmMethods = value) }
        }
        NumericBudgetField("Build minutes", budgets.buildMinutes) { value ->
            updateBudgets(state) { it.copy(buildMinutes = value) }
        }

        Text("Budget policy", style = MaterialTheme.typography.titleMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            BudgetPolicy.entries.forEach { policy ->
                FilterChip(
                    selected = state.config.budgetPolicy == policy,
                    onClick = { state.updateConfig { it.copy(budgetPolicy = policy) } },
                    label = { Text(policy.wireValue) },
                )
            }
        }

        val evaluation = state.budgetEvaluation()
        val measured = evaluation.measuredApkGrowthPercent
        if (measured != null) {
            InfoCard("Measured APK growth", String.format("%.2f%%", measured))
            InfoCard(
                "APK growth budget",
                when (evaluation.apkGrowthWithinBudget) {
                    true -> "PASS"
                    false -> "FAIL"
                    null -> "No configured limit"
                },
            )
        }
    }
}

@Composable
private fun BuildScreen(state: StudioState) {
    val scope = rememberCoroutineScope()
    ScreenColumn("Build console", state.statusMessage) {
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
                Text("Run Gradle task")
            }
            OutlinedButton(
                onClick = { scope.launch { state.runCliVersion() } },
                enabled = !state.busy && state.project != null,
            ) {
                Text("Check CLI")
            }
        }
        ConsoleOutput(state.consoleOutput)
    }
}

@Composable
private fun VerifyScreen(state: StudioState) {
    val scope = rememberCoroutineScope()
    ScreenColumn("Artifact verification", state.statusMessage) {
        InfoCard("Selected artifact", state.selectedArtifact?.toString() ?: "None")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = {
                chooseFile("Android artifact", "apk", "aab", "aar", "apks")?.let {
                    state.selectedArtifact = it
                }
            }) {
                Text("Select artifact")
            }
            state.project?.artifacts?.firstOrNull()?.let { artifact ->
                OutlinedButton(onClick = { state.selectedArtifact = artifact }) {
                    Text("Use latest discovered")
                }
            }
            Button(
                onClick = { scope.launch { state.verifySelectedArtifact() } },
                enabled = !state.busy && state.selectedArtifact != null,
            ) {
                Text("Verify")
            }
        }
        ConsoleOutput(state.consoleOutput)
    }
}

@Composable
private fun RetraceScreen(state: StudioState) {
    val scope = rememberCoroutineScope()
    ScreenColumn("Mapping / retrace", state.statusMessage) {
        OutlinedTextField(
            value = state.retraceExecutable,
            onValueChange = { state.retraceExecutable = it },
            label = { Text("Retrace executable") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )
        InfoCard("Mapping", state.mappingFile?.toString() ?: "None")
        InfoCard("Stacktrace", state.stacktraceFile?.toString() ?: "None")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = {
                chooseFile("R8 mapping", "txt")?.let { state.mappingFile = it }
            }) {
                Text("Select mapping")
            }
            OutlinedButton(onClick = {
                chooseFile("Stacktrace", "txt", "log")?.let { state.stacktraceFile = it }
            }) {
                Text("Select stacktrace")
            }
            Button(
                onClick = { scope.launch { state.runRetrace() } },
                enabled = !state.busy && state.mappingFile != null && state.stacktraceFile != null,
            ) {
                Text("Retrace")
            }
        }
        ConsoleOutput(state.consoleOutput)
    }
}

@Composable
private fun SecretsScreen(state: StudioState) {
    val secrets = state.config.secrets
    ScreenColumn("Secure secret providers", state.statusMessage) {
        Text(
            "Studio stores references only. There is intentionally no field for entering raw secret material.",
            style = MaterialTheme.typography.bodyMedium,
        )

        OutlinedTextField(
            value = secrets.provider.orEmpty(),
            onValueChange = { value ->
                state.updateConfig { it.copy(secrets = it.secrets.copy(provider = value)) }
            },
            label = { Text("Provider: env, file, ci, os_keychain, external_kms") },
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

        state.secretStatuses().forEach { status ->
            InfoCard(
                status.field,
                status.provider + " | " + when (status.available) {
                    true -> "available"
                    false -> "unavailable"
                    null -> "delegated"
                } + " | " + status.detail,
            )
        }
    }
}

@Composable
private fun ScreenColumn(
    title: String,
    status: String,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(title, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
        Text(status, style = MaterialTheme.typography.bodySmall)
        HorizontalDivider()
        content()
        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun InfoCard(label: String, value: String) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(label, style = MaterialTheme.typography.labelMedium)
            SelectionContainer {
                Text(value, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
private fun ConsoleOutput(output: String) {
    Card(Modifier.fillMaxWidth()) {
        SelectionContainer {
            Text(
                output.ifBlank { "Command output will appear here." },
                modifier = Modifier.fillMaxWidth().padding(14.dp),
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
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
        supportingText = { Text("Reference only, for example env:NEXORA_BUILD_SEED.") },
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

private fun chooseDirectory(): Path? {
    val chooser = JFileChooser()
    chooser.fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
    chooser.isMultiSelectionEnabled = false
    return if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
        chooser.selectedFile.toPath()
    } else {
        null
    }
}

private fun chooseFile(
    description: String,
    vararg extensions: String,
): Path? {
    val chooser = JFileChooser()
    chooser.fileSelectionMode = JFileChooser.FILES_ONLY
    chooser.isMultiSelectionEnabled = false
    if (extensions.isNotEmpty()) {
        chooser.fileFilter = javax.swing.filechooser.FileNameExtensionFilter(description, *extensions)
    }
    return if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
        chooser.selectedFile.toPath()
    } else {
        null
    }
}
