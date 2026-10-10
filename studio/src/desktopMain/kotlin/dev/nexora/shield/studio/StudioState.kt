package dev.nexora.shield.studio

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import dev.nexora.shield.studio.model.BudgetEvaluation
import dev.nexora.shield.studio.model.ConfigDocument
import dev.nexora.shield.studio.model.ImportedProject
import dev.nexora.shield.studio.model.PublicSecurityReport
import dev.nexora.shield.studio.model.SecretReferenceStatus
import dev.nexora.shield.studio.model.StudioConfig
import dev.nexora.shield.studio.service.ArtifactVerifier
import dev.nexora.shield.studio.service.BudgetEvaluator
import dev.nexora.shield.studio.service.ConfigCodec
import dev.nexora.shield.studio.service.GradleBuildService
import dev.nexora.shield.studio.service.ProjectImporter
import dev.nexora.shield.studio.service.ProductionReadinessService
import dev.nexora.shield.studio.service.RetraceService
import dev.nexora.shield.studio.service.SecretReferenceInspector
import dev.nexora.shield.studio.service.SecurityReportLoader
import java.nio.file.Path

class StudioState(
    private val importer: ProjectImporter = ProjectImporter(),
    private val configCodec: ConfigCodec = ConfigCodec(),
    private val reportLoader: SecurityReportLoader = SecurityReportLoader(),
    val buildService: GradleBuildService = GradleBuildService(),
    val productionReadinessService: ProductionReadinessService = ProductionReadinessService(),
    val artifactVerifier: ArtifactVerifier = ArtifactVerifier(),
    val retraceService: RetraceService = RetraceService(),
    private val secretInspector: SecretReferenceInspector = SecretReferenceInspector(),
) {
    var project by mutableStateOf<ImportedProject?>(null)
        private set

    var document by mutableStateOf<ConfigDocument?>(null)
        private set

    var config by mutableStateOf(StudioConfig())
        private set

    var report by mutableStateOf<PublicSecurityReport?>(null)
        private set

    var statusMessage by mutableStateOf("Import an Android project to begin.")
        private set

    var consoleOutput by mutableStateOf("")
        private set

    var busy by mutableStateOf(false)
        private set

    var cliExecutable by mutableStateOf("nexora-shield")
    var retraceExecutable by mutableStateOf("retrace")
    var gradleTask by mutableStateOf("assembleRelease")
    var selectedArtifact by mutableStateOf<Path?>(null)
    var mappingFile by mutableStateOf<Path?>(null)
    var stacktraceFile by mutableStateOf<Path?>(null)

    fun importProject(root: Path) {
        runCatching {
            val imported = importer.importProject(root)
            val loaded = configCodec.load(imported.configPath)
            project = imported
            document = loaded
            config = loaded.config
            selectedArtifact = imported.artifacts.firstOrNull()
            mappingFile = imported.mappings.firstOrNull()
            statusMessage = "Project imported: " + imported.root
        }.onFailure {
            statusMessage = "Import failed: " + (it.message ?: it::class.simpleName)
        }
    }

    fun updateConfig(transform: (StudioConfig) -> StudioConfig) {
        config = transform(config)
    }

    fun saveConfig() {
        val imported = project
        val current = document
        if (imported == null || current == null) {
            statusMessage = "Import a project before saving configuration."
            return
        }

        runCatching {
            document = configCodec.save(imported.configPath, current, config)
            statusMessage = "Configuration saved: " + imported.configPath
        }.onFailure {
            statusMessage = "Configuration save failed: " + (it.message ?: it::class.simpleName)
        }
    }

    fun loadReport(path: Path) {
        runCatching {
            report = reportLoader.load(path)
            statusMessage = "Public report loaded: " + path
        }.onFailure {
            statusMessage = "Report load failed: " + (it.message ?: it::class.simpleName)
        }
    }

    fun budgetEvaluation(): BudgetEvaluation = BudgetEvaluator.evaluate(config.budgets, report)

    fun secretStatuses(): List<SecretReferenceStatus> {
        val root = project?.root ?: return emptyList()
        return secretInspector.inspect(config.secrets, root)
    }

    suspend fun runGradleTask() {
        val root = project?.root ?: run {
            statusMessage = "Import a project before running Gradle."
            return
        }
        execute("Gradle task") { buildService.runTask(root, gradleTask) }
    }

    suspend fun runProductionReadinessCheck() {
        val root = project?.root ?: run {
            statusMessage = "Import a project before production planning."
            return
        }
        val artifact = selectedArtifact ?: run {
            statusMessage = "Select an APK for read-only production planning."
            return
        }
        val plannedOutput = root.resolve("build/nexora-shield/o1-diagnostic-placeholder.apk")
        execute("Read-only production preflight (NOT protected)") {
            productionReadinessService.inspect(
                artifact,
                plannedOutput,
                config.profile,
                cliExecutable,
                root,
            )
        }
    }

    suspend fun runCliVersion() {
        val root = project?.root ?: run {
            statusMessage = "Import a project before running the CLI."
            return
        }
        execute("CLI") { buildService.cliVersion(root, cliExecutable) }
    }

    suspend fun verifySelectedArtifact() {
        val root = project?.root ?: run {
            statusMessage = "Import a project before verification."
            return
        }
        val artifact = selectedArtifact ?: run {
            statusMessage = "Select an artifact to verify."
            return
        }
        execute("Artifact verification") {
            artifactVerifier.verify(artifact, root, cliExecutable).result
        }
    }

    suspend fun runRetrace() {
        val root = project?.root ?: run {
            statusMessage = "Import a project before retrace."
            return
        }
        val mapping = mappingFile ?: run {
            statusMessage = "Select a mapping.txt file."
            return
        }
        val stacktrace = stacktraceFile ?: run {
            statusMessage = "Select a stacktrace file."
            return
        }
        execute("Retrace") {
            retraceService.retrace(root, retraceExecutable, mapping, stacktrace)
        }
    }

    private suspend fun execute(
        label: String,
        block: suspend () -> dev.nexora.shield.studio.model.CommandResult,
    ) {
        if (busy) return
        busy = true
        statusMessage = label + " running..."
        try {
            val result = block()
            consoleOutput = result.output
            statusMessage = label + if (result.successful) {
                " completed successfully in " + result.durationMillis + " ms."
            } else {
                " failed with exit code " + result.exitCode + "."
            }
        } catch (error: Exception) {
            consoleOutput = error.stackTraceToString()
            statusMessage = label + " failed: " + (error.message ?: error::class.simpleName)
        } finally {
            busy = false
        }
    }
}
