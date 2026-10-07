package dev.nexora.shield.studio.service

import dev.nexora.shield.studio.model.BudgetEvaluation
import dev.nexora.shield.studio.model.CommandResult
import dev.nexora.shield.studio.model.PerformanceBudgets
import dev.nexora.shield.studio.model.PublicSecurityReport
import dev.nexora.shield.studio.model.SecretReferenceStatus
import dev.nexora.shield.studio.model.SecretSettings
import dev.nexora.shield.studio.model.VerificationResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.io.path.extension
import kotlin.io.path.isRegularFile

class SecurityReportLoader {
    fun load(path: Path): PublicSecurityReport {
        require(path.isRegularFile()) { "Public report file does not exist." }
        require(Files.size(path) <= MAX_REPORT_BYTES) { "Report exceeds the Studio size limit." }

        val root = Json.parseToJsonElement(Files.readString(path)).jsonObject
        require(root.containsKey("input_sha256") && root.containsKey("output_sha256")) {
            "The selected JSON is not a Nexora Shield public build report."
        }
        require(!root.containsKey("input_path") && !root.containsKey("created_unix_ms")) {
            "Private build metadata must not be loaded into the Studio report viewer."
        }

        return PublicSecurityReport(
            buildId = root.requiredString("build_id"),
            schemaVersion = root.requiredInt("schema_version"),
            profile = root.requiredString("profile"),
            inputSha256 = root.requiredString("input_sha256"),
            outputSha256 = root.requiredString("output_sha256"),
            inputSize = root.requiredLong("input_size"),
            outputSize = root.requiredLong("output_size"),
            entryCount = root.requiredInt("entry_count"),
            dexCount = root.requiredInt("dex_count"),
            manifestFormat = root.requiredString("manifest_format"),
            aligned = root.requiredBoolean("aligned"),
            signed = root.requiredBoolean("signed"),
            strippedSignatureEntries = root.requiredInt("stripped_signature_entries"),
            stages = root["stages"]?.jsonArray?.map { it.jsonPrimitive.content } ?: emptyList(),
        )
    }

    private fun JsonObject.requiredString(key: String): String =
        this[key]?.jsonPrimitive?.content ?: error("Missing public report field '$key'.")

    private fun JsonObject.requiredLong(key: String): Long =
        requiredString(key).toLongOrNull() ?: error("Public report field '$key' is not an integer.")

    private fun JsonObject.requiredInt(key: String): Int =
        requiredString(key).toIntOrNull() ?: error("Public report field '$key' is not an integer.")

    private fun JsonObject.requiredBoolean(key: String): Boolean =
        when (requiredString(key)) {
            "true" -> true
            "false" -> false
            else -> error("Public report field '$key' is not a boolean.")
        }

    private companion object {
        const val MAX_REPORT_BYTES = 4L * 1024L * 1024L
    }
}

object BudgetEvaluator {
    fun evaluate(
        budgets: PerformanceBudgets,
        report: PublicSecurityReport?,
    ): BudgetEvaluation {
        if (report == null || report.inputSize <= 0L) {
            return BudgetEvaluation(null, null)
        }
        val growth = ((report.outputSize - report.inputSize).toDouble() / report.inputSize.toDouble()) * 100.0
        val limit = budgets.apkGrowthPercent
        return BudgetEvaluation(
            measuredApkGrowthPercent = growth,
            apkGrowthWithinBudget = limit?.let { growth <= it },
        )
    }
}

class CommandRunner(
    private val maxOutputBytes: Int = 512 * 1024,
    private val timeoutSeconds: Long = 15 * 60,
) {
    suspend fun run(
        command: List<String>,
        workingDirectory: Path,
        environmentOverrides: Map<String, String> = emptyMap(),
    ): CommandResult = withContext(Dispatchers.IO) {
        require(command.isNotEmpty()) { "Command must not be empty." }
        require(workingDirectory.toFile().isDirectory) { "Working directory does not exist." }

        val started = System.nanoTime()
        val process = ProcessBuilder(command)
            .directory(workingDirectory.toFile())
            .redirectErrorStream(true)
            .apply { environment().putAll(environmentOverrides) }
            .start()

        val readerExecutor = Executors.newSingleThreadExecutor()
        val outputFuture = readerExecutor.submit<String> {
            process.inputStream.use { input ->
                val buffer = ByteArray(8192)
                val output = StringBuilder()
                var capturedBytes = 0
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    if (capturedBytes < maxOutputBytes) {
                        val allowed = minOf(read, maxOutputBytes - capturedBytes)
                        output.append(String(buffer, 0, allowed, StandardCharsets.UTF_8))
                        capturedBytes += allowed
                    }
                }
                if (capturedBytes >= maxOutputBytes) {
                    output.append("\\n[output truncated by Shield Studio]\\n")
                }
                output.toString()
            }
        }

        val completed = process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
        if (!completed) {
            process.destroy()
            if (!process.waitFor(2, TimeUnit.SECONDS)) {
                process.destroyForcibly()
            }
        }

        val output = runCatching { outputFuture.get(5, TimeUnit.SECONDS) }
            .getOrElse { "[unable to capture process output: " + it.message + "]" }
        readerExecutor.shutdownNow()

        CommandResult(
            exitCode = if (completed) process.exitValue() else -1,
            output = output,
            durationMillis = (System.nanoTime() - started) / 1_000_000,
            timedOut = !completed,
        )
    }
}

class GradleBuildService(
    private val commandRunner: CommandRunner = CommandRunner(),
) {
    fun commandForTask(projectRoot: Path, task: String): List<String> {
        require(TASK_NAME.matches(task)) {
            "Gradle task contains unsupported characters."
        }
        val wrapper = when {
            projectRoot.resolve("gradlew").isRegularFile() -> projectRoot.resolve("gradlew").toString()
            projectRoot.resolve("gradlew.bat").isRegularFile() -> projectRoot.resolve("gradlew.bat").toString()
            else -> "gradle"
        }
        return listOf(wrapper, task, "--no-daemon")
    }

    suspend fun runTask(projectRoot: Path, task: String): CommandResult =
        commandRunner.run(commandForTask(projectRoot, task), projectRoot)

    suspend fun cliVersion(projectRoot: Path, cliExecutable: String): CommandResult =
        commandRunner.run(listOf(cliExecutable, "--version"), projectRoot)

    private companion object {
        val TASK_NAME = Regex("^[:A-Za-z0-9_.-]+$")
    }
}

class ArtifactVerifier(
    private val commandRunner: CommandRunner = CommandRunner(),
) {
    fun commandFor(artifact: Path, cliExecutable: String): List<String> {
        require(artifact.isRegularFile()) { "Artifact does not exist." }
        val action = when (artifact.extension.lowercase()) {
            "apk" -> "verify"
            "aab" -> "aab-verify"
            "aar" -> "aar-verify"
            "apks" -> "apks-verify"
            else -> error("Unsupported artifact type '.${artifact.extension}'.")
        }
        return if (action == "verify") {
            listOf(cliExecutable, action, artifact.toAbsolutePath().normalize().toString(), "--signature")
        } else {
            listOf(cliExecutable, action, artifact.toAbsolutePath().normalize().toString())
        }
    }

    suspend fun verify(
        artifact: Path,
        projectRoot: Path,
        cliExecutable: String,
    ): VerificationResult {
        val command = commandFor(artifact, cliExecutable)
        return VerificationResult(
            artifact = artifact,
            command = command,
            result = commandRunner.run(command, projectRoot),
        )
    }
}

class RetraceService(
    private val commandRunner: CommandRunner = CommandRunner(),
) {
    fun commandFor(
        retraceExecutable: String,
        mapping: Path,
        stacktrace: Path,
    ): List<String> {
        require(retraceExecutable.isNotBlank()) { "Retrace executable must not be blank." }
        require(mapping.isRegularFile()) { "mapping.txt does not exist." }
        require(stacktrace.isRegularFile()) { "Stacktrace file does not exist." }
        return listOf(
            retraceExecutable,
            mapping.toAbsolutePath().normalize().toString(),
            stacktrace.toAbsolutePath().normalize().toString(),
        )
    }

    suspend fun retrace(
        projectRoot: Path,
        retraceExecutable: String,
        mapping: Path,
        stacktrace: Path,
    ): CommandResult =
        commandRunner.run(commandFor(retraceExecutable, mapping, stacktrace), projectRoot)
}

class SecretReferenceInspector {
    fun inspect(settings: SecretSettings, projectRoot: Path): List<SecretReferenceStatus> {
        val provider = settings.provider?.trim()?.lowercase().orEmpty()
        return listOfNotNull(
            status("signingKeyRef", settings.signingKeyRef, provider, projectRoot),
            status("buildSeedRef", settings.buildSeedRef, provider, projectRoot),
            status("buildNonceRef", settings.buildNonceRef, provider, projectRoot),
        )
    }

    private fun status(
        field: String,
        rawReference: String?,
        configuredProvider: String,
        projectRoot: Path,
    ): SecretReferenceStatus? {
        val reference = rawReference?.trim()?.takeIf(String::isNotEmpty) ?: return null
        val explicitPrefix = reference.substringBefore(':', missingDelimiterValue = "")
        val explicitValue = reference.substringAfter(':', missingDelimiterValue = "")
        val provider = if (explicitPrefix.isNotEmpty() && explicitValue.isNotEmpty()) {
            explicitPrefix.lowercase()
        } else {
            configuredProvider.ifEmpty { "external" }
        }
        val value = if (explicitPrefix.isNotEmpty() && explicitValue.isNotEmpty()) explicitValue else reference

        return when (provider) {
            "env" -> SecretReferenceStatus(
                field = field,
                reference = reference,
                provider = provider,
                available = !System.getenv(value).isNullOrEmpty(),
                detail = "Environment reference checked; value is never read into the UI.",
            )
            "file" -> {
                val candidate = Path.of(value)
                val resolved = if (candidate.isAbsolute) candidate else projectRoot.resolve(candidate)
                SecretReferenceStatus(
                    field = field,
                    reference = reference,
                    provider = provider,
                    available = resolved.normalize().isRegularFile(),
                    detail = "File presence checked; file contents are never rendered.",
                )
            }
            else -> SecretReferenceStatus(
                field = field,
                reference = reference,
                provider = provider.ifEmpty { "external" },
                available = null,
                detail = "Resolution delegated to the configured external provider.",
            )
        }
    }
}
