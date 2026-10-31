package dev.nexora.shield.studio.model

import java.nio.file.Path

enum class ShieldProfile(val wireValue: String) {
    STANDARD("standard"),
    HARDENED("hardened"),
    MAXIMUM("maximum");

    companion object {
        fun fromWire(value: String?): ShieldProfile =
            entries.firstOrNull { it.wireValue == value } ?: HARDENED
    }
}

enum class BudgetPolicy(val wireValue: String) {
    FAIL("fail"),
    WARN("warn"),
    ADAPTIVE("adaptive");

    companion object {
        fun fromWire(value: String?): BudgetPolicy =
            entries.firstOrNull { it.wireValue == value } ?: FAIL
    }
}

data class SelectorGroup(
    val name: String,
    val include: List<String> = emptyList(),
    val exclude: List<String> = emptyList(),
)

data class PerformanceBudgets(
    val apkGrowthPercent: Double? = null,
    val startupMs: Double? = null,
    val startupMsP50: Double? = null,
    val startupMsP95: Double? = null,
    val memoryMb: Double? = null,
    val vmMethods: Int? = null,
    val buildMinutes: Double? = null,
)

data class SecretSettings(
    val provider: String? = null,
    val signingKeyRef: String? = null,
    val buildSeedRef: String? = null,
    val buildNonceRef: String? = null,
)

data class StudioConfig(
    val schema: Int = 1,
    val applicationId: String = "com.example.app",
    val minSdk: Int = 24,
    val profile: ShieldProfile = ShieldProfile.HARDENED,
    val selectors: List<SelectorGroup> = emptyList(),
    val budgets: PerformanceBudgets = PerformanceBudgets(),
    val budgetPolicy: BudgetPolicy = BudgetPolicy.FAIL,
    val secrets: SecretSettings = SecretSettings(),
)

data class ConfigDocument(
    val root: LinkedHashMap<String, Any?>,
    val config: StudioConfig,
)

data class ImportedProject(
    val root: Path,
    val configPath: Path,
    val gradleSettings: List<Path>,
    val modules: List<Path>,
    val artifacts: List<Path>,
    val publicReports: List<Path>,
    val mappings: List<Path>,
)

data class PublicSecurityReport(
    val buildId: String,
    val schemaVersion: Int,
    val profile: String,
    val inputSha256: String,
    val outputSha256: String,
    val inputSize: Long,
    val outputSize: Long,
    val entryCount: Int,
    val dexCount: Int,
    val manifestFormat: String,
    val aligned: Boolean,
    val signed: Boolean,
    val strippedSignatureEntries: Int,
    val stages: List<String>,
    val productionProtected: Boolean = false,
    val protectionScope: String = "unverified-legacy",
)

data class BudgetEvaluation(
    val measuredApkGrowthPercent: Double?,
    val apkGrowthWithinBudget: Boolean?,
)

data class CommandResult(
    val exitCode: Int,
    val output: String,
    val durationMillis: Long,
    val timedOut: Boolean = false,
) {
    val successful: Boolean
        get() = exitCode == 0 && !timedOut
}

data class VerificationResult(
    val artifact: Path,
    val command: List<String>,
    val result: CommandResult,
)

data class SecretReferenceStatus(
    val field: String,
    val reference: String,
    val provider: String,
    val available: Boolean?,
    val detail: String,
)
