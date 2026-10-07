package dev.nexora.shield.studio.service

import dev.nexora.shield.studio.model.PerformanceBudgets
import dev.nexora.shield.studio.model.SecretSettings
import java.nio.file.Files
import kotlin.io.path.createTempDirectory
import kotlin.io.path.createTempFile
import kotlin.io.path.writeText
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class StudioServicesTest {
    @Test
    fun publicReportLoadsAndBudgetEvaluates() {
        val reportFile = createTempFile("nexora-public", ".json")
        reportFile.writeText(
            """
            {
              "build_id": "build-1",
              "schema_version": 1,
              "profile": "hardened",
              "input_sha256": "aa",
              "output_sha256": "bb",
              "input_size": 1000,
              "output_size": 1100,
              "entry_count": 12,
              "dex_count": 2,
              "manifest_format": "binary-xml",
              "aligned": true,
              "signed": true,
              "stripped_signature_entries": 2,
              "stages": ["normalized", "published"]
            }
            """.trimIndent(),
        )

        val report = SecurityReportLoader().load(reportFile)
        val evaluation = BudgetEvaluator.evaluate(
            PerformanceBudgets(apkGrowthPercent = 15.0),
            report,
        )

        assertEquals("build-1", report.buildId)
        assertTrue(report.signed)
        assertEquals(10.0, evaluation.measuredApkGrowthPercent)
        assertEquals(true, evaluation.apkGrowthWithinBudget)
    }

    @Test
    fun privateReportShapeIsRejected() {
        val reportFile = createTempFile("nexora-private", ".json")
        reportFile.writeText(
            """
            {
              "build_id": "build-1",
              "input_path": "/secret/input.apk",
              "created_unix_ms": 1
            }
            """.trimIndent(),
        )
        assertTrue(runCatching { SecurityReportLoader().load(reportFile) }.isFailure)
    }

    @Test
    fun artifactVerificationRoutesByExtension() {
        val root = createTempDirectory("nexora-verifier")
        val aab = root.resolve("app.aab")
        Files.write(aab, byteArrayOf(1))
        val command = ArtifactVerifier().commandFor(aab, "nexora-shield")
        assertEquals(listOf("nexora-shield", "aab-verify", aab.toAbsolutePath().normalize().toString()), command)

        val unknown = root.resolve("artifact.zip")
        Files.write(unknown, byteArrayOf(1))
        assertTrue(runCatching { ArtifactVerifier().commandFor(unknown, "nexora-shield") }.isFailure)
    }

    @Test
    fun secretInspectorNeverReturnsSecretValue() {
        val root = createTempDirectory("nexora-secrets")
        root.resolve("seed.ref").writeText("raw-secret-material")
        val statuses = SecretReferenceInspector().inspect(
            SecretSettings(
                provider = "file",
                buildSeedRef = "seed.ref",
                buildNonceRef = "external:nonce-id",
            ),
            root,
        )

        val seed = statuses.first { it.field == "buildSeedRef" }
        assertEquals(true, seed.available)
        assertFalse(seed.detail.contains("raw-secret-material"))
        assertFalse(seed.reference.contains("raw-secret-material"))

        val nonce = statuses.first { it.field == "buildNonceRef" }
        assertNull(nonce.available)
    }

    @Test
    fun commandRunnerExecutesArgumentVectorWithoutShell() = runBlocking {
        val root = createTempDirectory("nexora-command")
        val java = PathOfJava.executable()
        val result = CommandRunner(timeoutSeconds = 30).run(listOf(java, "-version"), root)
        assertTrue(result.successful)
        assertTrue(result.output.contains("version", ignoreCase = true))
    }

    private object PathOfJava {
        fun executable(): String {
            val name = if (System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) {
                "java.exe"
            } else {
                "java"
            }
            return java.nio.file.Path.of(System.getProperty("java.home"), "bin", name).toString()
        }
    }
}
