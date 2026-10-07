package dev.nexora.shield.studio.service

import dev.nexora.shield.studio.model.BudgetPolicy
import dev.nexora.shield.studio.model.PerformanceBudgets
import dev.nexora.shield.studio.model.SelectorGroup
import dev.nexora.shield.studio.model.ShieldProfile
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ConfigCodecTest {
    @Test
    fun roundTripPreservesUnknownAdvancedSections() {
        val root = createTempDirectory("nexora-studio-config")
        val path = root.resolve("nexora-shield.yml")
        path.writeText(
            """
            schema: 1
            application:
              id: com.example.original
              minSdk: 24
            profile: standard
            dex:
              rename: true
              metadataReduction: true
            selectors:
              sensitive:
                include:
                  - com.example.auth.**
                exclude: []
            """.trimIndent(),
        )

        val codec = ConfigCodec()
        val document = codec.load(path)
        val updated = document.config.copy(
            applicationId = "com.example.updated",
            profile = ShieldProfile.MAXIMUM,
            selectors = listOf(
                SelectorGroup(
                    name = "critical",
                    include = listOf("com.example.payments.**", "com.example.payments.**", " "),
                    exclude = listOf("com.example.payments.generated.**"),
                ),
            ),
            budgets = PerformanceBudgets(apkGrowthPercent = 15.0, vmMethods = 25),
            budgetPolicy = BudgetPolicy.FAIL,
        )

        codec.save(path, document, updated)
        val reloaded = codec.load(path)

        assertEquals("com.example.updated", reloaded.config.applicationId)
        assertEquals(ShieldProfile.MAXIMUM, reloaded.config.profile)
        assertEquals(listOf("com.example.payments.**"), reloaded.config.selectors.single().include)
        assertEquals(15.0, reloaded.config.budgets.apkGrowthPercent)
        assertEquals(25, reloaded.config.budgets.vmMethods)
        assertNotNull(reloaded.root["dex"])
        assertTrue(path.readText().contains("metadataReduction"))
    }

    @Test
    fun validationRejectsInvalidApplicationIdAndOldSdk() {
        val codec = ConfigCodec()
        assertFailsWith<IllegalArgumentException> {
            codec.validate(
                dev.nexora.shield.studio.model.StudioConfig(
                    applicationId = "not-valid",
                    minSdk = 23,
                ),
            )
        }
    }
}
