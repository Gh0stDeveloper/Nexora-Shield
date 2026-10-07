package dev.nexora.shield.studio.service

import java.nio.file.Files
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ProjectImporterTest {
    @Test
    fun discoversGradleProjectConfigArtifactsAndMappings() {
        val root = createTempDirectory("nexora-studio-project")
        root.resolve("settings.gradle.kts").writeText("rootProject.name = \"sample\"")
        root.resolve("build.gradle.kts").writeText("plugins {}")
        root.resolve("app").createDirectories()
        root.resolve("app/build.gradle.kts").writeText("plugins {}")
        root.resolve("nexora-shield.yml").writeText(
            """
            schema: 1
            application:
              id: com.example.sample
              minSdk: 24
            profile: hardened
            """.trimIndent(),
        )
        root.resolve("app/build/outputs/apk/release").createDirectories()
        Files.write(root.resolve("app/build/outputs/apk/release/app-release.apk"), byteArrayOf(1, 2, 3))
        root.resolve("app/build/reports/nexora-shield/release").createDirectories()
        root.resolve("app/build/reports/nexora-shield/release/report.json").writeText("{}")
        root.resolve("app/build/nexora-shield/mapping/release").createDirectories()
        root.resolve("app/build/nexora-shield/mapping/release/mapping.txt").writeText("a -> b:")

        val project = ProjectImporter().importProject(root)

        assertEquals(root.toRealPath(), project.root)
        assertEquals(root.resolve("nexora-shield.yml"), project.configPath)
        assertTrue(project.modules.any { it.fileName.toString() == "app" })
        assertTrue(project.artifacts.any { it.fileName.toString() == "app-release.apk" })
        assertTrue(project.publicReports.any { it.fileName.toString() == "report.json" })
        assertTrue(project.mappings.any { it.fileName.toString() == "mapping.txt" })
    }

    @Test
    fun rejectsDirectoryWithoutGradleMetadata() {
        val root = createTempDirectory("nexora-studio-empty")
        val result = runCatching { ProjectImporter().importProject(root) }
        assertTrue(result.isFailure)
    }
}
