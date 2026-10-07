package dev.nexora.shield.studio.service

import dev.nexora.shield.studio.model.ImportedProject
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.extension
import kotlin.io.path.isDirectory
import kotlin.io.path.isRegularFile
import kotlin.io.path.name

class ProjectImporter(
    private val maxDepth: Int = 6,
    private val maxEntries: Long = 20_000,
) {
    fun importProject(selectedRoot: Path): ImportedProject {
        require(selectedRoot.isDirectory()) { "Selected project root is not a directory." }

        val root = selectedRoot.toRealPath()
        val discovered = mutableListOf<Path>()

        Files.walk(root, maxDepth).use { stream ->
            stream
                .filter { path -> path == root || !Files.isSymbolicLink(path) }
                .limit(maxEntries)
                .forEach(discovered::add)
        }

        val settings = discovered
            .filter { it.isRegularFile() && (it.name == "settings.gradle.kts" || it.name == "settings.gradle") }
            .sorted()

        val modules = discovered
            .filter { it.isRegularFile() && (it.name == "build.gradle.kts" || it.name == "build.gradle") }
            .mapNotNull { it.parent }
            .distinct()
            .sorted()

        require(settings.isNotEmpty() || modules.isNotEmpty()) {
            "No Gradle project metadata was found under the selected directory."
        }

        val configPath = listOf(
            root.resolve("nexora-shield.yml"),
            root.resolve("nexora-shield.yaml"),
            root.resolve(".nexora/nexora-shield.yml"),
            root.resolve(".nexora/nexora-shield.yaml"),
        ).firstOrNull { it.isRegularFile() } ?: root.resolve("nexora-shield.yml")

        val artifacts = discovered
            .filter { it.isRegularFile() && it.extension.lowercase() in ARTIFACT_EXTENSIONS }
            .sortedByDescending { runCatching { Files.getLastModifiedTime(it).toMillis() }.getOrDefault(0L) }
            .take(100)

        val publicReports = discovered
            .filter {
                it.isRegularFile() &&
                    it.extension.equals("json", ignoreCase = true) &&
                    it.toString().contains("nexora-shield", ignoreCase = true)
            }
            .sortedByDescending { runCatching { Files.getLastModifiedTime(it).toMillis() }.getOrDefault(0L) }
            .take(100)

        val mappings = discovered
            .filter { it.isRegularFile() && it.name == "mapping.txt" }
            .sortedByDescending { runCatching { Files.getLastModifiedTime(it).toMillis() }.getOrDefault(0L) }
            .take(100)

        return ImportedProject(
            root = root,
            configPath = configPath,
            gradleSettings = settings,
            modules = modules,
            artifacts = artifacts,
            publicReports = publicReports,
            mappings = mappings,
        )
    }

    private companion object {
        val ARTIFACT_EXTENSIONS = setOf("apk", "aab", "aar", "apks")
    }
}
