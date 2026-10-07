package dev.nexora.shield.gradle

import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import java.io.File

abstract class NexoraShieldMappingTask : DefaultTask() {
    @get:Optional
    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val mappingFile: RegularFileProperty

    @get:OutputDirectory
    abstract val archiveDirectory: DirectoryProperty

    @get:Input
    abstract val variantName: Property<String>

    @TaskAction
    fun preserve() {
        val output = archiveDirectory.get().asFile
        output.deleteRecursively()
        output.mkdirs()

        val source = mappingFile.orNull?.asFile
        val available = source?.isFile == true
        if (available && source != null) {
            source.copyTo(File(output, "mapping.txt"), overwrite = true)
        }

        val escapedVariant = variantName.get()
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
        File(output, "state.json").writeText(
            "{\n" +
                "  \"schema\": 1,\n" +
                "  \"variant\": \"" + escapedVariant + "\",\n" +
                "  \"mappingAvailable\": " + available + "\n" +
                "}\n",
            Charsets.UTF_8,
        )
    }
}
