package dev.nexora.shield.gradle

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations
import java.util.zip.ZipFile
import javax.inject.Inject

abstract class NexoraShieldBundleValidationTask : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val bundleFile: RegularFileProperty

    @get:Input
    abstract val cliExecutable: Property<String>

    @get:Optional
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val bundletoolJar: RegularFileProperty

    @get:Input
    abstract val javaExecutable: Property<String>

    @get:OutputFile
    abstract val reportFile: RegularFileProperty

    @get:Inject
    abstract val execOperations: ExecOperations

    @TaskAction
    fun validateBundle() {
        val bundle = bundleFile.get().asFile
        if (!bundle.isFile) {
            throw GradleException("AAB '" + bundle.path + "' does not exist.")
        }

        execOperations.exec {
            commandLine(cliExecutable.get(), "aab-verify", bundle.absolutePath)
        }

        if (bundletoolJar.isPresent) {
            execOperations.exec {
                commandLine(
                    cliExecutable.get(),
                    "bundletool-validate",
                    bundle.absolutePath,
                    "--jar",
                    bundletoolJar.get().asFile.absolutePath,
                    "--java",
                    javaExecutable.get(),
                )
            }
        }

        var moduleCount = 0
        var dynamicFeatureCount = 0
        var baselineProfileCount = 0
        ZipFile(bundle).use { zip ->
            val names = zip.entries().asSequence().map { it.name }.toList()
            if ("BundleConfig.pb" !in names) {
                throw GradleException("AAB is missing BundleConfig.pb.")
            }
            if ("base/manifest/AndroidManifest.xml" !in names) {
                throw GradleException("AAB is missing the base module manifest.")
            }

            val modules = names
                .filter { it.endsWith("/manifest/AndroidManifest.xml") }
                .map { it.substringBefore('/') }
                .filter { it.isNotBlank() }
                .toSortedSet()
            moduleCount = modules.size
            dynamicFeatureCount = modules.count { it != "base" }
            baselineProfileCount = names.count {
                it.endsWith("/assets/dexopt/baseline.prof") ||
                    it.endsWith("/assets/dexopt/baseline.profm")
            }
        }

        val report = reportFile.get().asFile
        report.parentFile.mkdirs()
        report.writeText(
            "{\n" +
                "  \"schema\": 1,\n" +
                "  \"artifact\": \"aab\",\n" +
                "  \"modules\": " + moduleCount + ",\n" +
                "  \"dynamicFeatures\": " + dynamicFeatureCount + ",\n" +
                "  \"baselineProfileEntries\": " + baselineProfileCount + ",\n" +
                "  \"bundletoolValidated\": " + bundletoolJar.isPresent + "\n" +
                "}\n",
            Charsets.UTF_8,
        )
    }
}
