package dev.nexora.shield.gradle

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations
import java.util.zip.ZipFile
import javax.inject.Inject

abstract class NexoraShieldAarValidationTask : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val aarFile: RegularFileProperty

    @get:Input
    abstract val cliExecutable: Property<String>

    @get:Input
    abstract val requireConsumerRules: Property<Boolean>

    @get:OutputFile
    abstract val reportFile: RegularFileProperty

    @get:Inject
    abstract val execOperations: ExecOperations

    @TaskAction
    fun validateAar() {
        val aar = aarFile.get().asFile
        if (!aar.isFile) {
            throw GradleException("AAR '" + aar.path + "' does not exist.")
        }

        execOperations.exec {
            commandLine(cliExecutable.get(), "aar-verify", aar.absolutePath)
        }

        var consumerRules = 0
        var resourceEntries = 0
        var baselineProfiles = 0
        var resourceSymbols = false
        var aarMetadata = false

        ZipFile(aar).use { zip ->
            val names = zip.entries().asSequence().map { it.name }.toList()
            consumerRules = names.count {
                it == "proguard.txt" ||
                    it == "consumer-rules.pro" ||
                    it.startsWith("META-INF/proguard/")
            }
            resourceEntries = names.count { it.startsWith("res/") }
            baselineProfiles = names.count {
                it == "baseline-prof.txt" ||
                    it == "startup-prof.txt" ||
                    it.endsWith("/baseline-prof.txt") ||
                    it.endsWith("/startup-prof.txt")
            }
            resourceSymbols = "R.txt" in names
            aarMetadata = "META-INF/com/android/build/gradle/aar-metadata.properties" in names
        }

        if (requireConsumerRules.get() && consumerRules == 0) {
            throw GradleException(
                "Library protection mode requires packaged consumer ProGuard/R8 rules.",
            )
        }

        val report = reportFile.get().asFile
        report.parentFile.mkdirs()
        report.writeText(
            "{\n" +
                "  \"schema\": 1,\n" +
                "  \"artifact\": \"aar\",\n" +
                "  \"consumerRuleEntries\": " + consumerRules + ",\n" +
                "  \"resourceEntries\": " + resourceEntries + ",\n" +
                "  \"resourceSymbols\": " + resourceSymbols + ",\n" +
                "  \"aarMetadata\": " + aarMetadata + ",\n" +
                "  \"baselineProfileEntries\": " + baselineProfiles + "\n" +
                "}\n",
            Charsets.UTF_8,
        )
    }
}
