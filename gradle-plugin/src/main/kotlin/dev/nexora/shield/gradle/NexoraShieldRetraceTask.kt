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
import java.io.File
import java.nio.file.Files
import javax.inject.Inject

abstract class NexoraShieldRetraceTask : DefaultTask() {
    @get:Optional
    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val mappingFile: RegularFileProperty

    @get:Optional
    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val stackTraceFile: RegularFileProperty

    @get:Input
    abstract val retraceExecutable: Property<String>

    @get:OutputFile
    abstract val outputFile: RegularFileProperty

    @get:Inject
    abstract val execOperations: ExecOperations

    @TaskAction
    fun retrace() {
        val mapping = mappingFile.orNull?.asFile
            ?: throw GradleException("No R8 mapping is available for this variant.")
        if (!mapping.isFile) {
            throw GradleException("R8 mapping '" + mapping.path + "' does not exist.")
        }

        val trace = stackTraceFile.orNull?.asFile
            ?: throw GradleException(
                "Provide -PnexoraShield.stacktrace=<path-to-stacktrace> when running retrace.",
            )
        if (!trace.isFile) {
            throw GradleException("Stack trace '" + trace.path + "' does not exist.")
        }

        val output = outputFile.get().asFile
        output.parentFile.mkdirs()

        Files.newOutputStream(output.toPath()).use { stdout ->
            execOperations.exec {
                commandLine(resolveRetraceExecutable(), mapping.absolutePath, trace.absolutePath)
                standardOutput = stdout
            }
        }
    }

    private fun resolveRetraceExecutable(): String {
        val configured = retraceExecutable.get()
        if (configured != "retrace") {
            return configured
        }

        val sdk = System.getenv("ANDROID_SDK_ROOT") ?: System.getenv("ANDROID_HOME")
        if (sdk != null) {
            val unix = File(sdk, "cmdline-tools/latest/bin/retrace")
            if (unix.isFile) {
                return unix.absolutePath
            }
            val windows = File(sdk, "cmdline-tools/latest/bin/retrace.bat")
            if (windows.isFile) {
                return windows.absolutePath
            }
        }
        return configured
    }
}
