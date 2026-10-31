package dev.nexora.shield.gradle
import java.io.File
import org.gradle.api.GradleException
internal object IntegratedEngineCommand {
    fun append(command:MutableList<String>,configuration:File) {
        if (!configuration.isFile || configuration.extension!="nshield-private") throw GradleException("engineConfig must reference a private .nshield-private file.")
        if (command.getOrNull(1)!="protect" || command.contains("--plan-only") || command.contains("--engine-config")) throw GradleException("Integrated configuration requires the shared protect executor.")
        command += listOf("--engine-config",configuration.absolutePath)
    }
}
