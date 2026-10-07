package dev.nexora.shield.gradle

import java.io.File

internal object RetraceCommandBuilder {
    fun build(
        executable: String,
        mapping: File,
        stackTrace: File,
    ): List<String> {
        require(executable.isNotBlank()) { "Retrace executable must not be blank." }
        require(mapping.isFile) { "R8 mapping does not exist: " + mapping.path }
        require(stackTrace.isFile) { "Stack trace does not exist: " + stackTrace.path }

        return listOf(
            executable,
            mapping.absolutePath,
            stackTrace.absolutePath,
        )
    }
}
