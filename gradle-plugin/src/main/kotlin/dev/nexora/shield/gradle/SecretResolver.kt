package dev.nexora.shield.gradle

import org.gradle.api.GradleException
import java.io.File

internal object SecretResolver {
    fun resolve(
        reference: String,
        projectDirectory: File,
        environment: Map<String, String> = System.getenv(),
    ): String {
        val separator = reference.indexOf(':')
        if (separator <= 0 || separator == reference.lastIndex) {
            throw GradleException(
                "Secret reference must use 'env:NAME' or 'file:path' syntax.",
            )
        }

        val provider = reference.substring(0, separator)
        val value = reference.substring(separator + 1)

        return when (provider) {
            "env" -> environment[value]
                ?: throw GradleException("Required environment secret '$value' is not set.")

            "file" -> {
                val candidate = File(value)
                val file = if (candidate.isAbsolute) candidate else File(projectDirectory, value)
                if (!file.isFile) {
                    throw GradleException("Secret file '${file.path}' does not exist.")
                }
                file.readText(Charsets.UTF_8).trimEnd('\r', '\n')
            }

            else -> throw GradleException(
                "Unsupported secret provider '$provider'. Supported providers: env, file.",
            )
        }
    }
}
