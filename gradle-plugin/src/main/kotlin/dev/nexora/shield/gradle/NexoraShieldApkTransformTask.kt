package dev.nexora.shield.gradle

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.work.DisableCachingByDefault
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations
import java.io.File
import java.nio.file.Files
import javax.inject.Inject

@DisableCachingByDefault(
    because = "Protected outputs can depend on signing secrets and per-build diversification.",
)
abstract class NexoraShieldApkTransformTask : DefaultTask() {
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val inputDirectory: DirectoryProperty

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @get:OutputDirectory
    abstract val publicReportsDirectory: DirectoryProperty

    @get:OutputDirectory
    abstract val privateReportsDirectory: DirectoryProperty

    @get:Input
    abstract val variantName: Property<String>

    @get:Input
    abstract val profile: Property<String>

    @get:Input
    abstract val cliExecutable: Property<String>

    @get:Input
    abstract val allowUnsigned: Property<Boolean>

    @get:Input
    abstract val align: Property<Boolean>

    @get:Input
    abstract val minSdk: Property<Int>

    @get:Input
    abstract val publicReports: Property<Boolean>

    @get:Input
    abstract val privateReports: Property<Boolean>

    @get:Optional
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val signingKeystore: RegularFileProperty

    @get:Optional
    @get:Input
    abstract val signingAlias: Property<String>

    @get:Optional
    @get:Input
    abstract val storePasswordRef: Property<String>

    @get:Optional
    @get:Input
    abstract val keyPasswordRef: Property<String>

    @get:Input
    abstract val cacheKeyVersion: Property<String>

    @get:Inject
    abstract val execOperations: ExecOperations

    @TaskAction
    fun protect() {
        validateConfiguration()

        val inputRoot = inputDirectory.get().asFile.toPath()
        val outputRoot = outputDirectory.get().asFile.toPath()
        val publicRoot = publicReportsDirectory.get().asFile
        val privateRoot = privateReportsDirectory.get().asFile

        outputRoot.toFile().deleteRecursively()
        Files.createDirectories(outputRoot)
        publicRoot.deleteRecursively()
        privateRoot.deleteRecursively()
        publicRoot.mkdirs()
        privateRoot.mkdirs()

        val apkFiles = Files.walk(inputRoot).use { stream ->
            stream
                .filter { Files.isRegularFile(it) && it.fileName.toString().endsWith(".apk") }
                .sorted()
                .toList()
        }

        if (apkFiles.isEmpty()) {
            throw GradleException(
                "Nexora Shield found no APKs for variant '" + variantName.get() + "'.",
            )
        }

        copyNonApkFiles(inputRoot.toFile(), outputRoot.toFile())

        val secretEnvironment = linkedMapOf<String, String>()
        configureSigningEnvironment(secretEnvironment)

        apkFiles.forEach { inputApk ->
            val relative = inputRoot.relativize(inputApk)
            val outputApk = outputRoot.resolve(relative)
            Files.createDirectories(outputApk.parent)

            val stem = inputApk.fileName.toString().removeSuffix(".apk")
            val command = mutableListOf(
                cliExecutable.get(),
                "protect",
                inputApk.toFile().absolutePath,
                "--output",
                outputApk.toFile().absolutePath,
                "--profile",
                profile.get(),
                "--min-sdk",
                minSdk.get().toString(),
                "--force",
            )

            if (!align.get()) {
                command += "--no-align"
            }

            if (signingKeystore.isPresent) {
                command += listOf(
                    "--keystore",
                    signingKeystore.get().asFile.absolutePath,
                    "--alias",
                    signingAlias.get(),
                    "--ks-pass-env",
                    STORE_PASSWORD_ENV,
                    "--key-pass-env",
                    KEY_PASSWORD_ENV,
                )
            } else {
                command += "--unsigned"
            }

            if (publicReports.get()) {
                command += listOf(
                    "--public-report",
                    File(publicRoot, "$stem.json").absolutePath,
                )
            }
            if (privateReports.get()) {
                command += listOf(
                    "--private-report",
                    File(privateRoot, "$stem.private.json").absolutePath,
                )
            }

            execOperations.exec {
                commandLine(command)
                environment(secretEnvironment)
            }
        }

        File(publicRoot, "variant-summary.json").writeText(
            summaryJson(apkFiles.size),
            Charsets.UTF_8,
        )
    }

    private fun validateConfiguration() {
        if (profile.get() !in setOf("standard", "hardened", "maximum")) {
            throw GradleException(
                "Unsupported Nexora Shield profile '" + profile.get() + "'.",
            )
        }
        if (minSdk.get() < 24) {
            throw GradleException("Nexora Shield requires minSdk >= 24.")
        }

        val hasKeystore = signingKeystore.isPresent
        if (!hasKeystore && !allowUnsigned.get()) {
            throw GradleException(
                "Nexora Shield refuses unsigned output. Configure signingKeystore/signingAlias/" +
                    "password refs, or explicitly set allowUnsigned=true.",
            )
        }

        if (hasKeystore) {
            if (!signingAlias.isPresent || signingAlias.get().isBlank()) {
                throw GradleException("signingAlias is required when signingKeystore is configured.")
            }
            if (!storePasswordRef.isPresent || storePasswordRef.get().isBlank()) {
                throw GradleException(
                    "storePasswordRef is required when signingKeystore is configured.",
                )
            }
        }
    }

    private fun configureSigningEnvironment(target: MutableMap<String, String>) {
        if (!signingKeystore.isPresent) {
            return
        }

        val root = project.projectDir
        val storePassword = SecretResolver.resolve(storePasswordRef.get(), root)
        val keyPassword = if (keyPasswordRef.isPresent && keyPasswordRef.get().isNotBlank()) {
            SecretResolver.resolve(keyPasswordRef.get(), root)
        } else {
            storePassword
        }

        target[STORE_PASSWORD_ENV] = storePassword
        target[KEY_PASSWORD_ENV] = keyPassword
    }

    private fun copyNonApkFiles(inputRoot: File, outputRoot: File) {
        inputRoot.walkTopDown()
            .filter { it.isFile && !it.name.endsWith(".apk") }
            .forEach { source ->
                val relative = source.relativeTo(inputRoot)
                val destination = File(outputRoot, relative.path)
                destination.parentFile.mkdirs()
                source.copyTo(destination, overwrite = true)
            }
    }

    private fun summaryJson(apkCount: Int): String {
        return "{\n" +
            "  \"schema\": 1,\n" +
            "  \"variant\": \"" + jsonEscape(variantName.get()) + "\",\n" +
            "  \"profile\": \"" + jsonEscape(profile.get()) + "\",\n" +
            "  \"apkCount\": " + apkCount + ",\n" +
            "  \"signed\": " + signingKeystore.isPresent + ",\n" +
            "  \"aligned\": " + align.get() + ",\n" +
            "  \"publicReports\": " + publicReports.get() + ",\n" +
            "  \"privateReports\": " + privateReports.get() + ",\n" +
            "  \"cacheKeyVersion\": \"" + jsonEscape(cacheKeyVersion.get()) + "\"\n" +
            "}\n"
    }

    private fun jsonEscape(value: String): String =
        value.replace("\\", "\\\\").replace("\"", "\\\"")

    private companion object {
        const val STORE_PASSWORD_ENV = "NEXORA_SHIELD_GRADLE_STORE_PASSWORD"
        const val KEY_PASSWORD_ENV = "NEXORA_SHIELD_GRADLE_KEY_PASSWORD"
    }
}
