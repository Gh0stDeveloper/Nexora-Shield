package dev.nexora.shield.gradle

import com.android.build.api.artifact.ArtifactTransformationRequest
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.work.DisableCachingByDefault
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations
import java.io.File
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

    @get:Internal
    abstract val engineConfig: RegularFileProperty

    @get:Input
    abstract val allowUnsigned: Property<Boolean>

    @get:Input
    abstract val legacyPhaseAOnly: Property<Boolean>

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

    @get:Internal
    abstract val transformationRequest:
        Property<ArtifactTransformationRequest<NexoraShieldApkTransformTask>>

    @get:Inject
    abstract val execOperations: ExecOperations

    @TaskAction
    fun protect() {
        validateConfiguration()

        val outputRoot = outputDirectory.get().asFile
        val publicRoot = publicReportsDirectory.get().asFile
        val privateRoot = privateReportsDirectory.get().asFile

        if (!engineConfig.isPresent) {
            publicRoot.deleteRecursively()
            privateRoot.deleteRecursively()
        }
        publicRoot.mkdirs()
        privateRoot.mkdirs()

        val secretEnvironment = linkedMapOf<String, String>()
        configureSigningEnvironment(secretEnvironment)

        var apkCount = 0
        transformationRequest.get().submit(this) { builtArtifact ->
            val inputApk = File(builtArtifact.outputFile)
            if (!inputApk.isFile || !inputApk.name.endsWith(".apk")) {
                throw GradleException(
                    "Nexora Shield received an invalid APK artifact: " + inputApk.path,
                )
            }

            outputRoot.mkdirs()
            val outputApk = File(outputRoot, inputApk.name)
            executeProtection(inputApk,outputApk,publicRoot,privateRoot,secretEnvironment)

            apkCount += 1
            outputApk
        }

        if (apkCount == 0) {
            throw GradleException(
                "Nexora Shield found no APKs for variant '" + variantName.get() + "'.",
            )
        }

        File(publicRoot, "variant-summary.json").writeText(
            summaryJson(apkCount),
            Charsets.UTF_8,
        )
    }

    internal fun executeProtection(inputApk:File,outputApk:File,publicRoot:File,privateRoot:File,secretEnvironment:Map<String,String>) {
        validateConfiguration()
        val stem = inputApk.name.removeSuffix(".apk")
        val command = mutableListOf(
            cliExecutable.get(),
            if (legacyPhaseAOnly.get()) "package-apk" else "protect",
            inputApk.absolutePath,
            "--output",
            outputApk.absolutePath,
            "--profile",
            profile.get(),
            "--min-sdk",
            minSdk.get().toString(),
            "--force",
        )

        if (engineConfig.isPresent) { IntegratedEngineCommand.append(command, engineConfig.get().asFile) }

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

        if (!outputApk.isFile || outputApk.length() == 0L) {
            throw GradleException(
                "Nexora Shield did not produce a non-empty APK for " + inputApk.name,
            )
        }

    }

    private fun validateConfiguration() {
        if (engineConfig.isPresent && (legacyPhaseAOnly.get() || !align.get() || !signingKeystore.isPresent || !publicReports.get() || privateReports.get())) {
            throw GradleException("Integrated execution requires signing, alignment and public reports; configure encrypted retrace_output in the private engine file.")
        }
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

    private fun summaryJson(apkCount: Int): String {
        return "{\n" +
            "  \"schema\": 1,\n" +
            "  \"productionProtected\": false,\n" +
            "  \"protectionScope\": \"" + (if (engineConfig.isPresent) "o1-integrated-experimental" else "phase-a-packaging-only") + "\",\n" +
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
