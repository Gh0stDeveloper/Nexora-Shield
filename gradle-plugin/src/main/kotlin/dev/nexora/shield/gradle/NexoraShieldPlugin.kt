package dev.nexora.shield.gradle

import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.variant.ApplicationAndroidComponentsExtension
import com.android.build.api.variant.LibraryAndroidComponentsExtension
import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.register

class NexoraShieldPlugin : Plugin<Project> {
    override fun apply(project: Project) {
        val applicationModule = project.pluginManager.hasPlugin("com.android.application")
        val libraryModule = project.pluginManager.hasPlugin("com.android.library")

        if (applicationModule == libraryModule) {
            throw GradleException(
                "Apply exactly one of 'com.android.application' or 'com.android.library' " +
                    "before 'dev.nexora.shield'.",
            )
        }

        val extension = project.extensions.create(
            "nexoraShield",
            NexoraShieldExtension::class.java,
        )
        val lifecycle = project.tasks.register("nexoraShield") {
            group = TASK_GROUP
            description = "Runs Nexora Shield for every enabled Android variant."
        }

        if (applicationModule) {
            configureApplication(project, extension, lifecycle.name)
        } else {
            configureLibrary(project, extension, lifecycle.name)
        }
    }

    private fun configureApplication(
        project: Project,
        extension: NexoraShieldExtension,
        lifecycleTaskName: String,
    ) {
        val androidComponents = project.extensions.getByType(
            ApplicationAndroidComponentsExtension::class.java,
        )

        androidComponents.onVariants(androidComponents.selector().all()) { variant ->
            if (!variantEnabled(extension, variant.name, variant.buildType)) {
                return@onVariants
            }

            val capitalized = capitalizeVariant(variant.name)
            val protectTask = project.tasks.register<NexoraShieldApkTransformTask>(
                "nexoraShield" + capitalized,
            ) {
                group = TASK_GROUP
                description = "Protects the " + variant.name + " APK artifact with Nexora Shield."

                variantName.set(variant.name)
                profile.set(extension.profile)
                cliExecutable.set(extension.cliExecutable)
                allowUnsigned.set(extension.allowUnsigned)\n                legacyPhaseAOnly.set(extension.legacyPhaseAOnly)
                align.set(extension.align)
                minSdk.set(extension.minSdk)
                publicReports.set(extension.publicReports)
                privateReports.set(extension.privateReports)
                cacheKeyVersion.set(extension.cacheKeyVersion)

                signingKeystore.set(extension.signingKeystore)
                signingAlias.set(extension.signingAlias)
                storePasswordRef.set(extension.storePasswordRef)
                keyPasswordRef.set(extension.keyPasswordRef)

                publicReportsDirectory.set(
                    project.layout.buildDirectory.dir("reports/nexora-shield/" + variant.name),
                )
                privateReportsDirectory.set(
                    project.layout.buildDirectory.dir("nexora-shield/private/" + variant.name),
                )

                outputs.upToDateWhen {
                    !extension.signingKeystore.isPresent
                }
                outputs.cacheIf("explicit safe Nexora Shield build-cache mode") {
                    extension.buildCacheEnabled.get() &&
                        extension.allowUnsigned.get() &&
                        !extension.signingKeystore.isPresent &&
                        !extension.publicReports.get() &&
                        !extension.privateReports.get()
                }
            }

            val artifactTransformationRequest = variant.artifacts
                .use(protectTask)
                .wiredWithDirectories(
                    NexoraShieldApkTransformTask::inputDirectory,
                    NexoraShieldApkTransformTask::outputDirectory,
                )
                .toTransformMany(SingleArtifact.APK)

            protectTask.configure {
                transformationRequest.set(artifactTransformationRequest)
            }

            project.tasks.named(lifecycleTaskName).configure {
                dependsOn(protectTask)
            }

            if (extension.validateBundle.get()) {
                val bundleTask = project.tasks.register<NexoraShieldBundleValidationTask>(
                    "nexoraShieldValidate" + capitalized + "Bundle",
                ) {
                    group = TASK_GROUP
                    description = "Validates the " + variant.name + " AAB and optional bundletool contract."
                    bundleFile.set(variant.artifacts.get(SingleArtifact.BUNDLE))
                    cliExecutable.set(extension.cliExecutable)
                    javaExecutable.set(extension.javaExecutable)
                    if (extension.bundletoolJar.isPresent) {
                        bundletoolJar.set(extension.bundletoolJar)
                    }
                    reportFile.set(
                        project.layout.buildDirectory.file(
                            "reports/nexora-shield/" + variant.name + "/bundle-validation.json",
                        ),
                    )
                }
                project.tasks.named(lifecycleTaskName).configure {
                    dependsOn(bundleTask)
                }
            }

            registerMappingAndRetraceTasks(
                project = project,
                extension = extension,
                variantName = variant.name,
                capitalized = capitalized,
                minified = variant.isMinifyEnabled,
            )
        }
    }

    private fun configureLibrary(
        project: Project,
        extension: NexoraShieldExtension,
        lifecycleTaskName: String,
    ) {
        val androidComponents = project.extensions.getByType(
            LibraryAndroidComponentsExtension::class.java,
        )

        androidComponents.onVariants(androidComponents.selector().all()) { variant ->
            if (!variantEnabled(extension, variant.name, variant.buildType)) {
                return@onVariants
            }
            if (!extension.validateAar.get()) {
                return@onVariants
            }

            val capitalized = capitalizeVariant(variant.name)
            val aarTask = project.tasks.register<NexoraShieldAarValidationTask>(
                "nexoraShieldValidate" + capitalized + "Aar",
            ) {
                group = TASK_GROUP
                description =
                    "Validates the publishable " + variant.name + " AAR consumer contract."
                aarFile.set(variant.artifacts.get(SingleArtifact.AAR))
                cliExecutable.set(extension.cliExecutable)
                requireConsumerRules.set(extension.requireConsumerRules)
                reportFile.set(
                    project.layout.buildDirectory.file(
                        "reports/nexora-shield/" + variant.name + "/aar-validation.json",
                    ),
                )
            }

            project.tasks.named(lifecycleTaskName).configure {
                dependsOn(aarTask)
            }
        }
    }

    private fun variantEnabled(
        extension: NexoraShieldExtension,
        variantName: String,
        buildType: String?,
    ): Boolean {
        if (!extension.enabled.get()) {
            return false
        }
        if (extension.releaseOnly.get() && buildType != "release") {
            return false
        }
        val selected = extension.variants.get()
        return selected.isEmpty() || variantName in selected
    }

    private fun registerMappingAndRetraceTasks(
        project: Project,
        extension: NexoraShieldExtension,
        variantName: String,
        capitalized: String,
        minified: Boolean,
    ) {
        val mappingTask = project.tasks.register<NexoraShieldMappingTask>(
            "nexoraShieldPreserve" + capitalized + "Mapping",
        ) {
            group = TASK_GROUP
            description = "Preserves the R8 mapping for " + variantName + " after the Android build."
            this.variantName.set(variantName)
            archiveDirectory.set(
                project.layout.buildDirectory.dir("nexora-shield/mapping/" + variantName),
            )

            if (minified) {
                mappingFile.set(
                    project.layout.buildDirectory.file(
                        "outputs/mapping/" + variantName + "/mapping.txt",
                    ),
                )
                dependsOn("assemble" + capitalized)
            }

            onlyIf {
                extension.preserveMapping.get()
            }
        }

        project.tasks.register<NexoraShieldRetraceTask>(
            "nexoraShieldRetrace" + capitalized,
        ) {
            group = TASK_GROUP
            description = "Retraces a stack trace using the preserved " + variantName + " R8 mapping."
            dependsOn(mappingTask)
            retraceExecutable.set(extension.retraceExecutable)
            outputFile.set(
                project.layout.buildDirectory.file(
                    "reports/nexora-shield/" + variantName + "/retrace.txt",
                ),
            )

            if (minified) {
                mappingFile.set(
                    project.layout.buildDirectory.file(
                        "nexora-shield/mapping/" + variantName + "/mapping.txt",
                    ),
                )
            }

            val stackTrace = project.providers.gradleProperty("nexoraShield.stacktrace")
            if (stackTrace.isPresent) {
                stackTraceFile.set(
                    project.layout.projectDirectory.file(stackTrace.get()),
                )
            }
        }
    }

    private fun capitalizeVariant(name: String): String =
        name.replaceFirstChar { it.uppercaseChar() }

    private companion object {
        const val TASK_GROUP = "nexora shield"
    }
}
