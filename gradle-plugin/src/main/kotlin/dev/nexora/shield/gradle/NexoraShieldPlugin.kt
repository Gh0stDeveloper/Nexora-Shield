package dev.nexora.shield.gradle

import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.variant.ApplicationAndroidComponentsExtension
import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.register

class NexoraShieldPlugin : Plugin<Project> {
    override fun apply(project: Project) {
        if (!project.pluginManager.hasPlugin("com.android.application")) {
            throw GradleException(
                "Apply 'com.android.application' before 'dev.nexora.shield'. " +
                    "Phase J supports Android application modules; AAR/library mode belongs to Phase K.",
            )
        }

        val extension = project.extensions.create(
            "nexoraShield",
            NexoraShieldExtension::class.java,
        )
        val lifecycle = project.tasks.register("nexoraShield") {
            group = TASK_GROUP
            description = "Protects every Nexora Shield-enabled Android application variant."
        }

        val androidComponents = project.extensions.getByType(
            ApplicationAndroidComponentsExtension::class.java,
        )

        androidComponents.onVariants(androidComponents.selector().all()) { variant ->
            if (!extension.enabled.get()) {
                return@onVariants
            }
            if (extension.releaseOnly.get() && variant.buildType != "release") {
                return@onVariants
            }
            val selected = extension.variants.get()
            if (selected.isNotEmpty() && variant.name !in selected) {
                return@onVariants
            }

            val capitalized = variant.name.replaceFirstChar { it.uppercaseChar() }
            val protectTask = project.tasks.register<NexoraShieldApkTransformTask>(
                "nexoraShield" + capitalized,
            ) {
                group = TASK_GROUP
                description = "Protects the " + variant.name + " APK artifact with Nexora Shield."

                variantName.set(variant.name)
                profile.set(extension.profile)
                cliExecutable.set(extension.cliExecutable)
                allowUnsigned.set(extension.allowUnsigned)
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

            lifecycle.configure {
                dependsOn(protectTask)
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

    private companion object {
        const val TASK_GROUP = "nexora shield"
    }
}
