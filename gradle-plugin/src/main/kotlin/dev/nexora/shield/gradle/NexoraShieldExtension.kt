package dev.nexora.shield.gradle

import org.gradle.api.file.RegularFileProperty
import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.Property
import org.gradle.api.provider.SetProperty
import javax.inject.Inject

open class NexoraShieldExtension @Inject constructor(objects: ObjectFactory) {
    val enabled: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val releaseOnly: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val variants: SetProperty<String> = objects.setProperty(String::class.java).convention(emptySet())

    val profile: Property<String> = objects.property(String::class.java).convention("hardened")
    val cliExecutable: Property<String> = objects.property(String::class.java).convention("nexora-shield")
    val allowUnsigned: Property<Boolean> = objects.property(Boolean::class.java).convention(false)
    val align: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val minSdk: Property<Int> = objects.property(Int::class.java).convention(24)

    val publicReports: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val privateReports: Property<Boolean> = objects.property(Boolean::class.java).convention(false)

    val signingKeystore: RegularFileProperty = objects.fileProperty()
    val signingAlias: Property<String> = objects.property(String::class.java)
    val storePasswordRef: Property<String> = objects.property(String::class.java)
    val keyPasswordRef: Property<String> = objects.property(String::class.java)

    val preserveMapping: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val retraceExecutable: Property<String> = objects.property(String::class.java).convention("retrace")

    val validateBundle: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val bundletoolJar: RegularFileProperty = objects.fileProperty()
    val javaExecutable: Property<String> = objects.property(String::class.java).convention("java")

    val validateAar: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val requireConsumerRules: Property<Boolean> =
        objects.property(Boolean::class.java).convention(true)

    val buildCacheEnabled: Property<Boolean> =
        objects.property(Boolean::class.java).convention(false)
    val cacheKeyVersion: Property<String> =
        objects.property(String::class.java).convention("1")
}
