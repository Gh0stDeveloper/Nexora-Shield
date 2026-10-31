plugins {
    `java-gradle-plugin`
    `kotlin-dsl`
}

group = "dev.nexora.shield"
version = "1.0.0"

dependencies {
    compileOnly("com.android.tools.build:gradle:9.4.1")

    testImplementation(gradleTestKit())
    testImplementation("com.android.tools.build:gradle:9.4.1")
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

gradlePlugin {
    plugins {
        create("nexoraShield") {
            id = "dev.nexora.shield"
            implementationClass = "dev.nexora.shield.gradle.NexoraShieldPlugin"
            displayName = "Nexora Shield"
            description = "Variant-aware Android application hardening integration for Nexora Shield."
        }
    }
}

tasks.test {
    useJUnitPlatform { excludeTags("integrated-apk") }
}

tasks.register<Test>("integratedEngineTest") {
    description="Executes the real integrated APK engine through the plugin adapter."
    val unitTests=tasks.named<Test>("test")
    testClassesDirs=unitTests.get().testClassesDirs
    classpath=unitTests.get().classpath
    useJUnitPlatform {includeTags("integrated-apk")}
    testLogging {
        events("failed", "standardOut", "standardError")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
    outputs.upToDateWhen {false}
    outputs.cacheIf {false}
}
