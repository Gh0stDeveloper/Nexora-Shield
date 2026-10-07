import org.gradle.api.tasks.testing.Test
import org.jetbrains.compose.desktop.application.dsl.TargetFormat
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("multiplatform") version "2.4.20"
    id("org.jetbrains.compose") version "1.12.0"
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.20"
}

group = "dev.nexora.shield"
version = "1.0.0"

kotlin {
    jvm("desktop") {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }
    }

    sourceSets {
        val desktopMain by getting {
            dependencies {
                implementation(compose.desktop.currentOs)
                implementation(compose.material3)
                implementation(compose.materialIconsExtended)
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
                implementation("org.snakeyaml:snakeyaml-engine:3.1.1")
            }
        }

        val desktopTest by getting {
            dependencies {
                implementation(kotlin("test-junit5"))
                implementation("org.junit.jupiter:junit-jupiter:5.11.4")
            }
        }
    }
}

compose.desktop {
    application {
        mainClass = "dev.nexora.shield.studio.MainKt"

        nativeDistributions {
            targetFormats(TargetFormat.Dmg, TargetFormat.Msi, TargetFormat.Deb)
            packageName = "Nexora Shield Studio"
            packageVersion = "1.0.0"
            description = "Desktop control surface for Nexora Shield."
            vendor = "Gh0stDeveloper"
        }
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}
