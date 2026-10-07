plugins {
    id("com.android.library")
    id("dev.nexora.shield")
    id("maven-publish")
}

group = "dev.nexora"
version = "1.0.0"

android {
    namespace = "dev.nexora.shield.klibrary"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

nexoraShield {
    cliExecutable.set(
        providers.environmentVariable("NEXORA_SHIELD_CLI").orElse("nexora-shield"),
    )
    releaseOnly.set(true)
    validateAar.set(true)
    requireConsumerRules.set(true)
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                artifactId = "nexora-shield-k-library"
            }
        }
        repositories {
            maven {
                name = "phaseK"
                url = uri(rootProject.layout.buildDirectory.dir("phase-k-repo"))
            }
        }
    }
}
