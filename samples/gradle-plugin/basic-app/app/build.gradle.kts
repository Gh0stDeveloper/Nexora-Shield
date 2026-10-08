plugins {
    id("com.android.application")
    id("dev.nexora.shield")
}

android {
    namespace = "dev.nexora.shield.sample"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.nexora.shield.sample"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = false
        }
    }
}

nexoraShield {
    enabled.set(
        providers.gradleProperty("nexoraShieldEnabled")
            .map(String::toBoolean)
            .orElse(true),
    )
    cliExecutable.set(
        providers.environmentVariable("NEXORA_SHIELD_CLI").orElse("nexora-shield"),
    )
    releaseOnly.set(true)
    profile.set("hardened")\n    // This historical Phase J sample exercises Phase A packaging only,\n    // not production security controls. Production defaults fail closed.\n    legacyPhaseAOnly.set(true)

    // Sample-only: production releases should configure signingKeystore and
    // env:/file: password references instead of allowing unsigned output.
    allowUnsigned.set(true)
    align.set(false)

    publicReports.set(true)
    privateReports.set(false)
    buildCacheEnabled.set(false)
}
