plugins {
    id("com.android.application")
    id("dev.nexora.shield")
}

val uploadStore = providers.environmentVariable("NEXORA_K_UPLOAD_KEYSTORE")
val uploadStorePassword = providers.environmentVariable("NEXORA_K_UPLOAD_STORE_PASSWORD")
val uploadKeyPassword = providers.environmentVariable("NEXORA_K_UPLOAD_KEY_PASSWORD")
val uploadAlias = providers.environmentVariable("NEXORA_K_UPLOAD_ALIAS")

android {
    namespace = "dev.nexora.shield.kapp"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.nexora.shield.kapp"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }

    dynamicFeatures += setOf(":feature_payments")

    signingConfigs {
        create("upload") {
            if (uploadStore.isPresent) {
                storeFile = file(uploadStore.get())
                storePassword = uploadStorePassword.get()
                keyAlias = uploadAlias.get()
                keyPassword = uploadKeyPassword.get()
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (uploadStore.isPresent) {
                signingConfig = signingConfigs.getByName("upload")
            }
        }
    }
}

nexoraShield {
    cliExecutable.set(
        providers.environmentVariable("NEXORA_SHIELD_CLI").orElse("nexora-shield"),
    )
    releaseOnly.set(true)
    allowUnsigned.set(true)
    align.set(false)
    validateBundle.set(true)

    val bundletool = providers.environmentVariable("BUNDLETOOL_JAR")
    if (bundletool.isPresent) {
        bundletoolJar.set(file(bundletool.get()))
    }
}
