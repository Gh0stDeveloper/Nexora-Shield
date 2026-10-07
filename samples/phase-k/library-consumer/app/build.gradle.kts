plugins {
    id("com.android.application")
}

android {
    namespace = "dev.nexora.shield.kconsumer"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.nexora.shield.kconsumer"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }
}

dependencies {
    implementation("dev.nexora:nexora-shield-k-library:1.0.0")
}
