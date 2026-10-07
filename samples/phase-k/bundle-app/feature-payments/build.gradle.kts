plugins {
    id("com.android.dynamic-feature")
}

android {
    namespace = "dev.nexora.shield.kapp.payments"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
    }
}

dependencies {
    implementation(project(":app"))
}
