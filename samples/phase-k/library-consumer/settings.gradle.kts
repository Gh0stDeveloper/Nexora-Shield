pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven {
            url = uri("../library-publishing/build/phase-k-repo")
        }
        google()
        mavenCentral()
    }
}

rootProject.name = "nexora-shield-phase-k-library-consumer"
include(":app")
