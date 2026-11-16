import org.gradle.util.GradleVersion

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

val requiredGradle = GradleVersion.version("9.6.0")
require(GradleVersion.current() == requiredGradle) {
    "Aster BTLE Ring-1 requires Gradle 9.6.0 (found ${GradleVersion.current()})"
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "AsterBtleRing1"
include(":app")
