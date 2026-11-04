plugins {
    id("com.android.application")
}

android {
    namespace = "org.defenseunicorns.aster.btlering1"
    compileSdk = 37
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "org.defenseunicorns.aster.btlering1"
        minSdk = 29
        targetSdk = 37
        versionCode = 1
        versionName = "0.1"

        ndk {
            abiFilters += "arm64-v8a"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets.named("main") {
        jniLibs.srcDir(layout.buildDirectory.dir("generated/jniLibs"))
    }

    testOptions {
        unitTests.isReturnDefaultValues = false
    }
}

val buildRust by tasks.registering(Exec::class) {
    val output = layout.buildDirectory.dir("generated/jniLibs")
    inputs.dir(rootProject.file("../../crates"))
    inputs.dir(rootProject.file("../../third-party"))
    inputs.files(
        rootProject.file("../../Cargo.toml"),
        rootProject.file("../../Cargo.lock"),
        project.file("build-rust.sh"),
    )
    outputs.dir(output)
    commandLine("bash", project.file("build-rust.sh"), output.get().asFile.absolutePath)
}

tasks.named("preBuild").configure {
    dependsOn(buildRust)
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}
