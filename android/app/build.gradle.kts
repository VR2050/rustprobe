import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val localProperties = Properties().apply {
    val file = rootProject.file("local.properties")
    if (file.exists()) {
        file.inputStream().use(::load)
    }
}

val rustJniLibsDir = layout.projectDirectory.dir("src/main/jniLibs")
val rustBuildScript = rootProject.file("scripts/build-rust-android.sh")

fun sdkDir(): String {
    val configured = localProperties.getProperty("sdk.dir")
    return configured
        ?: System.getenv("ANDROID_SDK_ROOT")
        ?: System.getenv("ANDROID_HOME")
        ?: error("Android SDK path is not configured. Set sdk.dir or ANDROID_SDK_ROOT.")
}

val buildRustJni by tasks.registering(Exec::class) {
    group = "rust"
    description = "Build Rust Android JNI libraries for RustProbe."
    workingDir = rootProject.rootDir.parentFile

    val profile = providers
        .gradleProperty("rust.android.profile")
        .orElse("debug")

    commandLine(
        "bash",
        rustBuildScript.absolutePath,
        "--profile",
        profile.get(),
        "--sdk-dir",
        sdkDir(),
        "--output",
        rustJniLibsDir.asFile.absolutePath,
    )
}

android {
    namespace = "io.rustprobe.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.rustprobe.app"
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets["main"].jniLibs.srcDir(rustJniLibsDir)
}

tasks.named("preBuild").configure {
    dependsOn(buildRustJni)
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("androidx.appcompat:appcompat:1.7.1")
}
