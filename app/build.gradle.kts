import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.mozilla.rust-android-gradle.rust-android")
    kotlin("android")
    kotlin("kapt")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.dagger.hilt.android")
}

val minSdkVersion = 24
val cargoProfile = (findProperty("CARGO_PROFILE") as String?) ?: run {
    val isRelease = gradle.startParameter.taskNames.any { it.contains("Release", ignoreCase = true) }
    if (isRelease) "release" else "debug"
}

fun abiFromTarget(target: String): String = when {
    target.startsWith("aarch64") -> "arm64-v8a"
    target.startsWith("armv7") || target.startsWith("arm") -> "armeabi-v7a"
    target.startsWith("i686") -> "x86"
    target.startsWith("x86_64") -> "x86_64"
    else -> target
}

android {
    val javaVersion = JavaVersion.VERSION_17
    namespace = "app.slipnet"
    compileSdk = 35
    compileOptions {
        sourceCompatibility = javaVersion
        targetCompatibility = javaVersion
    }

    defaultConfig {
        applicationId = "app.slipnet"
        minSdk = minSdkVersion
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // Room schema export
        kapt {
            arguments {
                arg("room.schemaLocation", "$projectDir/schemas")
            }
        }
    }

    buildTypes {
        release {
            isShrinkResources = true
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    buildFeatures {
        compose = true
    }

    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
        }
    }
    ndkVersion = "29.0.14206865"
    packagingOptions.jniLibs.useLegacyPackaging = true
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

val cargoHome = System.getenv("HOME") + "/.cargo"
val cargoBin = "$cargoHome/bin"

cargo {
    cargoCommand = "$cargoBin/cargo"
    rustcCommand = "$cargoBin/rustc"
    module = "src/main/rust/slipstream-rust"
    libname = "slipstream"
    targets = listOf("arm", "arm64", "x86", "x86_64")
    profile = cargoProfile
    rustupChannel = "stable"
    extraCargoBuildArguments = listOf(
        "-p", "slipstream-ffi",
        "--features", "openssl-static,picoquic-minimal-build",
    )
    exec = { spec, toolchain ->
        // Add cargo to PATH
        val currentPath = System.getenv("PATH") ?: ""
        spec.environment("PATH", "$cargoHome/bin:$currentPath")
        // Try python3 first, fall back to python
        // The rust-android-gradle plugin will handle errors if python is not available
        spec.environment("RUST_ANDROID_GRADLE_PYTHON_COMMAND", "python3")
        spec.environment(
            "RUST_ANDROID_GRADLE_CC_LINK_ARG",
            "-Wl,-z,max-page-size=16384,-soname,lib$libname.so"
        )
        spec.environment(
            "RUST_ANDROID_GRADLE_LINKER_WRAPPER_PY",
            "$projectDir/src/main/rust/linker-wrapper.py"
        )
        spec.environment(
            "RUST_ANDROID_GRADLE_TARGET",
            "target/${toolchain.target}/$cargoProfile/lib$libname.so"
        )
        val abi = abiFromTarget(toolchain.target)
        spec.environment("ANDROID_NDK_HOME", android.ndkDirectory.absolutePath)
        spec.environment("ANDROID_ABI", abi)
        spec.environment("ANDROID_PLATFORM", "android-$minSdkVersion")
        spec.environment(
            "PICOQUIC_BUILD_DIR",
            "$projectDir/src/main/rust/slipstream-rust/.picoquic-build/$abi"
        )
        spec.environment("PICOQUIC_AUTO_BUILD", "1")
        spec.environment("BUILD_TYPE", if (cargoProfile == "release") "Release" else "Debug")

        // Add OpenSSL paths for picoquic build and openssl-sys
        // Note: Update this path to your local android-openssl location
        val opensslBase = file("${System.getenv("HOME")}/android-openssl/android-ssl/$abi")
        spec.environment("OPENSSL_DIR", opensslBase.absolutePath)
        spec.environment("OPENSSL_LIB_DIR", opensslBase.resolve("lib").absolutePath)
        spec.environment("OPENSSL_INCLUDE_DIR", opensslBase.resolve("include").absolutePath)
        // For picoquic build script
        spec.environment("OPENSSL_ROOT_DIR", opensslBase.absolutePath)
        spec.environment("OPENSSL_CRYPTO_LIBRARY", opensslBase.resolve("lib/libcrypto.a").absolutePath)
        spec.environment("OPENSSL_SSL_LIBRARY", opensslBase.resolve("lib/libssl.a").absolutePath)
        spec.environment("OPENSSL_USE_STATIC_LIBS", "1")

        val toolchainPrebuilt = android.ndkDirectory
            .resolve("toolchains/llvm/prebuilt")
            .listFiles()
            ?.firstOrNull { it.isDirectory }
        val toolchainBin = toolchainPrebuilt?.resolve("bin")
        if (toolchainBin != null) {
            spec.environment("AR", toolchainBin.resolve("llvm-ar").absolutePath)
            spec.environment("RANLIB", toolchainBin.resolve("llvm-ranlib").absolutePath)
        }
    }
}

tasks.whenTaskAdded {
    when (name) {
        "mergeDebugJniLibFolders", "mergeReleaseJniLibFolders" -> {
            dependsOn("cargoBuild")
            // Track Rust JNI output without adding a second source set (avoids duplicate resources).
            inputs.dir(layout.buildDirectory.dir("rustJniLibs/android"))
        }
    }
}

tasks.register<Exec>("cargoClean") {
    executable("$cargoBin/cargo")
    args("clean")
    workingDir("$projectDir/${cargo.module}")
}
tasks.named("clean") {
    dependsOn("cargoClean")
}

dependencies {
    // Compose BOM
    val composeBom = platform("androidx.compose:compose-bom:2024.02.00")
    implementation(composeBom)
    androidTestImplementation(composeBom)

    // Compose
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")

    // Activity Compose
    implementation("androidx.activity:activity-compose:1.8.2")

    // Lifecycle & ViewModel
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.7.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.7.0")

    // Navigation Compose
    implementation("androidx.navigation:navigation-compose:2.7.7")

    // Hilt
    implementation("com.google.dagger:hilt-android:2.51.1")
    kapt("com.google.dagger:hilt-compiler:2.51.1")
    implementation("androidx.hilt:hilt-navigation-compose:1.2.0")

    // Room
    implementation("androidx.room:room-runtime:2.6.1")
    implementation("androidx.room:room-ktx:2.6.1")
    kapt("androidx.room:room-compiler:2.6.1")

    // DataStore
    implementation("androidx.datastore:datastore-preferences:1.0.0")

    // Kotlin Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")

    // JSON serialization for Room converters
    implementation("com.google.code.gson:gson:2.10.1")

    // Core
    implementation("androidx.core:core-ktx:1.12.0")

    // Testing
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
}

kapt {
    correctErrorTypes = true
}
