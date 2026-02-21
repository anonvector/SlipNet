import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.net.URL
import java.io.FileOutputStream
import java.util.zip.ZipInputStream
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.mozilla.rust-android-gradle.rust-android")
    kotlin("android")
    kotlin("kapt")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.dagger.hilt.android")
}

val minSdkVersion = 24
val appVersionName = "1.8.6"
val appVersionCode = 26
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

// Signing configuration
val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties()
if (keystorePropertiesFile.exists()) {
    keystoreProperties.load(keystorePropertiesFile.inputStream())
}

// OpenSSL configuration
val opensslVersion = "3.0.15"
val opensslBaseDir = file("${System.getenv("HOME")}/android-openssl/android-ssl")
val supportedAbis = listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")

// Check if OpenSSL is available for all ABIs
fun isOpenSslAvailable(): Boolean {
    return supportedAbis.all { abi ->
        val libDir = opensslBaseDir.resolve("$abi/lib")
        val includeDir = opensslBaseDir.resolve("$abi/include")
        libDir.resolve("libssl.a").exists() &&
        libDir.resolve("libcrypto.a").exists() &&
        includeDir.exists()
    }
}

android {
    val javaVersion = JavaVersion.VERSION_17
    namespace = "app.slipnet"
    compileSdk = 36
    compileOptions {
        sourceCompatibility = javaVersion
        targetCompatibility = javaVersion
    }

    signingConfigs {
        create("release") {
            if (keystorePropertiesFile.exists()) {
                storeFile = file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["storePassword"] as String
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["keyPassword"] as String
            }
        }
    }

    defaultConfig {
        applicationId = "app.slipnet"
        minSdk = minSdkVersion
        targetSdk = 35
        versionCode = appVersionCode
        versionName = appVersionName

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isShrinkResources = true
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("release")
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    applicationVariants.all {
        outputs.all {
            val output = this as com.android.build.gradle.internal.api.BaseVariantOutputImpl
            val abiFilter = output.getFilter("ABI")
            val abi = abiFilter ?: "universal"
            val newName = "SlipNet-v${appVersionName}-${buildType.name}-${abi}.apk"
            output.outputFileName = newName
        }
    }

    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a")
            isUniversalApk = true
        }
    }
    ndkVersion = "29.0.14206865"
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    // Build hev-socks5-tunnel with ndk-build
    externalNativeBuild {
        ndkBuild {
            path = file("src/main/cpp/Android.mk")
        }
    }

}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

val cargoHome = System.getenv("HOME") + "/.cargo"
val cargoBin = "$cargoHome/bin"

// Task to setup OpenSSL for Android
tasks.register("setupOpenSsl") {
    group = "build setup"
    description = "Downloads and sets up OpenSSL for Android if not present"

    doLast {
        if (isOpenSslAvailable()) {
            println("OpenSSL for Android is already available at: $opensslBaseDir")
            return@doLast
        }

        println("OpenSSL for Android not found. Setting up...")

        val downloadUrl = "https://github.com/passy/build-openssl-android/releases/download/v${opensslVersion}/openssl-${opensslVersion}-android.zip"
        val tempZip = file("${buildDir}/tmp/openssl-android.zip")
        val extractDir = file("${buildDir}/tmp/openssl-extract")

        // Create directories
        tempZip.parentFile.mkdirs()
        extractDir.mkdirs()
        opensslBaseDir.mkdirs()

        println("Downloading OpenSSL from: $downloadUrl")

        try {
            // Try primary download source
            downloadFile(downloadUrl, tempZip)
        } catch (e: Exception) {
            println("Primary download failed, trying alternative source...")
            // Alternative: build from source using script
            val buildScript = file("$projectDir/scripts/build-openssl-android.sh")
            if (buildScript.exists()) {
                exec {
                    commandLine("bash", buildScript.absolutePath)
                    environment("OPENSSL_VERSION", opensslVersion)
                    environment("OUTPUT_DIR", opensslBaseDir.absolutePath)
                    environment("ANDROID_NDK_HOME", android.ndkDirectory.absolutePath)
                }
                return@doLast
            } else {
                throw GradleException("""
                    Failed to download OpenSSL for Android.

                    Please manually set up OpenSSL:
                    1. Download pre-built OpenSSL for Android
                    2. Extract to: $opensslBaseDir
                    3. Ensure each ABI folder (arm64-v8a, armeabi-v7a, x86, x86_64) contains:
                       - lib/libssl.a
                       - lib/libcrypto.a
                       - include/openssl/

                    Or run: ./scripts/build-openssl-android.sh
                """.trimIndent())
            }
        }

        println("Extracting OpenSSL...")
        extractZip(tempZip, extractDir)

        // Copy to final location
        supportedAbis.forEach { abi ->
            val srcDir = extractDir.resolve(abi)
            val dstDir = opensslBaseDir.resolve(abi)
            if (srcDir.exists()) {
                srcDir.copyRecursively(dstDir, overwrite = true)
                println("Installed OpenSSL for $abi")
            }
        }

        // Cleanup
        tempZip.delete()
        extractDir.deleteRecursively()

        println("OpenSSL setup complete!")
    }
}

fun downloadFile(url: String, destination: File) {
    URL(url).openStream().use { input ->
        FileOutputStream(destination).use { output ->
            input.copyTo(output)
        }
    }
}

fun extractZip(zipFile: File, destDir: File) {
    ZipInputStream(zipFile.inputStream()).use { zis ->
        var entry = zis.nextEntry
        while (entry != null) {
            val destFile = File(destDir, entry.name)
            if (entry.isDirectory) {
                destFile.mkdirs()
            } else {
                destFile.parentFile?.mkdirs()
                destFile.outputStream().use { fos ->
                    zis.copyTo(fos)
                }
            }
            entry = zis.nextEntry
        }
    }
}

// Task to verify OpenSSL setup
tasks.register("verifyOpenSsl") {
    group = "verification"
    description = "Verifies that OpenSSL for Android is properly set up"

    doLast {
        val missing = mutableListOf<String>()

        supportedAbis.forEach { abi ->
            val libDir = opensslBaseDir.resolve("$abi/lib")
            val includeDir = opensslBaseDir.resolve("$abi/include")

            if (!libDir.resolve("libssl.a").exists()) {
                missing.add("$abi/lib/libssl.a")
            }
            if (!libDir.resolve("libcrypto.a").exists()) {
                missing.add("$abi/lib/libcrypto.a")
            }
            if (!includeDir.resolve("openssl").exists()) {
                missing.add("$abi/include/openssl/")
            }
        }

        if (missing.isNotEmpty()) {
            throw GradleException("""
                OpenSSL for Android is not properly set up.
                Missing files in $opensslBaseDir:
                ${missing.joinToString("\n  - ", prefix = "  - ")}

                Run './gradlew setupOpenSsl' to download and set up OpenSSL.
            """.trimIndent())
        }

        println("OpenSSL verification passed! All required files present.")
    }
}

cargo {
    cargoCommand = "$cargoBin/cargo"
    rustcCommand = "$cargoBin/rustc"
    module = "src/main/rust/slipstream-rust"
    libname = "slipstream"
    targets = listOf("arm", "arm64", "x86", "x86_64")
    profile = cargoProfile
    rustupChannel = "stable"
    extraCargoBuildArguments = listOf(
        "-p", "slipstream-client",
        "--lib",  // Only build the library, not the binary (avoids overwriting cdylib with executable)
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
        val opensslAbiDir = opensslBaseDir.resolve(abi)
        spec.environment("OPENSSL_DIR", opensslAbiDir.absolutePath)
        spec.environment("OPENSSL_LIB_DIR", opensslAbiDir.resolve("lib").absolutePath)
        spec.environment("OPENSSL_INCLUDE_DIR", opensslAbiDir.resolve("include").absolutePath)
        // For picoquic build script
        spec.environment("OPENSSL_ROOT_DIR", opensslAbiDir.absolutePath)
        spec.environment("OPENSSL_CRYPTO_LIBRARY", opensslAbiDir.resolve("lib/libcrypto.a").absolutePath)
        spec.environment("OPENSSL_SSL_LIBRARY", opensslAbiDir.resolve("lib/libssl.a").absolutePath)
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

// Make cargo build tasks depend on OpenSSL verification
tasks.whenTaskAdded {
    when (name) {
        "cargoBuildArm", "cargoBuildArm64", "cargoBuildX86", "cargoBuildX86_64" -> {
            dependsOn("verifyOpenSsl")
        }
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
    // Combined Go library (DNSTT + Snowflake)
    // Built via: cd gomobile-build && make build
    implementation(files("libs/golibs.aar"))

    // Tor binary for Snowflake tunnel — libtor.so extracted from
    // info.guardianproject:tor-android:0.4.8.22 into jniLibs/
    // (AAR excluded as Gradle dep because its Kotlin metadata 2.3.0
    //  is incompatible with Room 2.6.1 kapt processor)

    // Compose BOM
    val composeBom = platform("androidx.compose:compose-bom:2026.01.01")
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
    implementation("androidx.activity:activity-compose:1.12.4")

    // Lifecycle & ViewModel
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.10.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.10.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.10.0")

    // Navigation Compose
    implementation("androidx.navigation:navigation-compose:2.9.7")

    // Hilt
    implementation("com.google.dagger:hilt-android:2.59.1")
    kapt("com.google.dagger:hilt-compiler:2.59.1")
    implementation("androidx.hilt:hilt-navigation-compose:1.3.0")

    // Room
    implementation( "androidx.room:room-runtime:2.8.4")
    implementation("androidx.room:room-ktx:2.8.4")
    kapt("androidx.room:room-compiler:2.8.4")

    // DataStore
    implementation("androidx.datastore:datastore-preferences:1.2.0")

    // Kotlin Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")

    // JSON serialization for Room converters
    implementation("com.google.code.gson:gson:2.13.2")

    // SSH tunneling library (mwiede fork — supports modern ciphers: AES-GCM, ChaCha20)
    implementation("com.github.mwiede:jsch:2.27.7")

    // OkHttp for DoH (HTTP/2, connection pooling, custom DNS resolver)
    implementation("com.squareup.okhttp3:okhttp:5.3.2")

    // Drag-and-drop reorderable LazyColumn
    implementation("sh.calvin.reorderable:reorderable:3.0.0")

    // QR code generation & scanning
    implementation("com.google.zxing:core:3.5.4")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")

    // Core
    implementation("androidx.core:core-ktx:1.17.0")

    // Testing
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
}

kapt {
    correctErrorTypes = true
    // Room schema export
    arguments {
        arg("room.schemaLocation", "$projectDir/schemas")
    }
}
