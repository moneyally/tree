// Tree for Android. The Rust client is cross-compiled with the NDK
// (scripts/android_lib.sh -> src/main/jniLibs) and reached through the
// generated UniFFI Kotlin bindings (JNA). The model and texts are shared
// with the desktop app (apps/shared).
plugins {
    id("com.android.application")
    kotlin("android")
    id("org.jetbrains.kotlin.plugin.compose")
}

val repoRoot = rootDir.parentFile.parentFile
val generated = layout.buildDirectory.dir("generated/uniffi")

val bindings by tasks.registering(Exec::class) {
    workingDir = repoRoot
    val out = generated.get().asFile
    outputs.dir(out)
    outputs.upToDateWhen { false }
    environment("CARGO_PROFILE_DEV_DEBUG", "0")
    commandLine(
        "sh", "-c",
        "cargo build -q -p tree-ffi && T=\${CARGO_TARGET_DIR:-target}/debug && \$T/uniffi-bindgen generate --library \$T/libtree_ffi.so --language kotlin --out-dir '${out.path}'",
    )
}

android {
    namespace = "app.tree.android"
    compileSdk = 35
    defaultConfig {
        applicationId = "app.tree.android"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }
    buildFeatures { compose = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    sourceSets["main"].kotlin.srcDirs(generated, File(repoRoot, "apps/shared/src/main/kotlin"))
    packaging { jniLibs { useLegacyPackaging = false } }
}

kotlin { jvmToolchain(21) }

tasks.named("preBuild") { dependsOn(bindings) }

dependencies {
    implementation(platform("androidx.compose:compose-bom:2025.05.00"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("net.java.dev.jna:jna:5.17.0@aar")
}
