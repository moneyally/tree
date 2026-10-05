// Tree desktop app (Compose for desktop, JVM). The Rust client library is
// built by cargo and reached through the generated UniFFI Kotlin bindings.
import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    kotlin("jvm") version "2.1.21"
    id("org.jetbrains.kotlin.plugin.compose") version "2.1.21"
    id("org.jetbrains.compose") version "1.8.2"
}

val repoRoot = rootDir.parentFile.parentFile
// cargo's output: CARGO_TARGET_DIR if set (a shared build directory), else target/.
val cargoTarget = File(System.getenv("CARGO_TARGET_DIR")?.let { File(it).let { f -> if (f.isAbsolute) f else File(repoRoot, it) } } ?: File(repoRoot, "target"), "debug")
val generated = layout.buildDirectory.dir("generated/uniffi")

val cargoBuild by tasks.registering(Exec::class) {
    workingDir = repoRoot
    environment("CARGO_PROFILE_DEV_DEBUG", "0")
    commandLine("cargo", "build", "-q", "-p", "tree-ffi")
}

val bindings by tasks.registering(Exec::class) {
    dependsOn(cargoBuild)
    workingDir = repoRoot
    val out = generated.get().asFile
    outputs.dir(out)
    // The library is cargo's output, not a Gradle input: regenerate every build.
    outputs.upToDateWhen { false }
    commandLine(
        File(cargoTarget, "uniffi-bindgen").path, "generate",
        "--library", File(cargoTarget, "libtree_ffi.so").path,
        "--language", "kotlin", "--out-dir", out.path,
    )
}

// The model and texts are shared with the Android app.
sourceSets { main { kotlin.srcDirs(generated, File(rootDir, "../shared/src/main/kotlin"), File(rootDir, "../ui/src/main/kotlin")); resources.srcDir(File(rootDir, "../ui/res")) } }
tasks.named("compileKotlin") { dependsOn(bindings) }

dependencies {
    implementation(compose.desktop.currentOs)
    implementation(compose.material3)
    implementation(compose.materialIconsExtended)
    implementation("net.java.dev.jna:jna:5.17.0")
    // QR codes: made and read in shared code (apps/shared/.../qr).
    implementation("com.google.zxing:core:3.5.4")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-swing:1.10.2")
    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
}

kotlin { jvmToolchain(21) }

tasks.withType<JavaExec>().configureEach {
    systemProperty("jna.library.path", cargoTarget.path)
}

tasks.test {
    useJUnitPlatform()
    // The Rust library is not a Gradle input: always run against the current one.
    outputs.upToDateWhen { false }
    systemProperty("jna.library.path", cargoTarget.path)
    environment("TREE_URL", System.getenv("TREE_URL") ?: "")
    testLogging { events("passed", "failed"); showStandardStreams = true }
}

compose.desktop {
    application {
        mainClass = "app.tree.desktop.MainKt"
        jvmArgs("-Djna.library.path=${cargoTarget.path}")
        nativeDistributions {
            targetFormats(TargetFormat.Deb, TargetFormat.Msi, TargetFormat.Dmg)
            packageName = "Tree"
            packageVersion = "1.0.0"
        }
    }
}
