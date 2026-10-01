// Runs the generated Kotlin bindings on the JVM against a local server
// (scripts/ffi_kotlin_demo.sh). The desktop app uses this same path.
plugins {
    kotlin("jvm") version "2.1.21"
    application
}

repositories { mavenCentral() }

dependencies {
    implementation("net.java.dev.jna:jna:5.17.0")
}

kotlin { jvmToolchain(21) }

sourceSets {
    main {
        kotlin.srcDir(System.getenv("TREE_KT_BINDINGS") ?: "build/generated")
    }
}

application {
    mainClass.set("DemoKt")
}

tasks.named<JavaExec>("run") {
    systemProperty("jna.library.path", System.getenv("TREE_LIB_DIR") ?: "")
    jvmArgs("-Dstdout.encoding=UTF-8")
    environment("TREE_URL", System.getenv("TREE_URL") ?: "")
}
