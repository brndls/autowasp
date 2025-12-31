/**
 * build.gradle.kts - Gradle Build Configuration for Autowasp
 *
 * This file defines:
 * - Plugins to use
 * - Java version
 * - Dependencies (external libraries)
 * - How to build the JAR file
 */

// ════════════════════════════════════════════════════════════════════════════
// PLUGINS
// ════════════════════════════════════════════════════════════════════════════
/**
 * Plugins add capabilities to Gradle:
 * - `java`: Provides Java compilation
 * - `shadow`: Creates "fat JAR" (JAR containing all dependencies)
 */
plugins {
    java
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

// ════════════════════════════════════════════════════════════════════════════
// PROJECT IDENTITY
// ════════════════════════════════════════════════════════════════════════════
/**
 * - group: Unique namespace (like reverse domain in Java)
 * - version: Software version (SNAPSHOT = still in development)
 */
group = "autowasp"
version = "2.0.0"

// ════════════════════════════════════════════════════════════════════════════
// JAVA CONFIGURATION
// ════════════════════════════════════════════════════════════════════════════
/**
 * Java 21 is the latest LTS (Long Term Support) with modern features:
 * - Virtual Threads (Project Loom)
 * - Pattern Matching for switch
 * - Record Patterns
 * - Sequenced Collections
 *
 * Burp Suite 2024+ supports Java 21.
 */
java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

// ════════════════════════════════════════════════════════════════════════════
// REPOSITORIES
// ════════════════════════════════════════════════════════════════════════════
/**
 * Repositories are where Gradle downloads dependencies from.
 * Maven Central is the largest public repository for Java libraries.
 */
repositories {
    mavenCentral()
}

// ════════════════════════════════════════════════════════════════════════════
// DEPENDENCIES
// ════════════════════════════════════════════════════════════════════════════
/**
 * Dependencies are external libraries required by the project.
 *
 * Dependency types:
 * - implementation: Required at compile AND runtime, included in JAR
 * - compileOnly: Required only at compile time, NOT included in JAR
 *                (Burp API is already provided by Burp Suite at runtime)
 *
 * Format: "groupId:artifactId:version"
 */
dependencies {
    // Burp Suite Montoya API - compile-only since Burp Suite provides it at runtime
    // Montoya API adalah pengganti modern untuk Legacy Extender API
    // Dokumentasi: https://portswigger.github.io/burp-extensions-montoya-api/javadoc/
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.12")

    // Apache Commons Collections - utilities for Collection types
    implementation("org.apache.commons:commons-collections4:4.5.0-M3")

    // Apache Commons Compress - for reading/writing archive files (ZIP, TAR)
    implementation("org.apache.commons:commons-compress:1.28.0")

    // Gson - Google's library for JSON parsing
    implementation("com.google.code.gson:gson:2.13.2")

    // Jsoup - library for parsing and manipulating HTML
    implementation("org.jsoup:jsoup:1.21.2")

    // Apache POI - library for creating Excel files (.xlsx)
    // Used for exporting reports to Excel
    // Version 5.x includes XMLBeans internally
    implementation("org.apache.poi:poi:5.5.1")
    implementation("org.apache.poi:poi-ooxml:5.5.1") {
        // Exclude BouncyCastle crypto library (not needed)
        exclude(group = "org.bouncycastle")
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TASKS
// ════════════════════════════════════════════════════════════════════════════
/**
 * Tasks are commands that Gradle can execute.
 * Example: ./gradlew build, ./gradlew shadowJar
 *
 * shadowJar = Task from Shadow plugin to create FAT JAR
 * Fat JAR = JAR containing all dependencies (can run standalone)
 */
tasks.shadowJar {
    // Output filename: autowasp-jar-with-dependencies.jar
    archiveBaseName.set("autowasp")
    archiveClassifier.set("jar-with-dependencies")

    // Manifest = metadata inside JAR
    // Main-Class = entry point class (implements BurpExtension)
    manifest {
        attributes["Main-Class"] = "autowasp.Autowasp"
    }
}

// When running `./gradlew build`, also run shadowJar
tasks.build {
    dependsOn(tasks.shadowJar)
}
