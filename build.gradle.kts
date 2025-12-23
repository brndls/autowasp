/**
 * build.gradle.kts - Konfigurasi Build Gradle untuk Autowasp
 * 
 * 📚 PEMBELAJARAN:
 * File ini adalah "resep" untuk membangun extension Autowasp.
 * Gradle akan membaca file ini untuk tahu:
 * - Plugin apa yang dipakai
 * - Versi Java berapa
 * - Dependencies (library) apa saja yang dibutuhkan
 * - Bagaimana cara membuat JAR file
 */

// ════════════════════════════════════════════════════════════════════════════
// PLUGINS
// ════════════════════════════════════════════════════════════════════════════
/**
 * 📚 PEMBELAJARAN: Plugins
 * Plugin menambahkan kemampuan ke Gradle. Seperti "extensions" di browser.
 * 
 * - `java`: Memberikan kemampuan compile Java
 * - `shadow`: Membuat "fat JAR" (JAR yang berisi semua dependencies)
 */
plugins {
    java
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

// ════════════════════════════════════════════════════════════════════════════
// PROJECT IDENTITY
// ════════════════════════════════════════════════════════════════════════════
/**
 * 📚 PEMBELAJARAN: Group & Version
 * - group: Namespace unik (seperti domain terbalik di Java: com.example.myapp)
 * - version: Versi software (SNAPSHOT = masih dalam development)
 */
group = "autowasp"
version = "1.0-SNAPSHOT"

// ════════════════════════════════════════════════════════════════════════════
// JAVA CONFIGURATION
// ════════════════════════════════════════════════════════════════════════════
/**
 * 📚 PEMBELAJARAN: Source & Target Compatibility
 * - sourceCompatibility: Versi Java yang dipakai untuk MENULIS kode
 * - targetCompatibility: Versi Java yang dipakai untuk MENJALANKAN kode
 * 
 * Di Fase 1 ini kita tetap pakai Java 8 dulu.
 * Di Fase 2 nanti kita upgrade ke Java 21.
 */
java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

// ════════════════════════════════════════════════════════════════════════════
// REPOSITORIES
// ════════════════════════════════════════════════════════════════════════════
/**
 * 📚 PEMBELAJARAN: Repositories
 * Repository adalah "toko" tempat Gradle mengunduh dependencies.
 * 
 * Maven Central = Repository publik terbesar untuk library Java
 * Seperti npm registry untuk JavaScript atau PyPI untuk Python
 */
repositories {
    mavenCentral()
}

// ════════════════════════════════════════════════════════════════════════════
// DEPENDENCIES
// ════════════════════════════════════════════════════════════════════════════
/**
 * 📚 PEMBELAJARAN: Dependencies
 * Dependencies adalah library eksternal yang dibutuhkan project.
 * 
 * Tipe dependency:
 * - implementation: Dibutuhkan saat compile DAN runtime, masuk ke JAR
 * - compileOnly: Hanya dibutuhkan saat compile, TIDAK masuk ke JAR
 *                (Burp API sudah ada di Burp Suite, jadi tidak perlu di-bundle)
 * 
 * Format: "groupId:artifactId:version"
 * Contoh: "com.google.code.gson:gson:2.8.5"
 *         └─ groupId ─────────┘ └─┘ └──┘
 *                          artifactId  version
 */
dependencies {
    // Burp Suite API - hanya dibutuhkan saat compile
    // Saat runtime, Burp Suite sudah menyediakan API ini
    compileOnly("net.portswigger.burp.extender:burp-extender-api:1.7.13")
    
    // Apache Commons Collections - utility untuk Collection (List, Map, Set)
    implementation("org.apache.commons:commons-collections4:4.4")
    
    // Apache Commons Compress - untuk membaca/membuat file archive (ZIP, TAR)
    implementation("org.apache.commons:commons-compress:1.19")
    
    // Gson - library dari Google untuk parsing JSON
    implementation("com.google.code.gson:gson:2.8.5")
    
    // Jsoup - library untuk parsing dan manipulasi HTML
    implementation("org.jsoup:jsoup:1.12.1")
    
    // Apache POI - library untuk membuat file Excel (.xlsx)
    // Digunakan untuk export report ke Excel
    implementation("org.apache.poi:poi:4.1.0")
    implementation("org.apache.poi:poi-ooxml:4.1.0") {
        // exclude = mengecualikan dependency tertentu
        // BouncyCastle adalah crypto library yang tidak kita butuhkan
        exclude(group = "org.bouncycastle")
    }
    implementation("org.apache.poi:poi-ooxml-schemas:4.1.0") {
        exclude(group = "org.bouncycastle")
    }
    
    // XMLBeans - dibutuhkan oleh Apache POI untuk membaca XML
    implementation("org.apache.xmlbeans:xmlbeans:3.1.0")
}

// ════════════════════════════════════════════════════════════════════════════
// TASKS
// ════════════════════════════════════════════════════════════════════════════
/**
 * 📚 PEMBELAJARAN: Tasks
 * Task adalah "perintah" yang bisa dijalankan Gradle.
 * Contoh: ./gradlew build, ./gradlew shadowJar
 * 
 * shadowJar = Task dari Shadow plugin untuk membuat FAT JAR
 * Fat JAR = JAR yang berisi semua dependencies (bisa langsung dijalankan)
 */
tasks.shadowJar {
    // Nama file output: autowasp-jar-with-dependencies.jar
    archiveBaseName.set("autowasp")
    archiveClassifier.set("jar-with-dependencies")
    
    // Manifest = metadata di dalam JAR
    // Main-Class = class yang dijalankan pertama kali
    manifest {
        attributes["Main-Class"] = "burp.BurpExtender"
    }
}

// Ketika menjalankan `./gradlew build`, otomatis jalankan shadowJar juga
tasks.build {
    dependsOn(tasks.shadowJar)
}
