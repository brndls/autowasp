/*
 * Copyright (c) 2026 Autowasp Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package autowasp.persistence;

import autowasp.logger.entrytable.LoggerEntry;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link ProjectSerializer}.
 * Tests JSON serialization, deserialization, and security validations.
 */
class ProjectSerializerTest {

    private ProjectSerializer serializer;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        serializer = new ProjectSerializer();
    }

    @Test
    void testSaveToJsonSuccess() throws IOException {
        // Arrange
        List<LoggerEntry> entries = new ArrayList<>();
        entries.add(new LoggerEntry("example.com", "Scanner", "XSS", "Cross-Site Scripting"));

        // Act
        serializer.saveToJson(entries, tempDir.toString());

        // Assert
        File savedFile = new File(tempDir.toFile(), "autowasp_project.json");
        assertTrue(savedFile.exists());
        assertTrue(savedFile.length() > 0);
    }

    @Test
    void testSaveToJsonInvalidDirectory() {
        // Arrange
        List<LoggerEntry> entries = new ArrayList<>();
        String invalidPath = tempDir.toString() + "/nonexistent";

        // Act & Assert
        assertThrows(IOException.class, () -> serializer.saveToJson(entries, invalidPath));
    }

    @Test
    void testSaveToJsonEmptyList() throws IOException {
        // Arrange
        List<LoggerEntry> entries = new ArrayList<>();

        // Act
        serializer.saveToJson(entries, tempDir.toString());

        // Assert
        File savedFile = new File(tempDir.toFile(), "autowasp_project.json");
        assertTrue(savedFile.exists());
    }

    @Test
    void testLoadFromJsonSuccess() throws IOException {
        // Arrange
        List<LoggerEntry> originalEntries = new ArrayList<>();
        originalEntries.add(new LoggerEntry("example.com", "Scanner", "SQLi", "SQL Injection"));
        serializer.saveToJson(originalEntries, tempDir.toString());

        File savedFile = new File(tempDir.toFile(), "autowasp_project.json");

        // Act
        List<LoggerEntry> loadedEntries = serializer.loadFromJson(savedFile.getAbsolutePath());

        // Assert
        assertNotNull(loadedEntries);
        assertEquals(1, loadedEntries.size());
        assertEquals("example.com", loadedEntries.get(0).getHost());
        assertEquals("SQLi", loadedEntries.get(0).getVulnType());
    }

    @Test
    void testLoadFromJsonFileNotFound() {
        // Arrange
        String nonExistentFile = tempDir.toString() + "/nonexistent.json";

        // Act & Assert
        assertThrows(FileNotFoundException.class, () -> serializer.loadFromJson(nonExistentFile));
    }

    @Test
    void testLoadFromJsonInvalidExtension() throws IOException {
        // Arrange
        File invalidFile = new File(tempDir.toFile(), "test.txt");
        Files.writeString(invalidFile.toPath(), "{}");

        // Act & Assert
        String path = invalidFile.getAbsolutePath();
        assertThrows(IllegalArgumentException.class, () -> serializer.loadFromJson(path));
    }

    @Test
    void testLoadFromJsonMalformedJson() throws IOException {
        // Arrange
        File malformedFile = new File(tempDir.toFile(), "malformed.json");
        Files.writeString(malformedFile.toPath(), "{invalid json");

        // Act & Assert
        String path = malformedFile.getAbsolutePath();
        assertThrows(Exception.class, () -> serializer.loadFromJson(path));
    }

    @Test
    void testLoadFromJsonEmptyFile() throws IOException {
        // Arrange
        File emptyFile = new File(tempDir.toFile(), "empty.json");
        Files.writeString(emptyFile.toPath(), "");

        // Act & Assert
        String path = emptyFile.getAbsolutePath();
        assertThrows(Exception.class, () -> serializer.loadFromJson(path));
    }

    @Test
    void testRoundTripSerialization() throws IOException {
        // Arrange
        List<LoggerEntry> originalEntries = new ArrayList<>();
        originalEntries.add(new LoggerEntry("example.com", "Scanner", "XSS", "Cross-Site Scripting"));
        originalEntries.add(new LoggerEntry("test.com", "Manual", "CSRF", "Cross-Site Request Forgery"));

        // Act
        serializer.saveToJson(originalEntries, tempDir.toString());
        File savedFile = new File(tempDir.toFile(), "autowasp_project.json");
        List<LoggerEntry> loadedEntries = serializer.loadFromJson(savedFile.getAbsolutePath());

        // Assert
        assertEquals(originalEntries.size(), loadedEntries.size());
        for (int i = 0; i < originalEntries.size(); i++) {
            assertEquals(originalEntries.get(i).getHost(), loadedEntries.get(i).getHost());
            assertEquals(originalEntries.get(i).getVulnType(), loadedEntries.get(i).getVulnType());
        }
    }

    @Test
    void testValidateDirectoryPathSuccess() throws IOException {
        // Act
        String canonicalPath = serializer.validateDirectoryPath(tempDir.toString());

        // Assert
        assertNotNull(canonicalPath);
        assertTrue(new File(canonicalPath).exists());
    }

    @Test
    void testValidateDirectoryPathNull() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> serializer.validateDirectoryPath(null));
    }

    @Test
    void testValidateDirectoryPathEmpty() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> serializer.validateDirectoryPath(""));
    }

    @Test
    void testValidateDirectoryPathWhitespace() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> serializer.validateDirectoryPath("   "));
    }

    @Test
    void testValidateDirectoryPathNonExistent() {
        // Arrange
        String nonExistentPath = tempDir.toString() + "/nonexistent";

        // Act & Assert
        assertThrows(FileNotFoundException.class, () -> serializer.validateDirectoryPath(nonExistentPath));
    }

    @Test
    void testValidateDirectoryPathIsFile() throws IOException {
        // Arrange
        File file = new File(tempDir.toFile(), "test.txt");
        Files.writeString(file.toPath(), "test");

        // Act & Assert
        String path = file.getAbsolutePath();
        assertThrows(IllegalArgumentException.class, () -> serializer.validateDirectoryPath(path));
    }

    @Test
    void testValidateFilePathSuccess() throws IOException {
        // Arrange
        File testFile = new File(tempDir.toFile(), "autowasp_project.json");
        Files.writeString(testFile.toPath(), "{}");

        // Act
        String canonicalPath = serializer.validateFilePath(testFile.getAbsolutePath(), "autowasp_project.json");

        // Assert
        assertNotNull(canonicalPath);
        assertTrue(canonicalPath.endsWith("autowasp_project.json"));
    }

    @Test
    void testValidateFilePathNull() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> serializer.validateFilePath(null, "test.json"));
    }

    @Test
    void testValidateFilePathEmpty() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> serializer.validateFilePath("", "test.json"));
    }

    @Test
    void testValidateFilePathWrongFileName() throws IOException {
        // Arrange
        File testFile = new File(tempDir.toFile(), "wrong.json");
        Files.writeString(testFile.toPath(), "{}");

        // Act & Assert
        String path = testFile.getAbsolutePath();
        assertThrows(IllegalArgumentException.class, () -> serializer.validateFilePath(path, "expected.json"));
    }

    @Test
    void testValidateFilePathNullExpectedName() throws IOException {
        // Arrange
        File testFile = new File(tempDir.toFile(), "any.json");
        Files.writeString(testFile.toPath(), "{}");

        // Act
        String canonicalPath = serializer.validateFilePath(testFile.getAbsolutePath(), null);

        // Assert
        assertNotNull(canonicalPath);
    }

    @Test
    void testSaveToJsonWithSpecialCharacters() throws IOException {
        // Arrange
        List<LoggerEntry> entries = new ArrayList<>();
        LoggerEntry entry = new LoggerEntry("example.com", "Scanner", "XSS", "Test <script>alert('xss')</script>");
        entries.add(entry);

        // Act
        serializer.saveToJson(entries, tempDir.toString());
        File savedFile = new File(tempDir.toFile(), "autowasp_project.json");
        List<LoggerEntry> loadedEntries = serializer.loadFromJson(savedFile.getAbsolutePath());

        // Assert
        assertEquals(1, loadedEntries.size());
        assertTrue(loadedEntries.get(0).getVulnType().contains("XSS"));
    }

    @Test
    void testSaveToJsonLargeDataset() throws IOException {
        // Arrange
        List<LoggerEntry> entries = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            entries.add(new LoggerEntry("example" + i + ".com", "Scanner", "XSS", "Issue " + i));
        }

        // Act
        serializer.saveToJson(entries, tempDir.toString());
        File savedFile = new File(tempDir.toFile(), "autowasp_project.json");
        List<LoggerEntry> loadedEntries = serializer.loadFromJson(savedFile.getAbsolutePath());

        // Assert
        assertEquals(100, loadedEntries.size());
    }

    @Test
    void testLoadFromJsonNullContent() throws IOException {
        // Arrange
        File nullFile = new File(tempDir.toFile(), "null.json");
        Files.writeString(nullFile.toPath(), "null");

        // Act & Assert
        String path = nullFile.getAbsolutePath();
        assertThrows(IOException.class, () -> serializer.loadFromJson(path));
    }
}
