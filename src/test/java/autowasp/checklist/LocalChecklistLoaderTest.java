/*
 * LocalChecklistLoaderTest.java - Unit tests for LocalChecklistLoader
 *
 * MIT License
 * Copyright (c) 2021-2026 Sahil Dhar (original author), brndls (contributor)
 *
 * - loadFromResources() - successful JSON load
 * - loadFromResources() - handle file not found
 * - parseCategory() - parse valid JSON structure
 * - parseCategory() - handle malformed JSON
 */
package autowasp.checklist;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link LocalChecklistLoader}.
 *
 * <p>
 * Test categories:
 * <ul>
 * <li>loadFromResources() - JSON loading from bundled resources</li>
 * <li>parseCategory() - JSON structure parsing</li>
 * <li>Error handling - File not found, malformed JSON</li>
 * </ul>
 */
class LocalChecklistLoaderTest {

    @Nested
    @DisplayName("loadFromResources() - Success Cases")
    class LoadFromResourcesSuccess {

        @Test
        @DisplayName("should load all checklist entries from bundled JSON")
        void testLoadFromResources_Success() {
            // Arrange
            LocalChecklistLoader loader = new LocalChecklistLoader();

            // Act
            List<ChecklistEntry> entries = loader.loadFromResources();

            // Assert
            assertFalse(entries.isEmpty(), "Should load at least one entry");
            assertTrue(entries.size() > 90, "WSTG v4.2 has 91+ test cases, got: " + entries.size());
        }

        @Test
        @DisplayName("should parse first entry with correct WSTG-INFO-01 reference")
        void testLoadFromResources_FirstEntryCorrect() {
            // Arrange
            LocalChecklistLoader loader = new LocalChecklistLoader();

            // Act
            List<ChecklistEntry> entries = loader.loadFromResources();
            ChecklistEntry firstEntry = entries.get(0);

            // Assert
            assertEquals("WSTG-INFO-01", firstEntry.refNumber);
            assertEquals("Information Gathering", firstEntry.category);
            assertTrue(firstEntry.testName.contains("Search Engine Discovery"));
        }
    }

    @Nested
    @DisplayName("parseCategory() - Valid JSON Structure")
    class ParseCategoryValidStructure {

        @Test
        @DisplayName("should parse category and test name correctly")
        void testLoadFromResources_ValidJsonStructure() {
            // Arrange
            LocalChecklistLoader loader = new LocalChecklistLoader();

            // Act
            List<ChecklistEntry> entries = loader.loadFromResources();
            ChecklistEntry firstEntry = entries.get(0);

            // Assert
            assertNotNull(firstEntry.refNumber, "Reference number should not be null");
            assertTrue(firstEntry.refNumber.startsWith("WSTG-"), "Reference should start with WSTG-");
            assertNotNull(firstEntry.category, "Category should not be null");
            assertNotNull(firstEntry.testName, "Test name should not be null");
            assertFalse(firstEntry.testName.isEmpty(), "Test name should not be empty");
        }

        @Test
        @DisplayName("should generate HTML summary from objectives")
        void testLoadFromResources_HtmlSummaryGenerated() {
            // Arrange
            LocalChecklistLoader loader = new LocalChecklistLoader();

            // Act
            List<ChecklistEntry> entries = loader.loadFromResources();
            ChecklistEntry entry = entries.get(0);

            // Assert
            assertTrue(entry.summaryHTML.startsWith("<ul>"), "Summary should start with <ul>");
            assertTrue(entry.summaryHTML.endsWith("</ul>"), "Summary should end with </ul>");
            assertTrue(entry.summaryHTML.contains("<li>"), "Summary should contain <li> elements");
        }

        @Test
        @DisplayName("should include reference URL in entry")
        void testLoadFromResources_ReferenceUrlIncluded() {
            // Arrange
            LocalChecklistLoader loader = new LocalChecklistLoader();

            // Act
            List<ChecklistEntry> entries = loader.loadFromResources();
            ChecklistEntry entry = entries.get(0);

            // Assert
            assertNotNull(entry.url, "URL should not be null");
            assertTrue(entry.url.startsWith("https://owasp.org"), "URL should point to OWASP");
            assertTrue(entry.referencesHTML.contains("href="), "References HTML should contain link");
        }
    }

    @Nested
    @DisplayName("Error Handling Cases")
    class ErrorHandlingCases {

        @Test
        @DisplayName("should return empty list when resource file not found")
        void testLoadFromResources_FileNotFound() {
            // Arrange - Create loader that returns null for resource stream
            LocalChecklistLoader loader = new LocalChecklistLoader() {
                @Override
                protected InputStream getResourceAsStream(String path) {
                    return null; // Simulate file not found
                }
            };

            // Act
            List<ChecklistEntry> entries = loader.loadFromResources();

            // Assert
            assertNotNull(entries, "Should return non-null list");
            assertTrue(entries.isEmpty(), "Should return empty list when file not found");
        }

        @Test
        @DisplayName("should return empty list when JSON is malformed")
        void testLoadFromResources_MalformedJson() {
            // Arrange - Create loader that loads malformed JSON
            LocalChecklistLoader loader = new LocalChecklistLoader() {
                @Override
                protected InputStream getResourceAsStream(String path) {
                    return getClass().getResourceAsStream("/wstg/malformed.json");
                }
            };

            // Act
            List<ChecklistEntry> entries = loader.loadFromResources();

            // Assert
            assertNotNull(entries, "Should return non-null list");
            assertTrue(entries.isEmpty(), "Should return empty list when JSON is malformed");
        }
    }

    @Nested
    @DisplayName("getVersion()")
    class GetVersionTests {

        @Test
        @DisplayName("should return bundled WSTG version")
        void testGetVersion() {
            // Arrange
            LocalChecklistLoader loader = new LocalChecklistLoader();

            // Act
            String version = loader.getVersion();

            // Assert
            assertEquals("4.2", version, "Should return WSTG v4.2");
        }
    }
}
