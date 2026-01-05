/*
 * Copyright (c) 2021 Government Technology Agency
 * Copyright (c) 2024-2026 Autowasp Contributors
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
package autowasp.logger;

import autowasp.http.HTTPRequestResponse;
import org.junit.jupiter.api.Test;

import java.net.URL;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link TrafficEntry}.
 * Tests constructor initialization and field access for the immutable data
 * model.
 */
@SuppressWarnings("deprecation") // URL(String) deprecated in Java 20, acceptable for test code
class TrafficEntryTest {

    @Test
    void testConstructorInitializesAllFields() throws Exception {
        // Arrange
        String flag = "CRITICAL";
        HTTPRequestResponse mockRequestResponse = mock(HTTPRequestResponse.class);
        URL url = new URL("https://example.com/api/test");
        TrafficInstance affectedInstance = new TrafficInstance();
        String evidence = "SQL injection detected";
        String trafficMsg = "Potential vulnerability found";

        // Act
        TrafficEntry entry = new TrafficEntry(flag, mockRequestResponse, url,
                affectedInstance, evidence, trafficMsg);

        // Assert
        assertEquals(flag, entry.flag);
        assertEquals(mockRequestResponse, entry.requestResponse);
        assertEquals(url, entry.url);
        assertEquals(affectedInstance, entry.affectedInstancesList);
        assertEquals(evidence, entry.evidence);
        assertEquals(trafficMsg, entry.trafficMsg);
    }

    @Test
    void testConstructorWithNullValues() throws Exception {
        // Arrange
        String flag = null;
        HTTPRequestResponse requestResponse = null;
        URL url = new URL("https://example.com");
        TrafficInstance affectedInstance = null;
        String evidence = null;
        String trafficMsg = null;

        // Act
        TrafficEntry entry = new TrafficEntry(flag, requestResponse, url,
                affectedInstance, evidence, trafficMsg);

        // Assert - should allow null values without throwing
        assertNull(entry.flag);
        assertNull(entry.requestResponse);
        assertNotNull(entry.url);
        assertNull(entry.affectedInstancesList);
        assertNull(entry.evidence);
        assertNull(entry.trafficMsg);
    }

    @Test
    void testConstructorWithMinimalData() throws Exception {
        // Arrange
        URL url = new URL("https://example.com");

        // Act
        TrafficEntry entry = new TrafficEntry(null, null, url, null, null, null);

        // Assert
        assertNotNull(entry);
        assertEquals(url, entry.url);
    }

    @Test
    void testFieldsArePublicAndFinal() throws Exception {
        // Arrange
        String flag = "INFO";
        URL url = new URL("https://example.com");
        TrafficEntry entry = new TrafficEntry(flag, null, url, null, null, null);

        // Assert - fields should be directly accessible (public)
        assertNotNull(entry.flag);
        assertNotNull(entry.url);
    }

    @Test
    void testWithDifferentURLSchemes() throws Exception {
        // Test HTTP
        URL httpUrl = new URL("http://example.com");
        TrafficEntry httpEntry = new TrafficEntry("TEST", null, httpUrl, null, null, null);
        assertEquals("http", httpEntry.url.getProtocol());

        // Test HTTPS
        URL httpsUrl = new URL("https://secure.example.com");
        TrafficEntry httpsEntry = new TrafficEntry("TEST", null, httpsUrl, null, null, null);
        assertEquals("https", httpsEntry.url.getProtocol());
    }

    @Test
    void testWithComplexURL() throws Exception {
        // Arrange
        URL complexUrl = new URL("https://example.com:8443/api/v1/users?id=123&filter=active#section");

        // Act
        TrafficEntry entry = new TrafficEntry("TEST", null, complexUrl, null, null, null);

        // Assert
        assertEquals("https", entry.url.getProtocol());
        assertEquals("example.com", entry.url.getHost());
        assertEquals(8443, entry.url.getPort());
        assertEquals("/api/v1/users", entry.url.getPath());
        assertEquals("id=123&filter=active", entry.url.getQuery());
        assertEquals("section", entry.url.getRef());
    }

    @Test
    void testWithDifferentFlagValues() throws Exception {
        // Arrange
        URL url = new URL("https://example.com");
        String[] flags = { "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "" };

        // Act & Assert
        for (String flag : flags) {
            TrafficEntry entry = new TrafficEntry(flag, null, url, null, null, null);
            assertEquals(flag, entry.flag);
        }
    }

    @Test
    void testWithLongEvidenceString() throws Exception {
        // Arrange
        URL url = new URL("https://example.com");
        String longEvidence = "A".repeat(10000); // 10KB evidence string

        // Act
        TrafficEntry entry = new TrafficEntry("TEST", null, url, null, longEvidence, null);

        // Assert
        assertEquals(10000, entry.evidence.length());
        assertEquals(longEvidence, entry.evidence);
    }

    @Test
    void testWithTrafficInstanceContainingFlags() throws Exception {
        // Arrange
        URL url = new URL("https://example.com");
        TrafficInstance instance = new TrafficInstance();
        instance.setXSS(true);
        instance.setUnencrypted(true);
        instance.setBase64(true);

        // Act
        TrafficEntry entry = new TrafficEntry("XSS", null, url, instance, null, null);

        // Assert
        assertTrue(entry.affectedInstancesList.isXSS());
        assertTrue(entry.affectedInstancesList.isUnencrypted());
        assertTrue(entry.affectedInstancesList.isBase64());
    }
}
