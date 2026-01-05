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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link InstanceState}.
 * Tests record equality, hashCode, and toString for persistence DTO.
 */
class InstanceStateTest {

        @Test
        void testRecordConstructor() {
                // Arrange
                byte[] request = "GET / HTTP/1.1".getBytes();
                byte[] response = "HTTP/1.1 200 OK".getBytes();

                // Act
                InstanceState state = new InstanceState(
                                "https://example.com/test",
                                "CERTAIN",
                                "HIGH",
                                request,
                                response,
                                "example.com",
                                443,
                                true);

                // Assert
                assertEquals("https://example.com/test", state.url());
                assertEquals("CERTAIN", state.confidence());
                assertEquals("HIGH", state.severity());
                assertArrayEquals(request, state.requestBytes());
                assertArrayEquals(response, state.responseBytes());
                assertEquals("example.com", state.host());
                assertEquals(443, state.port());
                assertTrue(state.secure());
        }

        @Test
        void testEqualsWithSameObject() {
                // Arrange
                InstanceState state = new InstanceState(
                                "https://example.com", "CERTAIN", "HIGH",
                                new byte[] { 1, 2, 3 }, new byte[] { 4, 5, 6 },
                                "example.com", 443, true);

                // Assert
                assertEquals(state, state);
        }

        @Test
        void testEqualsWithEqualObjects() {
                // Arrange
                byte[] request = new byte[] { 1, 2, 3 };
                byte[] response = new byte[] { 4, 5, 6 };

                InstanceState state1 = new InstanceState(
                                "https://example.com", "CERTAIN", "HIGH",
                                request, response, "example.com", 443, true);

                InstanceState state2 = new InstanceState(
                                "https://example.com", "CERTAIN", "HIGH",
                                request, response, "example.com", 443, true);

                // Assert
                assertEquals(state1, state2);
        }

        @Test
        void testEqualsWithDifferentUrl() {
                // Arrange
                InstanceState state1 = new InstanceState(
                                "https://example.com/path1", "CERTAIN", "HIGH",
                                new byte[] { 1 }, new byte[] { 2 }, "example.com", 443, true);

                InstanceState state2 = new InstanceState(
                                "https://example.com/path2", "CERTAIN", "HIGH",
                                new byte[] { 1 }, new byte[] { 2 }, "example.com", 443, true);

                // Assert
                assertNotEquals(state1, state2);
        }

        @Test
        void testEqualsWithDifferentRequestBytes() {
                // Arrange
                InstanceState state1 = new InstanceState(
                                "https://example.com", "CERTAIN", "HIGH",
                                new byte[] { 1, 2, 3 }, new byte[] { 4 }, "example.com", 443, true);

                InstanceState state2 = new InstanceState(
                                "https://example.com", "CERTAIN", "HIGH",
                                new byte[] { 1, 2, 4 }, new byte[] { 4 }, "example.com", 443, true);

                // Assert
                assertNotEquals(state1, state2);
        }

        @Test
        void testEqualsWithDifferentResponseBytes() {
                // Arrange
                InstanceState state1 = new InstanceState(
                                "https://example.com", "CERTAIN", "HIGH",
                                new byte[] { 1 }, new byte[] { 2, 3 }, "example.com", 443, true);

                InstanceState state2 = new InstanceState(
                                "https://example.com", "CERTAIN", "HIGH",
                                new byte[] { 1 }, new byte[] { 2, 4 }, "example.com", 443, true);

                // Assert
                assertNotEquals(state1, state2);
        }

        @Test
        void testEqualsWithDifferentPort() {
                // Arrange
                InstanceState state1 = new InstanceState(
                                "https://example.com", "CERTAIN", "HIGH",
                                new byte[] { 1 }, new byte[] { 2 }, "example.com", 443, true);

                InstanceState state2 = new InstanceState(
                                "https://example.com", "CERTAIN", "HIGH",
                                new byte[] { 1 }, new byte[] { 2 }, "example.com", 8443, true);

                // Assert
                assertNotEquals(state1, state2);
        }

        @Test
        void testEqualsWithDifferentSecureFlag() {
                // Arrange
                InstanceState state1 = new InstanceState(
                                "http://example.com", "CERTAIN", "HIGH",
                                new byte[] { 1 }, new byte[] { 2 }, "example.com", 80, true);

                InstanceState state2 = new InstanceState(
                                "http://example.com", "CERTAIN", "HIGH",
                                new byte[] { 1 }, new byte[] { 2 }, "example.com", 80, false);

                // Assert
                assertNotEquals(state1, state2);
        }

        @Test
        void testEqualsWithNull() {
                // Arrange
                InstanceState state = new InstanceState(
                                "https://example.com", "CERTAIN", "HIGH",
                                new byte[] { 1 }, new byte[] { 2 }, "example.com", 443, true);

                // Assert
                assertNotEquals(null, state);
        }

        @Test
        void testEqualsWithDifferentClass() {
                // Arrange
                InstanceState state = new InstanceState(
                                "https://example.com", "CERTAIN", "HIGH",
                                new byte[] { 1 }, new byte[] { 2 }, "example.com", 443, true);

                // Assert
                assertNotEquals("not an InstanceState", state);
        }

        @Test
        void testHashCodeConsistency() {
                // Arrange
                InstanceState state = new InstanceState(
                                "https://example.com", "CERTAIN", "HIGH",
                                new byte[] { 1, 2, 3 }, new byte[] { 4, 5, 6 },
                                "example.com", 443, true);

                // Act
                int hash1 = state.hashCode();
                int hash2 = state.hashCode();

                // Assert
                assertEquals(hash1, hash2);
        }

        @Test
        void testHashCodeEqualityContract() {
                // Arrange
                byte[] request = new byte[] { 1, 2, 3 };
                byte[] response = new byte[] { 4, 5, 6 };

                InstanceState state1 = new InstanceState(
                                "https://example.com", "CERTAIN", "HIGH",
                                request, response, "example.com", 443, true);

                InstanceState state2 = new InstanceState(
                                "https://example.com", "CERTAIN", "HIGH",
                                request, response, "example.com", 443, true);

                // Assert
                assertEquals(state1.hashCode(), state2.hashCode());
        }

        @Test
        void testToString() {
                // Arrange
                InstanceState state = new InstanceState(
                                "https://example.com", "FIRM", "MEDIUM",
                                new byte[] { 1, 2 }, new byte[] { 3, 4 },
                                "example.com", 443, true);

                // Act
                String result = state.toString();

                // Assert
                assertTrue(result.contains("InstanceState"));
                assertTrue(result.contains("url=https://example.com"));
                assertTrue(result.contains("confidence=FIRM"));
                assertTrue(result.contains("severity=MEDIUM"));
                assertTrue(result.contains("host=example.com"));
                assertTrue(result.contains("port=443"));
                assertTrue(result.contains("secure=true"));
        }

        @Test
        void testWithNullUrl() {
                // Arrange & Act
                InstanceState state = new InstanceState(
                                null, "TENTATIVE", "LOW",
                                new byte[] { 1 }, new byte[] { 2 }, "example.com", 80, false);

                // Assert
                assertNull(state.url());
                assertEquals("TENTATIVE", state.confidence());
        }

        @Test
        void testWithNullByteArrays() {
                // Arrange & Act
                InstanceState state = new InstanceState(
                                "https://example.com", "CERTAIN", "HIGH",
                                null, null, "example.com", 443, true);

                // Assert
                assertNull(state.requestBytes());
                assertNull(state.responseBytes());
        }

        @Test
        void testWithEmptyByteArrays() {
                // Arrange
                byte[] emptyRequest = new byte[0];
                byte[] emptyResponse = new byte[0];

                // Act
                InstanceState state = new InstanceState(
                                "https://example.com", "CERTAIN", "HIGH",
                                emptyRequest, emptyResponse, "example.com", 443, true);

                // Assert
                assertArrayEquals(new byte[0], state.requestBytes());
                assertArrayEquals(new byte[0], state.responseBytes());
        }

        @Test
        void testWithLargeByteArrays() {
                // Arrange
                byte[] largeRequest = new byte[10000];
                byte[] largeResponse = new byte[10000];
                for (int i = 0; i < 10000; i++) {
                        largeRequest[i] = (byte) (i % 256);
                        largeResponse[i] = (byte) ((i + 1) % 256);
                }

                // Act
                InstanceState state = new InstanceState(
                                "https://example.com", "CERTAIN", "HIGH",
                                largeRequest, largeResponse, "example.com", 443, true);

                // Assert
                assertArrayEquals(largeRequest, state.requestBytes());
                assertArrayEquals(largeResponse, state.responseBytes());
        }

        @Test
        void testDifferentConfidenceLevels() {
                // Arrange
                String[] confidenceLevels = { "CERTAIN", "FIRM", "TENTATIVE" };

                // Act & Assert
                for (String confidence : confidenceLevels) {
                        InstanceState state = new InstanceState(
                                        "https://example.com", confidence, "HIGH",
                                        new byte[] { 1 }, new byte[] { 2 }, "example.com", 443, true);
                        assertEquals(confidence, state.confidence());
                }
        }

        @Test
        void testDifferentSeverityLevels() {
                // Arrange
                String[] severityLevels = { "HIGH", "MEDIUM", "LOW", "INFO" };

                // Act & Assert
                for (String severity : severityLevels) {
                        InstanceState state = new InstanceState(
                                        "https://example.com", "CERTAIN", severity,
                                        new byte[] { 1 }, new byte[] { 2 }, "example.com", 443, true);
                        assertEquals(severity, state.severity());
                }
        }

        @Test
        void testPortBoundaries() {
                // Test minimum port
                InstanceState state1 = new InstanceState(
                                "https://example.com", "CERTAIN", "HIGH",
                                new byte[] { 1 }, new byte[] { 2 }, "example.com", 1, true);
                assertEquals(1, state1.port());

                // Test maximum port
                InstanceState state2 = new InstanceState(
                                "https://example.com", "CERTAIN", "HIGH",
                                new byte[] { 1 }, new byte[] { 2 }, "example.com", 65535, true);
                assertEquals(65535, state2.port());
        }

        @Test
        void testHttpAndHttpsVariants() {
                // HTTP
                InstanceState httpState = new InstanceState(
                                "http://example.com", "CERTAIN", "HIGH",
                                new byte[] { 1 }, new byte[] { 2 }, "example.com", 80, false);
                assertFalse(httpState.secure());
                assertEquals(80, httpState.port());

                // HTTPS
                InstanceState httpsState = new InstanceState(
                                "https://example.com", "CERTAIN", "HIGH",
                                new byte[] { 1 }, new byte[] { 2 }, "example.com", 443, true);
                assertTrue(httpsState.secure());
                assertEquals(443, httpsState.port());
        }
}
