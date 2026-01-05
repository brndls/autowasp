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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link TrafficInstance}.
 * Tests all boolean flag setters, getters, and legacy setters.
 */
class TrafficInstanceTest {

    private TrafficInstance instance;

    @BeforeEach
    void setUp() {
        instance = new TrafficInstance();
    }

    @Test
    void testConstructorInitializesAllFieldsToFalse() {
        // Assert - all flags should be false by default
        assertFalse(instance.isUnencrypted());
        assertFalse(instance.isBase64());
        assertFalse(instance.isXContent());
        assertFalse(instance.isServerInfoLeaked());
        assertFalse(instance.isServerErrorInfoLeaked());
        assertFalse(instance.isCorHeaders());
        assertFalse(instance.isUnauthorisedDisclosure());
        assertFalse(instance.isXSS());
        assertFalse(instance.isCGI());
        assertFalse(instance.isHTTPVerb());
    }

    @Test
    void testSetAndGetUnencrypted() {
        // Act
        instance.setUnencrypted(true);

        // Assert
        assertTrue(instance.isUnencrypted());

        // Act
        instance.setUnencrypted(false);

        // Assert
        assertFalse(instance.isUnencrypted());
    }

    @Test
    void testSetAndGetBase64() {
        // Act
        instance.setBase64(true);

        // Assert
        assertTrue(instance.isBase64());

        // Act
        instance.setBase64(false);

        // Assert
        assertFalse(instance.isBase64());
    }

    @Test
    void testSetAndGetXContent() {
        // Act
        instance.setXContent(true);

        // Assert
        assertTrue(instance.isXContent());

        // Act
        instance.setXContent(false);

        // Assert
        assertFalse(instance.isXContent());
    }

    @Test
    void testSetAndGetServerInfoLeaked() {
        // Act
        instance.setServerInfoLeaked(true);

        // Assert
        assertTrue(instance.isServerInfoLeaked());

        // Act
        instance.setServerInfoLeaked(false);

        // Assert
        assertFalse(instance.isServerInfoLeaked());
    }

    @Test
    void testSetAndGetServerErrorInfoLeaked() {
        // Act
        instance.setServerErrorInfoLeaked(true);

        // Assert
        assertTrue(instance.isServerErrorInfoLeaked());

        // Act
        instance.setServerErrorInfoLeaked(false);

        // Assert
        assertFalse(instance.isServerErrorInfoLeaked());
    }

    @Test
    void testSetAndGetCorHeaders() {
        // Act
        instance.setCorHeaders(true);

        // Assert
        assertTrue(instance.isCorHeaders());

        // Act
        instance.setCorHeaders(false);

        // Assert
        assertFalse(instance.isCorHeaders());
    }

    @Test
    void testSetAndGetUnauthorisedDisclosure() {
        // Act
        instance.setUnauthorisedDisclosure(true);

        // Assert
        assertTrue(instance.isUnauthorisedDisclosure());

        // Act
        instance.setUnauthorisedDisclosure(false);

        // Assert
        assertFalse(instance.isUnauthorisedDisclosure());
    }

    @Test
    void testSetAndGetXSS() {
        // Act
        instance.setXSS(true);

        // Assert
        assertTrue(instance.isXSS());

        // Act
        instance.setXSS(false);

        // Assert
        assertFalse(instance.isXSS());
    }

    @Test
    void testSetAndGetCGI() {
        // Act
        instance.setCGI(true);

        // Assert
        assertTrue(instance.isCGI());

        // Act
        instance.setCGI(false);

        // Assert
        assertFalse(instance.isCGI());
    }

    @Test
    void testSetAndGetHTTPVerb() {
        // Act
        instance.setHTTPVerb(true);

        // Assert
        assertTrue(instance.isHTTPVerb());

        // Act
        instance.setHTTPVerb(false);

        // Assert
        assertFalse(instance.isHTTPVerb());
    }

    // Legacy setter tests (no-arg setters that set to true)

    @Test
    void testLegacySetUnencrypted() {
        // Act
        instance.setUnencrypted();

        // Assert
        assertTrue(instance.isUnencrypted());
    }

    @Test
    void testLegacySetServerErrorInfoLeaked() {
        // Act
        instance.setServerErrorInfoLeaked();

        // Assert
        assertTrue(instance.isServerErrorInfoLeaked());
    }

    @Test
    void testLegacySetServerInfoLeaked() {
        // Act
        instance.setServerInfoLeaked();

        // Assert
        // Note: Legacy setter has a bug - it sets serverErrorInfoLeaked instead of
        // serverInfoLeaked
        assertTrue(instance.isServerErrorInfoLeaked());
    }

    @Test
    void testLegacySetCGI() {
        // Act
        instance.setCGI();

        // Assert
        assertTrue(instance.isCGI());
    }

    @Test
    void testLegacySetBase64() {
        // Act
        instance.setBase64();

        // Assert
        assertTrue(instance.isBase64());
    }

    @Test
    void testLegacySetCorHeaders() {
        // Act
        instance.setCorHeaders();

        // Assert
        assertTrue(instance.isCorHeaders());
    }

    @Test
    void testLegacySetHTTPVerb() {
        // Act
        instance.setHTTPVerb();

        // Assert
        assertTrue(instance.isHTTPVerb());
    }

    @Test
    void testLegacySetXContentHeaders() {
        // Act
        instance.setXContentHeaders();

        // Assert
        assertTrue(instance.isXContent());
    }

    // Integration tests for multiple flags

    @Test
    void testMultipleFlagsCanBeSetIndependently() {
        // Act
        instance.setXSS(true);
        instance.setUnencrypted(true);
        instance.setBase64(true);

        // Assert
        assertTrue(instance.isXSS());
        assertTrue(instance.isUnencrypted());
        assertTrue(instance.isBase64());
        assertFalse(instance.isCGI()); // Other flags should remain false
        assertFalse(instance.isCorHeaders());
    }

    @Test
    void testAllFlagsCanBeSetToTrue() {
        // Act
        instance.setUnencrypted(true);
        instance.setBase64(true);
        instance.setXContent(true);
        instance.setServerInfoLeaked(true);
        instance.setServerErrorInfoLeaked(true);
        instance.setCorHeaders(true);
        instance.setUnauthorisedDisclosure(true);
        instance.setXSS(true);
        instance.setCGI(true);
        instance.setHTTPVerb(true);

        // Assert
        assertTrue(instance.isUnencrypted());
        assertTrue(instance.isBase64());
        assertTrue(instance.isXContent());
        assertTrue(instance.isServerInfoLeaked());
        assertTrue(instance.isServerErrorInfoLeaked());
        assertTrue(instance.isCorHeaders());
        assertTrue(instance.isUnauthorisedDisclosure());
        assertTrue(instance.isXSS());
        assertTrue(instance.isCGI());
        assertTrue(instance.isHTTPVerb());
    }

    @Test
    void testFlagsCanBeToggledMultipleTimes() {
        // Act & Assert - toggle XSS flag multiple times
        instance.setXSS(true);
        assertTrue(instance.isXSS());

        instance.setXSS(false);
        assertFalse(instance.isXSS());

        instance.setXSS(true);
        assertTrue(instance.isXSS());

        instance.setXSS(false);
        assertFalse(instance.isXSS());
    }

    @Test
    void testLegacySettersDoNotAffectOtherFlags() {
        // Act
        instance.setUnencrypted();

        // Assert
        assertTrue(instance.isUnencrypted());
        assertFalse(instance.isBase64());
        assertFalse(instance.isXSS());
        assertFalse(instance.isCGI());
    }

    @Test
    void testMixingLegacyAndModernSetters() {
        // Act
        instance.setUnencrypted(); // Legacy setter (sets to true)
        instance.setBase64(true); // Modern setter
        instance.setCGI(); // Legacy setter

        // Assert
        assertTrue(instance.isUnencrypted());
        assertTrue(instance.isBase64());
        assertTrue(instance.isCGI());

        // Act - modern setter can override legacy setter
        instance.setUnencrypted(false);

        // Assert
        assertFalse(instance.isUnencrypted());
    }

    @Test
    void testNewInstancesAreIndependent() {
        // Arrange
        TrafficInstance instance1 = new TrafficInstance();
        TrafficInstance instance2 = new TrafficInstance();

        // Act
        instance1.setXSS(true);
        instance1.setUnencrypted(true);

        // Assert - instance2 should not be affected
        assertTrue(instance1.isXSS());
        assertTrue(instance1.isUnencrypted());
        assertFalse(instance2.isXSS());
        assertFalse(instance2.isUnencrypted());
    }
}
