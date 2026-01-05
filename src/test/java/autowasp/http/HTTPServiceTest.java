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

package autowasp.http;

import burp.api.montoya.http.HttpService;
import org.junit.jupiter.api.Test;

import java.io.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class HTTPServiceTest {

    @Test
    void testManualConstructor() {
        HTTPService service = new HTTPService("example.com", 8080, true);

        assertEquals("example.com", service.getHost());
        assertEquals(8080, service.getPort());
        assertTrue(service.isSecure());
        assertEquals("https", service.getProtocol());
    }

    @Test
    void testMontoyaConstructor() {
        // Mock the Montoya HttpService
        HttpService mockService = mock(HttpService.class);
        when(mockService.host()).thenReturn("api.example.com");
        when(mockService.port()).thenReturn(443);
        when(mockService.secure()).thenReturn(true);

        HTTPService service = new HTTPService(mockService);

        assertEquals("api.example.com", service.getHost());
        assertEquals(443, service.getPort());
        assertTrue(service.isSecure());
        assertEquals("https", service.getProtocol());
    }

    @Test
    void testInsecureProtocol() {
        HTTPService service = new HTTPService("localhost", 80, false);

        assertEquals("http", service.getProtocol());
        assertFalse(service.isSecure());
    }

    @Test
    void testToString() {
        HTTPService service = new HTTPService("test.com", 8443, true);
        assertEquals("https://test.com:8443", service.toString());

        HTTPService insecureService = new HTTPService("test.com", 80, false);
        assertEquals("http://test.com:80", insecureService.toString());
    }

    @Test
    void testNullHostHandling() {
        HTTPService service = new HTTPService(null, 80, false);
        assertEquals("", service.getHost());
    }

    // Additional tests for comprehensive coverage

    @Test
    void testEqualsWithSameObject() {
        HTTPService service = new HTTPService("example.com", 443, true);
        assertEquals(service, service);
    }

    @Test
    void testEqualsWithEqualObjects() {
        HTTPService service1 = new HTTPService("example.com", 443, true);
        HTTPService service2 = new HTTPService("example.com", 443, true);
        assertEquals(service1, service2);
    }

    @Test
    void testEqualsWithDifferentHost() {
        HTTPService service1 = new HTTPService("example.com", 443, true);
        HTTPService service2 = new HTTPService("different.com", 443, true);
        assertNotEquals(service1, service2);
    }

    @Test
    void testEqualsWithDifferentPort() {
        HTTPService service1 = new HTTPService("example.com", 443, true);
        HTTPService service2 = new HTTPService("example.com", 8443, true);
        assertNotEquals(service1, service2);
    }

    @Test
    void testEqualsWithDifferentSecureFlag() {
        HTTPService service1 = new HTTPService("example.com", 80, true);
        HTTPService service2 = new HTTPService("example.com", 80, false);
        assertNotEquals(service1, service2);
    }

    @Test
    void testEqualsWithNull() {
        HTTPService service = new HTTPService("example.com", 443, true);
        assertNotEquals(null, service);
    }

    @Test
    void testEqualsWithDifferentClass() {
        HTTPService service = new HTTPService("example.com", 443, true);
        assertNotEquals("not an HTTPService", service);
    }

    @Test
    void testHashCodeConsistency() {
        HTTPService service = new HTTPService("example.com", 443, true);
        int hash1 = service.hashCode();
        int hash2 = service.hashCode();
        assertEquals(hash1, hash2);
    }

    @Test
    void testHashCodeEqualityContract() {
        HTTPService service1 = new HTTPService("example.com", 443, true);
        HTTPService service2 = new HTTPService("example.com", 443, true);
        assertEquals(service1.hashCode(), service2.hashCode());
    }

    @Test
    void testHashCodeWithNullHost() {
        HTTPService service1 = new HTTPService(null, 80, false);
        HTTPService service2 = new HTTPService(null, 80, false);
        assertEquals(service1.hashCode(), service2.hashCode());
    }

    @Test
    void testStandardHTTPSPort() {
        HTTPService service = new HTTPService("secure.example.com", 443, true);
        assertEquals("https://secure.example.com:443", service.toString());
    }

    @Test
    void testStandardHTTPPort() {
        HTTPService service = new HTTPService("example.com", 80, false);
        assertEquals("http://example.com:80", service.toString());
    }

    @Test
    void testNonStandardPorts() {
        HTTPService service1 = new HTTPService("example.com", 8080, false);
        assertEquals("http://example.com:8080", service1.toString());

        HTTPService service2 = new HTTPService("example.com", 8443, true);
        assertEquals("https://example.com:8443", service2.toString());
    }

    @Test
    void testMontoyaConstructorWithInsecureService() {
        HttpService mockService = mock(HttpService.class);
        when(mockService.host()).thenReturn("insecure.example.com");
        when(mockService.port()).thenReturn(8080);
        when(mockService.secure()).thenReturn(false);

        HTTPService service = new HTTPService(mockService);

        assertEquals("insecure.example.com", service.getHost());
        assertEquals(8080, service.getPort());
        assertFalse(service.isSecure());
        assertEquals("http", service.getProtocol());
    }

    @Test
    void testMontoyaConstructorWithNullHost() {
        HttpService mockService = mock(HttpService.class);
        when(mockService.host()).thenReturn(null);
        when(mockService.port()).thenReturn(80);
        when(mockService.secure()).thenReturn(false);

        HTTPService service = new HTTPService(mockService);

        assertEquals("", service.getHost());
    }

    @Test
    void testSerialization() throws IOException, ClassNotFoundException {
        HTTPService original = new HTTPService("example.com", 443, true);

        // Serialize
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(original);
        oos.close();

        // Deserialize
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        HTTPService deserialized = (HTTPService) ois.readObject();
        ois.close();

        // Verify
        assertEquals(original, deserialized);
        assertEquals(original.getHost(), deserialized.getHost());
        assertEquals(original.getPort(), deserialized.getPort());
        assertEquals(original.isSecure(), deserialized.isSecure());
    }

    @Test
    void testSerializationWithNullHost() throws IOException, ClassNotFoundException {
        HTTPService original = new HTTPService(null, 80, false);

        // Serialize
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(original);
        oos.close();

        // Deserialize
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        HTTPService deserialized = (HTTPService) ois.readObject();
        ois.close();

        // Verify
        assertEquals(original, deserialized);
        assertEquals("", deserialized.getHost());
    }

    @Test
    void testToStringWithNullHost() {
        HTTPService service = new HTTPService(null, 443, true);
        assertEquals("https://:443", service.toString());
    }

    @Test
    void testPortBoundaries() {
        // Test minimum port
        HTTPService service1 = new HTTPService("example.com", 1, true);
        assertEquals(1, service1.getPort());

        // Test maximum port
        HTTPService service2 = new HTTPService("example.com", 65535, true);
        assertEquals(65535, service2.getPort());
    }

    @Test
    void testIPv4Address() {
        HTTPService service = new HTTPService("192.168.1.1", 8080, false);
        assertEquals("192.168.1.1", service.getHost());
        assertEquals("http://192.168.1.1:8080", service.toString());
    }

    @Test
    void testIPv6Address() {
        HTTPService service = new HTTPService("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 443, true);
        assertEquals("2001:0db8:85a3:0000:0000:8a2e:0370:7334", service.getHost());
    }

    @Test
    void testLocalhostVariants() {
        HTTPService service1 = new HTTPService("localhost", 8080, false);
        assertEquals("localhost", service1.getHost());

        HTTPService service2 = new HTTPService("127.0.0.1", 8080, false);
        assertEquals("127.0.0.1", service2.getHost());
    }
}
