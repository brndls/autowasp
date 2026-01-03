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
}
