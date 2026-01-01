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
