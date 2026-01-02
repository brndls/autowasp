package autowasp.logger.instancestable;

import autowasp.http.HTTPRequestResponse;
import org.junit.jupiter.api.Test;
import java.net.MalformedURLException;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class InstanceEntryTest {

    @Test
    void testConstructorWithWrapper() throws MalformedURLException {
        URL url = java.net.URI.create("http://example.com").toURL();
        HTTPRequestResponse mockWrapper = mock(HTTPRequestResponse.class);

        InstanceEntry entry = new InstanceEntry(url, "Certain", "High", mockWrapper);

        assertEquals("http://example.com", entry.getUrl());
        assertEquals("Certain", entry.getConfidence());
        assertEquals("High", entry.getSeverity());
        assertEquals(mockWrapper, entry.getRequestResponse());
        assertNotNull(entry.getRequestResponse());
    }

    @Test
    void testConstructorWithMontoya() throws MalformedURLException {
        URL url = java.net.URI.create("https://example.com").toURL();

        // Pass null to avoid triggering the HTTPRequestResponse conversion logic
        // which requires deep mocking of request()/response()/httpService() etc.
        // We are testing InstanceEntry logic here, not the Wrapper logic (tested
        // elsewhere).
        InstanceEntry entry = new InstanceEntry(url, "Tentative", "Low",
                (burp.api.montoya.http.message.HttpRequestResponse) null);

        assertEquals("https://example.com", entry.getUrl());
        assertNull(entry.getRequestResponse());
    }

    @Test
    void testSetters() throws MalformedURLException {
        URL url = java.net.URI.create("http://example.com").toURL();
        InstanceEntry entry = new InstanceEntry(url, "Tentative", "Low", (HTTPRequestResponse) null);

        entry.setConfidence("Firm");
        assertEquals("Firm", entry.getConfidence());

        entry.setSeverity("Medium");
        assertEquals("Medium", entry.getSeverity());
    }

    @Test
    void testNullUrl() {
        InstanceEntry entry = new InstanceEntry(null, "C", "S", (HTTPRequestResponse) null);
        assertEquals("", entry.getUrl());
    }
}
