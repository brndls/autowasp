package autowasp.http;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import org.junit.jupiter.api.Test;
import java.util.Collections;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ScanIssueTest {

    @Test
    void testScanIssueConstruction() {
        // Mock AuditIssue and its dependencies
        AuditIssue mockIssue = mock(AuditIssue.class);
        AuditIssueDefinition mockDef = mock(AuditIssueDefinition.class);
        HttpRequestResponse mockRR = mock(HttpRequestResponse.class);

        // Deep mock for HttpRequestResponse to prevent NPE in HTTPRequestResponse
        // constructor
        HttpRequest mockRequest = mock(HttpRequest.class);
        HttpResponse mockResponse = mock(HttpResponse.class);
        ByteArray mockByteArray = mock(ByteArray.class);
        when(mockByteArray.getBytes()).thenReturn(new byte[] {});
        when(mockRequest.toByteArray()).thenReturn(mockByteArray);
        when(mockResponse.toByteArray()).thenReturn(mockByteArray);

        // Mock HttpService for the request to avoid NPE in HTTPService constructor
        burp.api.montoya.http.HttpService mockHttpService = mock(burp.api.montoya.http.HttpService.class);
        when(mockHttpService.host()).thenReturn("example.com");
        when(mockHttpService.secure()).thenReturn(true);
        when(mockRequest.httpService()).thenReturn(mockHttpService);

        when(mockRR.request()).thenReturn(mockRequest);
        when(mockRR.response()).thenReturn(mockResponse);

        // Setup mock behavior
        when(mockIssue.name()).thenReturn("SQL Injection");
        when(mockIssue.detail()).thenReturn("Detail about SQLi");
        when(mockIssue.severity()).thenReturn(AuditIssueSeverity.HIGH);
        when(mockIssue.confidence()).thenReturn(AuditIssueConfidence.CERTAIN);
        when(mockIssue.baseUrl()).thenReturn("https://example.com");
        when(mockIssue.remediation()).thenReturn("Fix it.");

        // Mock Definition
        when(mockIssue.definition()).thenReturn(mockDef);
        when(mockDef.background()).thenReturn("Background info");
        when(mockDef.remediation()).thenReturn("Remediation info");

        // Mock RequestResponse list
        when(mockIssue.requestResponses()).thenReturn(Collections.singletonList(mockRR));

        ScanIssue scanIssue = new ScanIssue(mockIssue);

        assertEquals("SQL Injection", scanIssue.getIssueName());
        assertEquals("Detail about SQLi", scanIssue.getIssueDetail());
        assertEquals("High", scanIssue.getSeverity());
        assertEquals("Certain", scanIssue.getConfidence());
        assertEquals("Background info", scanIssue.getIssueBackground());
        assertEquals("Remediation info", scanIssue.getRemediationBackground());
        assertEquals("Fix it.", scanIssue.getRemediationDetail());
        assertEquals("https://example.com", scanIssue.getUrl().toString());
        assertEquals(1, scanIssue.getHttpMessages().length);
    }

    @Test
    void testSeverityConversion() {
        AuditIssue mockIssue = mock(AuditIssue.class);
        when(mockIssue.baseUrl()).thenReturn("http://example.com"); // Prevent NPE

        when(mockIssue.severity()).thenReturn(AuditIssueSeverity.MEDIUM);
        assertEquals("Medium", new ScanIssue(mockIssue).getSeverity());

        when(mockIssue.severity()).thenReturn(AuditIssueSeverity.LOW);
        assertEquals("Low", new ScanIssue(mockIssue).getSeverity());

        when(mockIssue.severity()).thenReturn(AuditIssueSeverity.INFORMATION);
        assertEquals("Information", new ScanIssue(mockIssue).getSeverity());

        when(mockIssue.severity()).thenReturn(null);
        assertEquals("Information", new ScanIssue(mockIssue).getSeverity());
    }

    @Test
    void testConfidenceConversion() {
        AuditIssue mockIssue = mock(AuditIssue.class);
        when(mockIssue.baseUrl()).thenReturn("http://example.com");

        when(mockIssue.confidence()).thenReturn(AuditIssueConfidence.FIRM);
        assertEquals("Firm", new ScanIssue(mockIssue).getConfidence());

        when(mockIssue.confidence()).thenReturn(AuditIssueConfidence.TENTATIVE);
        assertEquals("Tentative", new ScanIssue(mockIssue).getConfidence());

        when(mockIssue.confidence()).thenReturn(null);
        assertEquals("Tentative", new ScanIssue(mockIssue).getConfidence());
    }

    @Test
    void testNullDefinitionHandling() {
        AuditIssue mockIssue = mock(AuditIssue.class);
        when(mockIssue.baseUrl()).thenReturn("http://example.com");
        when(mockIssue.definition()).thenReturn(null);

        ScanIssue scanIssue = new ScanIssue(mockIssue);
        assertEquals("", scanIssue.getIssueBackground());
        assertEquals("", scanIssue.getRemediationBackground());
    }

    @Test
    void testUrlParsing() {
        AuditIssue mockIssue = mock(AuditIssue.class);

        // Test with port
        when(mockIssue.baseUrl()).thenReturn("https://example.com:8443");
        ScanIssue s1 = new ScanIssue(mockIssue);
        assertEquals(8443, s1.getHttpService().getPort());
        assertTrue(s1.getHttpService().isSecure());

        // Test default http port
        when(mockIssue.baseUrl()).thenReturn("http://example.com");
        ScanIssue s2 = new ScanIssue(mockIssue);
        assertEquals(80, s2.getHttpService().getPort());
        assertFalse(s2.getHttpService().isSecure());

        // Test default https port
        when(mockIssue.baseUrl()).thenReturn("https://example.com");
        ScanIssue s3 = new ScanIssue(mockIssue);
        assertEquals(443, s3.getHttpService().getPort());

        // Test invalid URL (should result in null url and null httpService)
        when(mockIssue.baseUrl()).thenReturn("invalid-url");
        ScanIssue s4 = new ScanIssue(mockIssue);
        assertNull(s4.getUrl());
        assertNull(s4.getHttpService());
    }
}
