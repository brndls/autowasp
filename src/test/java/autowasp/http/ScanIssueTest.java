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

    // Additional comprehensive tests

    @Test
    void testNullDetailHandling() {
        AuditIssue mockIssue = mock(AuditIssue.class);
        when(mockIssue.baseUrl()).thenReturn("http://example.com");
        when(mockIssue.detail()).thenReturn(null);

        ScanIssue scanIssue = new ScanIssue(mockIssue);
        assertEquals("", scanIssue.getIssueDetail());
    }

    @Test
    void testNullRemediationHandling() {
        AuditIssue mockIssue = mock(AuditIssue.class);
        when(mockIssue.baseUrl()).thenReturn("http://example.com");
        when(mockIssue.remediation()).thenReturn(null);

        ScanIssue scanIssue = new ScanIssue(mockIssue);
        assertEquals("", scanIssue.getRemediationDetail());
    }

    @Test
    void testNullBackgroundInDefinition() {
        AuditIssue mockIssue = mock(AuditIssue.class);
        AuditIssueDefinition mockDef = mock(AuditIssueDefinition.class);

        when(mockIssue.baseUrl()).thenReturn("http://example.com");
        when(mockIssue.definition()).thenReturn(mockDef);
        when(mockDef.background()).thenReturn(null);
        when(mockDef.remediation()).thenReturn(null);

        ScanIssue scanIssue = new ScanIssue(mockIssue);
        assertEquals("", scanIssue.getIssueBackground());
        assertEquals("", scanIssue.getRemediationBackground());
    }

    @Test
    void testNullRequestResponsesList() {
        AuditIssue mockIssue = mock(AuditIssue.class);
        when(mockIssue.baseUrl()).thenReturn("http://example.com");
        when(mockIssue.requestResponses()).thenReturn(null);

        ScanIssue scanIssue = new ScanIssue(mockIssue);
        assertNotNull(scanIssue.getHttpMessages());
        assertEquals(0, scanIssue.getHttpMessages().length);
    }

    @Test
    void testEmptyRequestResponsesList() {
        AuditIssue mockIssue = mock(AuditIssue.class);
        when(mockIssue.baseUrl()).thenReturn("http://example.com");
        when(mockIssue.requestResponses()).thenReturn(Collections.emptyList());

        ScanIssue scanIssue = new ScanIssue(mockIssue);
        assertNotNull(scanIssue.getHttpMessages());
        assertEquals(0, scanIssue.getHttpMessages().length);
    }

    @Test
    void testMultipleRequestResponses() {
        AuditIssue mockIssue = mock(AuditIssue.class);
        HttpRequestResponse mockRR1 = createMockRequestResponse();
        HttpRequestResponse mockRR2 = createMockRequestResponse();

        when(mockIssue.baseUrl()).thenReturn("http://example.com");
        when(mockIssue.requestResponses()).thenReturn(java.util.List.of(mockRR1, mockRR2));

        ScanIssue scanIssue = new ScanIssue(mockIssue);
        assertEquals(2, scanIssue.getHttpMessages().length);
    }

    @Test
    void testEqualsWithSameObject() {
        AuditIssue mockIssue = mock(AuditIssue.class);
        when(mockIssue.baseUrl()).thenReturn("http://example.com");

        ScanIssue scanIssue = new ScanIssue(mockIssue);
        assertEquals(scanIssue, scanIssue);
    }

    @Test
    void testEqualsWithEqualObjects() {
        AuditIssue mockIssue = mock(AuditIssue.class);
        when(mockIssue.baseUrl()).thenReturn("http://example.com");
        when(mockIssue.name()).thenReturn("XSS");
        when(mockIssue.detail()).thenReturn("Detail");

        ScanIssue scanIssue1 = new ScanIssue(mockIssue);
        ScanIssue scanIssue2 = new ScanIssue(mockIssue);

        assertEquals(scanIssue1, scanIssue2);
    }

    @Test
    void testEqualsWithDifferentName() {
        AuditIssue mockIssue1 = mock(AuditIssue.class);
        AuditIssue mockIssue2 = mock(AuditIssue.class);

        when(mockIssue1.baseUrl()).thenReturn("http://example.com");
        when(mockIssue1.name()).thenReturn("XSS");

        when(mockIssue2.baseUrl()).thenReturn("http://example.com");
        when(mockIssue2.name()).thenReturn("SQLi");

        ScanIssue scanIssue1 = new ScanIssue(mockIssue1);
        ScanIssue scanIssue2 = new ScanIssue(mockIssue2);

        assertNotEquals(scanIssue1, scanIssue2);
    }

    @Test
    void testEqualsWithNull() {
        AuditIssue mockIssue = mock(AuditIssue.class);
        when(mockIssue.baseUrl()).thenReturn("http://example.com");

        ScanIssue scanIssue = new ScanIssue(mockIssue);
        assertNotEquals(scanIssue, null);
    }

    @Test
    void testEqualsWithDifferentClass() {
        AuditIssue mockIssue = mock(AuditIssue.class);
        when(mockIssue.baseUrl()).thenReturn("http://example.com");

        ScanIssue scanIssue = new ScanIssue(mockIssue);
        assertNotEquals(scanIssue, "not a ScanIssue");
    }

    @Test
    void testHashCodeConsistency() {
        AuditIssue mockIssue = mock(AuditIssue.class);
        when(mockIssue.baseUrl()).thenReturn("http://example.com");
        when(mockIssue.name()).thenReturn("XSS");

        ScanIssue scanIssue = new ScanIssue(mockIssue);
        int hash1 = scanIssue.hashCode();
        int hash2 = scanIssue.hashCode();

        assertEquals(hash1, hash2);
    }

    @Test
    void testHashCodeEqualityContract() {
        AuditIssue mockIssue = mock(AuditIssue.class);
        when(mockIssue.baseUrl()).thenReturn("http://example.com");
        when(mockIssue.name()).thenReturn("XSS");

        ScanIssue scanIssue1 = new ScanIssue(mockIssue);
        ScanIssue scanIssue2 = new ScanIssue(mockIssue);

        assertEquals(scanIssue1.hashCode(), scanIssue2.hashCode());
    }

    @Test
    void testToString() {
        AuditIssue mockIssue = mock(AuditIssue.class);
        when(mockIssue.baseUrl()).thenReturn("http://example.com");
        when(mockIssue.name()).thenReturn("XSS");
        when(mockIssue.detail()).thenReturn("Detail");
        when(mockIssue.severity()).thenReturn(AuditIssueSeverity.HIGH);
        when(mockIssue.confidence()).thenReturn(AuditIssueConfidence.CERTAIN);

        ScanIssue scanIssue = new ScanIssue(mockIssue);
        String result = scanIssue.toString();

        assertTrue(result.contains("ScanIssue"));
        assertTrue(result.contains("XSS"));
        assertTrue(result.contains("High"));
        assertTrue(result.contains("Certain"));
    }

    @Test
    void testAllSeverityLevels() {
        AuditIssue mockIssue = mock(AuditIssue.class);
        when(mockIssue.baseUrl()).thenReturn("http://example.com");

        // HIGH
        when(mockIssue.severity()).thenReturn(AuditIssueSeverity.HIGH);
        assertEquals("High", new ScanIssue(mockIssue).getSeverity());

        // MEDIUM
        when(mockIssue.severity()).thenReturn(AuditIssueSeverity.MEDIUM);
        assertEquals("Medium", new ScanIssue(mockIssue).getSeverity());

        // LOW
        when(mockIssue.severity()).thenReturn(AuditIssueSeverity.LOW);
        assertEquals("Low", new ScanIssue(mockIssue).getSeverity());

        // INFORMATION
        when(mockIssue.severity()).thenReturn(AuditIssueSeverity.INFORMATION);
        assertEquals("Information", new ScanIssue(mockIssue).getSeverity());
    }

    @Test
    void testAllConfidenceLevels() {
        AuditIssue mockIssue = mock(AuditIssue.class);
        when(mockIssue.baseUrl()).thenReturn("http://example.com");

        // CERTAIN
        when(mockIssue.confidence()).thenReturn(AuditIssueConfidence.CERTAIN);
        assertEquals("Certain", new ScanIssue(mockIssue).getConfidence());

        // FIRM
        when(mockIssue.confidence()).thenReturn(AuditIssueConfidence.FIRM);
        assertEquals("Firm", new ScanIssue(mockIssue).getConfidence());

        // TENTATIVE
        when(mockIssue.confidence()).thenReturn(AuditIssueConfidence.TENTATIVE);
        assertEquals("Tentative", new ScanIssue(mockIssue).getConfidence());
    }

    @Test
    void testComplexUrlWithPath() {
        AuditIssue mockIssue = mock(AuditIssue.class);
        when(mockIssue.baseUrl()).thenReturn("https://example.com:8443/api/v1/users?id=123");

        ScanIssue scanIssue = new ScanIssue(mockIssue);
        assertEquals("https://example.com:8443/api/v1/users?id=123", scanIssue.getUrl().toString());
        assertEquals(8443, scanIssue.getHttpService().getPort());
        assertTrue(scanIssue.getHttpService().isSecure());
    }

    @Test
    void testIPv4Address() {
        AuditIssue mockIssue = mock(AuditIssue.class);
        when(mockIssue.baseUrl()).thenReturn("http://192.168.1.1:8080");

        ScanIssue scanIssue = new ScanIssue(mockIssue);
        assertEquals("192.168.1.1", scanIssue.getHttpService().getHost());
        assertEquals(8080, scanIssue.getHttpService().getPort());
    }

    // Helper method
    private HttpRequestResponse createMockRequestResponse() {
        HttpRequestResponse mockRR = mock(HttpRequestResponse.class);
        HttpRequest mockRequest = mock(HttpRequest.class);
        HttpResponse mockResponse = mock(HttpResponse.class);
        ByteArray mockByteArray = mock(ByteArray.class);
        burp.api.montoya.http.HttpService mockHttpService = mock(burp.api.montoya.http.HttpService.class);

        when(mockByteArray.getBytes()).thenReturn(new byte[] {});
        when(mockRequest.toByteArray()).thenReturn(mockByteArray);
        when(mockResponse.toByteArray()).thenReturn(mockByteArray);
        when(mockHttpService.host()).thenReturn("example.com");
        when(mockHttpService.secure()).thenReturn(true);
        when(mockRequest.httpService()).thenReturn(mockHttpService);
        when(mockRR.request()).thenReturn(mockRequest);
        when(mockRR.response()).thenReturn(mockResponse);

        return mockRR;
    }
}
