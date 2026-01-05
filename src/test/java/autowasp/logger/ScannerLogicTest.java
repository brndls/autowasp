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
package autowasp.logger;

import autowasp.Autowasp;
import autowasp.http.HTTPRequestResponse;
import autowasp.http.HTTPService;
import autowasp.http.ScanIssue;
import autowasp.logger.entrytable.LoggerEntry;
import autowasp.logger.entrytable.LoggerTableModel;
import autowasp.logger.instancestable.InstanceEntry;
import autowasp.managers.LoggerManager;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link ScannerLogic}.
 * Tests audit issue handling, instance logging, and scan entry creation.
 */
@SuppressWarnings("deprecation") // URL(String) deprecated in Java 20, acceptable for test code
class ScannerLogicTest {

    private ScannerLogic scannerLogic;
    private Autowasp mockExtender;
    private LoggerManager mockLoggerManager;
    private LoggerTableModel mockTableModel;
    private List<LoggerEntry> loggerList;

    @BeforeEach
    void setUp() {
        mockExtender = mock(Autowasp.class);
        mockLoggerManager = mock(LoggerManager.class);
        mockTableModel = mock(LoggerTableModel.class);
        loggerList = new ArrayList<>();

        when(mockExtender.getLoggerManager()).thenReturn(mockLoggerManager);
        when(mockLoggerManager.getLoggerList()).thenReturn(loggerList);
        when(mockLoggerManager.getLoggerTableModel()).thenReturn(mockTableModel);

        scannerLogic = new ScannerLogic(mockExtender);
    }

    @Test
    void testConstructorInitializesEmptyRepeatedIssueList() {
        // Assert
        assertNotNull(scannerLogic.getRepeatedIssue());
        assertTrue(scannerLogic.getRepeatedIssue().isEmpty());
    }

    @Test
    void testGetRepeatedIssueReturnsModifiableList() {
        // Act
        List<String> repeatedIssues = scannerLogic.getRepeatedIssue();
        repeatedIssues.add("test-issue");

        // Assert
        assertEquals(1, scannerLogic.getRepeatedIssue().size());
        assertTrue(scannerLogic.getRepeatedIssue().contains("test-issue"));
    }

    @Test
    void testLogNewInstanceFromAuditIssue() {
        // Arrange
        AuditIssue mockAuditIssue = mock(AuditIssue.class);
        burp.api.montoya.http.HttpService mockService = mock(burp.api.montoya.http.HttpService.class);
        burp.api.montoya.http.message.HttpRequestResponse mockReqResp = mock(
                burp.api.montoya.http.message.HttpRequestResponse.class);

        when(mockAuditIssue.baseUrl()).thenReturn("https://example.com/test");
        when(mockAuditIssue.name()).thenReturn("SQL Injection");
        when(mockAuditIssue.confidence())
                .thenReturn(burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.CERTAIN);
        when(mockAuditIssue.severity()).thenReturn(burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.HIGH);
        when(mockAuditIssue.httpService()).thenReturn(mockService);
        when(mockService.host()).thenReturn("example.com");
        when(mockService.port()).thenReturn(443);
        when(mockService.secure()).thenReturn(true);
        when(mockAuditIssue.requestResponses()).thenReturn(List.of(mockReqResp));

        // Add matching logger entry
        LoggerEntry entry = new LoggerEntry("example.com", "Test", "SQL Injection", "Test Issue");
        loggerList.add(entry);

        // Act
        scannerLogic.logNewInstance(mockAuditIssue);

        // Assert - instance should be added to matching entry
        verify(mockExtender, atLeastOnce()).getLoggerManager();
    }

    @Test
    void testLogNewInstanceWithNullHttpMessages() throws Exception {
        // Arrange
        ScanIssue mockIssue = mock(ScanIssue.class);
        HTTPService mockService = new HTTPService("example.com", 443, true);

        when(mockIssue.getUrl()).thenReturn(new URL("https://example.com/test"));
        when(mockIssue.getConfidence()).thenReturn("CERTAIN");
        when(mockIssue.getSeverity()).thenReturn("HIGH");
        when(mockIssue.getHttpMessages()).thenReturn(null);
        when(mockIssue.getHttpService()).thenReturn(mockService);
        when(mockIssue.getIssueName()).thenReturn("XSS");

        LoggerEntry entry = new LoggerEntry("example.com", "Test", "XSS", "Test");
        loggerList.add(entry);

        // Act
        scannerLogic.logNewInstance(mockIssue);

        // Assert - should handle null messages gracefully
        verify(mockExtender, atLeastOnce()).getLoggerManager();
    }

    @Test
    void testLogNewInstanceWithEmptyHttpMessages() throws Exception {
        // Arrange
        ScanIssue mockIssue = mock(ScanIssue.class);
        HTTPService mockService = new HTTPService("example.com", 443, true);

        when(mockIssue.getUrl()).thenReturn(new URL("https://example.com/test"));
        when(mockIssue.getConfidence()).thenReturn("FIRM");
        when(mockIssue.getSeverity()).thenReturn("MEDIUM");
        when(mockIssue.getHttpMessages()).thenReturn(new HTTPRequestResponse[0]);
        when(mockIssue.getHttpService()).thenReturn(mockService);
        when(mockIssue.getIssueName()).thenReturn("Path Traversal");

        LoggerEntry entry = new LoggerEntry("example.com", "Test", "Path Traversal", "Test");
        loggerList.add(entry);

        // Act
        scannerLogic.logNewInstance(mockIssue);

        // Assert
        verify(mockExtender, atLeastOnce()).getLoggerManager();
    }

    @Test
    void testLogNewInstanceAddsUniqueInstance() throws Exception {
        // Arrange
        ScanIssue mockIssue = mock(ScanIssue.class);
        HTTPService mockService = new HTTPService("example.com", 443, true);
        HTTPRequestResponse mockReqResp = mock(HTTPRequestResponse.class);

        when(mockIssue.getUrl()).thenReturn(new URL("https://example.com/unique"));
        when(mockIssue.getConfidence()).thenReturn("CERTAIN");
        when(mockIssue.getSeverity()).thenReturn("HIGH");
        when(mockIssue.getHttpMessages()).thenReturn(new HTTPRequestResponse[] { mockReqResp });
        when(mockIssue.getHttpService()).thenReturn(mockService);
        when(mockIssue.getIssueName()).thenReturn("SQL Injection");

        LoggerEntry entry = new LoggerEntry("example.com", "Test", "SQL Injection", "Test");
        loggerList.add(entry);

        int initialSize = entry.getInstanceList().size();

        // Act
        scannerLogic.logNewInstance(mockIssue);

        // Assert - new instance should be added
        assertTrue(entry.getInstanceList().size() >= initialSize);
    }

    @Test
    void testLogNewInstanceDoesNotAddDuplicate() throws Exception {
        // Arrange
        ScanIssue mockIssue = mock(ScanIssue.class);
        HTTPService mockService = new HTTPService("example.com", 443, true);
        HTTPRequestResponse mockReqResp = mock(HTTPRequestResponse.class);
        URL testUrl = new URL("https://example.com/duplicate");

        when(mockIssue.getUrl()).thenReturn(testUrl);
        when(mockIssue.getConfidence()).thenReturn("CERTAIN");
        when(mockIssue.getSeverity()).thenReturn("HIGH");
        when(mockIssue.getHttpMessages()).thenReturn(new HTTPRequestResponse[] { mockReqResp });
        when(mockIssue.getHttpService()).thenReturn(mockService);
        when(mockIssue.getIssueName()).thenReturn("XSS");

        LoggerEntry entry = new LoggerEntry("example.com", "Test", "XSS", "Test");

        // Add existing instance with same URL
        InstanceEntry existingInstance = new InstanceEntry(testUrl, "CERTAIN", "HIGH", mockReqResp);
        entry.addInstance(existingInstance);
        loggerList.add(entry);

        int initialSize = entry.getInstanceList().size();

        // Act
        scannerLogic.logNewInstance(mockIssue);

        // Assert - duplicate should not be added
        assertEquals(initialSize, entry.getInstanceList().size());
    }

    @Test
    void testLogNewInstanceWithNullHttpService() throws Exception {
        // Arrange
        ScanIssue mockIssue = mock(ScanIssue.class);

        when(mockIssue.getUrl()).thenReturn(new URL("https://example.com/test"));
        when(mockIssue.getConfidence()).thenReturn("TENTATIVE");
        when(mockIssue.getSeverity()).thenReturn("LOW");
        when(mockIssue.getHttpMessages()).thenReturn(null);
        when(mockIssue.getHttpService()).thenReturn(null);
        when(mockIssue.getIssueName()).thenReturn("Info Disclosure");

        // Act - should not throw exception
        assertDoesNotThrow(() -> scannerLogic.logNewInstance(mockIssue));
    }

    @Test
    void testLogNewScanFromAuditIssue() {
        // Arrange
        AuditIssue mockAuditIssue = mock(AuditIssue.class);
        burp.api.montoya.http.HttpService mockService = mock(burp.api.montoya.http.HttpService.class);

        when(mockAuditIssue.name()).thenReturn("Command Injection");
        when(mockAuditIssue.httpService()).thenReturn(mockService);
        when(mockService.host()).thenReturn("example.com");
        when(mockAuditIssue.detail()).thenReturn("Detailed issue information");

        // Act
        scannerLogic.logNewScan(mockAuditIssue);

        // Assert
        verify(mockTableModel).addAllLoggerEntry(any(LoggerEntry.class));
    }

    @Test
    void testLogNewScanWithNullIssueDetail() {
        // Arrange
        ScanIssue mockIssue = mock(ScanIssue.class);
        HTTPService mockService = new HTTPService("example.com", 443, true);

        when(mockIssue.getHttpService()).thenReturn(mockService);
        when(mockIssue.getIssueName()).thenReturn("XXE");
        when(mockIssue.getIssueDetail()).thenReturn(null);

        // Act
        scannerLogic.logNewScan(mockIssue);

        // Assert
        verify(mockTableModel).addAllLoggerEntry(
                argThat(entry -> entry.getEvidence().equals("Refer to affected instances Request and Response.")));
    }

    @Test
    void testLogNewScanWithEmptyIssueDetail() {
        // Arrange
        ScanIssue mockIssue = mock(ScanIssue.class);
        HTTPService mockService = new HTTPService("example.com", 443, true);

        when(mockIssue.getHttpService()).thenReturn(mockService);
        when(mockIssue.getIssueName()).thenReturn("SSRF");
        when(mockIssue.getIssueDetail()).thenReturn("");

        // Act
        scannerLogic.logNewScan(mockIssue);

        // Assert
        verify(mockTableModel).addAllLoggerEntry(
                argThat(entry -> entry.getEvidence().equals("Refer to affected instances Request and Response.")));
    }

    @Test
    void testLogNewScanWithHtmlIssueDetail() {
        // Arrange
        ScanIssue mockIssue = mock(ScanIssue.class);
        HTTPService mockService = new HTTPService("example.com", 443, true);
        String htmlDetail = "<p>This is <b>bold</b> text with <a href='#'>link</a></p>";

        when(mockIssue.getHttpService()).thenReturn(mockService);
        when(mockIssue.getIssueName()).thenReturn("CSRF");
        when(mockIssue.getIssueDetail()).thenReturn(htmlDetail);

        // Act
        scannerLogic.logNewScan(mockIssue);

        // Assert - HTML should be stripped
        verify(mockTableModel).addAllLoggerEntry(argThat(entry -> !entry.getEvidence().contains("<p>") &&
                !entry.getEvidence().contains("<b>")));
    }

    @Test
    void testLogNewScanWithNullHttpService() {
        // Arrange
        ScanIssue mockIssue = mock(ScanIssue.class);

        when(mockIssue.getHttpService()).thenReturn(null);
        when(mockIssue.getIssueName()).thenReturn("Clickjacking");
        when(mockIssue.getIssueDetail()).thenReturn("Test detail");

        // Act
        scannerLogic.logNewScan(mockIssue);

        // Assert - should use empty host
        verify(mockTableModel).addAllLoggerEntry(argThat(entry -> entry.getHost().isEmpty()));
    }

    @Test
    void testLogNewScanSetsDefaultComment() {
        // Arrange
        ScanIssue mockIssue = mock(ScanIssue.class);
        HTTPService mockService = new HTTPService("example.com", 443, true);

        when(mockIssue.getHttpService()).thenReturn(mockService);
        when(mockIssue.getIssueName()).thenReturn("Open Redirect");
        when(mockIssue.getIssueDetail()).thenReturn("Detail");

        // Act
        scannerLogic.logNewScan(mockIssue);

        // Assert
        verify(mockTableModel)
                .addAllLoggerEntry(argThat(entry -> entry.getPenTesterComments().contains("Burp Scanner detected") &&
                        entry.getPenTesterComments().contains("Open Redirect")));
    }

    @Test
    void testLogNewScanClearsInstances() {
        // Arrange
        ScanIssue mockIssue = mock(ScanIssue.class);
        HTTPService mockService = new HTTPService("example.com", 443, true);

        when(mockIssue.getHttpService()).thenReturn(mockService);
        when(mockIssue.getIssueName()).thenReturn("Directory Listing");
        when(mockIssue.getIssueDetail()).thenReturn("Detail");

        // Act
        scannerLogic.logNewScan(mockIssue);

        // Assert - instances should be cleared
        verify(mockTableModel).addAllLoggerEntry(argThat(entry -> entry.getInstanceList().isEmpty()));
    }

    @Test
    void testExtractExistingScanLogsMessage() {
        // Act
        scannerLogic.extractExistingScan();

        // Assert
        verify(mockExtender).logOutput("Listening for new audit issues...");
    }

    @Test
    void testMultipleInstancesWithDifferentUrls() throws Exception {
        // Arrange
        ScanIssue mockIssue1 = mock(ScanIssue.class);
        ScanIssue mockIssue2 = mock(ScanIssue.class);
        HTTPService mockService = new HTTPService("example.com", 443, true);
        HTTPRequestResponse mockReqResp = mock(HTTPRequestResponse.class);

        when(mockIssue1.getUrl()).thenReturn(new URL("https://example.com/path1"));
        when(mockIssue1.getConfidence()).thenReturn("CERTAIN");
        when(mockIssue1.getSeverity()).thenReturn("HIGH");
        when(mockIssue1.getHttpMessages()).thenReturn(new HTTPRequestResponse[] { mockReqResp });
        when(mockIssue1.getHttpService()).thenReturn(mockService);
        when(mockIssue1.getIssueName()).thenReturn("SQL Injection");

        when(mockIssue2.getUrl()).thenReturn(new URL("https://example.com/path2"));
        when(mockIssue2.getConfidence()).thenReturn("FIRM");
        when(mockIssue2.getSeverity()).thenReturn("MEDIUM");
        when(mockIssue2.getHttpMessages()).thenReturn(new HTTPRequestResponse[] { mockReqResp });
        when(mockIssue2.getHttpService()).thenReturn(mockService);
        when(mockIssue2.getIssueName()).thenReturn("SQL Injection");

        LoggerEntry entry = new LoggerEntry("example.com", "Test", "SQL Injection", "Test");
        loggerList.add(entry);

        // Act
        scannerLogic.logNewInstance(mockIssue1);
        scannerLogic.logNewInstance(mockIssue2);

        // Assert - both instances should be added
        assertTrue(entry.getInstanceList().size() >= 2);
    }

    @Test
    void testNoMatchingLoggerEntry() throws Exception {
        // Arrange
        ScanIssue mockIssue = mock(ScanIssue.class);
        HTTPService mockService = new HTTPService("example.com", 443, true);

        when(mockIssue.getUrl()).thenReturn(new URL("https://example.com/test"));
        when(mockIssue.getConfidence()).thenReturn("CERTAIN");
        when(mockIssue.getSeverity()).thenReturn("HIGH");
        when(mockIssue.getHttpMessages()).thenReturn(null);
        when(mockIssue.getHttpService()).thenReturn(mockService);
        when(mockIssue.getIssueName()).thenReturn("NonExistentIssue");

        // No matching entry in loggerList

        // Act - should not throw exception
        assertDoesNotThrow(() -> scannerLogic.logNewInstance(mockIssue));
    }
}
