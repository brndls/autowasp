package autowasp.integration;

import autowasp.logger.entrytable.LoggerEntry;
import autowasp.logger.instancestable.InstanceEntry;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ReportingIntegrationTest extends IntegrationTestBase {

    @Test
    void testExcelReportGenerationWithData(@TempDir Path tempDir) {
        // 1. Prepare Checklist Data
        checklistManager.getChecklistLogic().loadLocalCopy();
        assertFalse(checklistManager.getChecklistLog().isEmpty(), "Checklist should have items");

        // Mark first item as completed with comment
        checklistManager.getChecklistLog().get(0).setTestCaseCompleted(true);
        checklistManager.getChecklistLog().get(0).setPenTesterComments("WSTG Integration Completed");

        // 2. Prepare Logger Data
        LoggerEntry loggerEntry = new LoggerEntry("test.com", "Manual", "XSS", "WSTG-INPV-01");

        // Mock chain for HttpRequestResponse
        HttpRequestResponse mockReqResp = mock(HttpRequestResponse.class);
        HttpRequest mockReq = mock(HttpRequest.class);
        HttpResponse mockResp = mock(HttpResponse.class);
        ByteArray mockBytes = mock(ByteArray.class);
        HttpService mockService = mock(HttpService.class);

        when(mockReqResp.request()).thenReturn(mockReq);
        when(mockReqResp.response()).thenReturn(mockResp);
        when(mockReq.httpService()).thenReturn(mockService);
        when(mockReq.toByteArray()).thenReturn(mockBytes);
        when(mockResp.toByteArray()).thenReturn(mockBytes);
        when(mockBytes.getBytes()).thenReturn("sample http data".getBytes());
        when(mockService.host()).thenReturn("test.com");
        when(mockService.port()).thenReturn(443);
        when(mockService.secure()).thenReturn(true);
        when(mockReq.url()).thenReturn("https://test.com/xss");

        try {
            InstanceEntry instanceEntry = new InstanceEntry(
                    java.net.URI.create("https://test.com/xss").toURL(),
                    "Certain",
                    "High",
                    mockReqResp);
            loggerEntry.addInstance(instanceEntry);
            loggerManager.getLoggerTableModel().addAllLoggerEntry(loggerEntry);
        } catch (Exception e) {
            fail("Failed to setup logger entry: " + e.getMessage());
        }

        // 3. Generate Report
        File reportFile = tempDir.resolve("integration_report.xlsx").toFile();
        reportManager.generateExcelReport(reportFile);

        // 4. Verify File
        assertTrue(reportFile.exists(), "Report file should be created");
        assertTrue(reportFile.length() > 0, "Report file should not be empty");

        // Success log should be called in ReportManager
        verify(logging).logToOutput(contains("Report generation successful"));
    }
}
