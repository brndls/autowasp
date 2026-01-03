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

package autowasp.checklist;

import autowasp.Autowasp;
import autowasp.ExtenderPanelUI;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.UserInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.swing.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for ChecklistLogic.
 *
 * Tests now mock Burp's HTTP API (api.http().sendRequest()) instead of
 * Jsoup.connect()
 * following the refactoring for BApp Store Criteria #7 compliance.
 */
@ExtendWith(MockitoExtension.class)
class ChecklistLogicTest {

    @Mock
    private Autowasp mockExtender;

    // Use DEEP_STUBS to handle the chain api.http().sendRequest()
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private MontoyaApi mockApi;

    @Mock
    private Http mockHttp;

    @Mock
    private HttpRequestResponse mockHttpRequestResponse;

    @Mock
    private HttpResponse mockHttpResponse;

    @Mock
    private UserInterface mockUserInterface;

    @Mock
    private JFrame mockSuiteFrame;
    @Mock
    private ExtenderPanelUI mockPanelUI;
    @Mock
    private JLabel mockStatusLabel;
    @Mock
    private ChecklistTableModel mockChecklistTableModel;

    private ChecklistLogic checklistLogic;
    private MockedStatic<HttpRequest> mockedHttpRequest;

    @BeforeEach
    void setUp() {
        // Setup Extender mocks
        lenient().when(mockExtender.getExtenderPanelUI()).thenReturn(mockPanelUI);
        // Stub getter methods for encapsulated fields
        lenient().when(mockPanelUI.getScanStatusLabel()).thenReturn(mockStatusLabel);
        lenient().when(mockPanelUI.getSummaryTextPane()).thenReturn(new JTextPane());
        lenient().when(mockPanelUI.getHowToTestTextPane()).thenReturn(new JEditorPane());
        lenient().when(mockPanelUI.getReferencesTextPane()).thenReturn(new JTextPane());
        lenient().when(mockPanelUI.getCancelFetchButton()).thenReturn(new JButton());
        // Setup checklist fields using reflection because they are final in Autowasp
        lenient().when(mockExtender.getChecklistTableModel()).thenReturn(mockChecklistTableModel);
        setField(mockExtender, "checklistLog", new ArrayList<ChecklistEntry>());
        setField(mockExtender, "checkListHashMap", new HashMap<String, ChecklistEntry>());
        setField(mockExtender, "loggerList", new ArrayList<>());

        // Common API mocks
        lenient().when(mockExtender.getApi()).thenReturn(mockApi);
        lenient().when(mockApi.userInterface().swingUtils().suiteFrame()).thenReturn(mockSuiteFrame);
        lenient().when(mockApi.http()).thenReturn(mockHttp);

        checklistLogic = new ChecklistLogic(mockExtender);

        // Mock HttpRequest.httpRequestFromUrl() static method
        mockedHttpRequest = Mockito.mockStatic(HttpRequest.class);
    }

    // Helper to set private/final fields on mocks
    private void setField(Object target, String fieldName, Object value) {
        try {
            java.lang.reflect.Field field = target.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException("Failed to set field " + fieldName, e);
        }
    }

    @AfterEach
    void tearDown() {
        if (mockedHttpRequest != null) {
            mockedHttpRequest.close();
        }
    }

    /**
     * Helper to setup mock HTTP response for a given URL and HTML content.
     */
    private void setupMockHttpResponse(String url, String html, short statusCode) {
        HttpRequest mockRequest = mock(HttpRequest.class);
        mockedHttpRequest.when(() -> HttpRequest.httpRequestFromUrl(url)).thenReturn(mockRequest);
        when(mockHttp.sendRequest(mockRequest)).thenReturn(mockHttpRequestResponse);
        when(mockHttpRequestResponse.response()).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(statusCode);
        when(mockHttpResponse.bodyToString()).thenReturn(html);
    }

    /**
     * Helper to setup mock HTTP failure (throws exception or null response).
     */
    private void setupMockHttpFailure(String url) {
        HttpRequest mockRequest = mock(HttpRequest.class);
        mockedHttpRequest.when(() -> HttpRequest.httpRequestFromUrl(url)).thenReturn(mockRequest);
        when(mockHttp.sendRequest(mockRequest)).thenReturn(mockHttpRequestResponse);
        when(mockHttpRequestResponse.response()).thenReturn(null); // Simulate connection failure
    }

    @Test
    void testScrapePageURLsSuccess() {
        String testUrl = "http://example.com";
        String html = "<html><article><a href='http://link1.com'>Link 1</a><a href='http://link2.com'>Link 2</a></article></html>";

        setupMockHttpResponse(testUrl, html, (short) 200);

        List<String> results = checklistLogic.scrapePageURLs(testUrl);

        assertTrue(results.contains("http://link1.com"));
        verify(mockHttp, times(1)).sendRequest(any(HttpRequest.class));
    }

    @Test
    void testScrapePageURLsEmptyResponse() {
        String testUrl = "http://bad.com";

        setupMockHttpFailure(testUrl);

        List<String> results = checklistLogic.scrapePageURLs(testUrl);

        assertNotNull(results);
        assertTrue(results.isEmpty());
        // Verify 3 retries (sendRequest called 3 times)
        verify(mockHttp, times(3)).sendRequest(any(HttpRequest.class));
        verify(mockExtender).logError(contains("Failed to fetch after 3 attempts"));
    }

    @Test
    void testGetTableElementsValid() {
        String testUrl = "https://raw.githubusercontent.com/example/01-Category/test.md";
        String html = """
                # My Test Title
                Reference ID: WSTG-TEST-01
                Some other content""";

        setupMockHttpResponse(testUrl, html, (short) 200);

        Map<String, String> result = checklistLogic.getTableElements(testUrl);

        assertNotNull(result);
        assertEquals("WSTG-TEST-01", result.get("Reference Number"));
        assertEquals("Category", result.get("Category"));
        assertEquals("My Test Title", result.get("Test Name"));
    }

    @Test
    void testGetContentElementsValid() {
        String testUrl = "https://raw.githubusercontent.com/example/content.md";
        String html = """
                # Title
                ## Summary
                This is the summary.
                ## How to Test
                Step 1.""";

        setupMockHttpResponse(testUrl, html, (short) 200);

        Map<String, String> result = checklistLogic.getContentElements(testUrl);

        assertNotNull(result);
        assertTrue(result.containsKey("summary"));
        assertTrue(result.get("summary").contains("This is the summary."));
    }

    @Test
    void testLogNewChecklistEntrySuccess() {
        String testUrl = "https://raw.githubusercontent.com/example/02-Cat_One/test-Test_Two.md";
        String html = """
                # Test Two
                Refer: WSTG-TEST-02
                ## Summary
                Content
                ## How to Test
                Steps""";

        setupMockHttpResponse(testUrl, html, (short) 200);

        boolean result = checklistLogic.logNewChecklistEntry(testUrl);

        assertTrue(result);
        // Verify entry added to map and table
        verify(mockChecklistTableModel).addValueAt(any(ChecklistEntry.class), eq(0), eq(0));
        assertEquals(1, mockExtender.checkListHashMap.size());
        assertTrue(mockExtender.checkListHashMap.containsKey("WSTG-TEST-02"));
    }

    @Test
    void testLogNewChecklistEntryFailure() {
        String testUrl = "http://fail.com";

        setupMockHttpFailure(testUrl);

        boolean result = checklistLogic.logNewChecklistEntry(testUrl);

        assertFalse(result);
        verify(mockExtender).logOutput(contains("Skipping URL due to fetch failure"));
    }

    @Test
    void testToHash(@org.junit.jupiter.api.io.TempDir java.nio.file.Path tempDir) throws Exception {
        // Create a temporary file
        java.io.File tempFile = tempDir.resolve("testHash.txt").toFile();
        try (java.io.FileWriter writer = new java.io.FileWriter(tempFile)) {
            writer.write("test content");
        }

        // Calculate hash
        String hash = checklistLogic.toHash(tempFile);

        // SHA-256 of "test content"
        // echo -n "test content" | shasum -a 256
        // 6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72
        assertEquals("6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72", hash);
    }

    @Test
    void testSaveLocalCopy(@org.junit.jupiter.api.io.TempDir java.nio.file.Path tempDir) throws IOException {
        String destPath = tempDir.toAbsolutePath().toString();

        // Setup mock data
        ChecklistEntry entry1 = new ChecklistEntry(new HashMap<>(), new HashMap<>(), "url1");
        entry1.setRefNumber("REF1");
        mockExtender.checklistLog.add(entry1);

        checklistLogic.saveLocalCopy(destPath);

        // Verify file created
        java.io.File savedFile = new java.io.File(destPath, "OWASP_WSTG_local");
        assertTrue(savedFile.exists());
        assertTrue(savedFile.length() > 0);

        // Verify UI feedback
        verify(mockStatusLabel, atLeastOnce()).setText(contains("File saved to"));
        verify(mockExtender).issueAlert(contains("File saved to"));
    }

    @Test
    void testSaveToExcelFileNoContent(@org.junit.jupiter.api.io.TempDir java.nio.file.Path tempDir) {
        String destPath = tempDir.toAbsolutePath().toString();

        // No entries in checklistLog
        checklistLogic.saveToExcelFile(destPath);

        // Verify file created (even empty)
        java.io.File excelFile = new java.io.File(destPath, "OWASP Checklist.xlsx");
        assertTrue(excelFile.exists());

        verify(mockExtender).issueAlert(contains("Excel report generated"));
    }

    @Test
    void testFetchWithRetryNonOKStatusCode() {
        String testUrl = "http://notfound.com";

        // Setup mock to return 404
        HttpRequest mockRequest = mock(HttpRequest.class);
        mockedHttpRequest.when(() -> HttpRequest.httpRequestFromUrl(testUrl)).thenReturn(mockRequest);
        when(mockHttp.sendRequest(mockRequest)).thenReturn(mockHttpRequestResponse);
        when(mockHttpRequestResponse.response()).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn((short) 404);

        // scrapePageURLs internally calls fetchWithRetry
        List<String> results = checklistLogic.scrapePageURLs(testUrl);

        assertTrue(results.isEmpty());
        // Verify 3 retries for non-200 status
        verify(mockHttp, times(3)).sendRequest(any(HttpRequest.class));
    }
}
