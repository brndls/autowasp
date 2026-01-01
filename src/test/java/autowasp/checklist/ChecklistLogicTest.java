package autowasp.checklist;

import autowasp.Autowasp;
import autowasp.ExtenderPanelUI;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.UserInterface;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ChecklistLogicTest {

    @Mock
    private Autowasp mockExtender;

    // Use DEEP_STUBS to handle the chain
    // api.userInterface().swingUtils().suiteFrame()
    // without needing to import the SwingUtils class which is hard to find
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private MontoyaApi mockApi;

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
    private MockedStatic<Jsoup> mockedJsoup;

    @BeforeEach
    void setUp() {
        // Setup Extender mocks
        mockExtender.extenderPanelUI = mockPanelUI;
        mockPanelUI.scanStatusLabel = mockStatusLabel;

        // Setup checklist fields using reflection because they are final in Autowasp
        setField(mockExtender, "checklistTableModel", mockChecklistTableModel);
        setField(mockExtender, "checklistLog", new ArrayList<ChecklistEntry>());
        setField(mockExtender, "checkListHashMap", new HashMap<String, ChecklistEntry>());
        setField(mockExtender, "loggerList", new ArrayList<>());

        // Common API mocks
        lenient().when(mockExtender.getApi()).thenReturn(mockApi);
        // By using deep stubs on mockApi, we can just define the end result
        lenient().when(mockApi.userInterface().swingUtils().suiteFrame()).thenReturn(mockSuiteFrame);

        checklistLogic = new ChecklistLogic(mockExtender);

        // Mock Jsoup static methods
        mockedJsoup = Mockito.mockStatic(Jsoup.class, Mockito.CALLS_REAL_METHODS);
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
        if (mockedJsoup != null) {
            mockedJsoup.close();
        }
    }

    @Test
    void testScrapePageURLs_Success() throws IOException {
        String testUrl = "http://example.com";
        String html = "<html><article><a href='http://link1.com'>Link 1</a><a href='http://link2.com'>Link 2</a></article></html>";

        Connection mockConnection = mock(Connection.class);
        Connection mockConnectionWithTimeout = mock(Connection.class);
        Document mockDoc = Jsoup.parse(html);

        mockedJsoup.when(() -> Jsoup.connect(testUrl)).thenReturn(mockConnection);
        when(mockConnection.timeout(anyInt())).thenReturn(mockConnectionWithTimeout);
        when(mockConnectionWithTimeout.get()).thenReturn(mockDoc);

        List<String> results = checklistLogic.scrapePageURLs(testUrl);

        assertTrue(results.contains("http://link1.com"));
        verify(mockConnection, times(1)).timeout(10000);
    }

    @Test
    void testScrapePageURLs_EmptyResponse() throws IOException {
        String testUrl = "http://bad.com";

        Connection mockConnection = mock(Connection.class);
        Connection mockConnectionWithTimeout = mock(Connection.class);

        mockedJsoup.when(() -> Jsoup.connect(testUrl)).thenReturn(mockConnection);
        when(mockConnection.timeout(anyInt())).thenReturn(mockConnectionWithTimeout);
        when(mockConnectionWithTimeout.get()).thenThrow(new IOException("Network error"));

        List<String> results = checklistLogic.scrapePageURLs(testUrl);

        assertNotNull(results);
        assertTrue(results.isEmpty());
        // Verify 3 retries
        verify(mockConnectionWithTimeout, times(3)).get();
        verify(mockExtender).logError(contains("Failed to fetch after 3 attempts"));
    }

    @Test
    void testGetTableElements_Valid() throws IOException {
        String testUrl = "http://example.com/table";
        String html = "<html><body>" +
                "<table><tr><td>WSTG-TEST-01</td></tr></table>" +
                "<div id='blob-path'>" +
                "<span>0</span><span>1</span><span>2</span><span>3</span><span>4</span><span>5</span>" +
                "<span>src-INFO_Map_Apps</span>" +
                "<span>7</span>" +
                "<span>test-Check_Something.md</span>" +
                "</div>" +
                "</body></html>";

        Connection mockConnection = mock(Connection.class);
        Connection mockConnectionWithTimeout = mock(Connection.class);
        Document mockDoc = Jsoup.parse(html);

        mockedJsoup.when(() -> Jsoup.connect(testUrl)).thenReturn(mockConnection);
        when(mockConnection.timeout(anyInt())).thenReturn(mockConnectionWithTimeout);
        when(mockConnectionWithTimeout.get()).thenReturn(mockDoc);

        HashMap<String, String> result = checklistLogic.getTableElements(testUrl);

        assertNotNull(result);
        assertEquals("WSTG-TEST-01", result.get("Reference Number"));
        assertEquals("INFO Map Apps", result.get("Category"));
        assertEquals("Check Something", result.get("Test Name"));
    }

    @Test
    void testGetContentElements_Valid() throws IOException {
        String testUrl = "http://example.com/content";
        String html = "<html><article>" +
                "<h1>Title</h1>" +
                "<h2>Summary</h2>" +
                "<p>This is the summary.</p>" +
                "<h2>How To Test</h2>" +
                "<p>Step 1.</p>" +
                "</article></html>";

        Connection mockConnection = mock(Connection.class);
        Connection mockConnectionWithTimeout = mock(Connection.class);
        Document mockDoc = Jsoup.parse(html);

        mockedJsoup.when(() -> Jsoup.connect(testUrl)).thenReturn(mockConnection);
        when(mockConnection.timeout(anyInt())).thenReturn(mockConnectionWithTimeout);
        when(mockConnectionWithTimeout.get()).thenReturn(mockDoc);

        HashMap<String, String> result = checklistLogic.getContentElements(testUrl);

        assertNotNull(result);
        assertTrue(result.containsKey("summary"));
        assertTrue(result.get("summary").contains("This is the summary."));
    }

    @Test
    void testLogNewChecklistEntry_Success() throws IOException {
        String testUrl = "http://example.com/entry";
        String html = "<html><body>" +
                "<table><tr><td>WSTG-TEST-02</td></tr></table>" +
                "<div id='blob-path'>" +
                "<span>0</span><span>1</span><span>2</span><span>3</span><span>4</span><span>5</span>" +
                "<span>src-Cat_One</span>" +
                "<span>7</span>" +
                "<span>test-Test_Two.md</span>" +
                "</div>" +
                "<article><h2>Summary</h2><p>Content</p></article>" +
                "</body></html>";

        Connection mockConnection = mock(Connection.class);
        Connection mockConnectionWithTimeout = mock(Connection.class);
        Document mockDoc = Jsoup.parse(html);

        mockedJsoup.when(() -> Jsoup.connect(testUrl)).thenReturn(mockConnection);
        when(mockConnection.timeout(anyInt())).thenReturn(mockConnectionWithTimeout);
        when(mockConnectionWithTimeout.get()).thenReturn(mockDoc);

        boolean result = checklistLogic.logNewChecklistEntry(testUrl);

        assertTrue(result);
        // Verify entry added to map and table
        verify(mockChecklistTableModel).addValueAt(any(ChecklistEntry.class), eq(0), eq(0));
        assertEquals(1, mockExtender.checkListHashMap.size());
        assertTrue(mockExtender.checkListHashMap.containsKey("WSTG-TEST-02"));
    }

    @Test
    void testLogNewChecklistEntry_Failure() throws IOException {
        String testUrl = "http://fail.com";

        Connection mockConnection = mock(Connection.class);
        Connection mockConnectionWithTimeout = mock(Connection.class);

        // Fail to connect
        mockedJsoup.when(() -> Jsoup.connect(testUrl)).thenReturn(mockConnection);
        when(mockConnection.timeout(anyInt())).thenReturn(mockConnectionWithTimeout);
        when(mockConnectionWithTimeout.get()).thenThrow(new IOException("Fail"));

        boolean result = checklistLogic.logNewChecklistEntry(testUrl); // Retries internally then returns false

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
        entry1.refNumber = "REF1";
        checklistLogic.getClass(); // Just to reference access
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
    void testSaveToExcelFile_NoContent(@org.junit.jupiter.api.io.TempDir java.nio.file.Path tempDir) {
        String destPath = tempDir.toAbsolutePath().toString();

        // No entries in blacklistLog/checklistLog
        checklistLogic.saveToExcelFile(destPath);

        // Verify file created (even empty)
        java.io.File excelFile = new java.io.File(destPath, "OWASP Checklist.xlsx");
        assertTrue(excelFile.exists());

        verify(mockExtender).issueAlert(contains("Excel report generated"));
    }
}
