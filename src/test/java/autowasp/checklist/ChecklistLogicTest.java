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
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.swing.*;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ChecklistLogicTest {

    @Mock
    private Autowasp mockExtender;
    @Mock
    private MontoyaApi mockApi;
    @Mock
    private UserInterface mockUserInterface;
    // SwingUtils interface might typically be accessed via UserInterface, let's
    // just mock UserInterface

    @Mock
    private JFrame mockSuiteFrame;
    @Mock
    private ExtenderPanelUI mockPanelUI;
    @Mock
    private JLabel mockStatusLabel;

    private ChecklistLogic checklistLogic;
    private MockedStatic<Jsoup> mockedJsoup;

    @BeforeEach
    void setUp() {
        // Setup Extender mocks
        // Note: Some methods access fields directly (public fields in Autowasp?)
        // Let's check Autowasp class if fields are public. Assuming they are based on
        // usage.

        // Mock UI components accessed directly
        mockExtender.extenderPanelUI = mockPanelUI;
        mockPanelUI.scanStatusLabel = mockStatusLabel;

        checklistLogic = new ChecklistLogic(mockExtender);

        // Mock Jsoup static methods
        mockedJsoup = Mockito.mockStatic(Jsoup.class, Mockito.CALLS_REAL_METHODS);
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
        // Check for "http://link1.com" without trailing slash as Jsoup.parse base URI
        // is empty
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

        // This will trigger retries. 3 attempts.
        // Total delay: 1s + 2s + 4s = 7s.
        // We will accept this delay for now as refactoring "private static final" is
        // hard.

        List<String> results = checklistLogic.scrapePageURLs(testUrl);

        assertNotNull(results);
        assertTrue(results.isEmpty());

        verify(mockConnectionWithTimeout, times(3)).get();
        // verify(mockExtender.extenderPanelUI.scanStatusLabel).setText(contains("Failed
        // to fetch")); // Can't easily verify UI label setting if mock details are
        // complex, but we can verify logError
        verify(mockExtender).logError(contains("Failed to fetch"));
    }

    @Test
    void testGetTableElements_Valid() throws IOException {
        String testUrl = "http://example.com/table";
        // HTML mirroring structure expected by getTableElements
        // Element IDs: blob-path
        // Text structure: refNumber in first TD, category in 6th child of blob-path?,
        // testName in 8th child?
        // Let's match ChecklistLogic.java:181-186
        // Elements filePathElements = anyPage.getElementById("blob-path").children();
        // Elements filePathElements2 = anyPage.getElementsByTag("td");
        // refNumber = filePathElements2.first().text();
        // category = filePathElements.get(6).text()...
        // testName = filePathElements.get(8).text()...

        String html = "<html><body>" +
                "<table><tr><td>WSTG-TEST-01</td></tr></table>" +
                "<div id='blob-path'>" +
                "<span>0</span><span>1</span><span>2</span><span>3</span><span>4</span><span>5</span>" +
                "<span>src-INFO_Map_Apps</span>" + // index 6. split("-", 2)[1] -> INFO_Map_Apps -> replace _ with space
                "<span>7</span>" +
                "<span>test-Check_Something.md</span>" + // index 8. split("-", 2)[1] -> Check_Something.md -> replace _
                                                         // -> split [.] -> Check Something
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
        // HTML: <Article> ... <h2>header</h2> content ... </Article>

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
        assertTrue(result.containsKey("how to test"));
        assertTrue(result.get("how to test").contains("Step 1."));
    }

    @Test
    void testGetTableElements_Malformed() throws IOException {
        String testUrl = "http://bad-table.com";
        String html = "<html><body>No table here</body></html>";

        Connection mockConnection = mock(Connection.class);
        Connection mockConnectionWithTimeout = mock(Connection.class);
        Document mockDoc = Jsoup.parse(html);

        mockedJsoup.when(() -> Jsoup.connect(testUrl)).thenReturn(mockConnection);
        when(mockConnection.timeout(anyInt())).thenReturn(mockConnectionWithTimeout);
        when(mockConnectionWithTimeout.get()).thenReturn(mockDoc);

        HashMap<String, String> result = checklistLogic.getTableElements(testUrl);

        assertNull(result); // Should return null on exception (caught internally)
        verify(mockExtender).logError(contains("Error parsing table elements"));
    }

    @Test
    void testGetContentElements_MissingSections() throws IOException {
        String testUrl = "http://example.com/missing";
        String html = "<html><article><h1>No Headers</h1></article></html>";

        Connection mockConnection = mock(Connection.class);
        Connection mockConnectionWithTimeout = mock(Connection.class);
        Document mockDoc = Jsoup.parse(html);

        mockedJsoup.when(() -> Jsoup.connect(testUrl)).thenReturn(mockConnection);
        when(mockConnection.timeout(anyInt())).thenReturn(mockConnectionWithTimeout);
        when(mockConnectionWithTimeout.get()).thenReturn(mockDoc);

        HashMap<String, String> result = checklistLogic.getContentElements(testUrl);

        assertNotNull(result);
        // Logic will capture "No Headers" as a header and empty content
        assertTrue(result.containsKey("no headers"));
    }
}
