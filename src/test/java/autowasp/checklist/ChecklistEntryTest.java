package autowasp.checklist;

import org.junit.jupiter.api.Test;
import java.util.HashMap;
import static org.junit.jupiter.api.Assertions.*;

class ChecklistEntryTest {

    @Test
    void testHashMapConstructor() {
        HashMap<String, String> tableElements = new HashMap<>();
        tableElements.put("Reference Number", "REF-01");
        tableElements.put("Category", "Info");
        tableElements.put("Test Name", "Test 1");

        HashMap<String, String> contentElements = new HashMap<>();
        contentElements.put("summary", "<p>Summary</p>");
        contentElements.put("how to test", "<p>How</p>");
        contentElements.put("references", "<p>Ref</p>");

        ChecklistEntry entry = new ChecklistEntry(tableElements, contentElements, "http://example.com");

        assertEquals("REF-01", entry.getRefNumber());
        assertEquals("Info", entry.category);
        assertEquals("Test 1", entry.getTestName());
        assertEquals("<p>Summary</p>", entry.summaryHTML);
        assertEquals("http://example.com", entry.url);
        assertFalse(entry.isExcluded());
        assertFalse(entry.isTestcaseCompleted());
    }

    @Test
    void testDirectConstructor() {
        ChecklistEntry entry = new ChecklistEntry(
                "REF-02", "Cat", "Test 2", "Sum", "How", "Ref", "http://url.com");

        assertEquals("REF-02", entry.getRefNumber());
        assertEquals("Cat", entry.category);
        assertEquals("Test 2", entry.getTestName());
        assertEquals("Sum", entry.summaryHTML);
    }

    @Test
    void testCleanEntry() {
        // Create entry with empty maps which results in null fields
        ChecklistEntry entry = new ChecklistEntry(new HashMap<>(), new HashMap<>(), null);
        // Explicitly ensure nulls
        entry.refNumber = null;
        entry.category = null;
        entry.testName = null;
        entry.summaryHTML = null;
        entry.howToTestHTML = null;
        entry.referencesHTML = null;

        entry.cleanEntry();

        assertEquals("NIL", entry.refNumber);
        assertEquals("NIL", entry.category);
        assertEquals("NIL", entry.testName);
        assertEquals("NIL", entry.summaryHTML);
        assertEquals("NIL", entry.howToTestHTML);
        assertEquals("", entry.referencesHTML); // Special case
    }

    @Test
    void testSettersAndAppenders() {
        ChecklistEntry entry = new ChecklistEntry(new HashMap<>(), new HashMap<>(), "url");

        // Comments
        entry.setPenTesterComments("First.");
        assertEquals("First.", entry.pentesterComments);
        entry.setPenTesterComments("Second.");
        assertEquals("First.Second.", entry.pentesterComments);

        // Evidence
        entry.setEvidence("Ev1.");
        assertEquals("Ev1.", entry.evidence);
        entry.setEvidence("Ev2.");
        assertEquals("Ev1.Ev2.", entry.evidence);

        // Booleans
        entry.setExclusion(true);
        assertTrue(entry.isExcluded());

        entry.setTestCaseCompleted(true);
        assertTrue(entry.isTestcaseCompleted());

        entry.setTestBoolean(true);
        assertTrue(entry.getTestBool());
    }

    @Test
    void testClearers() {
        ChecklistEntry entry = new ChecklistEntry(new HashMap<>(), new HashMap<>(), "url");
        entry.setPenTesterComments("Comments");
        entry.setEvidence("Evidence");

        entry.clearComments();
        assertEquals("", entry.pentesterComments);

        entry.clearEvidences();
        assertEquals("", entry.evidence);
    }
}
