package autowasp.logger.entrytable;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class LoggerEntryTest {

    @Test
    void testConstructorAndGetters() {
        // Constructor: host, action, vulnType, checklistIssue
        LoggerEntry entry = new LoggerEntry("host", "action", "vulnType", "checklistIssue");

        assertEquals("host", entry.getHost());
        assertEquals("checklistIssue", entry.getChecklistIssue());
        assertEquals("Please insert comments", entry.getPenTesterComments());
        assertEquals("nil", entry.getEvidence());
        assertEquals("vulnType", entry.getVulnType());
        assertNotNull(entry.getInstanceList());
        assertTrue(entry.getInstanceList().isEmpty());
    }

    @Test
    void testConstructorWithComments() {
        // Constructor: host, action, vulnType, checklistIssue, comments
        LoggerEntry entry = new LoggerEntry("host", "action", "vulnType", "checklistIssue", "comments");
        assertEquals("comments", entry.getPenTesterComments());
        assertEquals("Please insert evidences", entry.getEvidence());
    }

    @Test
    void testSetters() {
        LoggerEntry entry = new LoggerEntry("h", "a", "v", "i");

        entry.setChecklistIssue("newIssue");
        assertEquals("newIssue", entry.getChecklistIssue());

        entry.setPenTesterComments("newComments");
        assertEquals("newComments", entry.getPenTesterComments());

        entry.setEvidence("newEvidence");
        assertEquals("newEvidence", entry.getEvidence());
    }

    @Test
    void testToString() {
        LoggerEntry entry = new LoggerEntry("h", "a", "v", "i");
        assertNotNull(entry.toString());
        assertTrue(entry.toString().contains("host: h"));
    }
}
