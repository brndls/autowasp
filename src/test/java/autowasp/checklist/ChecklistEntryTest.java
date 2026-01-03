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
        assertEquals("Info", entry.getCategory());
        assertEquals("Test 1", entry.getTestName());
        assertEquals("<p>Summary</p>", entry.getSummaryHTML());
        assertEquals("http://example.com", entry.getUrl());
        assertFalse(entry.isExcluded());
        assertFalse(entry.isTestcaseCompleted());
    }

    @Test
    void testDirectConstructor() {
        ChecklistEntry entry = new ChecklistEntry(
                "REF-02", "Cat", "Test 2", "Sum", "How", "Ref", "http://url.com");

        assertEquals("REF-02", entry.getRefNumber());
        assertEquals("Cat", entry.getCategory());
        assertEquals("Test 2", entry.getTestName());
        assertEquals("Sum", entry.getSummaryHTML());
    }

    @Test
    void testCleanEntry() {
        // Create entry with empty maps which results in null fields
        ChecklistEntry entry = new ChecklistEntry(new HashMap<>(), new HashMap<>(), null);
        // Explicitly ensure nulls
        entry.setRefNumber(null);
        entry.setCategory(null);
        entry.setTestName(null);
        entry.setSummaryHTML(null);
        entry.setHowToTestHTML(null);
        entry.setReferencesHTML(null);

        entry.cleanEntry();

        assertEquals("NIL", entry.getRefNumber());
        assertEquals("NIL", entry.getCategory());
        assertEquals("NIL", entry.getTestName());
        assertEquals("NIL", entry.getSummaryHTML());
        assertEquals("NIL", entry.getHowToTestHTML());
        assertEquals("", entry.getReferencesHTML()); // Special case
    }

    @Test
    void testSettersAndAppenders() {
        ChecklistEntry entry = new ChecklistEntry(new HashMap<>(), new HashMap<>(), "url");

        // Comments
        entry.setPenTesterComments("First.");
        assertEquals("First.", entry.getPenTesterComments());
        entry.setPenTesterComments("Second.");
        assertEquals("First.Second.", entry.getPenTesterComments());

        // Evidence
        entry.setEvidence("Ev1.");
        assertEquals("Ev1.", entry.getEvidence());
        entry.setEvidence("Ev2.");
        assertEquals("Ev1.Ev2.", entry.getEvidence());

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
        assertEquals("", entry.getPenTesterComments());

        entry.clearEvidences();
        assertEquals("", entry.getEvidence());
    }
}
