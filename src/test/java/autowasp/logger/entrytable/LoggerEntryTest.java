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
