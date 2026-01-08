/*
 * Copyright (c) 2021 Government Technology Agency
 * Copyright (c) 2024-2026 Autowasp Contributors
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

package autowasp.integration;

import autowasp.checklist.ChecklistEntry;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ChecklistPersistenceIntegrationTest extends IntegrationTestBase {

    @Test
    void testSaveAndRestoreChecklistState() {
        // 1. Load bundled checklist
        checklistManager.getChecklistLogic().loadLocalCopy();
        List<ChecklistEntry> entries = checklistManager.getChecklistLog();
        assertFalse(entries.isEmpty(), "Checklist should not be empty after loading local copy");

        // 2. Modify some entries
        ChecklistEntry firstEntry = entries.get(0);
        String refNumber = firstEntry.getRefNumber();
        firstEntry.setStatus(autowasp.checklist.ChecklistStatus.NA);
        firstEntry.setPenTesterComments("Integration test comment");
        firstEntry.setEvidence("Integration test evidence");

        // 3. Save state
        persistenceManager.saveAllState(checklistManager, loggerManager);

        // 4. Verify in-memory persistence store has data
        assertTrue(persistenceStore.containsKey("autowasp_checklist_state_json"),
                "Persistence store should contain checklist state key");
        String json = persistenceStore.get("autowasp_checklist_state_json");
        assertTrue(json.contains(refNumber), "JSON should contain the reference number");
        assertTrue(json.contains("Integration test comment"), "JSON should contain the comments");

        // 5. Simulate extension reload (Clear managers and restore)
        checklistManager.getChecklistLog().clear();
        checklistManager.getCheckListHashMap().clear();
        assertTrue(checklistManager.getChecklistLog().isEmpty());

        // Call restore state
        persistenceManager.restoreAllState(checklistManager, loggerManager);

        // 6. Verify restoration
        List<ChecklistEntry> restoredEntries = checklistManager.getChecklistLog();
        assertFalse(restoredEntries.isEmpty(), "Restored checklist should not be empty");

        ChecklistEntry restoredEntry = checklistManager.getCheckListHashMap().get(refNumber);
        assertNotNull(restoredEntry, "Restored entry should exist in hash map");
        assertEquals(autowasp.checklist.ChecklistStatus.NA, restoredEntry.getStatus(), "Restored entry should be NA");
        assertEquals("Integration test comment", restoredEntry.getPenTesterComments());
        assertEquals("Integration test evidence", restoredEntry.getEvidence());
    }
}
