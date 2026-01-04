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
        firstEntry.setExclusion(true);
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
        assertTrue(restoredEntry.isExcluded(), "Restored entry should be excluded");
        assertEquals("Integration test comment", restoredEntry.getPenTesterComments());
        assertEquals("Integration test evidence", restoredEntry.getEvidence());
    }
}
