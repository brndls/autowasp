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
import autowasp.persistence.AutowaspPersistence;
import autowasp.persistence.ChecklistState;
import autowasp.managers.ChecklistManager;
import autowasp.managers.UIManager;
import autowasp.ExtenderPanelUI;
import autowasp.managers.PersistenceManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.swing.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ChecklistLogicCoverageTest {

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private Autowasp mockExtender;

    @Mock
    private ChecklistManager mockChecklistManager;

    @Mock
    private PersistenceManager mockPersistenceManager;

    @Mock
    private AutowaspPersistence mockPersistence;

    @Mock
    private UIManager mockUIManager;

    @Mock
    private ExtenderPanelUI mockExtenderPanelUI;

    @Mock
    private ChecklistTableModel mockChecklistTableModel;

    private ChecklistLogic checklistLogic;
    private List<ChecklistEntry> checklistLog;
    private Map<String, ChecklistEntry> checklistHashMap;

    @BeforeEach
    void setUp() {
        checklistLog = new ArrayList<>();
        checklistHashMap = new HashMap<>();

        lenient().when(mockExtender.getChecklistManager()).thenReturn(mockChecklistManager);
        lenient().when(mockExtender.getPersistenceManager()).thenReturn(mockPersistenceManager);
        lenient().when(mockPersistenceManager.getPersistence()).thenReturn(mockPersistence);
        lenient().when(mockExtender.getUIManager()).thenReturn(mockUIManager);
        lenient().when(mockUIManager.getExtenderPanelUI()).thenReturn(mockExtenderPanelUI);
        lenient().when(mockExtenderPanelUI.getScanStatusLabel()).thenReturn(new JLabel());

        lenient().when(mockChecklistManager.getChecklistLog()).thenReturn(checklistLog);
        lenient().when(mockChecklistManager.getCheckListHashMap()).thenReturn(checklistHashMap);
        lenient().when(mockChecklistManager.getChecklistTableModel()).thenReturn(mockChecklistTableModel);

        checklistLogic = new ChecklistLogic(mockExtender);
    }

    @Test
    void testSaveLocalCopyWithNAEntry(@TempDir Path tempDir) throws IOException {
        String destPath = tempDir.toAbsolutePath().toString();

        ChecklistEntry entry = new ChecklistEntry(new HashMap<>(), new HashMap<>(), "url");
        entry.setStatus(ChecklistStatus.NA);
        checklistLog.add(entry);

        checklistLogic.saveLocalCopy(destPath);

        File savedFile = new File(destPath, "OWASP_WSTG_local");
        assertTrue(savedFile.exists());
    }

    @Test
    void testApplySavedPersistenceStateFull() {
        // Prepare mock entries
        ChecklistEntry entry1 = new ChecklistEntry(new HashMap<>(), new HashMap<>(), "url1");
        entry1.setRefNumber("REF-01");
        checklistHashMap.put("REF-01", entry1);

        ChecklistEntry entry2 = new ChecklistEntry(new HashMap<>(), new HashMap<>(), "url2");
        entry2.setRefNumber("REF-02");
        checklistHashMap.put("REF-02", entry2);

        ChecklistEntry entry3 = new ChecklistEntry(new HashMap<>(), new HashMap<>(), "url3");
        entry3.setRefNumber("REF-03");
        checklistHashMap.put("REF-03", entry3);

        // Prepare saved states
        List<ChecklistState> savedStates = new ArrayList<>();
        // 1. Modern status
        savedStates.add(new ChecklistState("REF-01", "FAIL", false, false, "Comment 1", "Evidence 1"));
        // 2. Legacy migration (NA)
        savedStates.add(new ChecklistState("REF-02", null, true, false, "Comment 2", ""));
        // 3. Legacy migration (DONE)
        savedStates.add(new ChecklistState("REF-03", null, false, true, "", "Evidence 3"));
        // 4. Invalid status
        savedStates.add(new ChecklistState("REF-04", "INVALID", false, false, "", ""));

        when(mockPersistence.loadChecklistState()).thenReturn(savedStates);

        // Try to call private method using reflection or just make it package-private
        // if needed?
        // Actually applySavedPersistenceState is private.
        // I can trigger it via loadLocalCopy if I mock the resource loading.
        // Or I can use a package-private access if I move the test to the same package.
        // Let's use reflection for simplicity in a unit test for coverage.

        try {
            java.lang.reflect.Method method = ChecklistLogic.class.getDeclaredMethod("applySavedPersistenceState");
            method.setAccessible(true);
            method.invoke(checklistLogic);
        } catch (Exception e) {
            fail("Reflection failed: " + e.getMessage());
        }

        assertEquals(ChecklistStatus.FAIL, entry1.getStatus());
        assertEquals("Comment 1", entry1.getPenTesterComments());
        assertEquals("Evidence 1", entry1.getEvidence());

        assertEquals(ChecklistStatus.NA, entry2.getStatus());
        assertEquals("Comment 2", entry2.getPenTesterComments());

        assertEquals(ChecklistStatus.DONE, entry3.getStatus());
        assertEquals("Evidence 3", entry3.getEvidence());

        verify(mockChecklistTableModel).fireTableDataChanged();
    }
}
