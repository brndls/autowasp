/*
 * Copyright (c) 2026 Autowasp
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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import autowasp.notes.Note;
import burp.api.montoya.persistence.PersistedObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.File;
import java.nio.file.Path;

class NotebookIntegrationTest extends IntegrationTestBase {

    @Test
    void testNotePersistenceAndReporting(@TempDir Path tempDir) {
        // 1. Setup - Mock persistence
        PersistedObject mockPersist = mock(PersistedObject.class);
        when(api.persistence().extensionData()).thenReturn(mockPersist);

        // 2. Add some notes via Manager
        String wstgId = "WSTG-INFO-01";
        extender.getNoteManager().addNote(Note.create("Note 1 for " + wstgId, wstgId));
        extender.getNoteManager().addNote(Note.create("Note 2 for " + wstgId, wstgId));
        extender.getNoteManager().addNote(Note.createGeneral("General observation"));

        // Verify save was called
        verify(mockPersist, atLeastOnce()).setString(eq("autowasp.notes"), anyString());

        // 3. Verify querying
        assertEquals(2, extender.getNoteManager().getNoteCountByWstgId(wstgId));
        assertEquals(1, extender.getNoteManager().getGeneralNotes().size());

        // 4. Test Report Generation with Notes
        checklistManager.getChecklistLogic().loadLocalCopy();
        File reportFile = tempDir.resolve("notebook_report.xlsx").toFile();

        // We need to ensure the checklist has the item we added notes to
        assertTrue(checklistManager.getChecklistLog().stream()
                .anyMatch(e -> e.getRefNumber().equals(wstgId)));

        // Generate Report
        reportManager.generateExcelReport(reportFile);

        // Verify report file
        assertTrue(reportFile.exists());
        assertTrue(reportFile.length() > 0);

        // Verify success log
        verify(logging, atLeastOnce()).logToOutput(contains("Report generation successful"));
    }
}
