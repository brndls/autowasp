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

package autowasp.ui;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import autowasp.managers.NoteManager;
import autowasp.notes.Note;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ChecklistNotesPanelTest {

    @Mock
    private NoteManager noteManager;

    private ChecklistNotesPanel notesPanel;

    @BeforeEach
    void setUp() {
        notesPanel = new ChecklistNotesPanel(noteManager);
    }

    @Test
    void testInitialization() {
        assertNotNull(notesPanel);
        verify(noteManager).addChangeListener(notesPanel);
    }

    @Test
    void testSetSelectedWstgId() {
        String wstgId = "WSTG-INFO-01";
        when(noteManager.getNotesByWstgId(wstgId)).thenReturn(Collections.emptyList());

        notesPanel.setSelectedWstgId(wstgId);
        // Verify it doesn't crash and calls manager
        verify(noteManager).getNotesByWstgId(wstgId);
    }

    @Test
    void testSetSelectedWstgIdWithNotes() {
        String wstgId = "WSTG-ID";
        Note note = Note.create("Test Note", wstgId);
        when(noteManager.getNotesByWstgId(wstgId)).thenReturn(List.of(note));

        notesPanel.setSelectedWstgId(wstgId);

        verify(noteManager).getNotesByWstgId(wstgId);
    }

    @Test
    void testSetSelectedWstgIdNull() {
        notesPanel.setSelectedWstgId(null);
        // Verify it doesn't crash
        assertNotNull(notesPanel);
    }

    @Test
    void testOnNotesChanged() {
        notesPanel.onNotesChanged();
        // verify it doesn't crash (runs on EDT later)
        assertNotNull(notesPanel);
    }
}
