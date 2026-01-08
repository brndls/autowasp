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
import javax.swing.JButton;
import javax.swing.JTextArea;
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

    private boolean shouldConfirmDelete = true;

    @BeforeEach
    void setUp() {
        notesPanel = new ChecklistNotesPanel(noteManager) {
            @Override
            protected boolean confirmDelete() {
                return shouldConfirmDelete;
            }
        };
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

    @Test
    void testAddNote() {
        String wstgId = "WSTG-ADD-01";
        when(noteManager.getNotesByWstgId(wstgId)).thenReturn(Collections.emptyList());
        notesPanel.setSelectedWstgId(wstgId);

        // Find "+ Add Note" button
        JButton addButton = findButtonWithMessage(notesPanel, "+ Add Note");
        assertNotNull(addButton, "Add button should be present");
        assertTrue(addButton.isEnabled(), "Add button should be enabled when WSTG ID is set");

        // Click it
        addButton.doClick();

        // Editor panel should be visible
        // We need to inspect the 'editorPanel'. It's private, but we can search for a
        // JTextArea which is inside it.
        JTextArea editorArea = findEditorArea(notesPanel);
        assertNotNull(editorArea, "Editor area should be present");
        assertTrue(editorArea.isVisible(), "Editor area should be visible after clicking Add");
    }

    @Test
    void testSaveNote() {
        String wstgId = "WSTG-SAVE-01";
        when(noteManager.getNotesByWstgId(wstgId)).thenReturn(Collections.emptyList());
        notesPanel.setSelectedWstgId(wstgId);

        // Open editor
        JButton addButton = findButtonWithMessage(notesPanel, "+ Add Note");
        addButton.doClick();

        // Type in editor
        JTextArea editorArea = findEditorArea(notesPanel);
        editorArea.setText("New test note content");

        // Save
        JButton saveButton = findButtonWithMessage(notesPanel, "Save");
        assertNotNull(saveButton, "Save button should be present");
        saveButton.doClick();

        // Verify manager called
        // Note: NoteManager.addNote calls persistence, but we mocked NoteManager.
        // We verify that addNote was called with a Note object containing our content
        verify(noteManager).addNote(argThat(note -> note.content().equals("New test note content") &&
                note.wstgId().equals(wstgId)));
    }

    @Test
    void testDeleteNote() {
        String wstgId = "WSTG-DEL-01";
        Note note = Note.create("Note to delete", wstgId);
        when(noteManager.getNotesByWstgId(wstgId)).thenReturn(List.of(note));

        notesPanel.setSelectedWstgId(wstgId);

        // Find Delete button (Note: Using helper method, assuming first "Delete" button
        // found corresponds to our note)
        JButton deleteButton = findButtonWithMessage(notesPanel, "Delete");
        assertNotNull(deleteButton, "Delete button should be present for existing note");

        // Set confirmation to true
        shouldConfirmDelete = true;

        deleteButton.doClick();

        // Verify deletion
        verify(noteManager).deleteNote(note.id());
    }

    @Test
    void testDeleteNoteCancelled() {
        String wstgId = "WSTG-DEL-02";
        Note note = Note.create("Note to keep", wstgId);
        when(noteManager.getNotesByWstgId(wstgId)).thenReturn(List.of(note));

        notesPanel.setSelectedWstgId(wstgId);

        JButton deleteButton = findButtonWithMessage(notesPanel, "Delete");
        assertNotNull(deleteButton);

        // Set confirmation to false
        shouldConfirmDelete = false;

        deleteButton.doClick();

        // Verify NO deletion
        verify(noteManager, never()).deleteNote(anyString());
    }

    private JButton findButtonWithMessage(java.awt.Container container, String text) {
        for (java.awt.Component comp : container.getComponents()) {
            if (comp instanceof JButton) {
                JButton btn = (JButton) comp;
                if (text.equals(btn.getText())) {
                    return btn;
                }
            } else if (comp instanceof java.awt.Container) {
                JButton found = findButtonWithMessage((java.awt.Container) comp, text);
                if (found != null)
                    return found;
            }
        }
        return null;
    }

    private JTextArea findEditorArea(java.awt.Container container) {
        for (java.awt.Component comp : container.getComponents()) {
            // Distinguish the editor textarea from the note display textareas.
            // The editor one is inside the editorPanel, which we can't easily identify by
            // class,
            // but we know the note display ones are not editable, while the editor one IS
            // editable.
            if (comp instanceof JTextArea) {
                JTextArea area = (JTextArea) comp;
                // Editor is created as new JTextArea(5, 20) and editable by default.
                // Display notes are setEditable(false).
                if (area.isEditable()) {
                    return area;
                }
            } else if (comp instanceof java.awt.Container) {
                JTextArea found = findEditorArea((java.awt.Container) comp);
                if (found != null)
                    return found;
            }
        }
        return null;
    }
}
