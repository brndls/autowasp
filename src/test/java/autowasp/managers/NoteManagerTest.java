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

package autowasp.managers;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import autowasp.notes.Note;
import autowasp.notes.NoteChangeListener;
import autowasp.notes.NoteStore;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class NoteManagerTest {

    @Mock
    private NoteStore store;
    @Mock
    private NoteChangeListener listener;

    private NoteManager noteManager;

    @BeforeEach
    void setUp() {
        when(store.loadNotes()).thenReturn(Collections.emptyList());
        noteManager = new NoteManager(store);
        noteManager.addChangeListener(listener);
    }

    @Test
    void testAddNote() {
        Note note = Note.create("Content", "WSTG-ID");
        noteManager.addNote(note);

        assertEquals(1, noteManager.getNoteCountByWstgId("WSTG-ID"));
        verify(store).saveNotes(anyList());
        verify(listener).onNotesChanged();
    }

    @Test
    void testUpdateNote() {
        Note note = Note.create("Old content", "WSTG-ID");
        noteManager.addNote(note);

        Note updatedNote = note.withUpdatedContent("New content");
        noteManager.updateNote(updatedNote);

        List<Note> notes = noteManager.getNotesByWstgId("WSTG-ID");
        assertEquals("New content", notes.get(0).content());
        verify(store, times(2)).saveNotes(anyList());
        verify(listener, times(2)).onNotesChanged();
    }

    @Test
    void testDeleteNote() {
        Note note = Note.create("Content", "WSTG-ID");
        noteManager.addNote(note);

        noteManager.deleteNote(note.id());
        assertEquals(0, noteManager.getNoteCountByWstgId("WSTG-ID"));
        verify(store, times(2)).saveNotes(anyList());
        verify(listener, times(2)).onNotesChanged();
    }

    @Test
    void testGetNotesGroupedByWstgId() {
        noteManager.addNote(Note.create("C1", "ID1"));
        noteManager.addNote(Note.create("C2", "ID1"));
        noteManager.addNote(Note.create("C3", "ID2"));

        Map<String, List<Note>> grouped = noteManager.getNotesGroupedByWstgId();
        assertEquals(2, grouped.get("ID1").size());
        assertEquals(1, grouped.get("ID2").size());
    }

    @Test
    void testGetGeneralNotes() {
        noteManager.addNote(Note.createGeneral("General"));
        noteManager.addNote(Note.create("Specific", "ID1"));

        assertEquals(1, noteManager.getGeneralNotes().size());
    }

    @Test
    void testRemoveChangeListener() {
        noteManager.removeChangeListener(listener);
        noteManager.addNote(Note.create("Content", "ID"));
        verify(listener, never()).onNotesChanged();
    }

    @Test
    void testUpdateNonExistentNote() {
        Note note = Note.create("Content", "ID");
        // Don't add it
        noteManager.updateNote(note);
        verify(store, never()).saveNotes(anyList());
    }

    @Test
    void testDeleteNonExistentNote() {
        noteManager.deleteNote("non-existent-id");
        verify(store, never()).saveNotes(anyList());
    }
}
