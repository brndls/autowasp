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

import autowasp.notes.Note;
import autowasp.notes.NoteChangeListener;
import autowasp.notes.NoteStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Manages CRUD operations for session notes.
 */
public class NoteManager {
    private final NoteStore store;
    private final List<Note> notes;
    private final List<NoteChangeListener> listeners;

    public NoteManager(NoteStore store) {
        this.store = store;
        this.notes = new ArrayList<>(store.loadNotes());
        this.listeners = new ArrayList<>();
    }

    // CRUD Operations

    public void addNote(Note note) {
        notes.add(note);
        saveAndNotify();
    }

    public void updateNote(Note updatedNote) {
        for (int i = 0; i < notes.size(); i++) {
            if (notes.get(i).id().equals(updatedNote.id())) {
                notes.set(i, updatedNote);
                saveAndNotify();
                return;
            }
        }
    }

    public void deleteNote(String noteId) {
        if (notes.removeIf(note -> note.id().equals(noteId))) {
            saveAndNotify();
        }
    }

    // Querying

    public List<Note> getNotesByWstgId(String wstgId) {
        return notes.stream()
                .filter(note -> note.wstgId().equals(wstgId))
                .sorted((n1, n2) -> n2.createdAt().compareTo(n1.createdAt())) // Newest first
                .collect(Collectors.toList());
    }

    public int getNoteCountByWstgId(String wstgId) {
        return (int) notes.stream()
                .filter(note -> note.wstgId().equals(wstgId))
                .count();
    }

    public List<Note> getGeneralNotes() {
        return getNotesByWstgId(Note.GENERAL_WSTG_ID);
    }

    public Map<String, List<Note>> getNotesGroupedByWstgId() {
        return notes.stream()
                .collect(Collectors.groupingBy(Note::wstgId));
    }

    // Listener Pattern

    public void addChangeListener(NoteChangeListener listener) {
        listeners.add(listener);
    }

    public void removeChangeListener(NoteChangeListener listener) {
        listeners.remove(listener);
    }

    private void saveAndNotify() {
        store.saveNotes(notes);
        for (NoteChangeListener listener : listeners) {
            listener.onNotesChanged();
        }
    }
}
