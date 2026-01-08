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

package autowasp.notes;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.PersistedObject;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class NoteStoreTest {

    @Mock
    private MontoyaApi api;
    @Mock
    private Persistence persistence;
    @Mock
    private PersistedObject extensionData;

    private NoteStore noteStore;

    @BeforeEach
    void setUp() {
        when(api.persistence()).thenReturn(persistence);
        when(persistence.extensionData()).thenReturn(extensionData);
        noteStore = new NoteStore(api);
    }

    @Test
    void testLoadNotesEmpty() {
        when(extensionData.getString("autowasp.notes")).thenReturn(null);
        List<Note> notes = noteStore.loadNotes();
        assertTrue(notes.isEmpty());
    }

    @Test
    void testSaveAndLoadNotes() {
        Note note = Note.create("Test content", "WSTG-ID");
        noteStore.saveNotes(List.of(note));

        verify(extensionData).setString(eq("autowasp.notes"), anyString());

        // Mock loading back
        String json = new com.google.gson.GsonBuilder()
                .registerTypeAdapter(java.time.Instant.class, new InstantTypeAdapter())
                .create()
                .toJson(List.of(note));

        when(extensionData.getString("autowasp.notes")).thenReturn(json);

        List<Note> loadedNotes = noteStore.loadNotes();
        assertEquals(1, loadedNotes.size());
        assertEquals(note.id(), loadedNotes.get(0).id());
        assertEquals(note.content(), loadedNotes.get(0).content());
    }

    @Test
    void testLoadCorruptedJson() {
        when(extensionData.getString("autowasp.notes")).thenReturn("invalid json");
        List<Note> notes = noteStore.loadNotes();
        assertTrue(notes.isEmpty());
    }
}
