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

import java.time.Instant;
import org.junit.jupiter.api.Test;

class NoteTest {

    @Test
    void testNoteCreation() {
        String content = "Test content";
        String wstgId = "WSTG-INFO-01";
        Note note = Note.create(content, wstgId);

        assertNotNull(note.id());
        assertEquals(content, note.content());
        assertEquals(wstgId, note.wstgId());
        assertNotNull(note.createdAt());
        assertEquals(note.createdAt(), note.updatedAt());
    }

    @Test
    void testGeneralNoteCreation() {
        String content = "General content";
        Note note = Note.createGeneral(content);

        assertTrue(note.isGeneral());
        assertEquals(Note.GENERAL_WSTG_ID, note.wstgId());
    }

    @Test
    void testNoteValidation() {
        assertThrows(NullPointerException.class, () -> new Note(null, "content", "id", Instant.now(), Instant.now()));
        assertThrows(NullPointerException.class, () -> new Note("id", null, "id", Instant.now(), Instant.now()));
        assertThrows(NullPointerException.class, () -> new Note("id", "content", null, Instant.now(), Instant.now()));

        String longContent = "a".repeat(10001);
        assertThrows(IllegalArgumentException.class, () -> Note.create(longContent, "WSTG-ID"));
    }

    @Test
    void testWithUpdatedContent() throws InterruptedException {
        Note note = Note.create("Old content", "WSTG-ID");
        Instant originalUpdate = note.updatedAt();

        Thread.sleep(1); // Ensure timestamp change
        Note updatedNote = note.withUpdatedContent("New content");

        assertEquals("New content", updatedNote.content());
        assertEquals(note.id(), updatedNote.id());
        assertEquals(note.createdAt(), updatedNote.createdAt());
        assertTrue(updatedNote.updatedAt().isAfter(originalUpdate));
    }
}
