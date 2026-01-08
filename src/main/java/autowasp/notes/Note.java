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

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents a session note linked to a WSTG checklist item.
 */
public record Note(
        String id, // UUID for unique identification
        String content, // Note content (plain text, max 10000 chars)
        String wstgId, // Linked WSTG test case ID (e.g., "WSTG-INFO-01", or "GENERAL")
        Instant createdAt, // Creation timestamp
        Instant updatedAt // Last update timestamp
) {
    public static final String GENERAL_WSTG_ID = "GENERAL";

    public Note {
        Objects.requireNonNull(id, "Note ID cannot be null");
        Objects.requireNonNull(content, "Note content cannot be null");
        Objects.requireNonNull(wstgId, "WSTG ID cannot be null");
        Objects.requireNonNull(createdAt, "Created timestamp cannot be null");
        Objects.requireNonNull(updatedAt, "Updated timestamp cannot be null");

        if (content.length() > 10000) {
            throw new IllegalArgumentException("Note content too long (max 10000 chars)");
        }
    }

    public static Note create(String content, String wstgId) {
        Instant now = Instant.now();
        return new Note(UUID.randomUUID().toString(), content, wstgId, now, now);
    }

    public static Note createGeneral(String content) {
        return create(content, GENERAL_WSTG_ID);
    }

    public Note withUpdatedContent(String newContent) {
        return new Note(this.id, newContent, this.wstgId, this.createdAt, Instant.now());
    }

    public boolean isGeneral() {
        return GENERAL_WSTG_ID.equals(wstgId);
    }
}
