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

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Manages persistence of notes to Burp project files.
 */
public class NoteStore {
    private static final String NOTES_KEY = "autowasp.notes";
    private final MontoyaApi api;
    private final Gson gson;

    public NoteStore(MontoyaApi api) {
        this.api = api;
        this.gson = new GsonBuilder()
                .registerTypeAdapter(Instant.class, new InstantTypeAdapter())
                .create();
    }

    public List<Note> loadNotes() {
        String json = api.persistence().extensionData().getString(NOTES_KEY);
        if (json == null || json.isBlank()) {
            return new ArrayList<>();
        }
        try {
            Type listType = new TypeToken<List<Note>>() {
            }.getType();
            return gson.fromJson(json, listType);
        } catch (Exception e) {
            // Handle corrupted JSON
            return new ArrayList<>();
        }
    }

    public void saveNotes(List<Note> notes) {
        String json = gson.toJson(notes);
        api.persistence().extensionData().setString(NOTES_KEY, json);
    }
}
