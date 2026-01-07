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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class InstantTypeAdapterTest {
    private Gson gson;

    @BeforeEach
    void setUp() {
        gson = new GsonBuilder()
                .registerTypeAdapter(Instant.class, new InstantTypeAdapter())
                .create();
    }

    @Test
    void testSerialization() {
        Instant now = Instant.now();
        String json = gson.toJson(now);
        assertEquals("\"" + now.toString() + "\"", json);
    }

    @Test
    void testDeserialization() {
        Instant now = Instant.now();
        String json = "\"" + now.toString() + "\"";
        Instant deserialized = gson.fromJson(json, Instant.class);
        assertEquals(now, deserialized);
    }

    @Test
    void testNullSerialization() {
        String json = gson.toJson(null, Instant.class);
        assertEquals("null", json);
    }

    @Test
    void testNullDeserialization() {
        Instant deserialized = gson.fromJson("null", Instant.class);
        assertNull(deserialized);
    }
}
