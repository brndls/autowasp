/*
 * Copyright (c) 2024-2026 Autowasp Contributors
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

package autowasp.checklist;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Loads WSTG checklist from bundled JSON resource.
 * Provides offline support (BApp Store Criteria #8).
 */
public class LocalChecklistLoader {

    private static final String CHECKLIST_PATH = "/wstg/checklist.json";

    /**
     * Load checklist entries from bundled JSON resource.
     *
     * @return List of ChecklistEntry objects, empty list if loading fails
     */
    public List<ChecklistEntry> loadFromResources() {
        List<ChecklistEntry> entries = new ArrayList<>();

        try (InputStream is = getResourceAsStream(CHECKLIST_PATH)) {
            if (is == null) {
                return entries;
            }

            Reader reader = new InputStreamReader(is, StandardCharsets.UTF_8);
            JsonObject root = JsonParser.parseReader(reader).getAsJsonObject();
            JsonObject categories = root.getAsJsonObject("categories");

            for (Map.Entry<String, JsonElement> categoryEntry : categories.entrySet()) {
                String categoryName = categoryEntry.getKey();
                JsonObject categoryObj = categoryEntry.getValue().getAsJsonObject();

                for (JsonElement testElement : categoryObj.getAsJsonArray("tests")) {
                    JsonObject test = testElement.getAsJsonObject();

                    String refNumber = test.get("id").getAsString();
                    String testName = test.get("name").getAsString();
                    String reference = test.get("reference").getAsString();

                    // Objectives -> Summary HTML (sebagai bullet list)
                    StringBuilder summaryHtml = new StringBuilder("<ul>");
                    for (JsonElement objective : test.getAsJsonArray("objectives")) {
                        String objText = objective.getAsString();
                        if (!objText.isEmpty()) {
                            summaryHtml.append("<li>").append(objText).append("</li>");
                        }
                    }
                    summaryHtml.append("</ul>");

                    // Buat ChecklistEntry menggunakan constructor kedua
                    ChecklistEntry entry = new ChecklistEntry(
                            refNumber,
                            categoryName,
                            testName,
                            summaryHtml.toString(),
                            "<p>See OWASP reference for detailed testing methodology.</p>",
                            "<p><a href=\"" + reference + "\">" + refNumber + "</a></p>",
                            reference);

                    entries.add(entry);
                }
            }
        } catch (Exception e) {
            // Return empty list on any error
            return new ArrayList<>();
        }

        return entries;
    }

    /**
     * Get resource as stream. Protected for testability.
     *
     * @param path Resource path
     * @return InputStream for the resource, or null if not found
     */
    protected InputStream getResourceAsStream(String path) {
        return getClass().getResourceAsStream(path);
    }

    /**
     * Get the bundled WSTG version info.
     *
     * @return Version string (e.g., "4.2")
     */
    public String getVersion() {
        return "4.2";
    }
}
