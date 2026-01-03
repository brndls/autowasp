/*
 * Copyright (c) 2026 Autowasp Contributors
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

package autowasp.persistence;

import autowasp.checklist.ChecklistEntry;
import autowasp.logger.entrytable.LoggerEntry;
import autowasp.logger.instancestable.InstanceEntry;
import autowasp.http.HTTPRequestResponse;
import autowasp.http.HTTPService;
import burp.api.montoya.MontoyaApi;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.PersistedObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AutowaspPersistenceTest {

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private MontoyaApi mockApi;

    @Mock
    private Persistence mockPersistence;

    @Mock
    private PersistedObject mockPersistedObject;

    @Mock
    private Logging mockLogging;

    private AutowaspPersistence autowaspPersistence;

    @BeforeEach
    void setUp() {
        lenient().when(mockApi.persistence()).thenReturn(mockPersistence);
        lenient().when(mockPersistence.extensionData()).thenReturn(mockPersistedObject);
        lenient().when(mockApi.logging()).thenReturn(mockLogging);
        autowaspPersistence = new AutowaspPersistence(mockApi);
    }

    @Test
    void testSaveChecklistState() {
        List<ChecklistEntry> entries = new ArrayList<>();
        Map<String, String> table = new HashMap<>();
        table.put("Reference Number", "WSTG-INFO-01");
        table.put("Category", "INFO");
        table.put("Test Name", "Info Gathering");

        ChecklistEntry entry = new ChecklistEntry(table, new HashMap<>(), "http://url");
        entry.setTestCaseCompleted(true);
        entry.setPenTesterComments("Test Comment");
        entries.add(entry);

        autowaspPersistence.saveChecklistState(entries);

        verify(mockPersistedObject).setString(eq("autowasp_checklist_state_json"), anyString());
    }

    @Test
    void testLoadChecklistState() {
        String json = "[{\"refNumber\":\"WSTG-INFO-01\",\"excluded\":false,\"completed\":true,\"comments\":\"Test Comment\",\"evidence\":\"Test Evidence\"}]";
        when(mockPersistedObject.getString("autowasp_checklist_state_json")).thenReturn(json);

        List<ChecklistState> results = autowaspPersistence.loadChecklistState();

        assertEquals(1, results.size());
        assertEquals("WSTG-INFO-01", results.get(0).refNumber());
        assertTrue(results.get(0).completed());
        assertEquals("Test Comment", results.get(0).comments());
    }

    @Test
    void testLoadChecklistStateEmpty() {
        when(mockPersistedObject.getString("autowasp_checklist_state_json")).thenReturn(null);

        List<ChecklistState> results = autowaspPersistence.loadChecklistState();

        assertNotNull(results);
        assertTrue(results.isEmpty());
    }

    @Test
    void testLoadChecklistStateCorrupted() {
        when(mockPersistedObject.getString("autowasp_checklist_state_json")).thenReturn("invalid-json");

        List<ChecklistState> results = autowaspPersistence.loadChecklistState();

        assertNotNull(results);
        assertTrue(results.isEmpty());
        verify(mockLogging).logToError(contains("Failed to load checklist state"));
    }

    @Test
    void testSaveLoggerState() {
        List<LoggerEntry> entries = new ArrayList<>();
        LoggerEntry entry = new LoggerEntry("host", "action", "vuln", "issue");

        HTTPService svc = new HTTPService("host", 443, true);
        HTTPRequestResponse reqRes = new HTTPRequestResponse(new byte[] { 1, 2, 3 }, new byte[] { 4, 5 }, svc);
        InstanceEntry inst = new InstanceEntry(null, "Certain", "High", reqRes);
        entry.addInstance(inst);
        entries.add(entry);

        autowaspPersistence.saveLoggerState(entries);

        verify(mockPersistedObject).setString(eq("autowasp_logger_state_json"), anyString());
    }

    @Test
    void testLoadLoggerState() {
        String json = "[{\"host\":\"host\",\"action\":\"action\",\"instances\":[]}]";
        when(mockPersistedObject.getString("autowasp_logger_state_json")).thenReturn(json);

        List<LoggerState> results = autowaspPersistence.loadLoggerState();

        assertEquals(1, results.size());
        assertEquals("host", results.get(0).host());
    }
}
