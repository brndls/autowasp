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

package autowasp.checklist;

import autowasp.Autowasp;
import autowasp.ExtenderPanelUI;
import burp.api.montoya.MontoyaApi;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.swing.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for ChecklistLogic.
 */
@ExtendWith(MockitoExtension.class)
class ChecklistLogicTest {

    @Mock
    private Autowasp mockExtender;

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private MontoyaApi mockApi;

    @Mock
    private JFrame mockSuiteFrame;

    @Mock
    private ExtenderPanelUI mockPanelUI;

    @Mock
    private JLabel mockStatusLabel;

    @Mock
    private ChecklistTableModel mockChecklistTableModel;

    @Mock
    private autowasp.managers.ChecklistManager mockChecklistManager;
    @Mock
    private autowasp.managers.LoggerManager mockLoggerManager;
    @Mock
    private autowasp.managers.UIManager mockUIManager;

    private ChecklistLogic checklistLogic;
    private List<ChecklistEntry> checklistLog;
    private Map<String, ChecklistEntry> checkListHashMap;

    @BeforeEach
    void setUp() {
        // Initialize data structures
        checklistLog = new ArrayList<>();
        checkListHashMap = new HashMap<>();

        // Setup Extender mocks
        lenient().when(mockExtender.getChecklistManager()).thenReturn(mockChecklistManager);
        lenient().when(mockExtender.getLoggerManager()).thenReturn(mockLoggerManager);
        lenient().when(mockExtender.getUIManager()).thenReturn(mockUIManager);

        // Setup UIManager
        lenient().when(mockUIManager.getExtenderPanelUI()).thenReturn(mockPanelUI);

        // Stub getter methods for encapsulated fields
        lenient().when(mockPanelUI.getScanStatusLabel()).thenReturn(mockStatusLabel);

        // Setup ChecklistManager
        lenient().when(mockChecklistManager.getChecklistTableModel()).thenReturn(mockChecklistTableModel);
        lenient().when(mockChecklistManager.getChecklistLog()).thenReturn(checklistLog);
        lenient().when(mockChecklistManager.getCheckListHashMap()).thenReturn(checkListHashMap);

        // Common API mocks
        lenient().when(mockExtender.getApi()).thenReturn(mockApi);
        lenient().when(mockApi.userInterface().swingUtils().suiteFrame()).thenReturn(mockSuiteFrame);

        checklistLogic = new ChecklistLogic(mockExtender);
    }

    @Test
    void testToHash(@org.junit.jupiter.api.io.TempDir java.nio.file.Path tempDir) throws Exception {
        // Create a temporary file
        java.io.File tempFile = tempDir.resolve("testHash.txt").toFile();
        try (java.io.FileWriter writer = new java.io.FileWriter(tempFile)) {
            writer.write("test content");
        }

        // Calculate hash
        String hash = checklistLogic.toHash(tempFile);

        // SHA-256 of "test content"
        assertEquals("6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72", hash);
    }

    @Test
    void testSaveLocalCopy(@org.junit.jupiter.api.io.TempDir java.nio.file.Path tempDir) throws IOException {
        String destPath = tempDir.toAbsolutePath().toString();

        // Setup mock data
        ChecklistEntry entry1 = new ChecklistEntry(new HashMap<>(), new HashMap<>(), "url1");
        entry1.setRefNumber("REF1");
        checklistLog.add(entry1);

        checklistLogic.saveLocalCopy(destPath);

        // Verify file created
        java.io.File savedFile = new java.io.File(destPath, "OWASP_WSTG_local");
        assertTrue(savedFile.exists());
        assertTrue(savedFile.length() > 0);

        // Verify UI feedback
        verify(mockStatusLabel, atLeastOnce()).setText(contains("File saved to"));
        verify(mockExtender).issueAlert(contains("File saved to"));
    }
}
