/*
 * Copyright (c) 2021 Government Technology Agency
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

package autowasp.managers;

import autowasp.Autowasp;
import autowasp.checklist.ChecklistEntry;
import autowasp.logger.entrytable.LoggerEntry;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

class ReportManagerTest {

    private Autowasp extender;
    private MontoyaApi api;
    private Logging logging;
    private LoggerManager loggerManager;
    private ChecklistManager checklistManager;
    private ReportManager reportManager;

    @BeforeEach
    void setUp() {
        extender = mock(Autowasp.class);
        api = mock(MontoyaApi.class);
        logging = mock(Logging.class);
        loggerManager = mock(LoggerManager.class);
        checklistManager = mock(ChecklistManager.class);

        when(extender.getApi()).thenReturn(api);
        when(api.logging()).thenReturn(logging);
        when(extender.getLoggerManager()).thenReturn(loggerManager);
        when(extender.getChecklistManager()).thenReturn(checklistManager);

        reportManager = new ReportManager(extender);
    }

    @Test
    void testGenerateExcelReport(@TempDir Path tempDir) {
        // Mock data
        List<LoggerEntry> loggerList = new ArrayList<>();
        LoggerEntry entry = new LoggerEntry("example.com", "GET", "XSS", "Reflected");

        // entry.getInstanceList().add(new InstanceEntry(...)); // Need valid mocks for
        // instances
        // Since InstanceEntry is hard to mock (requires RequestResponse), we'll skip
        // adding instances
        // to avoid complex setup, focusing on the file generation logic.

        loggerList.add(entry);
        when(loggerManager.getLoggerList()).thenReturn(loggerList);

        List<ChecklistEntry> checklistList = Collections.emptyList();
        when(checklistManager.getChecklistLog()).thenReturn(checklistList);

        // Test
        File reportFile = tempDir.resolve("report.xlsx").toFile();
        reportManager.generateExcelReport(reportFile);

        // Verify
        assertTrue(reportFile.exists());
        verify(logging).logToOutput(contains("Report generation successful"));
    }
}
