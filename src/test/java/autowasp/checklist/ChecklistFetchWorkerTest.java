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
import autowasp.logger.entrytable.LoggerTable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.swing.*;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ChecklistFetchWorkerTest {

    @Mock
    private Autowasp mockExtender;
    @Mock
    private ChecklistLogic mockChecklistLogic;
    @Mock
    private LoggerTable mockLoggerTable;
    @Mock
    private JLabel mockStatusLabel;
    @Mock
    private JProgressBar mockProgressBar;
    @Mock
    private JButton mockFetchButton;
    @Mock
    private JButton mockLocalButton;
    @Mock
    private JButton mockCancelButton;
    @Mock
    private JButton mockExcelButton;
    @Mock
    private JButton mockSaveButton;
    @Mock
    private Runnable mockOnComplete;

    private ChecklistFetchWorker worker;
    private AtomicBoolean running;
    private List<ChecklistEntry> checklistLog;

    @BeforeEach
    void setUp() throws Exception {
        running = new AtomicBoolean(true);
        checklistLog = new ArrayList<>();

        // Mock Autowasp dependencies
        // Mock Autowasp dependencies
        lenient().when(mockExtender.getChecklistLogic()).thenReturn(mockChecklistLogic);
        lenient().when(mockExtender.getLoggerTable()).thenReturn(mockLoggerTable);

        // Use reflection to set final field checklistLog
        Field checklistLogField = Autowasp.class.getField("checklistLog");
        checklistLogField.setAccessible(true);
        checklistLogField.set(mockExtender, checklistLog);

        worker = new ChecklistFetchWorker(new ChecklistFetchWorker.ChecklistFetchConfig(
                mockExtender,
                mockStatusLabel,
                mockProgressBar,
                mockFetchButton,
                mockLocalButton,
                mockCancelButton,
                mockExcelButton,
                mockSaveButton,
                running,
                mockOnComplete));
    }

    @Test
    void testDoInBackground_Success() {
        // ARRANGE
        List<String> mockUrls = Arrays.asList("http://example.com/1", "http://example.com/2");
        when(mockChecklistLogic.scrapeArticleURLs()).thenReturn(mockUrls);
        when(mockChecklistLogic.logNewChecklistEntry(anyString())).thenReturn(true);

        // ACT
        worker.doInBackground();

        // ASSERT
        verify(mockChecklistLogic).scrapeArticleURLs();
        verify(mockChecklistLogic, times(2)).logNewChecklistEntry(anyString());
    }

    @Test
    void testDoInBackground_Cancelled() {
        // ARRANGE
        List<String> mockUrls = Arrays.asList("http://example.com/1", "http://example.com/2");
        when(mockChecklistLogic.scrapeArticleURLs()).thenReturn(mockUrls);

        // Simulate cancellation before processing items
        running.set(false);

        // ACT
        worker.doInBackground();

        // ASSERT
        verify(mockChecklistLogic).scrapeArticleURLs();
        verify(mockChecklistLogic, never()).logNewChecklistEntry(anyString());
        // Verify checklistLog cleared - checking interaction with ArrayList mock or
        // list state.
        // Since it's a real list, we check state.
        assertTrue(checklistLog.isEmpty(), "Checklist log should be cleared on cancel");
    }

    @Test
    void testProcess_PublishesProgress() {
        // ARRANGE
        List<String> chunks = Arrays.asList("Status 1", "Status 2");

        // ACT
        worker.process(chunks);

        // ASSERT
        verify(mockStatusLabel).setText("Status 2");
    }

    @Test
    void testDone_Success() {
        // ARRANGE
        // ACT
        worker.done();

        // ASSERT
        verify(mockProgressBar).setVisible(false);
        verify(mockCancelButton).setEnabled(false);
        verify(mockFetchButton).setEnabled(true);
        verify(mockLocalButton).setEnabled(true);
        // Note: Specific status label verification depends on internal state
        // 'totalItems'
        // which implies different branches. We at least verify cleanup actions here.
    }
}
