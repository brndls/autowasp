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

package autowasp.logger.entrytable;

import autowasp.Autowasp;
import autowasp.ExtenderPanelUI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class LoggerTableModelPaginationTest {

    private LoggerTableModel model;
    private List<LoggerEntry> list;
    private Autowasp extender;
    private ExtenderPanelUI ui;

    @BeforeEach
    void setUp() {
        list = new ArrayList<>();
        extender = mock(Autowasp.class);
        ui = mock(ExtenderPanelUI.class);
        when(extender.getExtenderPanelUI()).thenReturn(ui);
        model = new LoggerTableModel(list, extender);
        model.setPageSize(100);
    }

    @Test
    void testMaxEntriesEnforcement() {
        // Add 10,005 entries
        for (int i = 0; i < 10005; i++) {
            model.addAllLoggerEntry(new LoggerEntry("host", "action", "vuln", "issue"));
        }

        // Should be capped at 10,000
        assertEquals(10000, list.size());
        verify(ui, atLeastOnce()).updateLoggerPageLabel();
    }

    @Test
    void testPaginationLogic() {
        // Add 250 entries (Page 0: 0-99, Page 1: 100-199, Page 2: 200-249)
        for (int i = 0; i < 250; i++) {
            list.add(new LoggerEntry("host" + i, "action", "vuln", "issue"));
        }

        assertEquals(3, model.getTotalPages());
        assertEquals(100, model.getRowCount()); // Page 0

        model.setCurrentPage(1);
        assertEquals(1, model.getCurrentPage());
        assertEquals(100, model.getRowCount()); // Page 1
        assertEquals("101", model.getValueAt(0, 0)); // First item on page 1 is index 100 (+1)

        model.setCurrentPage(2);
        assertEquals(50, model.getRowCount()); // Page 2 has only 50 items
        assertEquals("201", model.getValueAt(0, 0));
    }

    @Test
    void testClearListResetsPage() {
        for (int i = 0; i < 250; i++)
            list.add(new LoggerEntry("h", "a", "v", "i"));
        model.setCurrentPage(2);

        model.clearLoggerList();

        assertEquals(0, list.size());
        assertEquals(0, model.getCurrentPage());
        verify(ui, atLeastOnce()).updateLoggerPageLabel();
    }
}
