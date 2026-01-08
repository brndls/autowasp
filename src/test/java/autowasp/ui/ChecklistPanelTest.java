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

package autowasp.ui;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import autowasp.Autowasp;
import autowasp.checklist.ChecklistEntry;
import autowasp.checklist.ChecklistTable;
import autowasp.managers.ChecklistManager;
import autowasp.managers.NoteManager;
import autowasp.managers.ThemeManager;
import autowasp.managers.UIManager;
import java.awt.Color;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ChecklistPanelTest {

    private Autowasp extender;
    private NoteManager noteManager;
    private ChecklistManager checklistManager;
    private UIManager uiManager;
    private ThemeManager themeManager;
    private ChecklistTable checklistTable;

    private ChecklistPanel checklistPanel;

    @BeforeEach
    void setUp() {
        extender = mock(Autowasp.class);
        noteManager = mock(NoteManager.class);
        checklistManager = mock(ChecklistManager.class);
        uiManager = mock(UIManager.class);
        themeManager = mock(ThemeManager.class);

        // Required for ChecklistTable construction
        when(extender.getUIManager()).thenReturn(uiManager);
        when(uiManager.getThemeManager()).thenReturn(themeManager);
        when(themeManager.getBackgroundColor()).thenReturn(Color.WHITE);
        when(themeManager.getForegroundColor()).thenReturn(Color.BLACK);

        // Mock chain for ChecklistPanel
        when(extender.getChecklistManager()).thenReturn(checklistManager);

        // Use a REAL ChecklistTable to avoid Swing internal mocking issues (like
        // getTreeLock)
        DefaultTableModel model = new DefaultTableModel(new Object[] { "ID", "Ref", "Name", "Status", "Comment" }, 1);
        checklistTable = new ChecklistTable(model, extender);
        when(checklistManager.getChecklistTable()).thenReturn(checklistTable);

        checklistPanel = new ChecklistPanel(extender, noteManager);
    }

    @Test
    void testInitialization() {
        assertNotNull(checklistPanel);
        assertNotNull(checklistPanel.getNotesPanel());
    }

    @Test
    void testTableSelectionChangesNotes() {
        List<ChecklistEntry> checklistLog = new ArrayList<>();
        ChecklistEntry entry = new ChecklistEntry("WSTG-ID-01", "Cat", "Name", "Sum", "How", "Ref", "http://ex.com");
        checklistLog.add(entry);
        when(checklistManager.getChecklistLog()).thenReturn(checklistLog);

        when(noteManager.getNotesByWstgId("WSTG-ID-01")).thenReturn(Collections.emptyList());

        // Trigger selection on the real table
        checklistTable.setRowSelectionInterval(0, 0);

        // Allow some time for EDT events if any
        // Allow some time for EDT events if any
        try {
            // noinspection BusyWait
            Thread.sleep(100);
        } catch (InterruptedException ignored) {
            // Ignored for test timing
        }

        verify(noteManager, atLeastOnce()).getNotesByWstgId("WSTG-ID-01");
    }

    @Test
    void testTableSelectionCleared() {
        checklistTable.clearSelection();
        assertNotNull(checklistPanel.getNotesPanel());
    }

    @Test
    void testSearchFilter() {
        // Find the search field via component traversal
        JTextField searchField = findSearchField(checklistPanel);
        assertNotNull(searchField, "Search field should exist");

        // Set text to trigger filter
        searchField.setText("Info");

        // RowSorter is set on the table, verify it has a filter
        assertNotNull(checklistTable.getRowSorter(), "RowSorter should be set");
        // We can't easily inspect the RowFilter instance as it's private inside
        // TableRowSorter,
        // but we can verify that setting text didn't crash and presumably updated the
        // sorter.
        // A deeper test would be to inspect the view row count if we had data in the
        // model that matches/mismatches.
    }

    private JTextField findSearchField(java.awt.Container container) {
        for (java.awt.Component comp : container.getComponents()) {
            if (comp instanceof JTextField) {
                return (JTextField) comp;
            } else if (comp instanceof java.awt.Container) {
                JTextField found = findSearchField((java.awt.Container) comp);
                if (found != null)
                    return found;
            }
        }
        return null;
    }
}
