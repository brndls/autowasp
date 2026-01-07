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

import autowasp.Autowasp;
import autowasp.checklist.ChecklistEntry;
import autowasp.managers.NoteManager;
import java.awt.*;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

/**
 * Combined panel for the WSTG checklist table and session notes.
 */
public class ChecklistPanel extends JPanel {
    private final Autowasp extender;
    private final ChecklistNotesPanel notesPanel;
    private final JTextField searchField;
    private final JScrollPane tableScrollPane;

    public ChecklistPanel(Autowasp extender, NoteManager noteManager) {
        this.extender = extender;
        setLayout(new BorderLayout());

        // Notes Panel
        this.notesPanel = new ChecklistNotesPanel(noteManager);

        // Search Panel
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEADING, 5, 2));
        searchPanel.add(new JLabel("Search WSTG: "));
        searchField = new JTextField(20);

        // Theme application
        autowasp.managers.ThemeManager themeManager = extender.getUIManager().getThemeManager();
        searchField.setBackground(themeManager.getBackgroundColor());
        searchField.setForeground(themeManager.getForegroundColor());
        searchField.setCaretColor(themeManager.getForegroundColor());
        searchPanel.add(searchField);

        // Table Sorter
        TableRowSorter<TableModel> sorter = new TableRowSorter<>(
                extender.getChecklistManager().getChecklistTable().getModel());
        extender.getChecklistManager().getChecklistTable().setRowSorter(sorter);

        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                updateFilter();
            }

            public void removeUpdate(DocumentEvent e) {
                updateFilter();
            }

            public void changedUpdate(DocumentEvent e) {
                updateFilter();
            }

            private void updateFilter() {
                String text = searchField.getText();
                if (text.trim().isEmpty()) {
                    sorter.setRowFilter(null);
                } else {
                    sorter.setRowFilter(RowFilter.regexFilter("(?i)" + text));
                }
            }
        });

        // Table Panel
        JPanel tableWithSearchPanel = new JPanel(new BorderLayout());
        tableWithSearchPanel.add(searchPanel, BorderLayout.NORTH);
        tableScrollPane = new JScrollPane(extender.getChecklistManager().getChecklistTable());
        tableScrollPane.setPreferredSize(new Dimension(300, 200));
        tableScrollPane.setBorder(new EmptyBorder(0, 0, 10, 0));
        tableWithSearchPanel.add(tableScrollPane, BorderLayout.CENTER);

        // Selection Listener for Table
        extender.getChecklistManager().getChecklistTable().getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = extender.getChecklistManager().getChecklistTable().getSelectedRow();
                if (selectedRow != -1) {
                    int modelRow = extender.getChecklistManager().getChecklistTable()
                            .convertRowIndexToModel(selectedRow);
                    ChecklistEntry entry = extender.getChecklistManager().getChecklistLog().get(modelRow);
                    notesPanel.setSelectedWstgId(entry.getRefNumber());
                } else {
                    notesPanel.setSelectedWstgId(null);
                }
            }
        });

        // Split Pane (Horizontal) for Table and Notes
        JSplitPane horizontalSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        horizontalSplitPane.setLeftComponent(tableWithSearchPanel);
        horizontalSplitPane.setRightComponent(notesPanel);
        horizontalSplitPane.setResizeWeight(0.7);
        horizontalSplitPane.setDividerLocation(0.7);

        add(horizontalSplitPane, BorderLayout.CENTER);
    }

    public ChecklistNotesPanel getNotesPanel() {
        return notesPanel;
    }
}
