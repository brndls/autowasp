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

package autowasp.checklist;

import autowasp.Autowasp;

import javax.swing.*;
import javax.swing.table.TableModel;

public class ChecklistTable extends JTable {

    private static final long serialVersionUID = 1L;

    private final transient Autowasp extender;

    public ChecklistTable(TableModel tableModel, Autowasp extender) {
        super(tableModel);
        this.extender = extender;
        // Even parameters are default values for each column, odd parameters are max
        // value for that column
        setColumnWidths(200, 300, 1350, 1800, 150, 200, 200, 300);
        setupStatusColumn();
        extender.getUIManager().getThemeManager().applyThemeToTable(this);
    }

    private void setupStatusColumn() {
        JComboBox<ChecklistStatus> statusCombo = new JComboBox<>(ChecklistStatus.values());
        getColumnModel().getColumn(2).setCellEditor(new DefaultCellEditor(statusCombo));

        getColumnModel().getColumn(2).setCellRenderer(new javax.swing.table.DefaultTableCellRenderer() {
            @Override
            public java.awt.Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                    boolean hasFocus, int row, int column) {
                java.awt.Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row,
                        column);
                if (value instanceof ChecklistStatus status && !isSelected) {
                    c.setForeground(status.getColor());
                    c.setFont(c.getFont().deriveFont(java.awt.Font.BOLD));
                }
                return c;
            }
        });
    }

    public void setColumnWidths(int... widths) {
        for (int i = 0; i < widths.length; i += 2) {
            if ((i / 2) < columnModel.getColumnCount()) {
                columnModel.getColumn(i / 2).setPreferredWidth(widths[i]);
                columnModel.getColumn(i / 2).setMaxWidth(widths[i + 1]);
            }
        }
    }

    @Override
    public java.awt.Component prepareRenderer(javax.swing.table.TableCellRenderer renderer, int row, int column) {
        java.awt.Component c = super.prepareRenderer(renderer, row, column);
        if (!isRowSelected(row)) {
            c.setBackground(
                    row % 2 == 0 ? getBackground() : extender.getUIManager().getThemeManager().getAlternateRowColor());
        }
        return c;
    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend) {
        int modelRow = convertRowIndexToModel(row);
        ChecklistEntry checklistEntry = extender.getChecklistManager().getChecklistLog().get(modelRow);

        // Sets the text for each of the bottom tab panes. Setting the caret position to
        // 0 makes sure that the user starts reading from the top
        extender.getUIManager().getExtenderPanelUI().getSummaryTextPane().setText(checklistEntry.getSummaryHTML());
        extender.getUIManager().getExtenderPanelUI().getSummaryTextPane().setCaretPosition(0);
        extender.getUIManager().getExtenderPanelUI().getHowToTestTextPane().setText(checklistEntry.getHowToTestHTML());
        extender.getUIManager().getExtenderPanelUI().getHowToTestTextPane().setCaretPosition(0);
        extender.getUIManager().getExtenderPanelUI().getReferencesTextPane()
                .setText(checklistEntry.getReferencesHTML());
        extender.getUIManager().getExtenderPanelUI().getReferencesTextPane().setCaretPosition(0);

        super.changeSelection(row, col, toggle, extend);
    }
}
