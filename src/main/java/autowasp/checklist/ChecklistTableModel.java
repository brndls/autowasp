/*
 * Copyright (c) 2021 Government Technology Agency
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

import autowasp.*;

import javax.swing.table.AbstractTableModel;

public class ChecklistTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private final transient Autowasp extender;
    private final String[] columnNames = { "Reference Number", "Category", "Test Name", "Test Case Completed",
            "To Exclude" };

    public ChecklistTableModel(Autowasp extender) {
        this.extender = extender;
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public int getRowCount() {
        return extender.checklistLog.size();
    }

    @Override
    public String getColumnName(int columnIndex) {
        return columnNames[columnIndex];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ChecklistEntry checklistEntry = extender.checklistLog.get(rowIndex);
        if (columnIndex == 0) {
            return checklistEntry.getRefNumber();
        }
        if (columnIndex == 1) {
            return checklistEntry.getCategory();
        }
        if (columnIndex == 2) {
            return checklistEntry.getTestName();
        }
        if (columnIndex == 3) {
            return checklistEntry.isTestcaseCompleted();
        }
        if (columnIndex == 4) {
            return checklistEntry.isExcluded();
        }
        return "";
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return (getValueAt(0, column).getClass());
    }

    // Method to set value at selected row and column
    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        ChecklistEntry checklistEntry = extender.checklistLog.get(rowIndex);
        if (columnIndex == 3) {
            checklistEntry.setTestCaseCompleted((Boolean) aValue);
        } else if (columnIndex == 4) {
            checklistEntry.setExclusion((Boolean) aValue);
            // Refresh Mapping list for logger tab
            extender.getLoggerTable().resetList();
        }
    }

    public void addValueAt(ChecklistEntry entry, int rowIndex, int columnIndex) {
        extender.checklistLog.add(entry);
        fireTableRowsInserted(rowIndex, columnIndex);
    }

    // Method to restrict editable cell to those with dropdown combo.
    @Override
    public boolean isCellEditable(int row, int col) {
        return col == 3 || col == 4;
    }
}
