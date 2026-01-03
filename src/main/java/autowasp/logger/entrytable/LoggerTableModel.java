/*
 * Copyright (c) 2021 Government Technology Agency
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

import javax.swing.table.AbstractTableModel;
import java.util.List;

public class LoggerTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;
    private final autowasp.Autowasp extender;
    private final List<LoggerEntry> listFindingEntry;
    private final String[] columnNames = { "#", "Host", "Action", "Vuln Type", "Mapped to OWASP WSTG" };
    private int pageSize = 100;
    private int currentPage = 0;

    public LoggerTableModel(List<LoggerEntry> listFindingEntry, autowasp.Autowasp extender) {
        this.listFindingEntry = listFindingEntry;
        this.extender = extender;
    }

    // Pagination Methods
    public int getPageSize() {
        return pageSize;
    }

    public void setPageSize(int pageSize) {
        this.pageSize = pageSize;
        this.currentPage = 0;
        this.fireTableDataChanged();
    }

    public int getCurrentPage() {
        return currentPage;
    }

    public void setCurrentPage(int page) {
        if (page >= 0 && page < getTotalPages()) {
            this.currentPage = page;
            this.fireTableDataChanged();
        }
    }

    public int getTotalPages() {
        if (listFindingEntry.isEmpty())
            return 1;
        return (int) Math.ceil((double) listFindingEntry.size() / pageSize);
    }

    public void nextPage() {
        if (currentPage < getTotalPages() - 1) {
            currentPage++;
            this.fireTableDataChanged();
        }
    }

    public void previousPage() {
        if (currentPage > 0) {
            currentPage--;
            this.fireTableDataChanged();
        }
    }

    // Method to get column count
    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    // Method to get row count
    @Override
    public int getRowCount() {
        int start = currentPage * pageSize;
        if (start >= listFindingEntry.size())
            return 0;
        return Math.min(pageSize, listFindingEntry.size() - start);
    }

    // Method to get column name
    @Override
    public String getColumnName(int columnIndex) {
        return columnNames[columnIndex];
    }

    // Method to get value at selected row and column
    @Override
    public String getValueAt(int rowIndex, int columnIndex) {
        int actualIndex = (currentPage * pageSize) + rowIndex;
        if (actualIndex >= listFindingEntry.size())
            return "";

        String returnValue = "";
        LoggerEntry loggerEntry = listFindingEntry.get(actualIndex);
        switch (columnIndex) {
            case 0:
                returnValue = actualIndex + 1 + "";
                break;
            case 1:
                returnValue = loggerEntry.getHost();
                break;
            case 2:
                returnValue = loggerEntry.getAction();
                break;
            case 3:
                returnValue = loggerEntry.getVulnType();
                break;
            case 4:
                returnValue = loggerEntry.getChecklistIssue();
                break;
            default:
                break;
        }
        return returnValue;
    }

    // Method to set value at selected row and column
    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        int actualIndex = (currentPage * pageSize) + rowIndex;
        if (actualIndex >= listFindingEntry.size())
            return;

        LoggerEntry loggerEntry = listFindingEntry.get(actualIndex);
        if (columnIndex == 4) {
            loggerEntry.setChecklistIssue((String) aValue);
        }
    }

    private static final int MAX_ENTRIES = 10000;

    // Method to clear instance entry from table view
    public void clearLoggerList() {
        this.listFindingEntry.clear();
        this.currentPage = 0;
        this.fireTableDataChanged();
        if (extender.getExtenderPanelUI() != null) {
            extender.getExtenderPanelUI().updateLoggerPageLabel();
        }
    }

    // Method to re-add all entry from existing list to table view
    public void addAllLoggerEntry(LoggerEntry loggerEntry) {
        // Enforce maximum entries (FIFO)
        if (this.listFindingEntry.size() >= MAX_ENTRIES) {
            this.listFindingEntry.remove(0);
        }
        this.listFindingEntry.add(loggerEntry);
        this.fireTableDataChanged();
        if (extender.getExtenderPanelUI() != null) {
            extender.getExtenderPanelUI().updateLoggerPageLabel();
        }
    }

    // Method to update entry in table view
    public void updateLoggerEntryTable() {
        this.fireTableDataChanged();
    }

    // Method to restrict editable cell to those with dropdown combo.
    @Override
    public boolean isCellEditable(int row, int col) {
        return col == 4;
    }

    public LoggerEntry getLoggerEntryAt(int rowIndex) {
        int actualIndex = (currentPage * pageSize) + rowIndex;
        if (actualIndex >= 0 && actualIndex < listFindingEntry.size()) {
            return listFindingEntry.get(actualIndex);
        }
        return null;
    }

    public int getActualIndex(int rowIndex) {
        return (currentPage * pageSize) + rowIndex;
    }
}
