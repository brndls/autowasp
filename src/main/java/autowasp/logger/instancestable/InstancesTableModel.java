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

package autowasp.logger.instancestable;

import javax.swing.table.AbstractTableModel;
import java.util.List;

public class InstancesTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;
    private final List<InstanceEntry> listInstanceEntry;
    private final String[] columnNames = { "ID", "Instance URL Path", "Confidence", "Severity" };

    public InstancesTableModel(List<InstanceEntry> listInstanceEntry) {
        this.listInstanceEntry = listInstanceEntry;
    }

    // Method to get column count
    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    // Method to get row count
    @Override
    public int getRowCount() {
        return listInstanceEntry.size();
    }

    // Method to get column name
    @Override
    public String getColumnName(int columnIndex) {
        return columnNames[columnIndex];
    }

    // Method to get value at selected row and column
    @Override
    public String getValueAt(int rowIndex, int columnIndex) {
        String returnValue = "";
        InstanceEntry instanceEntry = listInstanceEntry.get(rowIndex);
        switch (columnIndex) {
            case 0:
                returnValue = rowIndex + 1 + "";
                break;
            case 1:
                returnValue = instanceEntry.getUrl();
                break;
            case 2:
                returnValue = instanceEntry.getConfidence();
                break;
            case 3:
                returnValue = instanceEntry.getSeverity();
                break;
            default:
                break;
        }

        return returnValue;
    }

    // Method to set value at selected row and column
    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        InstanceEntry instanceEntry = listInstanceEntry.get(rowIndex);
        if (columnIndex == 2) {
            instanceEntry.setConfidence((String) aValue);
        }
        if (columnIndex == 3) {
            instanceEntry.setSeverity((String) aValue);
        }
    }

    // Method to re-add all instances from existing list to table view
    public void addAllInstanceEntry(List<InstanceEntry> listInstanceEntry) {
        this.listInstanceEntry.addAll(listInstanceEntry);
        this.fireTableDataChanged();
    }

    // Method to clear instance entry from table view
    public void clearInstanceEntryList() {
        this.listInstanceEntry.clear();
    }

    // Method to restrict editable cell to those with dropdown combo.
    @Override
    public boolean isCellEditable(int row, int col) {
        return col == 2 || col == 3;
    }

}
