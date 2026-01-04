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

import autowasp.Autowasp;
import autowasp.checklist.ChecklistEntry;
// Explicit import might be needed if moved

import javax.swing.DefaultCellEditor;
import javax.swing.JComboBox;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;

public class LoggerTable extends JTable {

    private static final long serialVersionUID = 1L;
    private final transient Autowasp extender;
    private int currentRow;

    public LoggerTable(TableModel tableModel, Autowasp extender) {
        super(tableModel);
        this.extender = extender;
        setColumnWidths(50, 50, 150, 300, 150, 300, 150, 300, 200, Integer.MAX_VALUE);
        extender.getUIManager().getThemeManager().applyThemeToTable(this);
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

    public void setColumnWidths(int... widths) {
        for (int i = 0; i < widths.length; i += 2) {
            if ((i / 2) < columnModel.getColumnCount()) {
                columnModel.getColumn(i / 2).setPreferredWidth(widths[i]);
                columnModel.getColumn(i / 2).setMaxWidth(widths[i + 1]);
            }
        }
    }

    // Method for table view change selection
    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend) {
        int modelRow = convertRowIndexToModel(row);
        // Get the model and the actual entry
        LoggerTableModel model = (LoggerTableModel) getModel();
        LoggerEntry loggerEntry = model.getLoggerEntryAt(modelRow);

        if (loggerEntry != null) {
            currentRow = model.getActualIndex(modelRow);
            extender.getUIManager().setCurrentEntryRow(currentRow);
            extender.getUIManager().getExtenderPanelUI().getPenTesterCommentBox()
                    .setText(loggerEntry.getPenTesterComments());

            extender.getUIManager().getExtenderPanelUI().getEvidenceBox().setText(loggerEntry.getEvidence());
            extender.getLoggerManager().getInstancesTableModel().clearInstanceEntryList();
            extender.getLoggerManager().getInstancesTableModel().addAllInstanceEntry(loggerEntry.getInstanceList());

            super.changeSelection(row, col, toggle, extend);
            extender.getUIManager().getExtenderPanelUI().deleteEntryButtonEnabled();
        }
    }

    // Method to modify pentester's comments text field
    public void modifyComments(String comments) {
        extender.getLoggerManager().getLoggerList().get(currentRow).setPenTesterComments(comments);
        extender.getLoggerManager().getLoggerTableModel().fireTableDataChanged();
        // Checks if finding is mapped to a checklist entry
        // If it is, set the pentesterComments variable for that checklist entry
        if (extender.getLoggerManager().getLoggerList().get(currentRow).getIssueNumber() != null) {
            int issueNumber = extender.getLoggerManager().getLoggerList().get(currentRow).getIssueNumber();
            String finalComments = comments + "\n";
            extender.getChecklistManager().getChecklistLog().get(issueNumber).setPenTesterComments(finalComments);
            extender.getChecklistManager().getChecklistTableModel().triggerAutoSave();
        }
        extender.getLoggerManager().getLoggerTableModel().triggerAutoSave();
    }

    // Method to modify pentester's evidences text field
    public void modifyEvidence(String evidences) {
        extender.getLoggerManager().getLoggerList().get(currentRow).setEvidence(evidences);
        extender.getLoggerManager().getLoggerTableModel().fireTableDataChanged();
        // Checks if finding is mapped to a checklist entry
        // If it is, set the evidence variable for that checklist entry
        if (extender.getLoggerManager().getLoggerList().get(currentRow).getIssueNumber() != null) {
            int issueNumber = extender.getLoggerManager().getLoggerList().get(currentRow).getIssueNumber();
            String finalEvidence = evidences + "\n";
            extender.getChecklistManager().getChecklistLog().get(issueNumber).setEvidence(finalEvidence);
            extender.getChecklistManager().getChecklistTableModel().triggerAutoSave();
        }
        extender.getLoggerManager().getLoggerTableModel().triggerAutoSave();
    }

    // Method to setup WSTG mapping column with dropdown combo
    public void setUpIssueColumn(TableColumn column) {
        column.setCellEditor(new DefaultCellEditor(extender.getUIManager().getComboBox()));
    }

    // Method to generate WSTG list for dropdown
    public void generateWSTGList() {
        JComboBox<String> comboBox = extender.getUIManager().getComboBox();
        // Add an N.A. to mark finding as false positive
        comboBox.addItem("N.A.");
        for (ChecklistEntry entry : extender.getChecklistManager().getChecklistLog()) {
            String comboEntry = entry.getRefNumber() + " - " + entry.getTestName();
            comboBox.addItem(comboEntry);
        }
    }

    // Method to reset WSTG mapping column
    public void resetList() {
        extender.getUIManager().getComboBox().removeAllItems();
        JComboBox<String> comboBox = extender.getUIManager().getComboBox();
        // Add an N.A. to mark finding as false positive
        comboBox.addItem("N.A.");
        for (ChecklistEntry entry : extender.getChecklistManager().getChecklistLog()) {
            if (Boolean.FALSE.equals(entry.isExcluded())) {
                String comboEntry = entry.getRefNumber() + " - " + entry.getTestName();
                comboBox.addItem(comboEntry);
            }
        }
    }

    // Method to delete logger entry
    public void deleteEntry() {
        if (currentRow >= 0 && currentRow < extender.getLoggerManager().getLoggerList().size()) {
            extender.getUIManager().getExtenderPanelUI().getDeleteEntryButton().setEnabled(false);
            extender.getLoggerManager().getLoggerList().remove(currentRow);
            // update UI
            // Inform user about entry deletion
            extender.getUIManager().getExtenderPanelUI().getScanStatusLabel().setText("Entry deleted");
            extender.issueAlert("Entry deleted");
            // Repaint logger entries table
            extender.getLoggerManager().getLoggerTableModel().updateLoggerEntryTable();
            // Clear instance table
            extender.getLoggerManager().getInstancesTableModel().clearInstanceEntryList();
            extender.getLoggerManager().getLoggerTableModel().triggerAutoSave();
        }
    }

    // Method to clear all entries
    public void clearAllEntries() {
        extender.getLoggerManager().getLoggerTableModel().clearLoggerList();
        extender.getLoggerManager().getInstancesTableModel().clearInstanceEntryList();
        extender.getUIManager().getExtenderPanelUI().getScanStatusLabel().setText("All entries cleared");
        extender.getUIManager().getExtenderPanelUI().getDeleteEntryButton().setEnabled(false);
        extender.getLoggerManager().getLoggerTableModel().triggerAutoSave();
    }
}
