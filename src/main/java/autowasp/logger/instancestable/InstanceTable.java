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
package autowasp.logger.instancestable;

import autowasp.Autowasp;
// Import for correctness in new package

import javax.swing.DefaultCellEditor;
import javax.swing.JComboBox;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;

public class InstanceTable extends JTable {

    private static final long serialVersionUID = 1L;
    private final transient Autowasp extender;
    private int currentRow;

    public InstanceTable(TableModel tableModel, Autowasp extender) {
        super(tableModel);
        this.extender = extender;
        setColumnWidths(50, 80, 2500, 350, 150, 300, 150, Integer.MAX_VALUE);
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
    // Montoya API Migration: Using HttpRequestEditor.setRequest() and
    // HttpResponseEditor.setResponse()
    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend) {
        // show the log entry for the selected row
        currentRow = row;
        InstanceEntry instanceEntry = extender.getLoggerManager().getInstanceLog().get(row);
        if (instanceEntry.getRequestResponse() == null) {
            // Kosongkan editor jika tidak ada request/response
            extender.getUIManager().getExtenderPanelUI().getRequestEditor().setRequest(
                    burp.api.montoya.http.message.requests.HttpRequest.httpRequest(""));
            extender.getUIManager().getExtenderPanelUI().getResponseEditor().setResponse(
                    burp.api.montoya.http.message.responses.HttpResponse.httpResponse(""));
        } else {
            // Set request dan response ke editor
            // Montoya API: HttpRequest.httpRequest(ByteArray) dan
            // HttpResponse.httpResponse(ByteArray)
            byte[] reqBytes = instanceEntry.getRequestResponse().getRequest();
            byte[] resBytes = instanceEntry.getRequestResponse().getResponse();

            extender.getUIManager().getExtenderPanelUI().getRequestEditor().setRequest(
                    burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                            burp.api.montoya.core.ByteArray.byteArray(reqBytes)));
            extender.getUIManager().getExtenderPanelUI().getResponseEditor().setResponse(
                    burp.api.montoya.http.message.responses.HttpResponse.httpResponse(
                            burp.api.montoya.core.ByteArray.byteArray(resBytes)));
        }
        super.changeSelection(row, col, toggle, extend);
        extender.getUIManager().getExtenderPanelUI().deleteInstanceButtonEnabled();
    }

    // Method to setup confidence column with dropdown combo
    public void setUpConfidenceColumn(TableColumn column) {
        DefaultCellEditor dce = new DefaultCellEditor(extender.getUIManager().getComboBox2());
        column.setCellEditor(dce);
    }

    // Method to setup Severity column with dropdown combo
    public void setupSeverityColumn(TableColumn column) {
        DefaultCellEditor dce = new DefaultCellEditor(extender.getUIManager().getComboBox3());
        column.setCellEditor(dce);
    }

    // Method to prepare confidence dropdown combo
    public void generateConfidenceList() {
        JComboBox<String> comboBox = extender.getUIManager().getComboBox2();
        comboBox.addItem("False Positive");
        comboBox.addItem("Certain");
        comboBox.addItem("Firm");
        comboBox.addItem("Tentative");
    }

    // Method to prepare severity dropdown combo
    public void generateSeverityList() {
        JComboBox<String> comboBox = extender.getUIManager().getComboBox3();
        comboBox.addItem("High");
        comboBox.addItem("Medium");
        comboBox.addItem("Low");
        comboBox.addItem("Information");
    }

    // Method to delete instance
    public void deleteInstance() {
        // delete instance
        extender.getUIManager().getExtenderPanelUI().getDeleteInstanceButton().setEnabled(false);
        extender.getLoggerManager().getLoggerList().get(extender.getUIManager().getCurrentEntryRow()).getInstanceList()
                .remove(currentRow);
        // update UI
        // If there are remaining instances
        if (!extender.getLoggerManager().getLoggerList().get(extender.getUIManager().getCurrentEntryRow())
                .getInstanceList()
                .isEmpty()) {
            // Inform user about instance deletion
            extender.getUIManager().getExtenderPanelUI().getScanStatusLabel().setText("Instance deleted");
            extender.issueAlert("Instance deleted");
            // Repaint instances table
            extender.getLoggerManager().getInstancesTableModel().clearInstanceEntryList();
            extender.getLoggerManager().getInstancesTableModel()
                    .addAllInstanceEntry(extender.getLoggerManager().getLoggerList()
                            .get(extender.getUIManager().getCurrentEntryRow())
                            .getInstanceList());
        }
        // Else, no more instances left in entry
        else {
            // delete entries instead
            extender.getLoggerManager().getLoggerTable().deleteEntry();
        }
    }

}
