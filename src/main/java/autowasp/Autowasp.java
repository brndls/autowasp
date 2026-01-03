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

package autowasp;

// Montoya API imports
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

// Project imports
import autowasp.checklist.*;
import autowasp.http.*;
import autowasp.logger.ScannerLogic;
import autowasp.logger.TrafficEntry;
import autowasp.logger.TrafficLogic;
import autowasp.logger.entrytable.LoggerEntry;
import autowasp.logger.entrytable.LoggerTable;
import autowasp.logger.entrytable.LoggerTableModel;
import autowasp.logger.instancestable.InstanceEntry;
import autowasp.logger.instancestable.InstanceTable;
import autowasp.logger.instancestable.InstancesTableModel;

import javax.swing.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Autowasp - Burp Suite Extension for OWASP WSTG integration
 *
 * Migration from Legacy Extender API to Montoya API:
 *
 * Legacy API:
 * - implements IBurpExtender
 * - registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
 *
 * Learning Notes:
 * Montoya API uses BurpExtension interface with one method:
 * - initialize(MontoyaApi api): Called when extension is loaded
 * MontoyaApi provides access to all Burp Suite features
 */
public class Autowasp implements BurpExtension {

    // =====================================================================================
    // MONTOYA API REFERENCE
    // =====================================================================================
    /*
     * MontoyaApi is the replacement for IBurpExtenderCallbacks
     * It provides access to Burp Suite functionalities.
     * - api.http() -> HTTP request/response handling
     * - api.proxy() -> Proxy listener
     * - api.scanner() -> Scanner/Audit issues
     * - api.userInterface() -> UI components (tabs, editors)
     * - api.logging() -> Logging (stdout, stderr)
     * - api.scope() -> Scope checking
     */
    private MontoyaApi api;
    private Logging logging;

    // =====================================================================================
    // UI COMPONENTS
    // =====================================================================================
    // =====================================================================================
    // UI COMPONENTS
    // =====================================================================================
    private ExtenderPanelUI extenderPanelUI;
    private JSplitPane gtScannerSplitPane;

    // =====================================================================================
    // CHECKLIST COMPONENTS
    // =====================================================================================
    private ChecklistLogic checklistLogic;
    private ChecklistTableModel checklistTableModel;
    private ChecklistTable checklistTable;
    public final List<ChecklistEntry> checklistLog = new ArrayList<>();
    public final Map<String, ChecklistEntry> checkListHashMap = new HashMap<>();

    // =====================================================================================
    // LOGGER COMPONENTS
    // =====================================================================================
    private TrafficLogic trafficLogic;
    public final List<TrafficEntry> trafficLog = new ArrayList<>();
    private LoggerTableModel loggerTableModel;
    private InstancesTableModel instancesTableModel;
    private LoggerTable loggerTable;
    private InstanceTable instanceTable;
    public final List<LoggerEntry> loggerList = new ArrayList<>();
    public final List<InstanceEntry> instanceLog = new ArrayList<>();
    private ScannerLogic scannerLogic;

    // =====================================================================================
    // PROJECT WORKSPACE
    // =====================================================================================
    private ProjectWorkspaceFactory projectWorkspace;

    // =====================================================================================
    // UI HELPER COMPONENTS
    // =====================================================================================
    private JComboBox<String> comboBox;
    private JComboBox<String> comboBox2;
    private JComboBox<String> comboBox3;
    private int currentEntryRow;

    public void setCurrentEntryRow(int currentEntryRow) {
        this.currentEntryRow = currentEntryRow;
    }

    public int getCurrentEntryRow() {
        return currentEntryRow;
    }

    // =====================================================================================
    // MONTOYA API ENTRY POINT
    // =====================================================================================
    /**
     * This method is called when the extension is loaded into Burp Suite
     * Replaces registerExtenderCallbacks() from Legacy API
     *
     * @param api MontoyaApi instance to access Burp Suite features
     */
    @Override
    public void initialize(MontoyaApi api) {
        // Save reference to API
        this.api = api;
        this.logging = api.logging();

        // Set extension name (replaces callbacks.setExtensionName())
        api.extension().setName("Autowasp");

        // Log to Output tab (replaces stdout/stderr PrintWriter)
        logging.logToOutput("Autowasp extension loading...");

        // Initialize UI components
        this.extenderPanelUI = new ExtenderPanelUI(this);

        // Initialize logger features
        this.instancesTableModel = new InstancesTableModel(instanceLog);
        this.instanceTable = new InstanceTable(instancesTableModel, this);

        this.loggerTableModel = new LoggerTableModel(loggerList, this);
        this.loggerTable = new LoggerTable(loggerTableModel, this);

        this.scannerLogic = new ScannerLogic(this);
        this.trafficLogic = new TrafficLogic(this);

        // Initialize OWASP checklist feature
        this.checklistLogic = new ChecklistLogic(this);
        this.checklistTableModel = new ChecklistTableModel(this);
        this.checklistTable = new ChecklistTable(checklistTableModel, this);

        // Initialize project workspace
        this.projectWorkspace = new ProjectWorkspaceFactory(this);

        // Register context menu (replaces callbacks.registerContextMenuFactory())
        ContextMenuFactory contextMenu = new ContextMenuFactory(this);
        api.userInterface().registerContextMenuItemsProvider(contextMenu);

        // Setup ComboBox for table
        this.comboBox = new JComboBox<>();
        this.loggerTable.setUpIssueColumn(loggerTable.getColumnModel().getColumn(4));

        this.comboBox2 = new JComboBox<>();
        this.instanceTable.generateConfidenceList();
        instanceTable.setUpConfidenceColumn(instanceTable.getColumnModel().getColumn(2));

        this.comboBox3 = new JComboBox<>();
        this.instanceTable.generateSeverityList();
        instanceTable.setupSeverityColumn(instanceTable.getColumnModel().getColumn(3));

        // Create UI and register tab (executed on EDT)
        SwingUtilities.invokeLater(() -> {
            extenderPanelUI.run();

            // Register proxy handler (replaces callbacks.registerProxyListener())
            api.proxy().registerResponseHandler(new AutowaspProxyResponseHandler(this));

            // Register scanner/audit issue handler (replaces
            // callbacks.registerScannerListener())
            api.scanner().registerAuditIssueHandler(new AutowaspAuditIssueHandler(this));

            // Register tab to Burp Suite UI (replaces callbacks.addSuiteTab())
            api.userInterface().registerSuiteTab("Autowasp", gtScannerSplitPane);

            logging.logToOutput("Autowasp extension loaded successfully!");
        });

        // Register unload handler for clean unload (GUIDELINES.md §6)
        // Terminate any background threads if needed
        // Release resources
        api.extension().registerUnloadingHandler(() -> logging.logToOutput("Autowasp extension unloading..."));
    }

    // =====================================================================================
    // PUBLIC API ACCESSORS
    // =====================================================================================
    /**
     * Get MontoyaApi instance
     * Used by other components to access Burp Suite features
     */
    public MontoyaApi getApi() {
        return api;
    }

    /**
     * Get Logging instance for console output
     */
    public Logging getLogging() {
        return logging;
    }

    public ExtenderPanelUI getExtenderPanelUI() {
        return extenderPanelUI;
    }

    public JSplitPane getGtScannerSplitPane() {
        return gtScannerSplitPane;
    }

    public void setGtScannerSplitPane(JSplitPane gtScannerSplitPane) {
        this.gtScannerSplitPane = gtScannerSplitPane;
    }

    public ChecklistLogic getChecklistLogic() {
        return checklistLogic;
    }

    public ChecklistTableModel getChecklistTableModel() {
        return checklistTableModel;
    }

    public ChecklistTable getChecklistTable() {
        return checklistTable;
    }

    public TrafficLogic getTrafficLogic() {
        return trafficLogic;
    }

    public LoggerTableModel getLoggerTableModel() {
        return loggerTableModel;
    }

    public InstancesTableModel getInstancesTableModel() {
        return instancesTableModel;
    }

    public LoggerTable getLoggerTable() {
        return loggerTable;
    }

    public InstanceTable getInstanceTable() {
        return instanceTable;
    }

    public ScannerLogic getScannerLogic() {
        return scannerLogic;
    }

    public ProjectWorkspaceFactory getProjectWorkspace() {
        return projectWorkspace;
    }

    public JComboBox<String> getComboBox() {
        return comboBox;
    }

    public JComboBox<String> getComboBox2() {
        return comboBox2;
    }

    public JComboBox<String> getComboBox3() {
        return comboBox3;
    }

    /**
     * Log message to Output tab
     * Replaces stdout.println()
     */
    public void logOutput(String message) {
        logging.logToOutput(message);
    }

    /**
     * Log error to Error tab
     * Replaces stderr.println()
     */
    public void logError(String message) {
        logging.logToError(message);
    }

    /**
     * Log exception with stack trace to Error tab (GUIDELINES.md §5)
     * Preferred method for exception handling in background threads
     */
    public void logError(Exception e) {
        logging.logToError(e);
    }

    /**
     * Check if URL is in scope
     * Replaces callbacks.isInScope()
     */
    public boolean isInScope(String url) {
        return api.scope().isInScope(url);
    }

    /**
     * Show alert to user
     * Replaces callbacks.issueAlert()
     */
    public void issueAlert(String message) {
        // Montoya API does not have direct issueAlert
        // Using logging as alternative
        logging.logToOutput("[ALERT] " + message);
    }
}
