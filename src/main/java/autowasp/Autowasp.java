/*
 * Copyright (c) 2021 Government Technology Agency
 * Copyright (c) 2024 Autowasp Contributors
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
import autowasp.logger.entryTable.LoggerEntry;
import autowasp.logger.entryTable.LoggerTable;
import autowasp.logger.entryTable.LoggerTableModel;
import autowasp.logger.instancesTable.InstanceEntry;
import autowasp.logger.instancesTable.InstanceTable;
import autowasp.logger.instancesTable.InstancesTableModel;

import javax.swing.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

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
    public ExtenderPanelUI extenderPanelUI;
    public JSplitPane gtScannerSplitPane;

    // =====================================================================================
    // CHECKLIST COMPONENTS
    // =====================================================================================
    public ChecklistLogic checklistLogic;
    public ChecklistTableModel checklistTableModel;
    public ChecklistTable checklistTable;
    public final List<ChecklistEntry> checklistLog = new ArrayList<>();
    public final HashMap<String, ChecklistEntry> checkListHashMap = new HashMap<>();

    // =====================================================================================
    // LOGGER COMPONENTS
    // =====================================================================================
    public TrafficLogic trafficLogic;
    public final List<TrafficEntry> trafficLog = new ArrayList<>();
    public LoggerTableModel loggerTableModel;
    public InstancesTableModel instancesTableModel;
    public LoggerTable loggerTable;
    public InstanceTable instanceTable;
    public final List<LoggerEntry> loggerList = new ArrayList<>();
    public final List<InstanceEntry> instanceLog = new ArrayList<>();
    public ScannerLogic scannerLogic;

    // =====================================================================================
    // PROJECT WORKSPACE
    // =====================================================================================
    public ProjectWorkspaceFactory projectWorkspace;

    // =====================================================================================
    // UI HELPER COMPONENTS
    // =====================================================================================
    public JComboBox<String> comboBox;
    public JComboBox<String> comboBox2;
    public JComboBox<String> comboBox3;
    public int currentEntryRow;

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

        this.loggerTableModel = new LoggerTableModel(loggerList);
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
        api.extension().registerUnloadingHandler(() -> {
            logging.logToOutput("Autowasp extension unloading...");
            // Terminate any background threads if needed
            // Release resources
        });
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
