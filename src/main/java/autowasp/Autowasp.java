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
import autowasp.persistence.AutowaspPersistence;

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
    // MANAGERS (Phase 2 - Component Extraction)
    // =====================================================================================
    /*
     * Managers encapsulate related components to reduce coupling.
     * This reduces dependencies from 21 to 6 (api, logging, 4 managers).
     * 
     * - ChecklistManager: OWASP WSTG checklist components
     * - LoggerManager: HTTP traffic logging & scanning
     * - UIManager: User interface components
     * - PersistenceManager: Data persistence & project workspace
     */
    private autowasp.managers.ChecklistManager checklistManager;
    private autowasp.managers.LoggerManager loggerManager;
    private autowasp.managers.UIManager uiManager;
    private autowasp.managers.PersistenceManager persistenceManager;

    // =====================================================================================
    // LEGACY FIELDS (Temporary - for backward compatibility)
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

        // =====================================================================================
        // MANAGER INITIALIZATION (Phase 2 - Component Extraction)
        // =====================================================================================

        // Create managers
        this.checklistManager = new autowasp.managers.ChecklistManager(this);
        this.loggerManager = new autowasp.managers.LoggerManager(this);
        this.uiManager = new autowasp.managers.UIManager(this);
        this.persistenceManager = new autowasp.managers.PersistenceManager(this);

        // Initialize managers
        checklistManager.initialize();
        loggerManager.initialize();
        uiManager.initialize(checklistManager, loggerManager);
        persistenceManager.initialize();

        // Register context menu (replaces callbacks.registerContextMenuFactory())
        ContextMenuFactory contextMenu = new ContextMenuFactory(this);
        api.userInterface().registerContextMenuItemsProvider(contextMenu);

        // Setup ComboBox for table columns
        this.comboBox = new JComboBox<>();
        loggerManager.getLoggerTable().setUpIssueColumn(loggerManager.getLoggerTable().getColumnModel().getColumn(4));

        this.comboBox2 = new JComboBox<>();
        loggerManager.getInstanceTable().generateConfidenceList();
        loggerManager.getInstanceTable()
                .setUpConfidenceColumn(loggerManager.getInstanceTable().getColumnModel().getColumn(2));

        this.comboBox3 = new JComboBox<>();
        loggerManager.getInstanceTable().generateSeverityList();
        loggerManager.getInstanceTable()
                .setupSeverityColumn(loggerManager.getInstanceTable().getColumnModel().getColumn(3));

        // Create UI and register tab (executed on EDT)
        SwingUtilities.invokeLater(() -> {
            uiManager.getExtenderPanelUI().run();

            // Register proxy handler (replaces callbacks.registerProxyListener())
            api.proxy().registerResponseHandler(new AutowaspProxyResponseHandler(this));

            // Register scanner/audit issue handler (replaces
            // callbacks.registerScannerListener())
            api.scanner().registerAuditIssueHandler(new AutowaspAuditIssueHandler(this));

            // Register tab to Burp Suite UI (replaces callbacks.addSuiteTab())
            api.userInterface().registerSuiteTab("Autowasp", uiManager.getGtScannerSplitPane());

            logging.logToOutput("Autowasp extension loaded successfully!");

            // Restore state from persistence
            persistenceManager.restoreAllState(checklistManager, loggerManager);
        });

        // Register unload handler for clean unload (GUIDELINES.md §6)
        // Terminate any background threads if needed
        // Release resources
        api.extension().registerUnloadingHandler(
                () -> persistenceManager.saveAllState(checklistManager, loggerManager));
    }

    // =====================================================================================
    // PUBLIC API - Core Accessors
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

    // =====================================================================================
    // PUBLIC API - Manager Accessors
    // =====================================================================================

    public autowasp.managers.ChecklistManager getChecklistManager() {
        return checklistManager;
    }

    public autowasp.managers.LoggerManager getLoggerManager() {
        return loggerManager;
    }

    public autowasp.managers.UIManager getUIManager() {
        return uiManager;
    }

    public autowasp.managers.PersistenceManager getPersistenceManager() {
        return persistenceManager;
    }

    // =====================================================================================
    // LEGACY API - Component Accessors (Backward Compatibility)
    // =====================================================================================

    public ExtenderPanelUI getExtenderPanelUI() {
        return uiManager.getExtenderPanelUI();
    }

    public JSplitPane getGtScannerSplitPane() {
        return uiManager.getGtScannerSplitPane();
    }

    public void setGtScannerSplitPane(JSplitPane gtScannerSplitPane) {
        uiManager.setGtScannerSplitPane(gtScannerSplitPane);
    }

    public ChecklistLogic getChecklistLogic() {
        return checklistManager.getChecklistLogic();
    }

    public ChecklistTableModel getChecklistTableModel() {
        return checklistManager.getChecklistTableModel();
    }

    public ChecklistTable getChecklistTable() {
        return checklistManager.getChecklistTable();
    }

    public TrafficLogic getTrafficLogic() {
        return loggerManager.getTrafficLogic();
    }

    public LoggerTableModel getLoggerTableModel() {
        return loggerManager.getLoggerTableModel();
    }

    public InstancesTableModel getInstancesTableModel() {
        return loggerManager.getInstancesTableModel();
    }

    public LoggerTable getLoggerTable() {
        return loggerManager.getLoggerTable();
    }

    public InstanceTable getInstanceTable() {
        return loggerManager.getInstanceTable();
    }

    public ScannerLogic getScannerLogic() {
        return loggerManager.getScannerLogic();
    }

    public ProjectWorkspaceFactory getProjectWorkspace() {
        return persistenceManager.getProjectWorkspace();
    }

    public AutowaspPersistence getPersistence() {
        return persistenceManager.getPersistence();
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

    // =====================================================================================
    // LEGACY API - Data Accessors (for backward compatibility)
    // =====================================================================================
    // Public fields maintained for backward compatibility
    // Phase 4 will migrate these to proper encapsulation

    public final List<autowasp.checklist.ChecklistEntry> checklistLog = new ArrayList<>();
    public final Map<String, autowasp.checklist.ChecklistEntry> checkListHashMap = new HashMap<>();
    public final List<autowasp.logger.TrafficEntry> trafficLog = new ArrayList<>();
    public final List<autowasp.logger.entrytable.LoggerEntry> loggerList = new ArrayList<>();
    public final List<autowasp.logger.instancestable.InstanceEntry> instanceLog = new ArrayList<>();

    // =====================================================================================
    // UTILITY METHODS
    // =====================================================================================

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
