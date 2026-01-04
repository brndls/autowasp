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
// Project imports
import autowasp.http.ContextMenuFactory;
import javax.swing.SwingUtilities;

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

        // Initialize Managers UI connection
        uiManager.setupUI(loggerManager);

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
    // LEGACY API - Data Accessors (for backward compatibility)
    // =====================================================================================
    // Public fields removed in Phase 4 - Full Data Encapsulation

    // =====================================================================================
    // LEGACY API - Data Accessors (for backward compatibility)
    // =====================================================================================

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
