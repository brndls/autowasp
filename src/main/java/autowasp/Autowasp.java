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
 * Autowasp - Burp Suite Extension untuk integrasi OWASP WSTG
 * 
 * Migrasi dari Legacy Extender API ke Montoya API:
 * - IBurpExtender → BurpExtension
 * - registerExtenderCallbacks() → initialize(MontoyaApi)
 * - IBurpExtenderCallbacks → MontoyaApi
 * 
 * Catatan Pembelajaran:
 * Montoya API menggunakan interface BurpExtension dengan satu method:
 * - initialize(MontoyaApi api): Dipanggil saat extension di-load
 * MontoyaApi menyediakan akses ke semua fitur Burp Suite
 */
public class Autowasp implements BurpExtension {

    // ════════════════════════════════════════════════════════════════════════
    // MONTOYA API REFERENCE
    // ════════════════════════════════════════════════════════════════════════
    /**
     * MontoyaApi adalah pengganti IBurpExtenderCallbacks
     * Menyediakan akses ke:
     * - api.http() → HTTP request/response handling
     * - api.proxy() → Proxy listener
     * - api.scanner() → Scanner/Audit issues
     * - api.userInterface() → UI components (tabs, editors)
     * - api.logging() → Logging (stdout, stderr)
     * - api.scope() → Scope checking
     * - api.collaborator() → Burp Collaborator
     */
    private MontoyaApi api;
    private Logging logging;

    // ════════════════════════════════════════════════════════════════════════
    // UI COMPONENTS
    // ════════════════════════════════════════════════════════════════════════
    public ExtenderPanelUI extenderPanelUI;
    public JSplitPane gtScannerSplitPane;

    // ════════════════════════════════════════════════════════════════════════
    // CHECKLIST COMPONENTS
    // ════════════════════════════════════════════════════════════════════════
    public ChecklistLogic checklistLogic;
    public ChecklistTableModel checklistTableModel;
    public ChecklistTable checklistTable;
    public final List<ChecklistEntry> checklistLog = new ArrayList<>();
    public final HashMap<String, ChecklistEntry> checkListHashMap = new HashMap<>();

    // ════════════════════════════════════════════════════════════════════════
    // LOGGER COMPONENTS
    // ════════════════════════════════════════════════════════════════════════
    public TrafficLogic trafficLogic;
    public final List<TrafficEntry> trafficLog = new ArrayList<>();
    public LoggerTableModel loggerTableModel;
    public InstancesTableModel instancesTableModel;
    public LoggerTable loggerTable;
    public InstanceTable instanceTable;
    public final List<LoggerEntry> loggerList = new ArrayList<>();
    public final List<InstanceEntry> instanceLog = new ArrayList<>();
    public ScannerLogic scannerLogic;

    // ════════════════════════════════════════════════════════════════════════
    // PROJECT WORKSPACE
    // ════════════════════════════════════════════════════════════════════════
    public ProjectWorkspaceFactory projectWorkspace;

    // ════════════════════════════════════════════════════════════════════════
    // UI HELPER COMPONENTS
    // ════════════════════════════════════════════════════════════════════════
    public JComboBox<String> comboBox;
    public JComboBox<String> comboBox2;
    public JComboBox<String> comboBox3;
    public int currentEntryRow;

    // ════════════════════════════════════════════════════════════════════════
    // MONTOYA API ENTRY POINT
    // ════════════════════════════════════════════════════════════════════════
    /**
     * Method ini dipanggil saat extension di-load ke Burp Suite
     * Menggantikan registerExtenderCallbacks() dari Legacy API
     * 
     * @param api MontoyaApi instance untuk mengakses fitur Burp Suite
     */
    @Override
    public void initialize(MontoyaApi api) {
        // Simpan referensi ke API
        this.api = api;
        this.logging = api.logging();

        // Set nama extension (mengganti callbacks.setExtensionName())
        api.extension().setName("Autowasp");

        // Log ke Output tab (mengganti stdout/stderr PrintWriter)
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

        // Register context menu (mengganti callbacks.registerContextMenuFactory())
        ContextMenuFactory contextMenu = new ContextMenuFactory(this);
        api.userInterface().registerContextMenuItemsProvider(contextMenu);

        // Setup ComboBox untuk tabel
        this.comboBox = new JComboBox<>();
        this.loggerTable.setUpIssueColumn(loggerTable.getColumnModel().getColumn(4));

        this.comboBox2 = new JComboBox<>();
        this.instanceTable.generateConfidenceList();
        instanceTable.setUpConfidenceColumn(instanceTable.getColumnModel().getColumn(2));

        this.comboBox3 = new JComboBox<>();
        this.instanceTable.generateSeverityList();
        instanceTable.setupSeverityColumn(instanceTable.getColumnModel().getColumn(3));

        // Create UI dan register tab (dijalankan di EDT)
        SwingUtilities.invokeLater(() -> {
            extenderPanelUI.run();

            // Register proxy handler (mengganti callbacks.registerProxyListener())
            api.proxy().registerResponseHandler(new AutowaspProxyResponseHandler(this));

            // Register scanner/audit issue handler (mengganti
            // callbacks.registerScannerListener())
            api.scanner().registerAuditIssueHandler(new AutowaspAuditIssueHandler(this));

            // Register tab ke Burp Suite UI (mengganti callbacks.addSuiteTab())
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

    // ════════════════════════════════════════════════════════════════════════
    // PUBLIC API ACCESSORS
    // ════════════════════════════════════════════════════════════════════════
    /**
     * Mendapatkan MontoyaApi instance
     * Digunakan oleh komponen lain untuk mengakses fitur Burp Suite
     */
    public MontoyaApi getApi() {
        return api;
    }

    /**
     * Mendapatkan Logging instance untuk output ke console
     */
    public Logging getLogging() {
        return logging;
    }

    /**
     * Log pesan ke Output tab
     * Menggantikan stdout.println()
     */
    public void logOutput(String message) {
        logging.logToOutput(message);
    }

    /**
     * Log error ke Error tab
     * Menggantikan stderr.println()
     */
    public void logError(String message) {
        logging.logToError(message);
    }

    /**
     * Log exception dengan stack trace ke Error tab (GUIDELINES.md §5)
     * Preferred method untuk exception handling di background threads
     */
    public void logError(Exception e) {
        logging.logToError(e);
    }

    /**
     * Cek apakah URL dalam scope
     * Menggantikan callbacks.isInScope()
     */
    public boolean isInScope(String url) {
        return api.scope().isInScope(url);
    }

    /**
     * Tampilkan alert ke user
     * Menggantikan callbacks.issueAlert()
     */
    public void issueAlert(String message) {
        // Montoya API tidak memiliki issueAlert langsung
        // Menggunakan logging sebagai alternatif
        logging.logToOutput("[ALERT] " + message);
    }
}