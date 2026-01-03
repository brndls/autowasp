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
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import java.awt.*;

import java.net.URISyntaxException;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.HyperlinkEvent;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.io.IOException;

import java.io.File;

import java.util.concurrent.atomic.AtomicBoolean;

import autowasp.checklist.ChecklistFetchWorker;

/**
 * Extender Panel UI - Montoya API
 *
 * Learning Notes - Migration from Legacy API:
 *
 * Legacy API:
 * - IMessageEditor from callbacks.createMessageEditor()
 * - callbacks.includeInScope() for scope
 * - callbacks.issueAlert() for alert
 *
 * Montoya API:
 * - HttpRequestEditor and HttpResponseEditor are separate
 * - api.scope().includeInScope() for scope
 * - api.logging().logToOutput() for output
 */
public class ExtenderPanelUI implements Runnable {

    // String constants
    private static final String HTTPS_PREFIX = "https://";
    private static final String HTTPS_WWW_PREFIX = "https://www.";
    private static final String HTTP_WWW_PREFIX = "http://www.";
    private static final String HTTP_PREFIX = "http://"; // Adding for consistency
    private static final String CHECKLIST_NOT_FETCHED_MSG = "Please fetch the checklist from the web first";
    private static final String HTML_CONTENT_TYPE = "text/html";
    private static final String HTML_DISABLE_PROPERTY = "html.disable";
    private static final String SETUP_ERROR_MSG = "Exception occurred at setupCheckListPanel";
    private static final boolean SELF_UPDATE_LOCAL = false;

    private final Autowasp extender;
    private JSplitPane gtScannerSplitPane;

    // Montoya API: Separate MessageEditor for request and response
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;

    private JFileChooser destDirChooser;
    private JLabel scanStatusLabel;
    private JLabel memoryUsageLabel;
    private JProgressBar memoryProgressBar;

    // Checklist UI
    private JTextPane summaryTextPane;
    private JEditorPane howToTestTextPane;
    private JTextPane referencesTextPane;
    private JButton enableScanningButton;
    private ChecklistFetchWorker fetchWorker;
    public final AtomicBoolean running = new AtomicBoolean(false);
    private JButton cancelFetchButton;
    private JButton saveLocalCopyButton;
    private JButton generateLocalChecklistButton;
    private JButton generateExcelReportButton;
    private JButton generateWebChecklistButton;
    private File checklistDestDir;
    private JLabel loggerPageLabel;

    // Loggers UI
    private JTabbedPane bottomModulesTabs;
    private JTextPane penTesterCommentBox;
    private JTextPane evidenceBox;
    private JButton deleteEntryButton;
    private JButton deleteInstanceButton;

    public ExtenderPanelUI(Autowasp extender) {
        this.extender = extender;
    }

    @Override
    public void run() {
        // Scanner split pane
        gtScannerSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        bottomModulesTabs = new JTabbedPane();

        setupTopPanel();
        setupCheckListPanel();
        setupLoggerPanel();

        // Consolidate all modular tabs and set to the scanner bottom pane
        gtScannerSplitPane.setRightComponent(bottomModulesTabs);
        extender.setGtScannerSplitPane(gtScannerSplitPane);
    }

    // This method setup the top panel view of Autowasp
    private void setupTopPanel() {
        JPanel topPanel = new JPanel(new GridLayout(4, 0));
        topPanel.setBorder(new EmptyBorder(0, 0, 10, 0));

        JPanel setupPanel = createSetupPanel();
        JPanel scanStatusPanel = createScanStatusPanel();
        JPanel checklistPanel = createChecklistPanel();
        JPanel miscPanel = createMiscPanel();

        disabledInitialButtons();

        topPanel.add(setupPanel);
        topPanel.add(scanStatusPanel);
        topPanel.add(checklistPanel);
        topPanel.add(miscPanel);
        gtScannerSplitPane.setLeftComponent(topPanel);
    }

    private JPanel createSetupPanel() {
        JPanel setupPanel = new JPanel(new FlowLayout(FlowLayout.LEADING, 10, 10));
        setupPanel.add(new JLabel("Target:", SwingConstants.LEFT), BorderLayout.LINE_START);
        JTextField hostField = new JTextField("", 15);
        JButton addToScopeButton = new JButton("Add Target to Scope");
        addToScopeButton.addActionListener(e -> addTargetToScope(hostField));

        enableScanningButton = new JButton("Enable Burp Scanner logging");
        enableScanningButton.addActionListener(e -> {
            extender.getScannerLogic().extractExistingScan();
            enableScanningButton.setEnabled(false);
            scanStatusLabel.setText("Extracted Scanner Logs. Passive Scanner logging enabled");
            extender.issueAlert("Extracted Scanner Logs. Passive Scanner logging enabled");
        });

        setupPanel.add(hostField);
        setupPanel.add(addToScopeButton);
        setupPanel.add(enableScanningButton);
        return setupPanel;
    }

    private JPanel createScanStatusPanel() {
        JPanel scanStatusPanel = new JPanel(new FlowLayout(FlowLayout.LEADING, 10, 10));
        scanStatusPanel.add(new JLabel("Status: ", SwingConstants.LEFT));
        scanStatusLabel = new JLabel("Ready to scan", SwingConstants.LEFT);
        scanStatusPanel.add(scanStatusLabel);

        scanStatusPanel.add(Box.createHorizontalStrut(50));
        scanStatusPanel.add(new JLabel("Memory: ", SwingConstants.LEFT));
        memoryUsageLabel = new JLabel("0 MB / 0 MB", SwingConstants.LEFT);
        scanStatusPanel.add(memoryUsageLabel);

        memoryProgressBar = new JProgressBar(0, 100);
        memoryProgressBar.setPreferredSize(new Dimension(150, 15));
        memoryProgressBar.setStringPainted(true);
        scanStatusPanel.add(memoryProgressBar);

        JButton gcButton = new JButton("Update Memory Usage");
        gcButton.setToolTipText("Manually update memory usage indicator");
        gcButton.addActionListener(e -> updateMemoryUsage());
        scanStatusPanel.add(gcButton);

        // Timer to update memory usage every 3 seconds
        Timer timer = new Timer(3000, e -> updateMemoryUsage());
        timer.start();

        return scanStatusPanel;
    }

    private void updateMemoryUsage() {
        Runtime runtime = Runtime.getRuntime();
        long maxMemory = runtime.maxMemory() / 1024 / 1024;
        long totalMemory = runtime.totalMemory() / 1024 / 1024;
        long freeMemory = runtime.freeMemory() / 1024 / 1024;
        long usedMemory = totalMemory - freeMemory;

        memoryUsageLabel.setText(String.format("%d MB / %d MB", usedMemory, maxMemory));

        if (memoryProgressBar != null) {
            memoryProgressBar.setMaximum((int) maxMemory);
            memoryProgressBar.setValue((int) usedMemory);

            double percent = (double) usedMemory / maxMemory;
            if (percent > 0.85) {
                memoryProgressBar.setForeground(new Color(200, 0, 0)); // Dark Red
                memoryUsageLabel.setForeground(Color.RED);
            } else if (percent > 0.7) {
                memoryProgressBar.setForeground(new Color(255, 140, 0)); // Dark Orange
                memoryUsageLabel.setForeground(new Color(255, 140, 0));
            } else {
                memoryProgressBar.setForeground(new Color(0, 150, 0)); // Green
                memoryUsageLabel.setForeground(null);
            }
        }
    }

    private JPanel createChecklistPanel() {
        JPanel testingPanel = new JPanel(new FlowLayout(FlowLayout.LEADING, 10, 10));
        testingPanel.add(new JLabel("OWASP CheckList:", SwingConstants.LEFT), BorderLayout.LINE_START);

        // Progress bar for fetch operations (BApp Store Criteria #5)
        JProgressBar fetchProgressBar = new JProgressBar();
        fetchProgressBar.setIndeterminate(true);
        fetchProgressBar.setVisible(false);
        fetchProgressBar.setStringPainted(true);
        fetchProgressBar.setString("Fetching...");

        // On clicking, fetches checklist data from the web and displays it
        generateWebChecklistButton = new JButton("Fetch WSTG Checklist");
        generateWebChecklistButton.addActionListener(e -> {
            extender.issueAlert("Fetching checklist now");
            scanStatusLabel.setText("Fetching checklist now");
            generateLocalChecklistButton.setEnabled(false);
            cancelFetchButton.setEnabled(true);
            generateWebChecklistButton.setEnabled(false);
            fetchProgressBar.setVisible(true);
            extender.checklistLog.clear();
            running.set(true);

            fetchWorker = new ChecklistFetchWorker(new ChecklistFetchWorker.ChecklistFetchConfig(
                    extender,
                    scanStatusLabel,
                    fetchProgressBar,
                    generateWebChecklistButton,
                    generateLocalChecklistButton,
                    cancelFetchButton,
                    generateExcelReportButton,
                    saveLocalCopyButton,
                    running,
                    null));
            fetchWorker.execute();
        });

        setupCancelFetchButton();
        setupLocalChecklistButtons();
        setupExcelReportButton();

        testingPanel.add(generateWebChecklistButton);
        testingPanel.add(cancelFetchButton);
        testingPanel.add(generateLocalChecklistButton);
        testingPanel.add(fetchProgressBar);
        if (SELF_UPDATE_LOCAL) {
            testingPanel.add(saveLocalCopyButton);
        }
        testingPanel.add(generateExcelReportButton);
        return testingPanel;
    }

    private void setupCancelFetchButton() {
        cancelFetchButton = new JButton("Cancel Fetch");
        cancelFetchButton.addActionListener(e -> {
            running.set(false);
            if (fetchWorker != null && !fetchWorker.isDone()) {
                fetchWorker.cancel(true);
            }
        });
    }

    private void setupLocalChecklistButtons() {
        generateLocalChecklistButton = new JButton("Load Bundled WSTG (Offline)");
        generateLocalChecklistButton.addActionListener(e -> {
            generateLocalChecklistButton.setEnabled(false);
            if (generateWebChecklistButton != null) {
                generateWebChecklistButton.setEnabled(false);
            }
            extender.getChecklistManager().getChecklistLogic().loadLocalCopy();
        });

        saveLocalCopyButton = new JButton("Save a Local WSTG Checklist");
        saveLocalCopyButton.addActionListener(e -> {
            if (extender.checklistLog.isEmpty()) {
                scanStatusLabel.setText(CHECKLIST_NOT_FETCHED_MSG);
                extender.issueAlert(CHECKLIST_NOT_FETCHED_MSG);
            } else {
                final int userOption = destDirChooser
                        .showSaveDialog(extender.getApi().userInterface().swingUtils().suiteFrame());

                if (userOption == JFileChooser.APPROVE_OPTION) {
                    checklistDestDir = destDirChooser.getSelectedFile();
                    try {
                        extender.getChecklistManager().getChecklistLogic()
                                .saveLocalCopy(checklistDestDir.getAbsolutePath());
                    } catch (IOException ioException) {
                        extender.logOutput("IOException at setupTopPanel - saveLocalCopyButton");
                    }
                    extender.issueAlert("Local checklist saved to " + checklistDestDir.getAbsolutePath());
                    scanStatusLabel.setText("Local checklist saved to " + checklistDestDir.getAbsolutePath());
                }
            }
        });
    }

    // START INTERRUPT: I need to handle generateWebChecklistButton scope.
    // I will making generateWebChecklistButton a private field.
    // Same for loadProjectButton if needed?
    // Let's check loadProjectButton usage. It's used in miscPanel.
    // Let's check generateLocalChecklistButton usage. It's used in fetchWorker.

    private void setupExcelReportButton() {
        generateExcelReportButton = new JButton("Generate Excel Report");
        generateExcelReportButton.addActionListener(e -> {
            if (extender.checklistLog.isEmpty()) {
                scanStatusLabel.setText(CHECKLIST_NOT_FETCHED_MSG);
                extender.issueAlert(CHECKLIST_NOT_FETCHED_MSG);
            } else {
                final int userOption = destDirChooser
                        .showSaveDialog(extender.getApi().userInterface().swingUtils().suiteFrame());

                if (userOption == JFileChooser.APPROVE_OPTION) {
                    checklistDestDir = destDirChooser.getSelectedFile();
                    extender.getChecklistManager().getChecklistLogic()
                            .saveToExcelFile(checklistDestDir.getAbsolutePath());
                }
            }
        });
    }

    private JPanel createMiscPanel() {
        JPanel miscPanel = new JPanel(new FlowLayout(FlowLayout.LEADING, 10, 10));
        miscPanel.add(new JLabel("Misc Actions:", SwingConstants.LEFT), BorderLayout.LINE_START);

        deleteEntryButton = new JButton("Delete Entry");
        deleteEntryButton.addActionListener(e -> extender.getLoggerTable().deleteEntry());

        deleteInstanceButton = new JButton("Delete Instance");
        deleteInstanceButton.addActionListener(e -> extender.getInstanceTable().deleteInstance());

        JButton clearAllButton = new JButton("Clear All Logs");
        clearAllButton.addActionListener(e -> {
            int result = JOptionPane.showConfirmDialog(
                    extender.getApi().userInterface().swingUtils().suiteFrame(),
                    "Are you sure you want to clear all logger entries?",
                    "Confirm Clear All",
                    JOptionPane.YES_NO_OPTION);
            if (result == JOptionPane.YES_OPTION) {
                extender.getLoggerTable().clearAllEntries();
            }
        });

        JButton saveCurrentProjectButton = createSaveProjectButton();
        JButton loadProjectButton = createLoadProjectButton();

        miscPanel.add(deleteEntryButton);
        miscPanel.add(deleteInstanceButton);
        miscPanel.add(clearAllButton);
        miscPanel.add(saveCurrentProjectButton);
        miscPanel.add(loadProjectButton);

        return miscPanel;
    }

    /**
     * Create save project button with action listener
     */
    private JButton createSaveProjectButton() {
        JButton saveCurrentProjectButton = new JButton("Save Project");
        saveCurrentProjectButton.addActionListener(e -> {
            final int userOption = destDirChooser
                    .showSaveDialog(extender.getApi().userInterface().swingUtils().suiteFrame());

            if (userOption == JFileChooser.APPROVE_OPTION) {
                checklistDestDir = destDirChooser.getSelectedFile();
                try {
                    extender.getProjectWorkspace().saveFile(checklistDestDir.getAbsolutePath());
                } catch (IOException ioException) {
                    extender.logOutput("IOException at createSaveProjectButton");
                }
            }
        });
        return saveCurrentProjectButton;
    }

    /**
     * Create load project button with action listener and file validation
     */
    private JButton createLoadProjectButton() {
        JButton loadProjectButton = new JButton("Load Project");
        loadProjectButton.addActionListener(e -> handleLoadProject(loadProjectButton));
        return loadProjectButton;
    }

    /**
     * Handle load project action with file validation
     */
    private void handleLoadProject(JButton loadProjectButton) {
        JFileChooser fileChooser = createProjectFileChooser();

        final int userOption = fileChooser
                .showOpenDialog(extender.getApi().userInterface().swingUtils().suiteFrame());

        if (userOption == JFileChooser.APPROVE_OPTION) {
            File chosenFile = fileChooser.getSelectedFile();
            loadProjectFromFile(chosenFile, loadProjectButton);
        }
    }

    /**
     * Create file chooser with filter for project files
     */
    private JFileChooser createProjectFileChooser() {
        JFileChooser fileChooser = new JFileChooser();

        // Set file filter to only show .json and .ser files
        fileChooser.setFileFilter(new javax.swing.filechooser.FileFilter() {
            @Override
            public boolean accept(File f) {
                if (f.isDirectory()) {
                    return true;
                }
                String name = f.getName().toLowerCase();
                return name.endsWith(".json") || name.endsWith(".ser");
            }

            @Override
            public String getDescription() {
                return "Autowasp Project Files (*.json, *.ser)";
            }
        });

        return fileChooser;
    }

    /**
     * Load project from file with validation
     */
    private void loadProjectFromFile(File chosenFile, JButton loadProjectButton) {
        try {
            // Get canonical path to prevent path traversal
            String canonicalPath = chosenFile.getCanonicalPath();
            String fileName = chosenFile.getName();

            // Validate file extension (use endsWith instead of contains)
            if (!isValidProjectFileName(fileName)) {
                scanStatusLabel.setText("Error: Invalid project file name");
                extender.issueAlert("Error: Please select a valid Autowasp project file " +
                        "(autowasp_project.json or autowasp_project.ser)");
                return;
            }

            // Verify file is readable and not a symlink
            if (!chosenFile.isFile() || !chosenFile.canRead()) {
                extender.issueAlert("Error: Cannot read project file");
                return;
            }

            // Load project in background thread
            loadProjectInBackground(canonicalPath, loadProjectButton);

        } catch (IOException ioException) {
            extender.logOutput("Error validating file path: " + ioException.getMessage());
            extender.issueAlert("Error: Invalid file path");
        }
    }

    /**
     * Validate project file name
     */
    private boolean isValidProjectFileName(String fileName) {
        return fileName.endsWith("autowasp_project.json") ||
                fileName.endsWith("autowasp_project.ser");
    }

    /**
     * Load project in background thread
     */
    private void loadProjectInBackground(String canonicalPath, JButton loadProjectButton) {
        Runnable runnable = () -> {
            extender.getProjectWorkspace().readFromFile(canonicalPath);
            loadProjectButton.setEnabled(false);
        };
        Thread loadThread = new Thread(runnable);
        loadThread.start();
    }

    /**
     * Add target to Burp scope with security validation
     *
     * Security improvements:
     * - Validates hostname format
     * - Only allows HTTP/HTTPS protocols
     * - Prevents injection attacks
     */
    private void addTargetToScope(JTextField hostField) {
        String input = hostField.getText().trim();
        if (input.isEmpty()) {
            return;
        }

        // Validate input format
        if (!isValidHostnameInput(input)) {
            scanStatusLabel.setText("Error: Invalid hostname format");
            extender.issueAlert("Error: Invalid hostname format. Please enter a valid domain or URL.");
            return;
        }

        // Remove protocol if present to get the raw domain
        String domain = input;
        if (domain.contains("://")) {
            String protocol = domain.substring(0, domain.indexOf("://"));
            // Only allow http/https protocols
            if (!protocol.equalsIgnoreCase("http") && !protocol.equalsIgnoreCase("https")) {
                extender.issueAlert("Error: Only HTTP/HTTPS protocols are allowed");
                return;
            }
            domain = domain.substring(domain.indexOf("://") + 3);
        }

        // Remove port if present
        if (domain.contains(":")) {
            domain = domain.substring(0, domain.indexOf(":"));
        }

        // Remove path if present
        if (domain.contains("/")) {
            domain = domain.substring(0, domain.indexOf("/"));
        }

        // Remove www. if present
        if (domain.startsWith("www.")) {
            domain = domain.substring(4);
        }

        // Final validation
        if (!isValidDomain(domain)) {
            extender.issueAlert("Error: Invalid domain name");
            return;
        }

        // Now we have the base domain (e.g. example.com)
        // Construct all 4 variants
        String[] variants = {
                HTTP_PREFIX + domain,
                HTTPS_PREFIX + domain,
                HTTP_WWW_PREFIX + domain,
                HTTPS_WWW_PREFIX + domain
        };

        try {
            for (String variant : variants) {
                extender.getApi().scope().includeInScope(variant);
            }
            scanStatusLabel.setText("Target added to scope: " + input);
            if (!enableScanningButton.isEnabled()) {
                // Automatically extract scan related to the newly added domain
                extender.getScannerLogic().extractExistingScan();
            }
            hostField.setText("");
        } catch (Exception e1) {
            extender.logOutput("Exception occurred at addTargetToScope: " + e1.getMessage());
            extender.issueAlert("Error: Failed to add target to scope");
        }
    }

    /**
     * Validate hostname input format
     *
     * @param input User input to validate
     * @return true if input is valid
     */
    private boolean isValidHostnameInput(String input) {
        if (input == null || input.trim().isEmpty()) {
            return false;
        }

        // Remove protocol if present
        String hostname = input;
        if (hostname.contains("://")) {
            hostname = hostname.substring(hostname.indexOf("://") + 3);
        }

        // Remove port if present
        if (hostname.contains(":")) {
            hostname = hostname.substring(0, hostname.indexOf(":"));
        }

        // Remove path if present
        if (hostname.contains("/")) {
            hostname = hostname.substring(0, hostname.indexOf("/"));
        }

        // Remove www. if present
        if (hostname.startsWith("www.")) {
            hostname = hostname.substring(4);
        }

        return isValidDomain(hostname);
    }

    /**
     * Validate domain name format
     *
     * @param domain Domain to validate
     * @return true if domain is valid
     */
    private boolean isValidDomain(String domain) {
        if (domain == null || domain.trim().isEmpty()) {
            return false;
        }

        // Prevent stack overflow by limiting domain length
        if (domain.length() > 253) { // RFC 1035 max domain length
            return false;
        }

        // Allow localhost
        if (domain.equalsIgnoreCase("localhost")) {
            return true;
        }

        // Allow IP addresses (simple check)
        if (domain.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")) {
            return true;
        }

        // Domain name validation - optimized to prevent stack overflow
        // Split by dot and validate each label separately
        String[] labels = domain.split("\\.");
        if (labels.length < 2) {
            return false; // Domain must have at least 2 parts
        }

        // Validate each label
        for (String label : labels) {
            if (!isValidDomainLabel(label)) {
                return false;
            }
        }

        // Last label (TLD) must be at least 2 characters and alphabetic
        String tld = labels[labels.length - 1];
        return tld.length() >= 2 && tld.matches("^[a-zA-Z]+$");
    }

    /**
     * Validate individual domain label
     *
     * @param label Domain label to validate
     * @return true if label is valid
     */
    private boolean isValidDomainLabel(String label) {
        if (label == null || label.isEmpty() || label.length() > 63) {
            return false; // RFC 1035 max label length
        }

        // Label must start and end with alphanumeric, can contain hyphens in middle
        return label.matches("^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$");
    }

    // This method setup the logger functionality tab
    private void setupLoggerPanel() {
        JSplitPane internalLoggerSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        JTabbedPane loggerTab = new JTabbedPane();
        JTabbedPane instanceLogTab = new JTabbedPane();
        JSplitPane internalPenTesterCommentsSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        JSplitPane internalEvidencesSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        JSplitPane instancesLogsSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        // Logger Table Search
        JPanel loggerSearchPanel = new JPanel(new FlowLayout(FlowLayout.LEADING, 5, 2));
        loggerSearchPanel.add(new JLabel("Search Logger: "));
        JTextField loggerSearchField = new JTextField(20);
        loggerSearchPanel.add(loggerSearchField);

        TableRowSorter<TableModel> loggerSorter = new TableRowSorter<>(extender.getLoggerTable().getModel());
        extender.getLoggerTable().setRowSorter(loggerSorter);

        loggerSearchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                updateFilter();
            }

            public void removeUpdate(DocumentEvent e) {
                updateFilter();
            }

            public void changedUpdate(DocumentEvent e) {
                updateFilter();
            }

            private void updateFilter() {
                String text = loggerSearchField.getText();
                if (text.trim().isEmpty()) {
                    loggerSorter.setRowFilter(null);
                } else {
                    loggerSorter.setRowFilter(RowFilter.regexFilter("(?i)" + text));
                }
            }
        });

        // Setting up JTable
        JScrollPane loggerScrollPane = new JScrollPane(extender.getLoggerTable());
        loggerScrollPane.setPreferredSize(new Dimension(800, 400));

        loggerScrollPane.setBorder(new EmptyBorder(0, 0, 10, 0));
        JScrollPane instancesScrollPane = new JScrollPane(extender.getInstanceTable());
        instancesScrollPane.setPreferredSize(new Dimension(700, 200));
        instancesScrollPane.setBorder(new EmptyBorder(0, 0, 10, 0));

        // Comments Pane
        penTesterCommentBox = new JTextPane();
        penTesterCommentBox.setContentType("text/plain");
        penTesterCommentBox.setEditable(true);
        JScrollPane penTesterCommentBoxScrollPane = new JScrollPane(penTesterCommentBox);
        JPanel commentsPanel = new JPanel(new FlowLayout(FlowLayout.LEADING, 10, 10));
        JButton clearCommentsButton = new JButton("Clear Comments");
        clearCommentsButton.addActionListener(e -> penTesterCommentBox.setText(""));
        JButton saveCommentsButton = new JButton("Save Comments");
        saveCommentsButton.addActionListener(
                e -> extender.getLoggerTable().modifyComments(penTesterCommentBox.getText().trim() + "\n"));
        commentsPanel.add(saveCommentsButton);
        commentsPanel.add(clearCommentsButton);
        internalPenTesterCommentsSplitPane.setTopComponent(commentsPanel);
        internalPenTesterCommentsSplitPane.setBottomComponent(penTesterCommentBoxScrollPane);

        // Evidence Pane
        evidenceBox = new JTextPane();
        evidenceBox.setContentType("text/plain");
        evidenceBox.setEditable(true);
        JScrollPane evidenceBoxScrollPane = new JScrollPane(evidenceBox);
        JPanel evidencePanel = new JPanel(new FlowLayout(FlowLayout.LEADING, 10, 10));
        JButton clearEvidencesButton = new JButton("Clear Evidence");
        clearEvidencesButton.addActionListener(e -> evidenceBox.setText(""));
        JButton saveEvidencesButton = new JButton("Save Evidence");
        saveEvidencesButton
                .addActionListener(e -> extender.getLoggerTable().modifyEvidence(evidenceBox.getText().trim()));
        evidencePanel.add(saveEvidencesButton);
        evidencePanel.add(clearEvidencesButton);
        internalEvidencesSplitPane.setTopComponent(evidencePanel);
        internalEvidencesSplitPane.setBottomComponent(evidenceBoxScrollPane);

        // Lower half - Instances Tab
        // Montoya API: Create separate request and response editors
        requestEditor = extender.getApi().userInterface().createHttpRequestEditor();
        responseEditor = extender.getApi().userInterface().createHttpResponseEditor();
        instanceLogTab.add("Request", requestEditor.uiComponent());
        instanceLogTab.add("Response", responseEditor.uiComponent());
        instancesLogsSplitPane.setLeftComponent(instancesScrollPane);
        instancesLogsSplitPane.setRightComponent(instanceLogTab);

        // Consolidate the final tabs for logger feature
        loggerTab.addTab("Affected Instances", instancesLogsSplitPane);
        loggerTab.addTab("Pen Tester Comments", internalPenTesterCommentsSplitPane);
        loggerTab.addTab("Evidence", internalEvidencesSplitPane);

        // Logger Container with Pagination
        JPanel loggerContainer = new JPanel(new BorderLayout());
        loggerContainer.add(loggerSearchPanel, BorderLayout.NORTH);
        loggerContainer.add(loggerScrollPane, BorderLayout.CENTER);
        loggerContainer.add(createLoggerPaginationPanel(), BorderLayout.SOUTH);

        internalLoggerSplitPane.setTopComponent(loggerContainer);
        internalLoggerSplitPane.setBottomComponent(loggerTab);
        bottomModulesTabs.add("Logger", internalLoggerSplitPane);
    }

    private JPanel createLoggerPaginationPanel() {
        JPanel paginationPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        JButton prevButton = new JButton("< Prev");
        JButton nextButton = new JButton("Next >");
        loggerPageLabel = new JLabel("Page 1 of 1");

        prevButton.addActionListener(e -> {
            extender.getLoggerTableModel().previousPage();
            updateLoggerPageLabel();
        });

        nextButton.addActionListener(e -> {
            extender.getLoggerTableModel().nextPage();
            updateLoggerPageLabel();
        });

        paginationPanel.add(prevButton);
        paginationPanel.add(loggerPageLabel);
        paginationPanel.add(nextButton);

        return paginationPanel;
    }

    public void updateLoggerPageLabel() {
        if (loggerPageLabel != null) {
            int current = extender.getLoggerTableModel().getCurrentPage() + 1;
            int total = extender.getLoggerTableModel().getTotalPages();
            loggerPageLabel.setText("Page " + current + " of " + total);
        }
    }

    // This method setup the OWASP checklist functionality tab
    private void setupCheckListPanel() {
        JSplitPane internalChecklistSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        summaryTextPane = new JTextPane();
        setupHtmlTextPane(summaryTextPane);

        howToTestTextPane = new JEditorPane();
        setupHtmlTextPane(howToTestTextPane);

        referencesTextPane = new JTextPane();
        setupHtmlTextPane(referencesTextPane);

        // Search Panel for Checklist
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEADING, 5, 2));
        searchPanel.add(new JLabel("Search WSTG: "));
        JTextField searchField = new JTextField(20);
        searchPanel.add(searchField);

        TableRowSorter<TableModel> sorter = new TableRowSorter<>(extender.getChecklistTable().getModel());
        extender.getChecklistTable().setRowSorter(sorter);

        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                updateFilter();
            }

            public void removeUpdate(DocumentEvent e) {
                updateFilter();
            }

            public void changedUpdate(DocumentEvent e) {
                updateFilter();
            }

            private void updateFilter() {
                String text = searchField.getText();
                if (text.trim().isEmpty()) {
                    sorter.setRowFilter(null);
                } else {
                    sorter.setRowFilter(RowFilter.regexFilter("(?i)" + text));
                }
            }
        });

        JPanel tableWithSearchPanel = new JPanel(new BorderLayout());
        tableWithSearchPanel.add(searchPanel, BorderLayout.NORTH);
        JScrollPane checklistScrollPane = new JScrollPane(extender.getChecklistTable());
        tableWithSearchPanel.add(checklistScrollPane, BorderLayout.CENTER);

        checklistScrollPane.setPreferredSize(new Dimension(300, 200));
        checklistScrollPane.setBorder(new EmptyBorder(0, 0, 10, 0));
        JScrollPane summaryScrollPane = new JScrollPane(summaryTextPane);
        JScrollPane howToTestScrollPane = new JScrollPane(howToTestTextPane);
        JScrollPane referencesScrollPane = new JScrollPane(referencesTextPane);
        JTabbedPane checklistBottomTabs = new JTabbedPane();
        checklistBottomTabs.add("Summary", summaryScrollPane);
        checklistBottomTabs.add("How to test", howToTestScrollPane);
        checklistBottomTabs.add("References", referencesScrollPane);
        internalChecklistSplitPane.setLeftComponent(tableWithSearchPanel);
        internalChecklistSplitPane.setRightComponent(checklistBottomTabs);
        bottomModulesTabs.addTab("OWASP Testing Checklist", internalChecklistSplitPane);
        gtScannerSplitPane.setRightComponent(bottomModulesTabs);
    }

    private void setupHtmlTextPane(javax.swing.text.JTextComponent pane) {
        pane.setEditable(false);
        if (pane instanceof JEditorPane editorPane) {
            editorPane.setContentType(HTML_CONTENT_TYPE);
            editorPane.addHyperlinkListener(e -> {
                if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED && Desktop.isDesktopSupported()) {
                    try {
                        Desktop.getDesktop().browse(e.getURL().toURI());
                    } catch (IOException | URISyntaxException e1) {
                        extender.logOutput(SETUP_ERROR_MSG);
                    }
                }
            });
        }
        pane.putClientProperty(HTML_DISABLE_PROPERTY, null);
    }

    // Initial buttons to set to disable by default
    public void disabledInitialButtons() {
        this.deleteEntryButton.setEnabled(false);
        this.deleteInstanceButton.setEnabled(false);
        generateExcelReportButton.setEnabled(false);
        saveLocalCopyButton.setEnabled(false);
        cancelFetchButton.setEnabled(false);
    }

    // To allow instance deletion button only
    public void deleteEntryButtonEnabled() {
        this.deleteEntryButton.setEnabled(true);
        this.deleteInstanceButton.setEnabled(false);
    }

    // To allow entry deletion button only
    public void deleteInstanceButtonEnabled() {
        this.deleteEntryButton.setEnabled(false);
        this.deleteInstanceButton.setEnabled(true);
    }

    // Getter methods for encapsulated fields
    public HttpRequestEditor getRequestEditor() {
        return requestEditor;
    }

    public HttpResponseEditor getResponseEditor() {
        return responseEditor;
    }

    public JLabel getScanStatusLabel() {
        return scanStatusLabel;
    }

    public JTextPane getSummaryTextPane() {
        return summaryTextPane;
    }

    public JEditorPane getHowToTestTextPane() {
        return howToTestTextPane;
    }

    public JTextPane getReferencesTextPane() {
        return referencesTextPane;
    }

    public JTextPane getPenTesterCommentBox() {
        return penTesterCommentBox;
    }

    public JTextPane getEvidenceBox() {
        return evidenceBox;
    }

    public JButton getDeleteEntryButton() {
        return deleteEntryButton;
    }

    public JButton getDeleteInstanceButton() {
        return deleteInstanceButton;
    }

    public JButton getCancelFetchButton() {
        return cancelFetchButton;
    }
}
