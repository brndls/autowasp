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

package autowasp.managers;

import autowasp.Autowasp;
import autowasp.ExtenderPanelUI;

import javax.swing.*;
import java.awt.Color;

/**
 * UIManager - Manages User Interface components
 *
 * Responsibilities:
 * - Manage main UI panel and split panes
 * - Handle UI helper components (comboboxes)
 * - Setup column editors and renderers
 * - Coordinate UI initialization
 *
 * This manager encapsulates all UI-related functionality,
 * reducing coupling in the main Autowasp class.
 */
public class UIManager {

    // Reference to main extension
    private final Autowasp autowasp;

    // UI components
    private ExtenderPanelUI extenderPanelUI;
    private ThemeManager themeManager;
    private JSplitPane gtScannerSplitPane;

    // UI helper components (for table column editors)
    private JComboBox<String> comboBox; // Issue column
    private JComboBox<String> comboBox2; // Confidence column
    private JComboBox<String> comboBox3; // Severity column

    // UI state
    private int currentEntryRow;

    /**
     * Constructor
     *
     * @param autowasp Reference to main Autowasp extension
     */
    public UIManager(Autowasp autowasp) {
        this.autowasp = autowasp;
    }

    /**
     * Initialize UI components
     * Called during extension initialization
     *
     * @param checklistManager Reference to checklist manager (for UI setup)
     * @param loggerManager    Reference to logger manager (for UI setup)
     */
    public void initialize(ChecklistManager checklistManager, LoggerManager loggerManager) {
        // Initialize Theme Manager
        this.themeManager = new ThemeManager();

        // Initialize main UI panel
        this.extenderPanelUI = new ExtenderPanelUI(autowasp);

        // Initialize comboboxes for table column editors
        this.comboBox = new JComboBox<>();
        this.comboBox2 = new JComboBox<>();
        this.comboBox3 = new JComboBox<>();

        // Apply theme to comboboxes
        if (themeManager.isDarkMode()) {
            Color bg = themeManager.getBackgroundColor();
            Color fg = themeManager.getForegroundColor();
            this.comboBox.setBackground(bg);
            this.comboBox.setForeground(fg);
            this.comboBox2.setBackground(bg);
            this.comboBox2.setForeground(fg);
            this.comboBox3.setBackground(bg);
            this.comboBox3.setForeground(fg);
        }
    }

    /**
     * Setup UI components after managers are initialized
     * Must be called after ChecklistManager and LoggerManager are initialized
     *
     * @param loggerManager Reference to logger manager
     */
    public void setupUI(LoggerManager loggerManager) {
        // Setup issue column for logger table
        loggerManager.getLoggerTable().setUpIssueColumn(
                loggerManager.getLoggerTable().getColumnModel().getColumn(4));

        // Setup confidence column for instance table
        loggerManager.getInstanceTable().generateConfidenceList();
        loggerManager.getInstanceTable().setUpConfidenceColumn(
                loggerManager.getInstanceTable().getColumnModel().getColumn(2));

        // Setup severity column for instance table
        loggerManager.getInstanceTable().generateSeverityList();
        loggerManager.getInstanceTable().setupSeverityColumn(
                loggerManager.getInstanceTable().getColumnModel().getColumn(3));
    }

    // =====================================================================================
    // PUBLIC API - Component Accessors
    // =====================================================================================

    public ExtenderPanelUI getExtenderPanelUI() {
        return extenderPanelUI;
    }

    public ThemeManager getThemeManager() {
        return themeManager;
    }

    public JSplitPane getGtScannerSplitPane() {
        return gtScannerSplitPane;
    }

    public void setGtScannerSplitPane(JSplitPane gtScannerSplitPane) {
        this.gtScannerSplitPane = gtScannerSplitPane;
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

    public int getCurrentEntryRow() {
        return currentEntryRow;
    }

    public void setCurrentEntryRow(int currentEntryRow) {
        this.currentEntryRow = currentEntryRow;
    }
}
