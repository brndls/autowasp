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
import autowasp.checklist.ChecklistEntry;
import autowasp.checklist.ChecklistLogic;
import autowasp.checklist.ChecklistTable;
import autowasp.checklist.ChecklistTableModel;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * ChecklistManager - Manages OWASP WSTG Checklist components
 *
 * Responsibilities:
 * - Manage checklist logic and data structures
 * - Handle checklist UI components (table, model)
 * - Coordinate checklist state persistence
 * - Provide checklist API to other components
 *
 * This manager encapsulates all checklist-related functionality,
 * reducing coupling in the main Autowasp class.
 */
public class ChecklistManager {

    // Reference to main extension
    private final Autowasp autowasp;

    // Checklist components
    private ChecklistLogic checklistLogic;
    private ChecklistTableModel checklistTableModel;
    private ChecklistTable checklistTable;

    // Checklist data structures
    private final List<ChecklistEntry> checklistLog = new ArrayList<>();
    private final Map<String, ChecklistEntry> checkListHashMap = new HashMap<>();

    /**
     * Constructor
     *
     * @param autowasp Reference to main Autowasp extension
     */
    public ChecklistManager(Autowasp autowasp) {
        this.autowasp = autowasp;
    }

    /**
     * Initialize checklist components
     * Called during extension initialization
     */
    public void initialize() {
        this.checklistLogic = new ChecklistLogic(autowasp);
        this.checklistTableModel = new ChecklistTableModel(autowasp);
        this.checklistTable = new ChecklistTable(checklistTableModel, autowasp);
    }

    // =====================================================================================
    // PUBLIC API - Component Accessors
    // =====================================================================================

    public ChecklistLogic getChecklistLogic() {
        return checklistLogic;
    }

    public ChecklistTableModel getChecklistTableModel() {
        return checklistTableModel;
    }

    public ChecklistTable getChecklistTable() {
        return checklistTable;
    }

    public List<ChecklistEntry> getChecklistLog() {
        return checklistLog;
    }

    public Map<String, ChecklistEntry> getCheckListHashMap() {
        return checkListHashMap;
    }

    // =====================================================================================
    // STATE MANAGEMENT
    // =====================================================================================

    /**
     * Save checklist state to persistence
     * Called during extension unload
     */
    public void saveState() {
        autowasp.getPersistence().saveChecklistState(checklistLog);
    }

    /**
     * Restore checklist state from persistence
     * Called during extension initialization
     */
    public void restoreState() {
        autowasp.getPersistence().loadChecklistState().stream().findFirst().ifPresent(state -> {
            autowasp.getLogging().logToOutput("Found saved checklist state, restoring...");
            checklistLogic.loadLocalCopy(); // Load bundled as base
        });
    }
}
