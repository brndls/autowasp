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
import autowasp.ProjectWorkspaceFactory;
import autowasp.persistence.AutowaspPersistence;

/**
 * PersistenceManager - Manages Data Persistence & Project Workspace
 *
 * Responsibilities:
 * - Manage project workspace operations
 * - Coordinate data persistence (save/load)
 * - Handle state serialization/deserialization
 * - Provide unified persistence API
 *
 * This manager encapsulates all persistence-related functionality,
 * reducing coupling in the main Autowasp class.
 */
public class PersistenceManager {

    // Reference to main extension
    private final Autowasp autowasp;

    // Persistence components
    private ProjectWorkspaceFactory projectWorkspace;
    private AutowaspPersistence persistence;

    /**
     * Constructor
     *
     * @param autowasp Reference to main Autowasp extension
     */
    public PersistenceManager(Autowasp autowasp) {
        this.autowasp = autowasp;
    }

    /**
     * Initialize persistence components
     * Called during extension initialization
     */
    public void initialize() {
        this.projectWorkspace = new ProjectWorkspaceFactory(autowasp);
        this.persistence = new AutowaspPersistence(autowasp.getApi());
    }

    // =====================================================================================
    // PUBLIC API - Component Accessors
    // =====================================================================================

    public ProjectWorkspaceFactory getProjectWorkspace() {
        return projectWorkspace;
    }

    public AutowaspPersistence getPersistence() {
        return persistence;
    }

    // =====================================================================================
    // UNIFIED STATE MANAGEMENT
    // =====================================================================================

    /**
     * Save all extension state to persistence
     * Coordinates saving across all managers
     *
     * @param checklistManager Checklist manager to save state from
     * @param loggerManager    Logger manager to save state from
     */
    public void saveAllState(ChecklistManager checklistManager, LoggerManager loggerManager) {
        autowasp.getLogging().raiseInfoEvent("Autowasp extension unloading - Saving state...");
        checklistManager.saveState();
        loggerManager.saveState();
        autowasp.getLogging().raiseInfoEvent("Autowasp extension unloading - All resources released.");
    }

    /**
     * Restore all extension state from persistence
     * Coordinates restoration across all managers
     *
     * @param checklistManager Checklist manager to restore state to
     * @param loggerManager    Logger manager to restore state to
     */
    public void restoreAllState(ChecklistManager checklistManager, LoggerManager loggerManager) {
        checklistManager.restoreState();
        loggerManager.restoreState();
    }
}
