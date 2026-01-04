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
import autowasp.http.HTTPRequestResponse;
import autowasp.http.HTTPService;
import autowasp.logger.ScannerLogic;
import autowasp.logger.TrafficEntry;
import autowasp.logger.TrafficLogic;
import autowasp.logger.entrytable.LoggerEntry;
import autowasp.logger.entrytable.LoggerTable;
import autowasp.logger.entrytable.LoggerTableModel;
import autowasp.logger.instancestable.InstanceEntry;
import autowasp.logger.instancestable.InstanceTable;
import autowasp.logger.instancestable.InstancesTableModel;
import autowasp.persistence.InstanceState;
import autowasp.persistence.LoggerState;

import java.util.ArrayList;
import java.util.List;

/**
 * LoggerManager - Manages HTTP Traffic Logging & Scanning components
 *
 * Responsibilities:
 * - Manage traffic logging and analysis
 * - Handle logger/instance tables and models
 * - Coordinate scanner logic
 * - Provide traffic data API
 *
 * This manager encapsulates all logging and scanning functionality,
 * reducing coupling in the main Autowasp class.
 */
public class LoggerManager {

    // Reference to main extension
    private final Autowasp autowasp;

    // Logger components
    private TrafficLogic trafficLogic;
    private ScannerLogic scannerLogic;
    private LoggerTableModel loggerTableModel;
    private InstancesTableModel instancesTableModel;
    private LoggerTable loggerTable;
    private InstanceTable instanceTable;

    // Logger data structures
    private final List<TrafficEntry> trafficLog = new ArrayList<>();
    private final List<LoggerEntry> loggerList = new ArrayList<>();
    private final List<InstanceEntry> instanceLog = new ArrayList<>();

    /**
     * Constructor
     *
     * @param autowasp Reference to main Autowasp extension
     */
    public LoggerManager(Autowasp autowasp) {
        this.autowasp = autowasp;
    }

    /**
     * Initialize logger components
     * Called during extension initialization
     */
    public void initialize() {
        // Initialize table models
        this.instancesTableModel = new InstancesTableModel(instanceLog);
        this.instanceTable = new InstanceTable(instancesTableModel, autowasp);

        this.loggerTableModel = new LoggerTableModel(loggerList, autowasp);
        this.loggerTable = new LoggerTable(loggerTableModel, autowasp);

        // Initialize logic components
        this.scannerLogic = new ScannerLogic(autowasp);
        this.trafficLogic = new TrafficLogic(autowasp);
    }

    // =====================================================================================
    // PUBLIC API - Component Accessors
    // =====================================================================================

    public TrafficLogic getTrafficLogic() {
        return trafficLogic;
    }

    public ScannerLogic getScannerLogic() {
        return scannerLogic;
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

    public List<TrafficEntry> getTrafficLog() {
        return trafficLog;
    }

    public List<LoggerEntry> getLoggerList() {
        return loggerList;
    }

    public List<InstanceEntry> getInstanceLog() {
        return instanceLog;
    }

    // =====================================================================================
    // STATE MANAGEMENT
    // =====================================================================================

    /**
     * Save logger state to persistence
     * Called during extension unload
     */
    public void saveState() {
        autowasp.getPersistenceManager().getPersistence().saveLoggerState(loggerList);
    }

    /**
     * Restore logger state from persistence
     * Called during extension initialization
     */
    public void restoreState() {
        List<LoggerState> savedLoggerStates = autowasp.getPersistenceManager().getPersistence().loadLoggerState();
        if (savedLoggerStates.isEmpty()) {
            return;
        }

        autowasp.getLogging()
                .logToOutput("Restoring " + savedLoggerStates.size() + " logger entries from project file...");
        for (LoggerState state : savedLoggerStates) {
            LoggerEntry entry = new LoggerEntry(state.host(), state.action(), state.vulnType(), state.checklistIssue());
            entry.setPenTesterComments(state.comments());
            entry.setEvidence(state.evidence());

            for (InstanceState instState : state.instances()) {
                try {
                    java.net.URL url = new java.net.URI(instState.url()).toURL();
                    HTTPService svc = null;
                    if (instState.host() != null) {
                        svc = new HTTPService(instState.host(), instState.port(), instState.secure());
                    }
                    HTTPRequestResponse reqRes = new HTTPRequestResponse(
                            instState.requestBytes(),
                            instState.responseBytes(),
                            svc);
                    InstanceEntry instEntry = new InstanceEntry(url, instState.confidence(), instState.severity(),
                            reqRes);
                    entry.addInstance(instEntry);
                } catch (Exception e) {
                    autowasp.getLogging().logToError("Failed to restore instance entry: " + e.getMessage());
                }
            }
            loggerTableModel.addAllLoggerEntry(entry);
        }
        autowasp.getLogging().logToOutput("Logger state restored successfully.");
    }
}
