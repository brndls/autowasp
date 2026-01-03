/*
 * Copyright (c) 2026 Autowasp Contributors
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

package autowasp.persistence;

import autowasp.checklist.ChecklistEntry;
import autowasp.logger.entrytable.LoggerEntry;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;

/**
 * Handles persistence logic using Montoya's extensionData API.
 * This stores data directly into the Burp Suite project file (.burp).
 */
public class AutowaspPersistence {
    private static final String CHECKLIST_STATE_KEY = "autowasp_checklist_state_json";
    private static final String LOGGER_STATE_KEY = "autowasp_logger_state_json";
    private final MontoyaApi api;

    private final Gson gson;

    public AutowaspPersistence(MontoyaApi api) {
        this.api = api;
        this.gson = new Gson();
    }

    /**
     * Saves the current checklist state to the project file.
     *
     * @param entries List of ChecklistEntry objects from the table model.
     */
    public synchronized void saveChecklistState(List<ChecklistEntry> entries) {
        if (entries == null || entries.isEmpty()) {
            return;
        }

        try {
            List<ChecklistState> stateList = entries.stream()
                    .map(entry -> new ChecklistState(
                            entry.getRefNumber(),
                            entry.isExcluded(),
                            entry.isTestcaseCompleted(),
                            entry.getPenTesterComments(),
                            entry.getEvidence()))
                    .toList();

            String json = gson.toJson(stateList);
            api.persistence().extensionData().setString(CHECKLIST_STATE_KEY, json);
        } catch (Exception e) {
            api.logging().logToError("Failed to save checklist state: " + e.getMessage());
        }
    }

    /**
     * Loads the saved checklist state from the project file.
     *
     * @return List of ChecklistState objects or empty list if none found.
     */
    public List<ChecklistState> loadChecklistState() {
        PersistedObject projectData = api.persistence().extensionData();
        String json = projectData.getString(CHECKLIST_STATE_KEY);

        if (json == null || json.isEmpty()) {
            return new ArrayList<>();
        }

        try {
            Type listType = new TypeToken<ArrayList<ChecklistState>>() {
            }.getType();
            return gson.fromJson(json, listType);
        } catch (Exception e) {
            api.logging().logToError("Failed to load checklist state: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Saves the current logger state to the project file.
     *
     * @param entries List of LoggerEntry objects.
     */
    public synchronized void saveLoggerState(List<LoggerEntry> entries) {
        if (entries == null || entries.isEmpty()) {
            return;
        }

        try {
            List<LoggerState> stateList = entries.stream()
                    .map(this::mapToLoggerState)
                    .toList();

            String json = gson.toJson(stateList);
            api.persistence().extensionData().setString(LOGGER_STATE_KEY, json);
        } catch (Exception e) {
            api.logging().logToError("Failed to save logger state: " + e.getMessage());
        }
    }

    private LoggerState mapToLoggerState(LoggerEntry entry) {
        List<InstanceState> instances = entry.getInstanceList().stream()
                .map(this::mapToInstanceState)
                .toList();

        return new LoggerState(
                entry.getHost(),
                entry.getAction(),
                entry.getVulnType(),
                entry.getChecklistIssue(),
                instances,
                entry.getPenTesterComments(),
                entry.getEvidence(),
                entry.getIssueNumber());
    }

    private InstanceState mapToInstanceState(autowasp.logger.instancestable.InstanceEntry instance) {
        byte[] requestBytes = null;
        byte[] responseBytes = null;
        String host = null;
        int port = 0;
        boolean secure = false;

        if (instance.getRequestResponse() != null) {
            requestBytes = instance.getRequestResponse().getRequest();
            responseBytes = instance.getRequestResponse().getResponse();
            if (instance.getRequestResponse().getHttpService() != null) {
                host = instance.getRequestResponse().getHttpService().getHost();
                port = instance.getRequestResponse().getHttpService().getPort();
                secure = instance.getRequestResponse().getHttpService().isSecure();
            }
        }

        return new InstanceState(
                instance.getUrl(),
                instance.getConfidence(),
                instance.getSeverity(),
                requestBytes,
                responseBytes,
                host,
                port,
                secure);
    }

    /**
     * Loads the saved logger state from the project file.
     *
     *
     * @return List of LoggerState objects or empty list if none found.
     */
    public List<LoggerState> loadLoggerState() {
        PersistedObject projectData = api.persistence().extensionData();
        String json = projectData.getString(LOGGER_STATE_KEY);

        if (json == null || json.isEmpty()) {
            return new ArrayList<>();
        }

        try {
            Type listType = new TypeToken<ArrayList<LoggerState>>() {
            }.getType();
            return gson.fromJson(json, listType);
        } catch (Exception e) {
            api.logging().logToError("Failed to load logger state: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Checks if the current project is a temporary project.
     * extensionData in temporary projects is not saved to disk.
     *
     * @return true if temporary project, false otherwise.
     */
    public boolean isTemporaryProject() {
        // Montoya doesn't have a direct "isTemporaryProject" yet, but we can check if
        // persistent storage is supported
        // or just log that it might not persist.
        // For now, we assume if extensionData exists, we try to use it.
        return false;
    }
}
