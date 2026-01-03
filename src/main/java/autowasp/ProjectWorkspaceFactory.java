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

import autowasp.logger.entrytable.LoggerEntry;
import autowasp.persistence.ProjectSerializer;

import java.io.*;
import java.util.List;

/**
 * Project Workspace Factory - Secure persistence layer
 *
 * Refactored to use JSON-based serialization instead of Java serialization
 * to prevent deserialization attacks (Security Audit Fix #1).
 */
public class ProjectWorkspaceFactory implements Serializable {
    private final transient Autowasp extender;
    private final transient ProjectSerializer serializer;

    private static final String PROJECT_FILE_NAME = "autowasp_project.json";

    public ProjectWorkspaceFactory(Autowasp extender) {
        this.extender = extender;
        this.serializer = new ProjectSerializer();
    }

    /**
     * Save project to file directory using secure JSON format
     *
     * Security improvements:
     * - Uses JSON instead of Java serialization
     * - Validates directory path to prevent path traversal
     * - Uses canonical paths
     */
    public void saveFile(String absoluteFilePath) throws IOException {
        try {
            // Validate directory path
            String validatedPath = serializer.validateDirectoryPath(absoluteFilePath);

            // Save using JSON serializer
            serializer.saveToJson(extender.loggerList, validatedPath);

            // Construct display path
            String filePath = validatedPath + File.separator + PROJECT_FILE_NAME;

            // Update UI
            extender.getExtenderPanelUI().getScanStatusLabel()
                    .setText("File saved to " + filePath);
            extender.issueAlert("File saved to " + filePath);

        } catch (IOException e) {
            extender.logOutput("Error saving project: " + e.getMessage());
            extender.issueAlert("Error: Failed to save project - " + e.getMessage());
            throw e;
        }
    }

    /**
     * Load project from file directory
     *
     * Security improvements:
     * - Validates file path and extension
     * - Uses JSON deserialization (safe)
     * - Prevents path traversal attacks
     */
    public void readFromFile(String absoluteFilePath) {
        extender.getLoggerTableModel().clearLoggerList();

        try {
            // Validate file path
            String validatedPath = serializer.validateFilePath(absoluteFilePath, PROJECT_FILE_NAME);

            // Load using JSON serializer
            List<LoggerEntry> entries = serializer.loadFromJson(validatedPath);

            // Add entries to logger
            for (LoggerEntry entry : entries) {
                extender.getLoggerTableModel().addAllLoggerEntry(entry);
                extender.getScannerLogic().repeatedIssue.add(entry.getVulnType());
            }

            // Update UI
            extender.getExtenderPanelUI().getScanStatusLabel()
                    .setText("Project loaded from " + validatedPath);
            extender.issueAlert("Project loaded successfully");

        } catch (FileNotFoundException e) {
            extender.logOutput("File not found: " + e.getMessage());
            extender.issueAlert("Error: Project file not found");
        } catch (IOException e) {
            extender.logOutput("Cannot read file: " + e.getMessage());
            extender.issueAlert("Error: Cannot read project file - " + e.getMessage());
        } catch (IllegalArgumentException e) {
            extender.logOutput("Invalid file: " + e.getMessage());
            extender.issueAlert("Error: Invalid project file - " + e.getMessage());
        }
    }
}
