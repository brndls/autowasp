/*
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

package autowasp.persistence;

import autowasp.logger.entrytable.LoggerEntry;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.*;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

/**
 * Project Serializer - Secure JSON-based persistence
 *
 * Replaces Java Serialization with JSON to prevent deserialization attacks.
 * This addresses the critical security vulnerability identified in the security
 * audit.
 */
public class ProjectSerializer {

    private static final String PROJECT_FILE_EXTENSION = ".json";
    private final Gson gson;

    public ProjectSerializer() {
        this.gson = new GsonBuilder()
                .setPrettyPrinting()
                .create();
    }

    /**
     * Save project data to JSON file
     *
     * @param loggerEntries    List of logger entries to save
     * @param absoluteFilePath Directory path where file will be saved
     * @throws IOException              if file cannot be written
     * @throws IllegalArgumentException if path is invalid
     */
    public void saveToJson(List<LoggerEntry> loggerEntries, String absoluteFilePath) throws IOException {
        // Validate and canonicalize directory path
        File directory = new File(absoluteFilePath);

        if (!directory.exists() || !directory.isDirectory()) {
            throw new IOException("Invalid directory: " + absoluteFilePath);
        }

        // Get canonical path to prevent path traversal
        String canonicalDir = directory.getCanonicalPath();

        // Construct file path
        String fileName = "autowasp_project" + PROJECT_FILE_EXTENSION;
        File outputFile = new File(canonicalDir, fileName);
        String filePath = outputFile.getCanonicalPath();

        // Verify output file is within the intended directory
        if (!filePath.startsWith(canonicalDir)) {
            throw new IOException("Path traversal detected: " + filePath);
        }

        // Serialize to JSON
        String json = gson.toJson(loggerEntries);

        // Write to file with UTF-8 encoding
        try (BufferedWriter writer = Files.newBufferedWriter(
                outputFile.toPath(), StandardCharsets.UTF_8)) {
            writer.write(json);
        }
    }

    /**
     * Load project data from JSON file
     *
     * @param absoluteFilePath Path to the JSON file
     * @return List of logger entries
     * @throws IOException              if file cannot be read
     * @throws IllegalArgumentException if file is invalid
     */
    public List<LoggerEntry> loadFromJson(String absoluteFilePath) throws IOException {
        // Validate file path
        File file = new File(absoluteFilePath);

        if (!file.exists() || !file.isFile()) {
            throw new FileNotFoundException("File not found: " + absoluteFilePath);
        }

        // Get canonical path to prevent path traversal
        String canonicalPath = file.getCanonicalPath();
        String fileName = file.getName();

        // Validate file extension
        if (!fileName.endsWith(PROJECT_FILE_EXTENSION)) {
            throw new IllegalArgumentException(
                    "Invalid file type. Expected " + PROJECT_FILE_EXTENSION + " file");
        }

        // Verify file is readable
        if (!file.canRead()) {
            throw new IOException("Cannot read file: " + canonicalPath);
        }

        // Read JSON content
        String json;
        try (BufferedReader reader = Files.newBufferedReader(
                file.toPath(), StandardCharsets.UTF_8)) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            json = sb.toString();
        }

        // Deserialize from JSON
        Type listType = new TypeToken<List<LoggerEntry>>() {
        }.getType();
        List<LoggerEntry> entries = gson.fromJson(json, listType);

        if (entries == null) {
            throw new IOException("Failed to parse JSON file");
        }

        return entries;
    }

    /**
     * Validate directory path for security
     *
     * @param directoryPath Path to validate
     * @return Canonical path if valid
     * @throws IOException if path is invalid or contains traversal
     */
    public String validateDirectoryPath(String directoryPath) throws IOException {
        if (directoryPath == null || directoryPath.trim().isEmpty()) {
            throw new IllegalArgumentException("Directory path cannot be empty");
        }

        File directory = new File(directoryPath);

        if (!directory.exists()) {
            throw new FileNotFoundException("Directory does not exist: " + directoryPath);
        }

        if (!directory.isDirectory()) {
            throw new IllegalArgumentException("Path is not a directory: " + directoryPath);
        }

        // Get canonical path to resolve any .. or symlinks
        String canonicalPath = directory.getCanonicalPath();

        // Additional security check: ensure no suspicious patterns
        if (canonicalPath.contains("..")) {
            throw new IOException("Path traversal detected in canonical path");
        }

        return canonicalPath;
    }

    /**
     * Validate file path for security
     *
     * @param filePath         Path to validate
     * @param expectedFileName Expected file name (e.g., "autowasp_project.json")
     * @return Canonical path if valid
     * @throws IOException if path is invalid
     */
    public String validateFilePath(String filePath, String expectedFileName) throws IOException {
        if (filePath == null || filePath.trim().isEmpty()) {
            throw new IllegalArgumentException("File path cannot be empty");
        }

        File file = new File(filePath);

        // Get canonical path
        String canonicalPath = file.getCanonicalPath();
        String fileName = file.getName();

        // Validate file name if specified
        if (expectedFileName != null && !fileName.equals(expectedFileName)) {
            throw new IllegalArgumentException(
                    "Invalid file name. Expected: " + expectedFileName + ", got: " + fileName);
        }

        // Check for path traversal in canonical path
        if (canonicalPath.contains("..")) {
            throw new IOException("Path traversal detected");
        }

        return canonicalPath;
    }
}
