/*
 * Copyright (c) 2021 Government Technology Agency
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

import java.io.*;

public class ProjectWorkspaceFactory implements Serializable {
    private final transient Autowasp extender;
    private static final String PROJECT_FILE_NAME = "autowasp_project.ser";

    public ProjectWorkspaceFactory(Autowasp extender) {
        this.extender = extender;
    }

    // Method to save project to file directory
    public void saveFile(String absoluteFilePath) throws IOException {
        String filePath = absoluteFilePath + File.separator + PROJECT_FILE_NAME;
        try (FileOutputStream fileOutputStream = new FileOutputStream(filePath);
                ObjectOutputStream outputStream = new ObjectOutputStream(fileOutputStream)) {
            for (LoggerEntry loggerEntry : extender.loggerList) {
                outputStream.writeObject(loggerEntry);
            }
            extender.getExtenderPanelUI().getScanStatusLabel()
                    .setText("File saved to " + filePath);
            extender.issueAlert("File saved to " + filePath);
        }
    }

    // Method to obtain file directory
    public void readFromFile(String absoluteFilePath) {
        extender.getLoggerTableModel().clearLoggerList();

        try (FileInputStream fileInputStream = new FileInputStream(absoluteFilePath);
                ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream)) {

            readEntriesFromStream(objectInputStream);

        } catch (FileNotFoundException e) {
            extender.logOutput("File not found");
        } catch (IOException e) {
            extender.logOutput("Cannot read file");
        } catch (ClassNotFoundException e) {
            extender.logOutput("LoggerEntry class not found");
        }
    }

    private void readEntriesFromStream(ObjectInputStream objectInputStream) throws IOException, ClassNotFoundException {
        boolean eof = false;
        while (!eof) {
            try {
                LoggerEntry loggerEntryTemp = (LoggerEntry) objectInputStream.readObject();
                extender.getLoggerTableModel().addAllLoggerEntry(loggerEntryTemp);
                extender.getScannerLogic().repeatedIssue.add(loggerEntryTemp.getVulnType());
            } catch (EOFException e) {
                eof = true;
            }
        }
    }

    // Method for save closing of FileOutputStream

}
