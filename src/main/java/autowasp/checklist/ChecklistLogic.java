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

package autowasp.checklist;

import autowasp.Autowasp;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/* Notes:
 * 1. The WSTG checklist is now bundled as a JSON resource for consistency and offline support.
 */

public class ChecklistLogic implements Serializable {

    private final transient Autowasp extender;

    public ChecklistLogic(Autowasp extender) {
        this.extender = extender;
    }

    /**
     * Show user-friendly error dialog using Burp's suiteFrame() as parent.
     * BApp Store Criteria #10: Parent GUI elements correctly.
     *
     * @param message Error message to display
     */
    private void showErrorDialog(String message) {
        javax.swing.JOptionPane.showMessageDialog(
                extender.getApi().userInterface().swingUtils().suiteFrame(),
                message,
                "Autowasp Error",
                javax.swing.JOptionPane.ERROR_MESSAGE);
    }

    // Saves a local copy of the checklist in a file called OWASPChecklistData.txt
    // at the directory dictated by the user
    public void saveLocalCopy(String absoluteFilePath) throws IOException {
        String filePath = absoluteFilePath + File.separator + "OWASP_WSTG_local";
        try (FileOutputStream fileOutputStream = new FileOutputStream(filePath);
                ObjectOutputStream outputStream = new ObjectOutputStream(fileOutputStream)) {

            for (ChecklistEntry entry : extender.getChecklistManager().getChecklistLog()) {
                // To ensure entries appear in the local copy archive, we reset NA to a baseline
                // status.
                // This ensures they aren't permanently excluded when shared as a template.
                if (entry.getStatus() == ChecklistStatus.NA) {
                    ChecklistEntry tempChecklistEntry = entry;
                    tempChecklistEntry.setStatus(ChecklistStatus.TODO);
                    outputStream.writeObject(tempChecklistEntry);
                } else {
                    outputStream.writeObject(entry);
                }
            }

            extender.getUIManager().getExtenderPanelUI().getScanStatusLabel()
                    .setText("File saved to " + filePath);
            extender.issueAlert("File saved to " + filePath);
        }
    }

    /**
     * Loads WSTG checklist from bundled JSON resource.
     * BApp Store Criteria #8: Support Offline Working.
     */
    public void loadLocalCopy() {
        extender.getChecklistManager().getChecklistLog().clear();
        extender.getChecklistManager().getCheckListHashMap().clear();

        LocalChecklistLoader loader = new LocalChecklistLoader();
        List<ChecklistEntry> entries = loader.loadFromResources();

        if (entries.isEmpty()) {
            extender.logOutput("Failed to load bundled WSTG checklist");
            showErrorDialog("Failed to load bundled WSTG checklist. The resource file may be missing.");
            return;
        }

        for (ChecklistEntry entry : entries) {
            extender.getChecklistManager().getCheckListHashMap().put(entry.getRefNumber(), entry);
            loadNewChecklistEntry(entry);
        }

        // Apply saved persistence state (Phase 7.1)
        applySavedPersistenceState();

        extender.getLoggerManager().getLoggerTable().generateWSTGList();
        extender.logOutput("Loaded " + entries.size() + " items from bundled WSTG v" + loader.getVersion());
    }

    /**
     * Applies saved state (checkboxes, comments) from extensionData to the current
     * checklist.
     */
    private void applySavedPersistenceState() {
        List<autowasp.persistence.ChecklistState> savedStates = extender.getPersistenceManager().getPersistence()
                .loadChecklistState();
        if (savedStates.isEmpty()) {
            return;
        }

        int restoredCount = 0;
        for (autowasp.persistence.ChecklistState state : savedStates) {
            ChecklistEntry entry = extender.getChecklistManager().getCheckListHashMap().get(state.refNumber());
            if (entry != null) {
                restoreEntryState(entry, state);
                restoredCount++;
            }
        }

        if (restoredCount > 0) {
            extender.logOutput("Restored persistence state for " + restoredCount + " checklist items.");
            // Refresh table UI
            extender.getChecklistManager().getChecklistTableModel().fireTableDataChanged();
        }
    }

    private void restoreEntryState(ChecklistEntry entry, autowasp.persistence.ChecklistState state) {
        entry.setStatus(determineStatus(state));

        if (state.comments() != null && !state.comments().isEmpty()) {
            entry.clearComments(); // Clear default "Please insert comments" if any
            entry.setPenTesterComments(state.comments());
        }
        if (state.evidence() != null && !state.evidence().isEmpty()) {
            entry.clearEvidences(); // Clear default "nil" if any
            entry.setEvidence(state.evidence());
        }
    }

    private ChecklistStatus determineStatus(autowasp.persistence.ChecklistState state) {
        // 1. Check for modern status string
        if (state.status() != null) {
            try {
                return ChecklistStatus.valueOf(state.status());
            } catch (IllegalArgumentException e) {
                return ChecklistStatus.TODO;
            }
        }

        // 2. Migration from legacy booleans
        if (state.excluded()) {
            return ChecklistStatus.NA;
        } else if (state.completed()) {
            return ChecklistStatus.DONE;
        }
        return ChecklistStatus.TODO;
    }

    // Adds a ChecklistEntry object created from a local saved file to the
    // checklistLog using the setValueAt() method
    public void loadNewChecklistEntry(ChecklistEntry entry) {
        int row = this.extender.getChecklistManager().getChecklistLog().size();
        extender.getChecklistManager().getChecklistTableModel().addValueAt(entry, row, row);
    }

    // Logic to calculate file hash
    public String toHash(File chosenFile) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String result = "";

        try (FileInputStream fis = new FileInputStream(chosenFile)) {
            byte[] dataBytes = new byte[1024];
            int readCount;
            while ((readCount = fis.read(dataBytes)) != -1) {
                md.update(dataBytes, 0, readCount);
            }
            byte[] mdbytes = md.digest();

            // convert the byte to hex format method
            StringBuilder sb = new StringBuilder();
            for (byte mdbyte : mdbytes) {
                sb.append(Integer.toString((mdbyte & 0xff) + 0x100, 16).substring(1));
            }
            result = sb.toString();
        } catch (IOException ioe) {
            extender.logError("Error exception at toHash");
        }

        return result;
    }
}
