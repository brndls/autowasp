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

package autowasp.checklist;

import autowasp.Autowasp;

import javax.swing.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * SwingWorker for fetching WSTG checklist from web.
 * BApp Store Criteria #5: Use Background Threads for Long-running Operations
 *
 * Uses SwingWorker to ensure:
 * - Network operations run in background thread
 * - UI updates (progress, status) are dispatched to EDT via process()
 * - Cancel handling via isCancelled()
 */
public class ChecklistFetchWorker extends SwingWorker<Void, String> {

    /**
     * Configuration for ChecklistFetchWorker components.
     */
    public record ChecklistFetchConfig(
            Autowasp extender,
            JLabel statusLabel,
            JProgressBar progressBar,
            JButton fetchButton,
            JButton localButton,
            JButton cancelButton,
            JButton excelButton,
            JButton saveButton,
            AtomicBoolean running,
            Runnable onComplete) {
    }

    private final ChecklistFetchConfig config;

    private int successCount = 0;
    private int skippedCount = 0;
    private int totalItems = 0;

    /**
     * Constructor for ChecklistFetchWorker.
     *
     * @param extender     Main Autowasp instance
     * @param statusLabel  Label to display status
     * @param progressBar  Progress bar for fetch indication
     * @param fetchButton  Fetch button (to disable/enable)
     * @param localButton  Load local button (to disable/enable)
     * @param cancelButton Cancel button
     * @param excelButton  Export Excel button
     * @param saveButton   Save local copy button
     * @param running      AtomicBoolean for cancel flag
     * @param onComplete   Callback after fetch completes
     */
    public ChecklistFetchWorker(ChecklistFetchConfig config) {
        this.config = config;
    }

    @Override
    protected Void doInBackground() {
        List<String> articleURLs = config.extender().getChecklistManager().getChecklistLogic().scrapeArticleURLs();

        if (articleURLs.isEmpty()) {
            publish("Failed to fetch article URLs. Check network connection.");
            return null;
        }

        totalItems = articleURLs.size();

        for (String urlStr : articleURLs) {
            // Check for cancellation
            if (isCancelled() || !config.running().get()) {
                config.extender().getChecklistManager().getChecklistLog().clear();
                return null;
            }

            try {
                Thread.sleep(500);
                boolean success = config.extender().getChecklistManager().getChecklistLogic()
                        .logNewChecklistEntry(urlStr);
                if (success) {
                    successCount++;
                } else {
                    skippedCount++;
                }
                // Publish progress update
                publish("Fetching " + (successCount + skippedCount) + "/" + totalItems
                        + " (skipped: " + skippedCount + ")");
            } catch (InterruptedException e) {
                config.extender().getApi().logging().logToError("Fetch interrupted: " + e.getMessage());
                Thread.currentThread().interrupt();
                return null;
            }
        }

        return null;
    }

    @Override
    protected void process(List<String> chunks) {
        // process() is called on EDT, safe to update UI
        if (!chunks.isEmpty()) {
            String latestStatus = chunks.get(chunks.size() - 1);
            config.statusLabel().setText(latestStatus);
        }
    }

    @Override
    protected void done() {
        // done() is called on EDT after doInBackground() completes
        config.progressBar().setVisible(false);
        config.cancelButton().setEnabled(false);
        config.fetchButton().setEnabled(true);
        config.localButton().setEnabled(true);

        if (isCancelled() || !config.running().get()) {
            config.statusLabel().setText("Fetch checklist cancelled");
            config.extender().issueAlert("Fetch checklist cancelled");
        } else if (totalItems == 0) {
            // Fetch failed completely
            config.statusLabel().setText("Failed to fetch article URLs. Check network connection.");
        } else {
            config.excelButton().setEnabled(true);
            config.saveButton().setEnabled(true);
            String summary = "Fetch complete: " + successCount + " loaded, " + skippedCount + " skipped";
            config.statusLabel().setText(summary);
            config.extender().issueAlert(summary);
            config.extender().getLoggerManager().getLoggerTable().generateWSTGList();
        }

        if (config.onComplete() != null) {
            config.onComplete().run();
        }
    }
}
