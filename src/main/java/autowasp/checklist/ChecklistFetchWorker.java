/*
 * MIT License
 *
 * Copyright (c) 2026 Autowasp Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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

    private final Autowasp extender;
    private final JLabel statusLabel;
    private final JProgressBar progressBar;
    private final JButton fetchButton;
    private final JButton localButton;
    private final JButton cancelButton;
    private final JButton excelButton;
    private final JButton saveButton;
    private final AtomicBoolean running;
    private final Runnable onComplete;

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
    public ChecklistFetchWorker(
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
        this.extender = extender;
        this.statusLabel = statusLabel;
        this.progressBar = progressBar;
        this.fetchButton = fetchButton;
        this.localButton = localButton;
        this.cancelButton = cancelButton;
        this.excelButton = excelButton;
        this.saveButton = saveButton;
        this.running = running;
        this.onComplete = onComplete;
    }

    @Override
    protected Void doInBackground() {
        List<String> articleURLs = extender.checklistLogic.scrapeArticleURLs();

        if (articleURLs.isEmpty()) {
            publish("Failed to fetch article URLs. Check network connection.");
            return null;
        }

        totalItems = articleURLs.size();

        for (String urlStr : articleURLs) {
            // Check for cancellation
            if (isCancelled() || !running.get()) {
                extender.checklistLog.clear();
                break;
            }

            try {
                Thread.sleep(500);
                boolean success = extender.checklistLogic.logNewChecklistEntry(urlStr);
                if (success) {
                    successCount++;
                } else {
                    skippedCount++;
                }
                // Publish progress update
                publish("Fetching " + (successCount + skippedCount) + "/" + totalItems
                        + " (skipped: " + skippedCount + ")");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        return null;
    }

    @Override
    protected void process(List<String> chunks) {
        // process() is called on EDT, safe to update UI
        if (!chunks.isEmpty()) {
            String latestStatus = chunks.get(chunks.size() - 1);
            statusLabel.setText(latestStatus);
        }
    }

    @Override
    protected void done() {
        // done() is called on EDT after doInBackground() completes
        progressBar.setVisible(false);
        cancelButton.setEnabled(false);
        fetchButton.setEnabled(true);
        localButton.setEnabled(true);

        if (isCancelled() || !running.get()) {
            statusLabel.setText("Fetch checklist cancelled");
            extender.issueAlert("Fetch checklist cancelled");
        } else if (totalItems == 0) {
            // Fetch failed completely
            statusLabel.setText("Failed to fetch article URLs. Check network connection.");
        } else {
            excelButton.setEnabled(true);
            saveButton.setEnabled(true);
            String summary = "Fetch complete: " + successCount + " loaded, " + skippedCount + " skipped";
            statusLabel.setText(summary);
            extender.issueAlert(summary);
            extender.loggerTable.generateWSTGList();
        }

        if (onComplete != null) {
            onComplete.run();
        }
    }
}
