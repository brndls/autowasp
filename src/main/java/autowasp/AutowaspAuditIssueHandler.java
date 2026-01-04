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

package autowasp;

// Montoya API - correct package: scanner.audit not scanner.audit.issues
import burp.api.montoya.scanner.audit.AuditIssueHandler;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

/**
 * Audit Issues Handler - Montoya API
 *
 * Learning Notes - Migration from Legacy API:
 *
 * Legacy API uses IScannerListener with method:
 * - newScanIssue(IScanIssue issue)
 *
 * Montoya API uses AuditIssueHandler with method:
 * - handleNewAuditIssue(AuditIssue issue) - void return
 *
 * Terminology differences:
 * - Legacy: "Scanner" / "ScanIssue"
 * - Montoya: "Audit" / "AuditIssue"
 */
public class AutowaspAuditIssueHandler implements AuditIssueHandler {

    private final Autowasp extender;

    public AutowaspAuditIssueHandler(Autowasp extender) {
        this.extender = extender;
    }

    /**
     * Called when a new audit/scan issue is found
     * Replaces newScanIssue() from Legacy API
     *
     * Note: This method is void, does not return a value
     */

    @Override
    public void handleNewAuditIssue(AuditIssue auditIssue) {
        try {
            // Check if URL is in scope
            String baseUrl = auditIssue.baseUrl();

            if (extender.isInScope(baseUrl)) {
                String issueName = auditIssue.name();

                // Cek apakah issue sudah pernah di-log (avoid duplicate)
                if (!extender.getLoggerManager().getScannerLogic().getRepeatedIssue().contains(issueName)) {
                    // Add to the list of logged issues
                    extender.getLoggerManager().getScannerLogic().getRepeatedIssue().add(issueName);

                    // Alert user
                    extender.issueAlert("New Scan found: " + issueName);

                    // Log scan issue baru
                    extender.getLoggerManager().getScannerLogic().logNewScan(auditIssue);

                    // Log instance
                    extender.getLoggerManager().getScannerLogic().logNewInstance(auditIssue);
                } else {
                    // Issue sudah ada, hanya log instance baru
                    extender.getLoggerManager().getScannerLogic().logNewInstance(auditIssue);
                }
            }
        } catch (Exception e) {
            extender.logError(e);
        }
    }
}
