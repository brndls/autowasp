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

package autowasp.logger;

import autowasp.Autowasp;
import autowasp.http.HTTPRequestResponse;
import autowasp.http.ScanIssue;
import autowasp.logger.entrytable.LoggerEntry;
import autowasp.logger.instancestable.InstanceEntry;
import autowasp.utils.AutowaspConstants;

// Montoya API imports
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * Scanner Logic - Montoya API
 *
 * Learning Notes - Migration from Legacy API:
 *
 * Legacy API:
 * - IScanIssue from callbacks.getScanIssues()
 * - callbacks.registerScannerListener()
 *
 * Montoya API:
 * - AuditIssue from AuditIssueHandler
 * - No direct access to "all scan issues" like legacy API
 * - Must maintain own list of issues via AuditIssueHandler
 * - api.scanner().registerAuditIssueHandler()
 *
 * Perubahan terminologi:
 * - Scanner -> Audit
 * - ScanIssue -> AuditIssue
 */
public class ScannerLogic {
    private final Autowasp extender;
    public final List<String> repeatedIssue;

    public List<String> getRepeatedIssue() {
        return repeatedIssue;
    }

    public ScannerLogic(Autowasp extender) {
        this.extender = extender;
        this.repeatedIssue = new ArrayList<>();
    }

    /**
     * Method to log new instance of AuditIssue (Montoya API)
     */
    public void logNewInstance(AuditIssue auditIssue) {
        // Convert to ScanIssue wrapper
        ScanIssue issue = new ScanIssue(auditIssue);
        logNewInstance(issue);
    }

    /**
     * Method to log new scan of AuditIssue (Montoya API)
     */
    public void logNewScan(AuditIssue auditIssue) {
        // Convert to ScanIssue wrapper
        ScanIssue issue = new ScanIssue(auditIssue);
        logNewScan(issue);
    }

    /**
     * Method to log new instance to a particular issue
     */
    public void logNewInstance(ScanIssue issue) {
        // form up instances information
        URL url = issue.getUrl();
        String confidence = issue.getConfidence();
        String severity = issue.getSeverity();
        HTTPRequestResponse requestResponse = null;

        if (issue.getHttpMessages() != null && issue.getHttpMessages().length != 0) {
            requestResponse = issue.getHttpMessages()[0];
        }

        InstanceEntry instance = new InstanceEntry(url, confidence, severity, requestResponse);
        String issueHost = issue.getHttpService() != null ? issue.getHttpService().getHost() : "";
        String issueVulnType = issue.getIssueName();

        for (LoggerEntry entry : this.extender.loggerList) {
            if (entry.getHost().equals(issueHost) && entry.getVulnType().equals(issueVulnType)) {
                addInstanceIfUnique(entry, instance);
            }
        }
    }

    private void addInstanceIfUnique(LoggerEntry entry, InstanceEntry instance) {
        boolean isUnique = true;
        String newUrl = instance.getUrl();

        for (InstanceEntry ie : entry.getInstanceList()) {
            if (newUrl != null && !newUrl.isEmpty() && ie.getUrl().equals(newUrl)) {
                isUnique = false;
                break;
            }
        }

        if (isUnique) {
            entry.addInstance(instance);
        }
    }

    /**
     * Method to log new scan entry
     */
    public void logNewScan(ScanIssue issue) {
        // Form scan issue information
        String host = issue.getHttpService() != null ? issue.getHttpService().getHost() : "";
        String action = AutowaspConstants.ACTION_BURP_SCANNER;

        String issueName = "";
        String vulnType = issue.getIssueName();
        String defaultComments = "Burp Scanner detected the following issue type: " + issue.getIssueName();
        String evidences = issue.getIssueDetail();
        if (evidences == null || evidences.isEmpty()) {
            evidences = "Refer to affected instances Request and Response.";
        }
        Document document = Jsoup.parse(evidences);
        evidences = document.text();

        LoggerEntry entry = new LoggerEntry(host, action, vulnType, issueName);
        entry.clearInstances();
        entry.setPenTesterComments(defaultComments);
        entry.setEvidence(evidences);
        extender.getLoggerTableModel().addAllLoggerEntry(entry);
    }

    /**
     * Extract existing scan issues (jika diperlukan)
     *
     * Note: In Montoya API, there is no direct method to get
     * all scan issues. We must rely on our own list. AuditIssueHandler
     * saat scan berjalan.
     */
    public void extractExistingScan() {
        // In Montoya API, issues are received via AuditIssueHandler
        // There is no callbacks.getScanIssues() equivalent
        extender.logOutput("Listening for new audit issues...");
    }
}
