/*
 * Copyright (c) 2021 Government Technology Agency
 * Copyright (c) 2024 Autowasp Contributors
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

package autowasp.http;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * Scan Issue Wrapper - Montoya API
 * 
 * Catatan Pembelajaran - Migrasi dari Legacy API:
 * 
 * Legacy API:
 * - IScanIssue dengan getIssueBackground(), getRemediationBackground()
 * 
 * Montoya API:
 * - AuditIssue dengan definition() untuk mendapatkan background info
 * - Tidak ada method langsung background()/remediationBackground()
 * - Gunakan definition().description() dan definition().remediation()
 */
public class ScanIssue {

    private final HTTPService httpService;
    private final URL url;
    private final HTTPRequestResponse[] httpMessages;
    private final String detail;
    private final String severity;
    private final String confidence;
    private final String name;
    private final String remediation;
    private final String background;
    private final String remediationBackground;

    /**
     * Constructor dari Montoya AuditIssue
     */
    public ScanIssue(AuditIssue auditIssue) {
        this.name = auditIssue.name();
        this.detail = auditIssue.detail() != null ? auditIssue.detail() : "";
        this.severity = convertSeverity(auditIssue.severity());
        this.confidence = convertConfidence(auditIssue.confidence());

        // Di Montoya API, background dan remediation background
        // didapat dari definition() jika tersedia
        if (auditIssue.definition() != null) {
            this.background = auditIssue.definition().background() != null ? auditIssue.definition().background()
                    : "";
            this.remediationBackground = auditIssue.definition().remediation() != null
                    ? auditIssue.definition().remediation()
                    : "";
        } else {
            this.background = "";
            this.remediationBackground = "";
        }

        this.remediation = auditIssue.remediation() != null ? auditIssue.remediation() : "";

        // Parse URL
        URL parsedUrl = null;
        try {
            parsedUrl = java.net.URI.create(auditIssue.baseUrl()).toURL();
        } catch (Exception e) {
            // Log error, keep null
        }
        this.url = parsedUrl;

        // Create HTTPService dari base URL
        if (parsedUrl != null) {
            boolean secure = "https".equalsIgnoreCase(parsedUrl.getProtocol());
            int port = parsedUrl.getPort();
            if (port == -1) {
                port = secure ? 443 : 80;
            }
            this.httpService = new HTTPService(parsedUrl.getHost(), port, secure);
        } else {
            this.httpService = null;
        }

        // Convert HttpRequestResponse list ke HTTPRequestResponse array
        List<HttpRequestResponse> requestResponses = auditIssue.requestResponses();
        List<HTTPRequestResponse> convertedList = new ArrayList<>();
        if (requestResponses != null) {
            for (HttpRequestResponse rr : requestResponses) {
                convertedList.add(new HTTPRequestResponse(rr));
            }
        }
        this.httpMessages = convertedList.toArray(new HTTPRequestResponse[0]);
    }

    /**
     * Konversi AuditIssueSeverity enum ke String
     */
    private String convertSeverity(AuditIssueSeverity severity) {
        if (severity == null)
            return "Information";
        return switch (severity) {
            case HIGH -> "High";
            case MEDIUM -> "Medium";
            case LOW -> "Low";
            case INFORMATION -> "Information";
            default -> "Information";
        };
    }

    /**
     * Konversi AuditIssueConfidence enum ke String
     */
    private String convertConfidence(AuditIssueConfidence confidence) {
        if (confidence == null)
            return "Tentative";
        return switch (confidence) {
            case CERTAIN -> "Certain";
            case FIRM -> "Firm";
            case TENTATIVE -> "Tentative";
            default -> "Tentative";
        };
    }

    public URL getUrl() {
        return url;
    }

    public String getIssueName() {
        return name;
    }

    public String getSeverity() {
        return severity;
    }

    public String getConfidence() {
        return confidence;
    }

    public String getIssueBackground() {
        return background;
    }

    public String getRemediationBackground() {
        return remediationBackground;
    }

    public String getIssueDetail() {
        return detail;
    }

    public String getRemediationDetail() {
        return remediation;
    }

    public HTTPRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    public HTTPService getHttpService() {
        return httpService;
    }
}
