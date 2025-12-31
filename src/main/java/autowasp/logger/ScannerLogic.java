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

package autowasp.logger;

import autowasp.Autowasp;
import autowasp.http.HTTPRequestResponse;
import autowasp.http.ScanIssue;
import autowasp.logger.entryTable.LoggerEntry;
import autowasp.logger.instancesTable.InstanceEntry;

// Montoya API imports
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import java.net.URL;
import java.util.ArrayList;

/**
 * Scanner Logic - Montoya API
 * 
 * Catatan Pembelajaran - Migrasi dari Legacy API:
 * 
 * Legacy API:
 * - IScanIssue dari callbacks.getScanIssues()
 * - callbacks.registerScannerListener()
 * 
 * Montoya API:
 * - AuditIssue dari AuditIssueHandler
 * - api.scanner().registerAuditIssueHandler()
 * 
 * Perubahan terminologi:
 * - Scanner → Audit
 * - ScanIssue → AuditIssue
 */
public class ScannerLogic {
	private final Autowasp extender;
	public final ArrayList<String> repeatedIssue;

	public ArrayList<String> getRepeatedIssue() {
		return repeatedIssue;
	}

	public ScannerLogic(Autowasp extender) {
		this.extender = extender;
		this.repeatedIssue = new ArrayList<>();
	}

	/**
	 * Method untuk log new instance dari AuditIssue (Montoya API)
	 */
	public void logNewInstance(AuditIssue auditIssue) {
		// Konversi ke ScanIssue wrapper
		ScanIssue issue = new ScanIssue(auditIssue);
		logNewInstance(issue);
	}

	/**
	 * Method untuk log new scan dari AuditIssue (Montoya API)
	 */
	public void logNewScan(AuditIssue auditIssue) {
		// Konversi ke ScanIssue wrapper
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
				boolean toAddFlag = true;
				for (InstanceEntry ie : entry.getInstanceList()) {
					// check if instanceList contain similar URL.
					if (url != null && ie.getUrl().equals(url.toString())) {
						// if url is not unique, set toAddFlag to false
						toAddFlag = false;
					}
				}
				// add new instance if toAddFlag is true
				if (toAddFlag) {
					entry.addInstance(instance);
				}
			}
		}
	}

	/**
	 * Method to log new scan entry
	 */
	public void logNewScan(ScanIssue issue) {
		// Form scan issue information
		String host = issue.getHttpService() != null ? issue.getHttpService().getHost() : "";
		String action = "Burp Scanner";
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
		entry.instancesList.clear();
		entry.setPenTesterComments(defaultComments);
		entry.setEvidence(evidences);
		extender.loggerTableModel.addAllLoggerEntry(entry);
	}

	/**
	 * Extract existing scan issues (jika diperlukan)
	 * 
	 * Catatan: Di Montoya API, tidak ada metode langsung untuk mendapatkan
	 * semua existing scan issues. Issues diterima melalui AuditIssueHandler
	 * saat scan berjalan.
	 */
	public void extractExistingScan() {
		// Di Montoya API, issues diterima melalui AuditIssueHandler
		// Tidak ada callbacks.getScanIssues() equivalent
		extender.logOutput("Listening for new audit issues...");
	}
}
