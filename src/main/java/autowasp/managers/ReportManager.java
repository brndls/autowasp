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

package autowasp.managers;

import autowasp.Autowasp;
import autowasp.reporting.excel.ExcelReportWriter;
import burp.api.montoya.MontoyaApi;
import autowasp.logger.entrytable.LoggerEntry;
import autowasp.logger.instancestable.InstanceEntry;
import autowasp.reporting.ReportStatistics;

import java.io.File;

/**
 * Manages the generation of reports.
 */
public class ReportManager {

    private final Autowasp extender;
    private final MontoyaApi api;

    public ReportManager(Autowasp extender) {
        this.extender = extender;
        this.api = extender.getApi();
    }

    /**
     * Generates an Excel report at the specified file location.
     *
     * @param file The file to save the report to.
     */
    public void generateExcelReport(File file) {
        // We'll implement this properly in the next steps
        // For now, this is just scaffolding
        try {
            if (!file.getName().toLowerCase().endsWith(".xlsx")) {
                file = new File(file.getAbsolutePath() + ".xlsx");
            }

            ReportStatistics stats = calculateStatistics();
            ExcelReportWriter writer = new ExcelReportWriter(extender);
            writer.save(file, stats);

            api.logging().logToOutput("Report generation successful: " + file.getAbsolutePath());
        } catch (Exception e) {
            api.logging().logToError("Failed to generate report: " + e.getMessage(), e);
            // Using IllegalStateException instead of generic RuntimeException
            throw new IllegalStateException("Failed to generate report: " + e.getMessage(), e);
        }
    }

    private ReportStatistics calculateStatistics() {
        int total = 0;
        int critical = 0;
        int high = 0;
        int medium = 0;
        int low = 0;
        int info = 0;

        for (LoggerEntry entry : extender.getLoggerManager().getLoggerList()) {
            for (InstanceEntry instance : entry.getInstanceList()) {
                total++;
                String severity = instance.getSeverity();
                if (severity == null)
                    severity = "Information";

                severity = severity.toLowerCase();

                if (severity.contains("critical"))
                    critical++;
                else if (severity.contains("high"))
                    high++;
                else if (severity.contains("medium"))
                    medium++;
                else if (severity.contains("low"))
                    low++;
                else
                    info++; // Default to info
            }
        }
        return new ReportStatistics(total, critical, high, medium, low, info);
    }
}
