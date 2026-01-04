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

package autowasp.reporting;

/**
 * Holds statistics for report generation.
 *
 * @param totalFindings Total number of log entries
 * @param criticalCount Number of critical findings
 * @param highCount     Number of high findings
 * @param mediumCount   Number of medium findings
 * @param lowCount      Number of low findings
 * @param infoCount     Number of info findings
 */
public record ReportStatistics(
                int totalFindings,
                int criticalCount,
                int highCount,
                int mediumCount,
                int lowCount,
                int infoCount) {
}
