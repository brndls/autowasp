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
