package autowasp.reporting.excel;

import autowasp.Autowasp;
import autowasp.checklist.ChecklistEntry;
import autowasp.logger.entrytable.LoggerEntry;
import autowasp.logger.instancestable.InstanceEntry;
import autowasp.managers.LoggerManager;
import autowasp.reporting.ReportStatistics;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.List;

/**
 * Handles the generation of Excel reports.
 */
public class ExcelReportWriter {

    private final Autowasp extender;
    private final Workbook workbook;
    private final CellStyle headerStyle;
    private final CellStyle dateStyle;

    public ExcelReportWriter(Autowasp extender) {
        this.extender = extender;
        this.workbook = new XSSFWorkbook();
        this.headerStyle = createHeaderStyle();
        this.dateStyle = createDateStyle();
    }

    /**
     * Creates and saves the report to the specified file.
     *
     * @param file  The file to save the report to.
     * @param stats Statistics for the summary sheet.
     * @throws IOException If an I/O error occurs.
     */
    public void save(File file, ReportStatistics stats) throws IOException {
        LoggerManager loggerManager = extender.getLoggerManager();
        List<LoggerEntry> entries = loggerManager.getLoggerList();

        // Create Sheets
        createSummarySheet(stats);
        createFindingsSheet(entries);

        // TODO: Create Checklist Sheet in next step
        createChecklistSheet(extender.getChecklistManager().getChecklistLog());

        // Write to file
        try (FileOutputStream fileOut = new FileOutputStream(file)) {
            workbook.write(fileOut);
        } finally {
            workbook.close();
        }
    }

    private void createChecklistSheet(List<ChecklistEntry> checklist) {
        Sheet sheet = workbook.createSheet("WSTG Checklist");
        String[] headers = { "ID", "Category", "Test Name", "Status", "Excluded", "Reference", "Comments" };

        // Header
        Row headerRow = sheet.createRow(0);
        for (int i = 0; i < headers.length; i++) {
            Cell cell = headerRow.createCell(i);
            cell.setCellValue(headers[i]);
            cell.setCellStyle(headerStyle);
        }

        // Data
        int rowNum = 1;
        for (ChecklistEntry entry : checklist) {
            Row row = sheet.createRow(rowNum++);
            row.createCell(0).setCellValue(entry.getRefNumber());
            row.createCell(1).setCellValue(entry.getCategory());
            row.createCell(2).setCellValue(entry.getTestName());
            row.createCell(3).setCellValue(entry.isTestcaseCompleted() ? "Completed" : "Pending");
            row.createCell(4).setCellValue(entry.isExcluded() ? "Yes" : "No");
            row.createCell(5).setCellValue(entry.getUrl());
            row.createCell(6).setCellValue(entry.getPenTesterComments());
        }

        // Auto-size columns
        for (int i = 0; i < headers.length; i++) {
            sheet.autoSizeColumn(i);
        }
    }

    private void createSummarySheet(ReportStatistics stats) {
        Sheet sheet = workbook.createSheet("Dashboard");

        // Title
        Row titleRow = sheet.createRow(0);
        Cell titleCell = titleRow.createCell(0);
        titleCell.setCellValue("Security Assessment Summary");
        titleCell.setCellStyle(headerStyle);

        // Date
        Row dateRow = sheet.createRow(1);
        dateRow.createCell(0).setCellValue("Generated Date:");
        Cell dateCell = dateRow.createCell(1);
        dateCell.setCellValue(new Date());
        dateCell.setCellStyle(dateStyle);

        // Stats Table
        String[] headers = { "Severity", "Count" };
        Row statsHeader = sheet.createRow(3);
        statsHeader.createCell(0).setCellValue(headers[0]);
        statsHeader.createCell(1).setCellValue(headers[1]);
        statsHeader.getCell(0).setCellStyle(headerStyle);
        statsHeader.getCell(1).setCellStyle(headerStyle);

        Object[][] data = {
                { "Critical", stats.criticalCount() },
                { "High", stats.highCount() },
                { "Medium", stats.mediumCount() },
                { "Low", stats.lowCount() },
                { "Information", stats.infoCount() },
                { "Total", stats.totalFindings() }
        };

        int rowNum = 4;
        for (Object[] rowData : data) {
            Row row = sheet.createRow(rowNum++);
            row.createCell(0).setCellValue((String) rowData[0]);
            row.createCell(1).setCellValue((Integer) rowData[1]);
        }

        sheet.autoSizeColumn(0);
        sheet.autoSizeColumn(1);
    }

    private void createFindingsSheet(List<LoggerEntry> entries) {
        Sheet sheet = workbook.createSheet("Findings");
        String[] headers = { "ID", "Vulnerability", "Severity", "Confidence", "URL", "Ref (WSTG)", "Comments" };

        // Create Header Row
        Row headerRow = sheet.createRow(0);
        for (int i = 0; i < headers.length; i++) {
            Cell cell = headerRow.createCell(i);
            cell.setCellValue(headers[i]);
            cell.setCellStyle(headerStyle);
        }

        // Populate Data (Flattened: One row per Instance)
        int rowNum = 1;
        int id = 1;

        for (LoggerEntry entry : entries) {
            // Include entry-level info even if no instances?
            // If we have instances, list them. If not, list the entry as 1 row.

            if (entry.getInstanceList().isEmpty()) {
                Row row = sheet.createRow(rowNum++);
                row.createCell(0).setCellValue(id++);
                row.createCell(1).setCellValue(entry.getVulnType());
                row.createCell(2).setCellValue("-");
                row.createCell(3).setCellValue("-");
                row.createCell(4).setCellValue(entry.getHost());
                row.createCell(5).setCellValue(entry.getChecklistIssue());
                row.createCell(6).setCellValue(entry.getPenTesterComments());
            } else {
                for (InstanceEntry instance : entry.getInstanceList()) {
                    Row row = sheet.createRow(rowNum++);
                    row.createCell(0).setCellValue(id++);
                    row.createCell(1).setCellValue(entry.getVulnType());
                    row.createCell(2).setCellValue(instance.getSeverity());
                    row.createCell(3).setCellValue(instance.getConfidence());
                    row.createCell(4).setCellValue(instance.getUrl());
                    row.createCell(5).setCellValue(entry.getChecklistIssue());
                    row.createCell(6).setCellValue(entry.getPenTesterComments());
                }
            }
        }

        // Auto-size columns
        for (int i = 0; i < headers.length; i++) {
            sheet.autoSizeColumn(i);
        }
    }

    private CellStyle createHeaderStyle() {
        CellStyle style = workbook.createCellStyle();
        Font font = workbook.createFont();
        font.setBold(true);
        font.setFontHeightInPoints((short) 12);
        style.setFont(font);
        style.setBorderBottom(BorderStyle.THIN);
        style.setFillForegroundColor(IndexedColors.GREY_25_PERCENT.getIndex());
        style.setFillPattern(FillPatternType.SOLID_FOREGROUND);
        return style;
    }

    private CellStyle createDateStyle() {
        CellStyle style = workbook.createCellStyle();
        style.setDataFormat(workbook.createDataFormat().getFormat("yyyy-mm-dd hh:mm"));
        return style;
    }
}
