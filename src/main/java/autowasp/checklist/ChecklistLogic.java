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

package autowasp.checklist;

import autowasp.Autowasp;
import autowasp.logger.entrytable.LoggerEntry;
import autowasp.logger.instancestable.InstanceEntry;

// Montoya HTTP API imports (BApp Store Criteria #7)
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.ss.usermodel.CreationHelper;
import org.apache.poi.ss.usermodel.FillPatternType;
import org.apache.poi.ss.usermodel.Hyperlink;
import org.apache.poi.ss.usermodel.IndexedColors;
import org.apache.poi.xssf.usermodel.XSSFCell;
import org.apache.poi.xssf.usermodel.XSSFCellStyle;
import org.apache.poi.xssf.usermodel.XSSFFont;
import org.apache.poi.xssf.usermodel.XSSFRow;
import org.apache.poi.common.usermodel.HyperlinkType;

/* Notes:
 * 1. The URL for the OWASP content page is currently pointing to our own branch of OWASP's repository.
 * 2. The "fetch checklist" function currently takes around 3 minutes to fetch the data.
 */

public class ChecklistLogic implements Serializable {

    private final transient Autowasp extender;
    public static final String GITHUB_URL_BASE = "https://github.com/OWASP/www-project-web-security-testing-guide/blob/master/v42/4-Web_Application_Security_Testing/";
    public static final String GITHUB_RAW_BASE_URL = GITHUB_URL_BASE
            .replace("github.com", "raw.githubusercontent.com")
            .replace("/blob/", "/");
    public static final String GITHUB_REPO_URL = GITHUB_RAW_BASE_URL + "README.md";
    private static final String NEWLINE_REGEX = "\\r?\\n";
    private static final String DOUBLE_NEWLINE_REGEX = "\\r?\\n\\r?\\n";
    private static final String HTML_START = "<html><body>";
    private static final String HTML_END = "</body></html>";

    // Retry configuration
    private static final int MAX_RETRY_ATTEMPTS = 3;
    private static final long INITIAL_BACKOFF_MS = 1000;

    public ChecklistLogic(Autowasp extender) {
        this.extender = extender;
    }

    /**
     * Fetch a URL using Burp's networking API with retry logic and exponential
     * backoff.
     * BApp Store Criteria #7: Use Burp Networking.
     *
     * @param url The URL to fetch
     * @return Document if successful, null if all retries failed
     */
    private Document fetchWithRetry(String url) {
        int attempt = 0;
        Exception lastException = null;

        while (attempt < MAX_RETRY_ATTEMPTS) {
            try {
                return attemptFetch(url);
            } catch (Exception e) {
                lastException = e;
                attempt++;
                handleFetchError(url, attempt, e);

                if (attempt < MAX_RETRY_ATTEMPTS) {
                    performBackoff(attempt);
                }
            }
        }

        // All retries failed
        extender.logError("Failed to fetch after " + MAX_RETRY_ATTEMPTS + " attempts: " + url
                + (lastException != null ? " - " + lastException.getMessage() : ""));
        return null;
    }

    private Document attemptFetch(String url) throws IOException {
        // Use Burp's HTTP client for BApp Store compliance (Criteria #7)
        // This ensures proxy settings and session handling rules are respected
        HttpRequest request = HttpRequest.httpRequestFromUrl(url);
        HttpRequestResponse response = extender.getApi().http().sendRequest(request);
        HttpResponse httpResponse = response.response();

        if (httpResponse != null && httpResponse.statusCode() == 200) {
            String html = httpResponse.bodyToString();
            // Use Jsoup.parse() for HTML parsing only (no connection)
            // Base URL is provided for resolving relative links
            return Jsoup.parse(html, url);
        }

        // Non-200 response, treat as failure for retry
        String statusInfo = httpResponse != null
                ? "HTTP " + httpResponse.statusCode()
                : "null response";
        throw new IOException(statusInfo);
    }

    private void handleFetchError(String url, int attempt, Exception e) {
        extender.logOutput("Fetch attempt " + attempt + "/" + MAX_RETRY_ATTEMPTS
                + " failed for: " + url + " (" + e.getMessage() + ")");
    }

    private void performBackoff(int attempt) {
        try {
            // Exponential backoff: 1s, 2s, 4s
            long backoff = INITIAL_BACKOFF_MS * (1L << (attempt - 1));
            Thread.sleep(backoff);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Show user-friendly error dialog using Burp's suiteFrame() as parent.
     * BApp Store Criteria #10: Parent GUI elements correctly.
     *
     * @param message Error message to display
     */
    private void showErrorDialog(String message) {
        javax.swing.JOptionPane.showMessageDialog(
                extender.getApi().userInterface().swingUtils().suiteFrame(),
                message,
                "Autowasp Error",
                javax.swing.JOptionPane.ERROR_MESSAGE);
    }

    // Returns a list containing the URLs of all the test articles in order of
    // reference number
    public List<String> scrapeArticleURLs() {
        // Get the URLs located within the main content page (README.md)
        List<String> sectionContentPageURLs = scrapeRawMarkdownURLs(GITHUB_REPO_URL);

        // Remove introduction if it exists (usually the first one)
        if (!sectionContentPageURLs.isEmpty() && sectionContentPageURLs.get(0).contains("00-Introduction")) {
            sectionContentPageURLs.remove(0);
        }

        List<String> articleURLs = new ArrayList<>();
        for (String url : sectionContentPageURLs) {
            // Each section is also a README.md in a subdirectory
            List<String> sectionArticleURLs = scrapeRawMarkdownURLs(url);
            articleURLs.addAll(sectionArticleURLs);
        }

        // Filter valid test case files (excluding non-test markdown files)
        articleURLs.removeIf(url -> {
            boolean isMarkdown = url.toLowerCase().endsWith(".md");
            boolean isReadme = url.toLowerCase().endsWith("readme.md");
            boolean isIntroduction = url.contains("00-Introduction");

            return !isMarkdown || isReadme || isIntroduction;
        });

        return articleURLs;
    }

    /**
     * Helper to scrape URLs from raw markdown content using regex.
     *
     * @param rawUrl The raw URL of the markdown file
     * @return List of absolute URLs found in the markdown
     */
    private List<String> scrapeRawMarkdownURLs(String rawUrl) {
        List<String> urls = new ArrayList<>();
        HttpRequest request = HttpRequest.httpRequestFromUrl(rawUrl);
        HttpRequestResponse response = extender.getApi().http().sendRequest(request);
        HttpResponse httpResponse = response.response();

        if (httpResponse == null || httpResponse.statusCode() != 200) {
            return urls;
        }

        String content = httpResponse.bodyToString();
        // Regex to find markdown links: [label](path/to/file.md)
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\\[.*?\\]\\((.*?\\.md)\\)");
        java.util.regex.Matcher matcher = pattern.matcher(content);

        String baseUrl = rawUrl.substring(0, rawUrl.lastIndexOf('/') + 1);

        while (matcher.find()) {
            String link = matcher.group(1);
            if (!link.startsWith("http")) {
                // Resolve relative path
                link = baseUrl + link;
            }
            urls.add(link);
        }
        return urls;
    }

    public List<String> scrapePageURLs(String anyURL) {
        // This method preserved for backward compatibility if needed,
        // but scrapeRawMarkdownURLs is preferred for raw content.
        if (anyURL.contains("raw.githubusercontent.com")) {
            return scrapeRawMarkdownURLs(anyURL);
        }

        Document anyPage = fetchWithRetry(anyURL);
        if (anyPage == null) {
            extender.getExtenderPanelUI().getScanStatusLabel().setText("Failed to fetch: " + anyURL);
            return new ArrayList<>();
        }

        try {
            // Fallback for HTML pages (old behavior)
            Elements articles = anyPage.getElementsByTag("Article");
            if (articles.isEmpty()) {
                // If no <Article> tag (GitHub blob view change), try parsing links directly
                return anyPage.select("a[href]").eachAttr("abs:href");
            }
            return articles.get(0).select("a[href]").eachAttr("abs:href");
        } catch (Exception e) {
            extender.logError("Error parsing page structure: " + anyURL);
            return new ArrayList<>();
        }
    }

    // Gets the Reference Number, Category, and Title of the article from raw
    // markdown.
    public Map<String, String> getTableElements(String anyURL) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(anyURL);
        HttpRequestResponse response = extender.getApi().http().sendRequest(request);
        HttpResponse httpResponse = response.response();

        if (httpResponse == null || httpResponse.statusCode() != 200) {
            return Collections.emptyMap();
        }

        String content = httpResponse.bodyToString();
        Map<String, String> tableElements = new HashMap<>();

        String refNumber = deriveRefNumber(anyURL, content);
        tableElements.put(ChecklistEntry.REF_NUMBER_KEY, refNumber);

        // Extract Title (usually first # heading)
        java.util.regex.Pattern titlePattern = java.util.regex.Pattern.compile("^#\\s+(.*)$",
                java.util.regex.Pattern.MULTILINE);
        java.util.regex.Matcher titleMatcher = titlePattern.matcher(content);
        String testName = titleMatcher.find() ? titleMatcher.group(1).trim() : "Unknown Test";

        // Category from URL path
        String category = "Unknown Category";
        String[] pathParts = anyURL.split("/");
        for (String part : pathParts) {
            if (part.matches("\\d+-.*")) {
                category = part.split("-", 2)[1].replace("_", " ");
                break;
            }
        }

        tableElements.put(ChecklistEntry.CATEGORY_KEY, category);
        tableElements.put(ChecklistEntry.TEST_NAME_KEY, testName);
        return tableElements;
    }

    /*
     * Gets the "Summary", "How To Test", and "References" sections of the article
     * from raw markdown.
     */
    public Map<String, String> getContentElements(String anyURL) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(anyURL);
        HttpRequestResponse response = extender.getApi().http().sendRequest(request);
        HttpResponse httpResponse = response.response();

        if (httpResponse == null || httpResponse.statusCode() != 200) {
            return Collections.emptyMap();
        }

        String content = httpResponse.bodyToString();
        Map<String, String> contentElements = new HashMap<>();

        // Get Reference Number (from content or URL)
        String refNumber = deriveRefNumber(anyURL, content);

        // Derive official OWASP URL from raw URL
        String officialUrl = anyURL
                .replace("raw.githubusercontent.com/OWASP/wstg/stable/document/",
                        "owasp.org/www-project-web-security-testing-guide/stable/")
                .replace("raw.githubusercontent.com/OWASP/www-project-web-security-testing-guide/master/v42/",
                        "owasp.org/www-project-web-security-testing-guide/v42/")
                .replace(".md", "");

        // Initialize references with at least the official link (ensures it's never
        // empty)
        String refLink = "<p><b>Official WSTG Reference:</b><br/>" +
                "<a href=\"" + officialUrl + "\">" + refNumber + "</a></p><hr/>";
        contentElements.put(ChecklistEntry.REFERENCES_KEY, HTML_START + refLink + HTML_END);

        // Basic Markdown section splitter
        String[] sections = content.split("(?m)^##\\s+");
        for (String section : sections) {
            String[] lines = section.split(NEWLINE_REGEX, 2);
            if (lines.length < 2)
                continue;

            String header = lines[0].trim().toLowerCase();
            String body = lines[1].trim();
            String htmlBody = markdownToHtml(body);

            if (header.contains(ChecklistEntry.SUMMARY_KEY)) {
                contentElements.put(ChecklistEntry.SUMMARY_KEY, HTML_START + htmlBody + HTML_END);
            } else if (header.contains(ChecklistEntry.HOW_TO_TEST_KEY)) {
                contentElements.put(ChecklistEntry.HOW_TO_TEST_KEY, HTML_START + htmlBody + HTML_END);
            } else if (header.contains(ChecklistEntry.REFERENCES_KEY)) {
                // Append section content to the official link
                contentElements.put(ChecklistEntry.REFERENCES_KEY, HTML_START + refLink + htmlBody + HTML_END);
            }
        }

        return contentElements;
    }

    /**
     * Minimal Markdown to HTML converter for Burp's JEditorPane.
     * Handles basic bold, lists, code, and paragraphs.
     */
    private String markdownToHtml(String markdown) {
        if (markdown == null || markdown.isEmpty())
            return "";

        // Process blocks
        StringBuilder result = new StringBuilder();
        // Split by code blocks first
        String[] blocks = markdown.split("(?m)^```");
        boolean isCode = false;

        for (String block : blocks) {
            if (isCode) {
                result.append(processCodeBlock(block));
            } else {
                result.append(processRegularBlocks(block));
            }
            isCode = !isCode;
        }

        return result.toString();
    }

    private String processCodeBlock(String block) {
        String[] parts = block.split(NEWLINE_REGEX, 2);
        String code = parts.length > 1 ? parts[1].trim() : "";
        // Escape entities for code blocks
        String escapedCode = code.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
        return "<pre style='background-color:#f4f4f4;padding:5px;'><code>" + escapedCode + "</code></pre>";
    }

    private String processRegularBlocks(String block) {
        StringBuilder result = new StringBuilder();
        String[] subBlocks = block.split(DOUBLE_NEWLINE_REGEX);
        for (String sub : subBlocks) {
            String trimmed = sub.trim();
            if (trimmed.isEmpty())
                continue;

            if (trimmed.startsWith("###")) {
                result.append(processHeader(trimmed, 3));
            } else if (trimmed.startsWith("####")) {
                result.append(processHeader(trimmed, 4));
            } else if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
                result.append(processList(trimmed));
            } else {
                result.append("<p>").append(applyInlineFormatting(trimmed)).append("</p>");
            }
        }
        return result.toString();
    }

    private String processHeader(String header, int level) {
        String content = header.substring(level).trim();
        return "<h" + level + ">" + applyInlineFormatting(content) + "</h" + level + ">";
    }

    private String processList(String listBlock) {
        StringBuilder result = new StringBuilder("<ul>");
        for (String item : listBlock.split(NEWLINE_REGEX)) {
            String trimmedItem = item.trim();
            if (trimmedItem.startsWith("- ") || trimmedItem.startsWith("* ")) {
                String content = trimmedItem.substring(2).trim();
                result.append("<li>").append(applyInlineFormatting(content)).append("</li>");
            }
        }
        result.append("</ul>");
        return result.toString();
    }

    private String applyInlineFormatting(String text) {
        if (text == null || text.isEmpty())
            return "";

        // Escape entities
        String formatted = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");

        // Bold (** or __)
        formatted = formatted.replaceAll("(\\*\\*|__)(.*?)\\1", "<b>$2</b>");

        // Italic (* or _)
        formatted = formatted.replaceAll("(\\*|_)(.*?)\\1", "<i>$2</i>");

        // Inline Code (`)
        formatted = formatted.replaceAll("`(.*?)`", "<code>$1</code>");

        // Links [text](url)
        formatted = formatted.replaceAll("\\[(.*?)\\]\\((.*?)\\)", "<a href=\"$2\">$1</a>");

        // Convert internal newlines to spaces for paragraph flow
        return formatted.replace("\n", " ");
    }

    private String deriveRefNumber(String url, String content) {
        // 1. Try to find WSTG ID pattern in content (e.g., WSTG-INFO-01)
        java.util.regex.Pattern idPattern = java.util.regex.Pattern.compile("WSTG-[A-Z]+-\\d+");
        java.util.regex.Matcher idMatcher = idPattern.matcher(content);
        if (idMatcher.find()) {
            return idMatcher.group();
        }

        // 2. Derive from URL and Filename (useful for sub-checklists like 05.1)
        String categoryCode = getCategoryCode(url);
        String filename = url.substring(url.lastIndexOf('/') + 1);
        // Match numbers at start of filename (e.g., 05 or 05.1)
        java.util.regex.Pattern filePattern = java.util.regex.Pattern.compile("^(\\d+(\\.\\d+)?)-");
        java.util.regex.Matcher fileMatcher = filePattern.matcher(filename);

        if (fileMatcher.find()) {
            return "WSTG-" + categoryCode + "-" + fileMatcher.group(1);
        }

        return "WSTG-UNKNOWN";
    }

    private String getCategoryCode(String url) {
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("/(\\d{2})-.*?/");
        java.util.regex.Matcher matcher = pattern.matcher(url);
        if (matcher.find()) {
            String num = matcher.group(1);
            switch (num) {
                case "01":
                    return "INFO";
                case "02":
                    return "CONF";
                case "03":
                    return "IDNT";
                case "04":
                    return "ATHN";
                case "05":
                    return "ATHZ";
                case "06":
                    return "SESS";
                case "07":
                    return "INPV";
                case "08":
                    return "ERRH";
                case "09":
                    return "CRYP";
                case "10":
                    return "BUSL";
                case "11":
                    return "CLNT";
                default:
                    return "GENR";
            }
        }
        return "GENR";
    }

    // Saves a local copy of the checklist in a file called OWASPChecklistData.txt
    // at the directory dictated by the user
    public void saveLocalCopy(String absoluteFilePath) throws IOException {
        String filePath = absoluteFilePath + File.separator + "OWASP_WSTG_local";
        try (FileOutputStream fileOutputStream = new FileOutputStream(filePath);
                ObjectOutputStream outputStream = new ObjectOutputStream(fileOutputStream)) {

            for (ChecklistEntry entry : extender.checklistLog) {
                if (entry.isExcluded()) {
                    ChecklistEntry tempChecklistEntry = entry;
                    tempChecklistEntry.setExclusion(false);
                    outputStream.writeObject(tempChecklistEntry);
                } else {
                    outputStream.writeObject(entry);
                }
            }

            extender.getExtenderPanelUI().getScanStatusLabel()
                    .setText("File saved to " + filePath);
            extender.issueAlert("File saved to " + filePath);
        }
    }

    /**
     * Loads WSTG checklist from bundled JSON resource.
     * BApp Store Criteria #8: Support Offline Working.
     */
    public void loadLocalCopy() {
        extender.checklistLog.clear();
        extender.checkListHashMap.clear();

        LocalChecklistLoader loader = new LocalChecklistLoader();
        List<ChecklistEntry> entries = loader.loadFromResources();

        if (entries.isEmpty()) {
            extender.logOutput("Failed to load bundled WSTG checklist");
            showErrorDialog("Failed to load bundled WSTG checklist. The resource file may be missing.");
            return;
        }

        for (ChecklistEntry entry : entries) {
            extender.checkListHashMap.put(entry.getRefNumber(), entry);
            loadNewChecklistEntry(entry);
        }

        extender.getLoggerTable().generateWSTGList();
        extender.logOutput("Loaded " + entries.size() + " items from bundled WSTG v" + loader.getVersion());
    }

    // Saves a local excel file at the directory specified by the user
    public void saveToExcelFile(String absoluteFilePath) {
        populateChecklistEntryData();

        try (XSSFWorkbook checklistWorkbook = new XSSFWorkbook()) {
            XSSFSheet checklistSheet = checklistWorkbook.createSheet("OWASP Checklist");

            createHeaderRow(checklistWorkbook, checklistSheet);
            writeChecklistRows(checklistWorkbook, checklistSheet);

            autoSizeColumns(checklistSheet);

            writeToFile(checklistWorkbook, absoluteFilePath);
        } catch (IOException e) {
            extender.issueAlert("Error initializing workbook");
        }
    }

    private void populateChecklistEntryData() {
        for (LoggerEntry findingEntry : extender.loggerList) {
            processFindingEntry(findingEntry);
        }
    }

    private void processFindingEntry(LoggerEntry findingEntry) {
        String issue = findingEntry.getChecklistIssue();
        if (issue == null || issue.isEmpty() || "N.A.".equals(issue)) {
            return;
        }

        int cutIndex = issue.indexOf(" -");
        if (cutIndex == -1) {
            return;
        }

        String findingRefID = issue.substring(0, cutIndex);
        ChecklistEntry checklistEntry = extender.checkListHashMap.get(findingRefID);

        if (checklistEntry != null) {
            StringBuilder comments = new StringBuilder();
            comments.append(findingEntry.getPenTesterComments());
            comments.append("\nAffected Instance include(s):\n");
            for (InstanceEntry instanceEntry : findingEntry.getInstanceList()) {
                if (!"False Positive".equals(instanceEntry.getConfidence())) {
                    comments.append(instanceEntry.getUrl()).append(" - (")
                            .append(instanceEntry.getConfidence())
                            .append(")\n");
                }
            }
            String evidence = findingEntry.getEvidence() + "\n\n";
            comments.append("\n\n");

            checklistEntry.setPenTesterComments(comments.toString());
            checklistEntry.setEvidence(evidence);
        }
    }

    private void createHeaderRow(XSSFWorkbook checklistWorkbook, XSSFSheet checklistSheet) {
        XSSFCellStyle headerStyle = checklistWorkbook.createCellStyle();
        XSSFFont headerFont = checklistWorkbook.createFont();
        headerFont.setBold(true);
        headerStyle.setFont(headerFont);
        headerStyle.setFillForegroundColor(IndexedColors.LIGHT_GREEN.getIndex());
        headerStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);

        XSSFRow columnHeadersRow = checklistSheet.createRow(0);
        String[] headerArray = new String[] { ChecklistEntry.REF_NUMBER_KEY, ChecklistEntry.CATEGORY_KEY,
                ChecklistEntry.TEST_NAME_KEY,
                "Pentester Comments",
                "Evidence", "URL" };
        for (int i = 0; i < 6; i++) {
            XSSFCell cell = columnHeadersRow.createCell(i);
            cell.setCellValue(headerArray[i]);
            cell.setCellStyle(headerStyle);
        }
    }

    private void writeChecklistRows(XSSFWorkbook checklistWorkbook, XSSFSheet checklistSheet) {
        XSSFCellStyle urlStyle = checklistWorkbook.createCellStyle();
        urlStyle.setWrapText(true);
        XSSFFont urlFont = checklistWorkbook.createFont();
        urlFont.setUnderline(org.apache.poi.ss.usermodel.Font.U_SINGLE);
        urlFont.setColor(IndexedColors.BLUE.getIndex());
        urlStyle.setFont(urlFont);

        XSSFCellStyle cellStyle = checklistWorkbook.createCellStyle();
        cellStyle.setWrapText(true);

        int rowNum = 0;
        for (int i = 0; i < extender.checklistLog.size(); i++) {
            ChecklistEntry entry = extender.checklistLog.get(i);
            String[] contentArray = new String[] { entry.getRefNumber(), entry.getCategory(), entry.getTestName(),
                    entry.getPenTesterComments().trim(), entry.getEvidence().trim(), entry.getUrl() };
            entry.clearComments();
            entry.clearEvidences();

            if (contentArray[3].equals(""))
                contentArray[3] = "N.A.";
            if (contentArray[4].equals(""))
                contentArray[4] = "N.A.";

            XSSFRow row = checklistSheet.createRow(++rowNum);
            for (int j = 0; j < 6; j++) {
                XSSFCell cell = row.createCell(j);
                cell.setCellValue(contentArray[j]);
                if (j != 5) {
                    cell.setCellStyle(cellStyle);
                } else {
                    cell.setCellStyle(urlStyle);
                    CreationHelper helper = checklistWorkbook.getCreationHelper();
                    Hyperlink articleLink = helper.createHyperlink(HyperlinkType.URL);
                    articleLink.setAddress(entry.getUrl());
                    cell.setHyperlink(articleLink);
                }
            }
            row.setHeight((short) -1);
        }
    }

    private void autoSizeColumns(XSSFSheet checklistSheet) {
        if (checklistSheet.getPhysicalNumberOfRows() > 0) {
            org.apache.poi.ss.usermodel.Row headerRow = checklistSheet.getRow(0);
            if (headerRow != null) {
                for (int i = 0; i < headerRow.getPhysicalNumberOfCells(); i++) {
                    checklistSheet.autoSizeColumn(i);
                }
            }
        }
        checklistSheet.setColumnWidth(3, 25600);
        checklistSheet.setColumnWidth(4, 25600);
    }

    private void writeToFile(XSSFWorkbook checklistWorkbook, String absoluteFilePath) {
        try {
            FileOutputStream excelWriter = new FileOutputStream(
                    new File(absoluteFilePath + File.separator + "OWASP Checklist.xlsx"));
            checklistWorkbook.write(excelWriter);
            excelWriter.close();
            extender.issueAlert("Excel report generated!");
            extender.getExtenderPanelUI().getScanStatusLabel().setText("Excel report generated!");
        } catch (IOException e) {
            extender.issueAlert("Error, file not found");
        }
    }

    /**
     * Constructs a new ChecklistEntry object and adds it to the checklistLog.
     * Returns false if fetch failed (skip-and-continue behavior).
     *
     * @param url The URL to fetch and create entry from
     * @return true if successful, false if skipped due to fetch failure
     */
    public boolean logNewChecklistEntry(String url) {
        Map<String, String> tableElements = this.getTableElements(url);
        Map<String, String> contentElements = this.getContentElements(url);

        // Skip-and-continue: return false if either fetch failed
        if (tableElements == null || tableElements.isEmpty() || contentElements == null || contentElements.isEmpty()) {
            extender.logOutput("Skipping URL due to fetch failure: " + url);
            return false;
        }

        int row = this.extender.checklistLog.size();
        ChecklistEntry checklistEntry = new ChecklistEntry(tableElements, contentElements, url);
        checklistEntry.cleanEntry();
        extender.getChecklistTableModel().addValueAt(checklistEntry, row, row);
        extender.checkListHashMap.put(checklistEntry.getRefNumber(), checklistEntry);
        return true;
    }

    // Adds a ChecklistEntry object created from a local saved file to the
    // checklistLog using the setValueAt() method
    public void loadNewChecklistEntry(ChecklistEntry entry) {
        int row = this.extender.checklistLog.size();
        extender.getChecklistTableModel().addValueAt(entry, row, row);
    }

    // Logic to calculate file hash
    public String toHash(File chosenFile) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String result = "";

        try (FileInputStream fis = new FileInputStream(chosenFile)) {
            byte[] dataBytes = new byte[1024];
            int readCount;
            while ((readCount = fis.read(dataBytes)) != -1) {
                md.update(dataBytes, 0, readCount);
            }
            byte[] mdbytes = md.digest();

            // convert the byte to hex format method
            StringBuilder sb = new StringBuilder();
            for (byte mdbyte : mdbytes) {
                sb.append(Integer.toString((mdbyte & 0xff) + 0x100, 16).substring(1));
            }
            result = sb.toString();
        } catch (IOException ioe) {
            extender.logError("Error exception at toHash");
        }

        return result;
    }

    // Method for save closing of FileOutputStream
    public void safeClose(FileOutputStream fos) {
        if (fos != null) {
            try {
                fos.close();
            } catch (IOException e) {
                extender.logOutput("FileOutputStream cannot perform safeClose");
            }
        }
    }

}
