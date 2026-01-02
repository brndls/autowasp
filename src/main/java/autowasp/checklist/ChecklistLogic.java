/*
 * Copyright (c) 2021 Government Technology Agency
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
import org.jsoup.nodes.Element;
import org.jsoup.parser.Tag;
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
    private transient Document anyPage;
    public static final String GITHUB_REPO_URL = "https://github.com/GovTech-CSG/wstg/blob/master/document/4-Web_Application_Security_Testing/README.md";

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
        // Get the URLs located within the main content page, which link to each
        // individual section's content pages
        List<String> sectionContentPageURLs = scrapePageURLs(GITHUB_REPO_URL);
        sectionContentPageURLs.remove(0); // Removes the link to the introduction page

        // Get the URLs for every individual article within each individual section's
        // content page
        List<String> articleURLs = new ArrayList<>();
        for (String url : sectionContentPageURLs) {
            List<String> sectionArticleURLs = scrapePageURLs(url);
            articleURLs.addAll(sectionArticleURLs);
        }

        // Cleans the list of URLs to exclude external links and links to headers within
        // the pages
        articleURLs.removeIf(url -> {
            // do another check to remove "sub" article of a test cases
            String[] array = url.split("/");
            int subArticleIndex = array[array.length - 1].indexOf(".");
            // Condition 1 filters out external URLs,
            // while condition 2 filters out anchor URLs that link to headers within the
            // article,
            // condition 3 filters out README.md and
            // condition 4 filters out sub-articles
            return !url.contains("https://github.com") || url.contains("#")
                    || url.contains("README.md") || url.contains("00")
                    || subArticleIndex == 2;
        });
        return articleURLs;
    }

    // A general method to scrape all the URLs that exist on a page and return a
    // list containing them. Returns empty list on failure (skip-and-continue).
    public List<String> scrapePageURLs(String anyURL) {
        anyPage = fetchWithRetry(anyURL);
        if (anyPage == null) {
            extender.getExtenderPanelUI().getScanStatusLabel().setText("Failed to fetch: " + anyURL);
            return new ArrayList<>();
        }

        try {
            Elements pageElements = anyPage.getElementsByTag("Article").get(0).children();
            return pageElements.select("a[href]").eachAttr("abs:href");
        } catch (Exception e) {
            extender.logError("Error parsing page structure: " + anyURL);
            return new ArrayList<>();
        }
    }

    // Gets the Reference Number, Category, and Title of the article saved in a hash
    // map. Returns null on failure (skip-and-continue).
    public Map<String, String> getTableElements(String anyURL) {
        anyPage = fetchWithRetry(anyURL);
        if (anyPage == null) {
            return Collections.emptyMap();
        }

        try {
            Elements filePathElements = anyPage.getElementById("blob-path").children();
            Elements filePathElements2 = anyPage.getElementsByTag("td");

            String refNumber = filePathElements2.first().text();
            String category = filePathElements.get(6).text().split("-", 2)[1].replace("_", " ");
            String testName = filePathElements.get(8).text().split("-", 2)[1].replace("_", " ");
            testName = testName.split("[.]", 2)[0];

            Map<String, String> tableElements = new HashMap<>();
            tableElements.put("Reference Number", refNumber);
            tableElements.put("Category", category);
            tableElements.put("Test Name", testName);
            return tableElements;
        } catch (Exception e) {
            extender.logError("Error parsing table elements for: " + anyURL + " - " + e.getMessage());
            return Collections.emptyMap();
        }
    }

    /*
     * Gets the "Summary", "How To Test", and "References" sections of the article
     * saved in a hash map, with HTML format preserved to be rendered
     * within the Burp UI elements. Returns null on failure (skip-and-continue).
     */
    public Map<String, String> getContentElements(String anyURL) {
        anyPage = fetchWithRetry(anyURL);
        if (anyPage == null) {
            return Collections.emptyMap();
        }

        try {
            Element article = anyPage.getElementsByTag("Article").get(0);
            article.append("<h2>Ending marker</h2>");
            Elements articleElements = article.children();

            // Replace img tags to href as extender does not pull images
            Elements img = article.getElementsByTag("img");
            for (Element e : img) {
                String absoluteUrl = e.absUrl("src");
                Element newElement = new Element(Tag.valueOf("a"), "");
                newElement.attr("href", absoluteUrl);
                newElement.append("Refer to image here");
                e.replaceWith(newElement);
            }

            // State machine to extract content sections
            int index = 0;
            int state = 0;
            String currentHeader = "";
            StringBuilder currentParagraphs = new StringBuilder();
            Map<String, String> contentElements = new HashMap<>();

            while (index < articleElements.size()) {
                switch (state) {
                    case 0:
                        currentHeader = articleElements.get(index).text().toLowerCase();
                        state = 1;
                        index++;
                        break;
                    case 1:
                        if (articleElements.get(index).tagName().equals("h2")) {
                            state = 2;
                        } else {
                            currentParagraphs.append(articleElements.get(index).toString());
                            index++;
                        }
                        break;
                    case 2:
                        contentElements.put(currentHeader, currentParagraphs.toString());
                        currentHeader = "";
                        currentParagraphs = new StringBuilder();
                        state = 0;
                        break;
                    default:
                        // Ignore other states or unknown elements
                        break;
                }
            }
            return contentElements;
        } catch (Exception e) {
            extender.logError("Error parsing content for: " + anyURL + " - " + e.getMessage());
            return Collections.emptyMap();
        }
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
        String[] headerArray = new String[] { "Reference Number", "Category", "Test Name", "Pentester Comments",
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
