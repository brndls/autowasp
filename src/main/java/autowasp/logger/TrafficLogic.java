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
import autowasp.http.HTTPService;
import autowasp.logger.entryTable.LoggerEntry;
import autowasp.logger.instancesTable.InstanceEntry;

// Montoya API imports
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.InterceptedResponse;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Traffic Logic - Montoya API
 *
 * Learning Notes - Migration from Legacy API:
 *
 * Legacy API:
 * - IRequestInfo from helpers.analyzeRequest()
 * - IResponseInfo from helpers.analyzeResponse()
 * - InterceptProxyMessage for proxy messages
 *
 * Montoya API:
 * - HttpRequest.headers() directly access headers
 * - HttpResponse.headers() directly access headers
 * - InterceptedResponse/InterceptedRequest from proxy handler
 *
 * Benefits:
 * 1. No need for helpers for parsing - already available directly
 * 2. Header as List<HttpHeader> which is typed
 * 3. Access URL directly from request.url()
 */
public class TrafficLogic {
    private final Autowasp extender;

    // Flags to avoid duplicate logs
    boolean secHeaderFlag = false;
    boolean cookieOverallFlag = false;
    boolean httpRequestFlag = false;
    boolean basicAuthenticationFlag = false;
    boolean serverDetailFlag = false;
    boolean serverErrorLeakedInfoFlag = false;
    boolean corHeadersFlag = false;
    boolean unauthorisedDisclosureHostnameFlag = false;
    boolean urlManipulationFlag = false;
    boolean xssFlag = false;
    boolean cgiFlag = false;
    boolean cgiUrls = false;
    boolean httpVerbFlag = false;

    private String evidence;
    private String trafficMsg;
    private String flag;

    // Data for the message currently being processed
    // Data for the message currently being processed
    private HttpRequest currentRequest;
    private HttpResponse httpResponse;
    private HTTPService httpService;

    private TrafficInstance affectedInstancesList;
    private List<HttpHeader> requestHeaders = new ArrayList<>();
    private List<HttpHeader> responseHeaders = new ArrayList<>();

    public final ArrayList<String> cgiUrlList;
    public String burpCollaboratorHost;

    final ArrayList<String> httpVerbList = new ArrayList<>();

    public TrafficLogic(Autowasp extender) {
        this.extender = extender;
        this.buildHttpVerbList();
        this.cgiUrlList = new ArrayList<>();

        // Generate Collaborator host (will be set after api available)
        // In Montoya API: api.collaborator().createClient().generatePayload()
        try {
            this.burpCollaboratorHost = extender.getApi().collaborator()
                    .createClient().generatePayload().toString();
        } catch (Exception e) {
            this.burpCollaboratorHost = "collaborator.example.com";
            extender.logError("Could not generate Collaborator host: " + e.getMessage());
        }
    }

    /**
     * Classify traffic from InterceptedResponse (Montoya API)
     * Replaces classifyTraffic(InterceptProxyMessage)
     */
    public void classifyTraffic(InterceptedResponse response) {
        this.resetLogMsg();
        this.currentRequest = response.initiatingRequest();
        this.httpResponse = response;

        // Extract HTTPService
        this.httpService = new HTTPService(currentRequest.httpService());

        // Get headers
        this.requestHeaders = currentRequest.headers();
        this.responseHeaders = httpResponse.headers();

        // Check HTTP protocol (not encrypted)
        if (!httpRequestFlag && !httpService.isSecure()) {
            verifyHTTPRequest();
        }
        if (!serverDetailFlag) {
            verifyServerInfoLeakage();
        }
        if (!serverErrorLeakedInfoFlag) {
            verifyServerErrorLeakage();
        }
        if (!basicAuthenticationFlag) {
            verifyBasicAuthentication();
        }
        if (!urlManipulationFlag) {
            try {
                if (httpResponse.statusCode() == 302 && !httpService.isSecure()) {
                    verifyUrlManipulation();
                }
            } catch (Exception e) {
                extender.logOutput("Exception occurred at classifyTraffic()");
            }
        }
        if (!corHeadersFlag) {
            verifyCorHeaders();
        }
        if (!httpVerbFlag) {
            verifyHttpVerbRequest();
        }
        if (!secHeaderFlag) {
            verifyXContentHeaders();
        }
    }

    // Method to inspect response content headers
    private void verifyXContentHeaders() {
        boolean xcontentFlag = false;
        this.trafficMsg = "";
        this.evidence = "";

        for (HttpHeader header : responseHeaders) {
            String name = header.name().toLowerCase();
            String value = header.value();

            if (name.contains("x-content-type-options")) {
                this.trafficMsg = "[+] X-Content-Type-Options header implemented\n";
                this.evidence += header.name() + ": " + value + "\n";
                xcontentFlag = true;
            }
            if (name.contains("x-frame-options")) {
                this.trafficMsg = "[+] X-Frame-Options implemented\n";
                this.evidence += header.name() + ": " + value + "\n";
                xcontentFlag = true;
            }
            if (name.contains("x-xss-protection")) {
                this.trafficMsg = "[+] X-XSS-Protection implemented\n";
                this.evidence += header.name() + ": " + value + "\n";
                xcontentFlag = true;
            }
            if (name.contains("content-type")) {
                this.trafficMsg = "[+] Content-Type implemented\n";
                this.evidence += header.name() + ": " + value + "\n";
                xcontentFlag = true;
            }
        }

        if (xcontentFlag) {
            this.secHeaderFlag = true;
            affectedInstancesList.setXContentHeaders();
            this.flag = "Content frame(s) implementation";
            storeTrafficFinding();
        }
    }

    // Method to verify HTTP verb request submission
    private void verifyHttpVerbRequest() {
        try {
            String requestString = currentRequest.toString();
            String[] lines = requestString.split("\n");

            if (lines[0].contains("POST")) {
                this.evidence = "";

                for (String method : httpVerbList) {
                    String newRequestString = requestString.replace("POST", method);

                    // Create request with new method using Montoya API
                    HttpRequest newRequest = HttpRequest.httpRequest(
                            currentRequest.httpService(),
                            newRequestString);

                    // Send request
                    HttpResponse newResponse = extender.getApi().http()
                            .sendRequest(newRequest).response();

                    int newStatusCode = newResponse.statusCode();

                    if (newStatusCode < 400) {
                        this.evidence += "Ran method: " + method +
                                "  and response status code returns " + newStatusCode + "\n";
                    }
                }

                if (!this.evidence.isEmpty()) {
                    this.trafficMsg = "[+] Possible dangerous HTTP method could be used on this site";
                } else {
                    this.trafficMsg = "[+] No dangerous HTTP method could be used on this site";
                }
                this.flag = "HTTP verb testing";
                affectedInstancesList.setHttpVerb();
                this.httpVerbFlag = true;
                storeTrafficFinding();
            }
        } catch (Exception e) {
            extender.logOutput("Exception occurred at verifyHttpVerbRequest()");
        }
    }

    // Method to inspect for CORS headers
    private void verifyCorHeaders() {
        for (HttpHeader header : responseHeaders) {
            String headerString = header.name() + ": " + header.value();
            if (headerString.toLowerCase().contains("access-control-allow-origin: *")) {
                this.corHeadersFlag = true;
                this.trafficMsg = "[+] Insecure implementation of CORS Header\n";
                this.evidence = headerString + "\n";
                this.flag = "CORS headers implementation";
                affectedInstancesList.setCorHeaders();
                storeTrafficFinding();
            }
        }
    }

    // Method to inspect for URL manipulation
    private void verifyUrlManipulation() {
        if (!requestHeaders.isEmpty()) {
            try {
                // Get path from first line
                String firstLine = currentRequest.toString().split("\n")[0];
                String directory = firstLine.split(" ")[1];

                if (!directory.endsWith("/") && !directory.contains(".")) {
                    this.urlManipulationFlag = true;
                    String urlString = "https://" + burpCollaboratorHost + directory;

                    // Create request to collaborator
                    HttpRequest maliciousRequest = HttpRequest.httpRequestFromUrl(urlString);
                    HttpResponse newResponse = extender.getApi().http()
                            .sendRequest(maliciousRequest).response();

                    if (newResponse.statusCode() == 302) {
                        for (HttpHeader header : newResponse.headers()) {
                            String location = "location: " + urlString;
                            if ((header.name() + ": " + header.value())
                                    .toLowerCase().contains(location.toLowerCase())) {
                                this.trafficMsg = "[+] Manipulation of URL to redirect victim IS possible on this site";
                            } else {
                                this.trafficMsg = "[+] Manipulation of URL to redirect victim IS NOT possible on this site";
                            }
                        }
                    } else {
                        this.trafficMsg = "[+] Manipulation of URL to redirect victim IS NOT possible on this site";
                    }

                    this.evidence = "MANIPULATED REQUEST\n" + maliciousRequest.toString();
                    this.evidence += "\n\nRESPONSE\n" + newResponse.toString();

                    this.urlManipulationFlag = true;
                    this.flag = "URL Manipulation";
                    storeTrafficFinding();
                }
            } catch (Exception e) {
                extender.logOutput("MalformedURLException at verifyUrlManipulation()");
            }
        }
    }

    // Method to identify the use of basic authentication headers
    private void verifyBasicAuthentication() {
        for (HttpHeader header : requestHeaders) {
            String headerString = header.name() + ": " + header.value();
            if (headerString.toLowerCase().contains("authorization: basic")) {
                String[] tokens = headerString.split(" ");
                String encode = tokens[2];
                byte[] decodeBytes = Base64.getDecoder().decode(encode);
                String decode = new String(decodeBytes, StandardCharsets.UTF_8);

                this.basicAuthenticationFlag = true;
                this.flag = "Base64 weak authentication request";
                this.trafficMsg = "[+] Basic Authentication request is being used\n";
                this.trafficMsg += "Encoded found: " + encode + "\n";
                this.trafficMsg += "Decoded found: " + decode + "\n";
                this.evidence = headerString + "\n";
                this.affectedInstancesList.setBase64();
                storeTrafficFinding();
            }
        }
    }

    // Method to inspect for server error leakage
    private void verifyServerErrorLeakage() {
        try {
            if (responseHeaders.size() > 2) {
                HttpHeader header = responseHeaders.get(2);
                String name = header.name().toLowerCase();
                String value = header.value();

                if (name.contains("server") && !value.isEmpty() &&
                        httpResponse.statusCode() >= 500) {
                    trafficMsg = "[+] Potential Server Details : " + value +
                            "from server error page\n";

                    this.serverErrorLeakedInfoFlag = true;
                    this.flag = "Server response header revealed from error response";
                    affectedInstancesList.setServerErrorInfoLeaked();
                    this.evidence = header.name() + ": " + value + "\n";
                    storeTrafficFinding();
                }
            }
        } catch (Exception e) {
            extender.logOutput("Exception occurred at verifyServerErrorLeakage");
        }
    }

    // Method to inspect for server info
    private void verifyServerInfoLeakage() {
        boolean toLog = false;
        try {
            if (responseHeaders.size() > 2) {
                HttpHeader header = responseHeaders.get(2);
                String name = header.name().toLowerCase();
                String value = header.value();

                if (name.contains("server") && !value.isEmpty()) {
                    trafficMsg = "[+] Potential Server Details : " + value + "\n";
                    toLog = true;
                }

                if (name.contains("x-powered-by") && !value.isEmpty()) {
                    trafficMsg = "[+] Web Server powered by : " + value + "\n";
                    toLog = true;
                }

                if (toLog) {
                    this.serverDetailFlag = true;
                    this.flag = "Server Information Leakage";
                    affectedInstancesList.setServerInfoLeaked();
                    this.evidence = header.name() + ": " + value + "\n";
                    storeTrafficFinding();
                }
            }
        } catch (Exception e) {
            extender.logOutput("Exception occurred at verifyServerInfoLeakage");
        }
    }

    // Method to inspect for non-secure network traffic
    private void verifyHTTPRequest() {
        this.httpRequestFlag = true;
        trafficMsg = "[+] A proxy intercepted a request on : " + httpService.getHost();
        flag = "Communication over unencrypted channel";
        affectedInstancesList.setUnencrypted();

        int statusCode = httpResponse.statusCode();
        if (statusCode == 200) {
            trafficMsg += "\n[+] Server response with " + statusCode;
            trafficMsg += "\n[+] Potential sensitive information being transmitted over non-SSL connections";
        } else if (statusCode == 302 || statusCode == 301 || statusCode == 304) {
            trafficMsg += "\n[+] Server response return " + statusCode;
            trafficMsg += "\nRedirection Message from a HTTP Request detected";
        }

        // Build evidence from response headers
        StringBuilder evidenceBuilder = new StringBuilder();
        int count = 0;
        for (HttpHeader header : responseHeaders) {
            if (count++ >= 5)
                break;
            evidenceBuilder.append(header.name()).append(": ")
                    .append(header.value()).append("\n");
        }
        evidence = evidenceBuilder.toString();
        storeTrafficFinding();
    }

    // Method to build HTTP Verb list
    private void buildHttpVerbList() {
        this.httpVerbList.add("POST");
        this.httpVerbList.add("PUT");
        this.httpVerbList.add("DELETE");
        this.httpVerbList.add("TRACE");
        this.httpVerbList.add("TRACK");
        this.httpVerbList.add("CONNECT");
        this.httpVerbList.add("PROPFIND");
        this.httpVerbList.add("PROPPATCH");
        this.httpVerbList.add("MKCOL");
        this.httpVerbList.add("MOVE");
        this.httpVerbList.add("LOCK");
        this.httpVerbList.add("UNLOCK");
        this.httpVerbList.add("VERSION-CONTROL");
        this.httpVerbList.add("REPORT");
        this.httpVerbList.add("CHECKOUT");
        this.httpVerbList.add("CHECKIN");
        this.httpVerbList.add("UNCHECKOUT");
        this.httpVerbList.add("MKWORKSPACE");
        this.httpVerbList.add("UPDATE");
        this.httpVerbList.add("LABEL");
        this.httpVerbList.add("MERGE");
        this.httpVerbList.add("BASELINE-CONTROL");
        this.httpVerbList.add("MKACTIVITY");
        this.httpVerbList.add("ORDERPATCH");
        this.httpVerbList.add("ACL");
        this.httpVerbList.add("PATCH");
        this.httpVerbList.add("SEARCH");
        this.httpVerbList.add("ARBITARY");
    }

    // Method to clear log message
    private void resetLogMsg() {
        evidence = null;
        trafficMsg = null;
        affectedInstancesList = new TrafficInstance();
        currentRequest = null;
        httpResponse = null;
        httpService = null;
        requestHeaders = new ArrayList<>();
        responseHeaders = new ArrayList<>();
    }

    // Method to store traffic findings to Autowasp
    private void storeTrafficFinding() {
        String host = httpService.getHost();
        String action = "Automated Traffic";
        String vulnType = flag;
        String issue = "";
        String comments = "Automated Traffic logging detected the following issue: " + flag;
        LoggerEntry findingEntry = new LoggerEntry(host, action, vulnType, issue);
        findingEntry.setEvidence(evidence);

        try {
            URL url = java.net.URI.create(currentRequest.url()).toURL();
            String confidence = "Certain";
            String severity = "~";

            // Create HTTPRequestResponse from InterceptedResponse
            HTTPRequestResponse requestResponse = new HTTPRequestResponse(
                    currentRequest.toByteArray().getBytes(),
                    httpResponse.toByteArray().getBytes(),
                    httpService);

            InstanceEntry instanceEntry = new InstanceEntry(url, confidence, severity, requestResponse);
            findingEntry.addInstance(instanceEntry);
            findingEntry.setPenTesterComments(comments + "\n" + trafficMsg);

            extender.loggerTableModel.addAllLoggerEntry(findingEntry);
        } catch (Exception e) {
            extender.logError("MalformedURLException at storeTrafficFinding: " + e.getMessage());
        }

        this.resetLogMsg();
    }
}
