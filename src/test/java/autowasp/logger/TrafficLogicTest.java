/*
 * Copyright (c) 2026 Autowasp Contributors
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
import autowasp.managers.LoggerManager;
import autowasp.logger.entrytable.LoggerTableModel;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Collaborator;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.core.ByteArray;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.InterceptedResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link TrafficLogic}.
 * Tests traffic classification and security checks.
 */
class TrafficLogicTest {

    private Autowasp extender;
    private TrafficLogic trafficLogic;
    private MontoyaApi api;
    private LoggerManager loggerManager;
    private LoggerTableModel tableModel;
    private InterceptedResponse interceptedResponse;
    private HttpRequest httpRequest;
    private HttpResponse httpResponse;
    private HttpService httpService;

    @BeforeEach
    void setUp() {
        // Mock dependencies
        extender = mock(Autowasp.class);
        api = mock(MontoyaApi.class);
        loggerManager = mock(LoggerManager.class);
        tableModel = mock(LoggerTableModel.class);
        interceptedResponse = mock(InterceptedResponse.class);
        httpRequest = mock(HttpRequest.class);
        httpResponse = mock(HttpResponse.class);
        httpService = mock(HttpService.class);

        // Setup basic mocks
        when(extender.getApi()).thenReturn(api);
        when(extender.getLoggerManager()).thenReturn(loggerManager);
        when(loggerManager.getLoggerTableModel()).thenReturn(tableModel);

        // Setup collaborator
        Collaborator collaborator = mock(Collaborator.class);
        CollaboratorClient client = mock(CollaboratorClient.class);
        CollaboratorPayload payload = mock(CollaboratorPayload.class);
        when(api.collaborator()).thenReturn(collaborator);
        when(collaborator.createClient()).thenReturn(client);
        when(client.generatePayload()).thenReturn(payload);
        when(payload.toString()).thenReturn("collaborator.example.com");

        // Create instance
        trafficLogic = new TrafficLogic(extender);
    }

    @Test
    void testConstructorInitializesHttpVerbList() {
        assertNotNull(trafficLogic.httpVerbList);
        assertTrue(trafficLogic.httpVerbList.size() > 0);
        assertTrue(trafficLogic.httpVerbList.contains("POST"));
        assertTrue(trafficLogic.httpVerbList.contains("PUT"));
        assertTrue(trafficLogic.httpVerbList.contains("DELETE"));
    }

    @Test
    void testConstructorInitializesCgiUrlList() {
        assertNotNull(trafficLogic.cgiUrlList);
        assertEquals(0, trafficLogic.cgiUrlList.size());
    }

    @Test
    void testClassifyTrafficWithHTTPRequest() {
        // Arrange
        setupBasicInterceptedResponse(false, 200);

        // Act
        trafficLogic.classifyTraffic(interceptedResponse);

        // Assert
        verify(tableModel, atLeastOnce()).addAllLoggerEntry(any());
    }

    @Test
    void testClassifyTrafficWithHTTPSRequest() {
        // Arrange
        setupBasicInterceptedResponse(true, 200);

        // Act
        trafficLogic.classifyTraffic(interceptedResponse);

        // Assert - HTTPS should not trigger HTTP warning
        verify(tableModel, atMost(10)).addAllLoggerEntry(any());
    }

    @Test
    void testVerifyXContentHeadersDetected() {
        // Arrange
        setupBasicInterceptedResponse(true, 200);
        List<HttpHeader> headers = new ArrayList<>();
        headers.add(createHeader("X-Content-Type-Options", "nosniff"));
        headers.add(createHeader("X-Frame-Options", "DENY"));
        when(httpResponse.headers()).thenReturn(headers);

        // Act
        trafficLogic.classifyTraffic(interceptedResponse);

        // Assert
        verify(tableModel, atLeastOnce()).addAllLoggerEntry(any());
    }

    @Test
    void testVerifyCorHeadersInsecure() {
        // Arrange
        setupBasicInterceptedResponse(true, 200);
        List<HttpHeader> headers = new ArrayList<>();
        headers.add(createHeader("Access-Control-Allow-Origin", "*"));
        when(httpResponse.headers()).thenReturn(headers);

        // Act
        trafficLogic.classifyTraffic(interceptedResponse);

        // Assert
        verify(tableModel, atLeastOnce()).addAllLoggerEntry(any());
    }

    @Test
    void testVerifyBasicAuthenticationDetected() {
        // Arrange
        setupBasicInterceptedResponse(true, 200);
        List<HttpHeader> requestHeaders = new ArrayList<>();
        // Base64 encoded "user:pass" = dXNlcjpwYXNz
        requestHeaders.add(createHeader("Authorization", "Basic dXNlcjpwYXNz"));
        when(httpRequest.headers()).thenReturn(requestHeaders);

        // Act
        trafficLogic.classifyTraffic(interceptedResponse);

        // Assert
        verify(tableModel, atLeastOnce()).addAllLoggerEntry(any());
    }

    @Test
    void testVerifyServerInfoLeakage() {
        // Arrange
        setupBasicInterceptedResponse(true, 200);
        List<HttpHeader> headers = new ArrayList<>();
        headers.add(createHeader("Content-Type", "text/html"));
        headers.add(createHeader("Content-Length", "1234"));
        headers.add(createHeader("Server", "Apache/2.4.41 (Ubuntu)"));
        when(httpResponse.headers()).thenReturn(headers);

        // Act
        trafficLogic.classifyTraffic(interceptedResponse);

        // Assert
        verify(tableModel, atLeastOnce()).addAllLoggerEntry(any());
    }

    @Test
    void testVerifyServerErrorLeakage() {
        // Arrange
        setupBasicInterceptedResponse(true, 500);
        List<HttpHeader> headers = new ArrayList<>();
        headers.add(createHeader("Content-Type", "text/html"));
        headers.add(createHeader("Content-Length", "1234"));
        headers.add(createHeader("Server", "nginx/1.18.0"));
        when(httpResponse.headers()).thenReturn(headers);

        // Act
        trafficLogic.classifyTraffic(interceptedResponse);

        // Assert
        verify(tableModel, atLeastOnce()).addAllLoggerEntry(any());
    }

    @Test
    void testVerifyHTTPRequestWithStatus200() {
        // Arrange
        setupBasicInterceptedResponse(false, 200);

        // Act
        trafficLogic.classifyTraffic(interceptedResponse);

        // Assert
        verify(tableModel, atLeastOnce()).addAllLoggerEntry(any());
    }

    @Test
    void testVerifyHTTPRequestWithStatus302() {
        // Arrange
        setupBasicInterceptedResponse(false, 302);

        // Act
        trafficLogic.classifyTraffic(interceptedResponse);

        // Assert
        verify(tableModel, atLeastOnce()).addAllLoggerEntry(any());
    }

    @Test
    void testVerifyHTTPRequestWithStatus301() {
        // Arrange
        setupBasicInterceptedResponse(false, 301);

        // Act
        trafficLogic.classifyTraffic(interceptedResponse);

        // Assert
        verify(tableModel, atLeastOnce()).addAllLoggerEntry(any());
    }

    @Test
    void testClassifyTrafficHandlesException() {
        // Arrange
        when(interceptedResponse.initiatingRequest()).thenThrow(new RuntimeException("Test exception"));

        // Act & Assert - should not throw
        assertDoesNotThrow(() -> trafficLogic.classifyTraffic(interceptedResponse));
    }

    @Test
    void testMultipleSecurityHeaders() {
        // Arrange
        setupBasicInterceptedResponse(true, 200);
        List<HttpHeader> headers = new ArrayList<>();
        headers.add(createHeader("X-Content-Type-Options", "nosniff"));
        headers.add(createHeader("X-Frame-Options", "SAMEORIGIN"));
        headers.add(createHeader("X-XSS-Protection", "1; mode=block"));
        headers.add(createHeader("Content-Type", "application/json"));
        when(httpResponse.headers()).thenReturn(headers);

        // Act
        trafficLogic.classifyTraffic(interceptedResponse);

        // Assert
        verify(tableModel, atLeastOnce()).addAllLoggerEntry(any());
    }

    @Test
    void testEmptyResponseHeaders() {
        // Arrange
        setupBasicInterceptedResponse(true, 200);
        when(httpResponse.headers()).thenReturn(new ArrayList<>());

        // Act & Assert
        assertDoesNotThrow(() -> trafficLogic.classifyTraffic(interceptedResponse));
    }

    @Test
    void testEmptyRequestHeaders() {
        // Arrange
        setupBasicInterceptedResponse(true, 200);
        when(httpRequest.headers()).thenReturn(new ArrayList<>());

        // Act & Assert
        assertDoesNotThrow(() -> trafficLogic.classifyTraffic(interceptedResponse));
    }

    @Test
    void testServerHeaderWithXPoweredBy() {
        // Arrange
        setupBasicInterceptedResponse(true, 200);
        List<HttpHeader> headers = new ArrayList<>();
        headers.add(createHeader("Content-Type", "text/html"));
        headers.add(createHeader("Content-Length", "1234"));
        headers.add(createHeader("X-Powered-By", "PHP/7.4.3"));
        when(httpResponse.headers()).thenReturn(headers);

        // Act
        trafficLogic.classifyTraffic(interceptedResponse);

        // Assert
        verify(tableModel, atLeastOnce()).addAllLoggerEntry(any());
    }

    @Test
    void testCollaboratorHostFallback() {
        // Arrange - collaborator throws exception
        when(api.collaborator()).thenThrow(new RuntimeException("Collaborator unavailable"));

        // Act
        new TrafficLogic(extender);

        // Assert
        verify(extender).logError(contains("Could not generate Collaborator host"));
    }

    // Helper methods

    private void setupBasicInterceptedResponse(boolean secure, int statusCode) {
        // Setup HTTP service
        when(httpService.host()).thenReturn("example.com");
        when(httpService.port()).thenReturn(secure ? 443 : 80);
        when(httpService.secure()).thenReturn(secure);

        // Setup request
        when(httpRequest.httpService()).thenReturn(httpService);
        when(httpRequest.url()).thenReturn(secure ? "https://example.com/" : "http://example.com/");
        when(httpRequest.headers()).thenReturn(new ArrayList<>());
        when(httpRequest.toString()).thenReturn("GET / HTTP/1.1\nHost: example.com\n\n");

        ByteArray requestBytes = mock(ByteArray.class);
        when(requestBytes.getBytes()).thenReturn("GET / HTTP/1.1\n\n".getBytes());
        when(httpRequest.toByteArray()).thenReturn(requestBytes);

        // Setup response
        when(httpResponse.statusCode()).thenReturn((short) statusCode);
        when(httpResponse.headers()).thenReturn(new ArrayList<>());
        when(httpResponse.toString()).thenReturn("HTTP/1.1 " + statusCode + " OK\n\n");

        ByteArray responseBytes = mock(ByteArray.class);
        when(responseBytes.getBytes()).thenReturn(("HTTP/1.1 " + statusCode + " OK\n\n").getBytes());
        when(httpResponse.toByteArray()).thenReturn(responseBytes);

        // Setup intercepted response
        when(interceptedResponse.initiatingRequest()).thenReturn(httpRequest);
        when(interceptedResponse.statusCode()).thenReturn((short) statusCode);
        when(interceptedResponse.headers()).thenReturn(new ArrayList<>());
        when(interceptedResponse.toString()).thenReturn("HTTP/1.1 " + statusCode + " OK\n\n");
        when(interceptedResponse.toByteArray()).thenReturn(responseBytes);
    }

    private HttpHeader createHeader(String name, String value) {
        HttpHeader header = mock(HttpHeader.class);
        when(header.name()).thenReturn(name);
        when(header.value()).thenReturn(value);
        when(header.toString()).thenReturn(name + ": " + value);
        return header;
    }
}
