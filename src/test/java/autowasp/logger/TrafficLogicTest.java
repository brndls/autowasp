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

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.InterceptedResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.*;

import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link TrafficLogic}.
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
        extender = mock(Autowasp.class);
        api = mock(MontoyaApi.class);
        loggerManager = mock(LoggerManager.class);
        tableModel = mock(LoggerTableModel.class);
        interceptedResponse = mock(InterceptedResponse.class);
        httpRequest = mock(HttpRequest.class);
        httpResponse = mock(HttpResponse.class);
        httpService = mock(HttpService.class);

        when(extender.getApi()).thenReturn(api);
        when(extender.getLoggerManager()).thenReturn(loggerManager);
        when(loggerManager.getLoggerTableModel()).thenReturn(tableModel);

        Collaborator collaborator = mock(Collaborator.class);
        CollaboratorClient client = mock(CollaboratorClient.class);
        CollaboratorPayload payload = mock(CollaboratorPayload.class);
        when(api.collaborator()).thenReturn(collaborator);
        when(collaborator.createClient()).thenReturn(client);
        when(client.generatePayload()).thenReturn(payload);
        when(payload.toString()).thenReturn("collaborator.example.com");

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
        setupBasicInterceptedResponse(false, 200);
        assertDoesNotThrow(() -> trafficLogic.classifyTraffic(interceptedResponse));
    }

    @Test
    void testClassifyTrafficWithHTTPSRequest() {
        setupBasicInterceptedResponse(true, 200);
        assertDoesNotThrow(() -> trafficLogic.classifyTraffic(interceptedResponse));
    }

    @Test
    void testClassifyTrafficWithNullRequest() {
        when(interceptedResponse.initiatingRequest()).thenReturn(null);
        assertDoesNotThrow(() -> trafficLogic.classifyTraffic(interceptedResponse));
    }

    @Test
    void testClassifyTrafficWithEmptyHeaders() {
        setupBasicInterceptedResponse(true, 200);
        when(httpResponse.headers()).thenReturn(new ArrayList<>());
        when(httpRequest.headers()).thenReturn(new ArrayList<>());
        assertDoesNotThrow(() -> trafficLogic.classifyTraffic(interceptedResponse));
    }

    @Test
    void testClassifyTrafficWithStatus302() {
        setupBasicInterceptedResponse(false, 302);
        assertDoesNotThrow(() -> trafficLogic.classifyTraffic(interceptedResponse));
    }

    @Test
    void testClassifyTrafficWithStatus301() {
        setupBasicInterceptedResponse(false, 301);
        assertDoesNotThrow(() -> trafficLogic.classifyTraffic(interceptedResponse));
    }

    @Test
    void testClassifyTrafficWithStatus500() {
        setupBasicInterceptedResponse(true, 500);
        assertDoesNotThrow(() -> trafficLogic.classifyTraffic(interceptedResponse));
    }

    @Test
    void testCollaboratorHostFallback() {
        when(api.collaborator()).thenThrow(new RuntimeException("Collaborator unavailable"));
        new TrafficLogic(extender);
        verify(extender).logError(contains("Could not generate Collaborator host"));
    }

    @Test
    void testHttpVerbListContainsExpectedMethods() {
        assertTrue(trafficLogic.httpVerbList.contains("POST"));
        assertTrue(trafficLogic.httpVerbList.contains("PUT"));
        assertTrue(trafficLogic.httpVerbList.contains("DELETE"));
        assertTrue(trafficLogic.httpVerbList.contains("TRACE"));
        assertTrue(trafficLogic.httpVerbList.contains("PATCH"));
    }

    @Test
    void testCgiUrlListIsModifiable() {
        trafficLogic.cgiUrlList.add("test.cgi");
        assertEquals(1, trafficLogic.cgiUrlList.size());
        assertTrue(trafficLogic.cgiUrlList.contains("test.cgi"));
    }

    // Helper method
    private void setupBasicInterceptedResponse(boolean secure, int statusCode) {
        when(httpService.host()).thenReturn("example.com");
        when(httpService.port()).thenReturn(secure ? 443 : 80);
        when(httpService.secure()).thenReturn(secure);

        when(httpRequest.httpService()).thenReturn(httpService);
        when(httpRequest.url()).thenReturn(secure ? "https://example.com/" : "http://example.com/");
        when(httpRequest.headers()).thenReturn(new ArrayList<>());
        when(httpRequest.toString()).thenReturn("GET / HTTP/1.1\nHost: example.com\n\n");

        ByteArray requestBytes = mock(ByteArray.class);
        when(requestBytes.getBytes()).thenReturn("GET / HTTP/1.1\n\n".getBytes());
        when(httpRequest.toByteArray()).thenReturn(requestBytes);

        when(httpResponse.statusCode()).thenReturn((short) statusCode);
        when(httpResponse.headers()).thenReturn(new ArrayList<>());
        when(httpResponse.toString()).thenReturn("HTTP/1.1 " + statusCode + " OK\n\n");

        ByteArray responseBytes = mock(ByteArray.class);
        when(responseBytes.getBytes()).thenReturn(("HTTP/1.1 " + statusCode + " OK\n\n").getBytes());
        when(httpResponse.toByteArray()).thenReturn(responseBytes);

        when(interceptedResponse.initiatingRequest()).thenReturn(httpRequest);
        when(interceptedResponse.statusCode()).thenReturn((short) statusCode);
        when(interceptedResponse.headers()).thenReturn(new ArrayList<>());
        when(interceptedResponse.toString()).thenReturn("HTTP/1.1 " + statusCode + " OK\n\n");
        when(interceptedResponse.toByteArray()).thenReturn(responseBytes);
    }
}
