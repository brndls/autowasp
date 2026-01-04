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

package autowasp.http;

import autowasp.Autowasp;
import autowasp.logger.entrytable.LoggerEntry;
import autowasp.logger.instancestable.InstanceEntry;

// Montoya API imports
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;

import javax.swing.*;
import java.awt.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * Context Menu Factory - Montoya API
 *
 * Learning Notes - Migration from Legacy API:
 *
 * Legacy API:
 * - implements IContextMenuFactory
 * - createMenuItems(IContextMenuInvocation)
 * - Using byte constants for context (CONTEXT_PROXY_HISTORY, etc)
 *
 * Montoya API:
 * - implements ContextMenuItemsProvider
 * - provideMenuItems(ContextMenuEvent)
 * - Using InvocationSource enum for context
 *
 * Benefits:
 * 1. Event object is richer and easier to use
 * 2. Method names are more consistent with Java conventions
 * 3. Access to requests/responses is more straightforward
 */
public class ContextMenuFactory implements ContextMenuItemsProvider {

    private final Autowasp extender;
    private static final String URL_PREFIX = "URL = ";
    private static final String ERROR_PARSING_URL = "Error parsing URL: ";

    public ContextMenuFactory(Autowasp autowasp) {
        this.extender = autowasp;
    }

    /**
     * Provide menu items berdasarkan context invocation
     * Replaces createMenuItems() from Legacy API
     */
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        if (event.invocationType() == InvocationType.PROXY_HISTORY) {
            menuItems.addAll(createProxyHistoryMenuItems(event));
        } else if (event.invocationType() == InvocationType.INTRUDER_PAYLOAD_POSITIONS ||
                event.invocationType() == InvocationType.INTRUDER_ATTACK_RESULTS) {
            menuItems.addAll(createIntruderMenuItems(event));
        } else if (event.invocationType() == InvocationType.SITE_MAP_TABLE ||
                event.invocationType() == InvocationType.SITE_MAP_TREE) {
            menuItems.addAll(createTargetMenuItems(event));
        } else if (event.messageEditorRequestResponse().isPresent()) {
            menuItems.addAll(createMessageEditorMenuItems(event));
        }

        return menuItems;
    }

    private List<Component> createProxyHistoryMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();
        List<HttpRequestResponse> selectedItems = event.selectedRequestResponses();
        if (!selectedItems.isEmpty()) {
            JMenuItem item = new JMenuItem("Send to Autowasp (Proxy)");
            item.addActionListener(e -> {
                String comments = getAnnotationsComment(selectedItems.get(0));
                logToAutowasp("Sent from Proxy History", comments, selectedItems);
            });
            items.add(item);
        }
        return items;
    }

    private List<Component> createIntruderMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();
        List<HttpRequestResponse> selectedItems = event.selectedRequestResponses();
        if (!selectedItems.isEmpty()) {
            JMenuItem item = new JMenuItem("Send to Autowasp (Intruder)");
            item.addActionListener(e -> {
                String comments = getAnnotationsComment(selectedItems.get(0));
                logToAutowasp("Sent from Intruder", comments, selectedItems);
            });
            items.add(item);
        }
        return items;
    }

    private List<Component> createTargetMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();
        List<HttpRequestResponse> selectedItems = event.selectedRequestResponses();
        if (!selectedItems.isEmpty()) {
            JMenuItem item = new JMenuItem("Send to Autowasp (Target)");
            item.addActionListener(e -> {
                String comments = getAnnotationsComment(selectedItems.get(0));
                logToAutowasp("Sent from Target", comments, selectedItems);
            });
            items.add(item);
        }
        return items;
    }

    private List<Component> createMessageEditorMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();
        JMenuItem item = new JMenuItem("Send to Autowasp");
        item.addActionListener(e -> {
            burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse editorReqResp = event
                    .messageEditorRequestResponse().get();
            logEditorRequestToAutowasp("Sent from Message Editor", editorReqResp);
        });
        items.add(item);
        return items;
    }

    /**
     * Get comment from annotations
     * Montoya API uses annotations() to get notes
     */
    private String getAnnotationsComment(HttpRequestResponse requestResponse) {
        if (requestResponse.annotations() != null &&
                requestResponse.annotations().notes() != null) {
            return requestResponse.annotations().notes();
        }
        return "";
    }

    /**
     * Log finding ke Autowasp logger
     */
    private void logToAutowasp(String action, String comments, List<HttpRequestResponse> selectedItems) {
        // Get host from first request
        HttpRequestResponse firstItem = selectedItems.get(0);
        String host = firstItem.request().httpService().host();

        String vulnType = "~";
        String issue = "";
        LoggerEntry findingEntry = new LoggerEntry(host, action, vulnType, issue, comments);
        String confidence = "";
        String severity = "~";

        for (HttpRequestResponse httpRequestResponse : selectedItems) {
            try {
                // Create URL from request
                URL url = java.net.URI.create(httpRequestResponse.request().url()).toURL();
                extender.issueAlert(URL_PREFIX + url.toString());

                // Create instance entry with data from Montoya API
                InstanceEntry instanceEntry = new InstanceEntry(
                        url,
                        confidence,
                        severity,
                        httpRequestResponse);
                findingEntry.addInstance(instanceEntry);
            } catch (Exception e) {
                extender.logError(ERROR_PARSING_URL + e.getMessage());
            }
        }

        extender.getLoggerManager().getLoggerTableModel().addAllLoggerEntry(findingEntry);
    }

    /**
     * Log request/response from message editor (Repeater, etc.) to Autowasp logger
     */
    private void logEditorRequestToAutowasp(String action,
            burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse editorReqResp) {
        // Get the request from the editor
        burp.api.montoya.http.message.requests.HttpRequest request = editorReqResp.requestResponse().request();
        String host = request.httpService().host();
        String vulnType = "~";
        String issue = "";
        LoggerEntry findingEntry = new LoggerEntry(host, action, vulnType, issue, "");
        String confidence = "";
        String severity = "~";

        try {
            URL url = java.net.URI.create(request.url()).toURL();
            extender.issueAlert(URL_PREFIX + url.toString());

            // Use the full HttpRequestResponse from the editor
            HttpRequestResponse requestResponse = editorReqResp.requestResponse();

            InstanceEntry instanceEntry = new InstanceEntry(
                    url,
                    confidence,
                    severity,
                    requestResponse);
            findingEntry.addInstance(instanceEntry);
        } catch (Exception e) {
            extender.logError(ERROR_PARSING_URL + e.getMessage());
        }

        extender.getLoggerManager().getLoggerTableModel().addAllLoggerEntry(findingEntry);
    }
}
