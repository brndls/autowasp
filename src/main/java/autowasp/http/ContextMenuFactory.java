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

        // Dapatkan invocation type (mengganti getInvocationContext())
        InvocationType invocationType = event.invocationType();

        // Dapatkan selected request/responses
        List<HttpRequestResponse> selectedItems = event.selectedRequestResponses();

        if (selectedItems.isEmpty()) {
            return menuItems; // No item selected
        }

        JMenuItem item;

        // Context menu for Proxy History
        if (invocationType == InvocationType.PROXY_HISTORY) {
            item = new JMenuItem("Send proxy finding to Autowasp", null);
            item.addActionListener(e -> {
                String action = "Sent from Proxy History";
                String comments = getAnnotationsComment(selectedItems.get(0));
                logToAutowasp(action, comments, selectedItems);
            });
            menuItems.add(item);
        }
        // Context menu for Repeater - check MESSAGE_EDITOR in Repeater
        else if (invocationType == InvocationType.MESSAGE_EDITOR_REQUEST ||
                invocationType == InvocationType.MESSAGE_VIEWER_REQUEST) {
            item = new JMenuItem("Send repeater finding to Autowasp", null);
            item.addActionListener(e -> {
                String action = "Sent from Repeater";
                String comments = getAnnotationsComment(selectedItems.get(0));
                logToAutowasp(action, comments, selectedItems);
            });
            menuItems.add(item);
        }
        // Context menu for Intruder
        else if (invocationType == InvocationType.INTRUDER_PAYLOAD_POSITIONS ||
                invocationType == InvocationType.INTRUDER_ATTACK_RESULTS) {
            item = new JMenuItem("Send intruder finding to Autowasp", null);
            item.addActionListener(e -> {
                String action = "Sent from Intruder";
                String comments = getAnnotationsComment(selectedItems.get(0));
                logToAutowasp(action, comments, selectedItems);
            });
            menuItems.add(item);
        }

        return menuItems;
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
                extender.issueAlert("URL = " + url.toString());

                // Create instance entry with data from Montoya API
                InstanceEntry instanceEntry = new InstanceEntry(
                        url,
                        confidence,
                        severity,
                        httpRequestResponse);
                findingEntry.addInstance(instanceEntry);
            } catch (Exception e) {
                extender.logError("Error parsing URL: " + e.getMessage());
            }
        }

        extender.getLoggerTableModel().addAllLoggerEntry(findingEntry);
    }
}
