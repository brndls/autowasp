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
import autowasp.logger.entryTable.LoggerEntry;
import autowasp.logger.instancesTable.InstanceEntry;

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
 * Catatan Pembelajaran - Migrasi dari Legacy API:
 * 
 * Legacy API:
 * - implements IContextMenuFactory
 * - createMenuItems(IContextMenuInvocation invocation) -> List<JMenuItem>
 * - Menggunakan byte constants untuk context (CONTEXT_PROXY_HISTORY, dll)
 * 
 * Montoya API:
 * - implements ContextMenuItemsProvider
 * - provideMenuItems(ContextMenuEvent event) -> List<Component>
 * - Menggunakan enum InvocationSource untuk context
 * 
 * Keuntungan Montoya API:
 * 1. Enum lebih type-safe daripada byte constants
 * 2. Method names lebih consistent dengan Java conventions
 * 3. Akses ke requests/responses lebih straightforward
 */
public class ContextMenuFactory implements ContextMenuItemsProvider {

    private final Autowasp extender;

    public ContextMenuFactory(Autowasp autowasp) {
        this.extender = autowasp;
    }

    /**
     * Provide menu items berdasarkan context invocation
     * Menggantikan createMenuItems() dari Legacy API
     */
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        // Dapatkan invocation type (mengganti getInvocationContext())
        InvocationType invocationType = event.invocationType();

        // Dapatkan selected request/responses
        List<HttpRequestResponse> selectedItems = event.selectedRequestResponses();

        if (selectedItems.isEmpty()) {
            return menuItems; // Tidak ada item yang dipilih
        }

        JMenuItem item;

        // Context menu untuk Proxy History
        if (invocationType == InvocationType.PROXY_HISTORY) {
            item = new JMenuItem("Send proxy finding to Autowasp", null);
            item.addActionListener(e -> {
                String action = "Sent from Proxy History";
                String comments = getAnnotationsComment(selectedItems.get(0));
                logToAutowasp(action, comments, selectedItems);
            });
            menuItems.add(item);
        }
        // Context menu untuk Repeater - cek MESSAGE_EDITOR di Repeater
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
        // Context menu untuk Intruder
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
     * Mendapatkan comment dari annotations
     * Montoya API menggunakan annotations() untuk mendapatkan notes
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
        // Dapatkan host dari request pertama
        HttpRequestResponse firstItem = selectedItems.get(0);
        String host = firstItem.request().httpService().host();

        String vulnType = "~";
        String issue = "";
        LoggerEntry findingEntry = new LoggerEntry(host, action, vulnType, issue, comments);
        String confidence = "";
        String severity = "~";

        for (HttpRequestResponse httpRequestResponse : selectedItems) {
            try {
                // Buat URL dari request
                URL url = java.net.URI.create(httpRequestResponse.request().url()).toURL();
                extender.issueAlert("URL = " + url.toString());

                // Buat instance entry dengan data dari Montoya API
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

        extender.loggerTableModel.addAllLoggerEntry(findingEntry);
    }
}
