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

package autowasp.integration;

import autowasp.Autowasp;
import autowasp.managers.ChecklistManager;
import autowasp.managers.LoggerManager;
import autowasp.managers.PersistenceManager;
import autowasp.managers.ReportManager;
import autowasp.managers.UIManager;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.ui.UserInterface;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.stubbing.Answer;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Base class for Integration Tests.
 * Sets up a mocked Montoya API environment and initializes real Managers.
 */
public abstract class IntegrationTestBase {
    protected Autowasp extender;
    protected MontoyaApi api;
    protected Logging logging;
    protected Extension extension;
    protected UserInterface userInterface;
    protected Proxy proxy;
    protected Scanner scanner;
    protected Scope scope;
    protected Persistence persistence;
    protected PersistedObject persistedObject;

    protected ChecklistManager checklistManager;
    protected LoggerManager loggerManager;
    protected UIManager uiManager;
    protected PersistenceManager persistenceManager;
    protected ReportManager reportManager;

    // In-memory store to simulate Burp's extensionData persistence
    protected final Map<String, String> persistenceStore = new HashMap<>();

    @BeforeEach
    void setUp() {
        // Mock API components
        api = mock(MontoyaApi.class);
        logging = mock(Logging.class);
        extension = mock(Extension.class);
        userInterface = mock(UserInterface.class);
        proxy = mock(Proxy.class);
        scanner = mock(Scanner.class);
        scope = mock(Scope.class);
        persistence = mock(Persistence.class);
        persistedObject = mock(PersistedObject.class);

        when(api.logging()).thenReturn(logging);
        when(api.extension()).thenReturn(extension);
        when(api.userInterface()).thenReturn(userInterface);
        when(api.proxy()).thenReturn(proxy);
        when(api.scanner()).thenReturn(scanner);
        when(api.scope()).thenReturn(scope);
        when(api.persistence()).thenReturn(persistence);
        when(persistence.extensionData()).thenReturn(persistedObject);

        // Simulate PersistedObject behavior
        persistenceStore.clear();
        doAnswer((Answer<Void>) invocation -> {
            String key = invocation.getArgument(0);
            String value = invocation.getArgument(1);
            persistenceStore.put(key, value);
            return null;
        }).when(persistedObject).setString(anyString(), anyString());

        when(persistedObject.getString(anyString())).thenAnswer((Answer<String>) invocation -> {
            String key = invocation.getArgument(0);
            return persistenceStore.get(key);
        });

        // Mock Extender (Autowasp main class)
        extender = mock(Autowasp.class);
        when(extender.getApi()).thenReturn(api);
        when(extender.getLogging()).thenReturn(logging);

        // Initialize Real Managers with Mocked Extender
        checklistManager = new ChecklistManager(extender);
        loggerManager = new LoggerManager(extender);
        uiManager = new UIManager(extender);
        persistenceManager = new PersistenceManager(extender);
        reportManager = new ReportManager(extender);

        // Setup manager accessors in mocked extender
        when(extender.getChecklistManager()).thenReturn(checklistManager);
        when(extender.getLoggerManager()).thenReturn(loggerManager);
        when(extender.getUIManager()).thenReturn(uiManager);
        when(extender.getPersistenceManager()).thenReturn(persistenceManager);
        when(extender.getReportManager()).thenReturn(reportManager);

        // Standard Init Sequence
        uiManager.initialize(checklistManager, loggerManager);
        checklistManager.initialize();
        loggerManager.initialize();
        persistenceManager.initialize();
    }
}
