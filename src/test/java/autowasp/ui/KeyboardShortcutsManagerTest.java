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

package autowasp.ui;

import autowasp.Autowasp;
import autowasp.ExtenderPanelUI;
import autowasp.managers.LoggerManager;
import autowasp.managers.UIManager;
import autowasp.logger.entrytable.LoggerTable;
import autowasp.logger.instancestable.InstanceTable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class KeyboardShortcutsManagerTest {

    private Autowasp extender;
    private KeyboardShortcutsManager shortcutsManager;
    private JPanel mainPanel;
    private UIManager uiManager;
    private ExtenderPanelUI extenderPanelUI;
    private LoggerManager loggerManager;
    private LoggerTable loggerTable;
    private InstanceTable instanceTable;

    @BeforeEach
    void setUp() {
        extender = mock(Autowasp.class);
        uiManager = mock(UIManager.class);
        extenderPanelUI = mock(ExtenderPanelUI.class);
        loggerManager = mock(LoggerManager.class);
        loggerTable = mock(LoggerTable.class);
        instanceTable = mock(InstanceTable.class);

        when(extender.getUIManager()).thenReturn(uiManager);
        when(uiManager.getExtenderPanelUI()).thenReturn(extenderPanelUI);
        when(extender.getLoggerManager()).thenReturn(loggerManager);
        when(loggerManager.getLoggerTable()).thenReturn(loggerTable);
        when(loggerManager.getInstanceTable()).thenReturn(instanceTable);

        shortcutsManager = new KeyboardShortcutsManager(extender);
        mainPanel = new JPanel();
    }

    @Test
    void testRegisterGlobalShortcuts() {
        shortcutsManager.registerGlobalShortcuts(mainPanel);

        InputMap inputMap = mainPanel.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        ActionMap actionMap = mainPanel.getActionMap();

        // Verify shortcuts are registered
        assertNotNull(inputMap.allKeys(), "InputMap keys should not be null");
        assertNotNull(actionMap.allKeys(), "ActionMap keys should not be null");

        // Check for specific shortcut presence
        boolean found = false;
        for (KeyStroke ks : inputMap.allKeys()) {
            if (ks.getKeyCode() == KeyEvent.VK_W &&
                    (ks.getModifiers() & (InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK)) != 0) {
                found = true;
                break;
            }
        }
        assertTrue(found, "Shortcut Ctrl+Shift+W should be registered");
    }

    @Test
    void testActionTrigger() {
        // This test ensures that the ActionMap keys actually map to something
        shortcutsManager.registerGlobalShortcuts(mainPanel);
        ActionMap actionMap = mainPanel.getActionMap();

        assertNotNull(actionMap.get("addToWSTG"), "Action 'addToWSTG' should be present");
        assertNotNull(actionMap.get("deleteItem"), "Action 'deleteItem' should be present");

        // Verify that triggering doesn't throw exceptions
        assertDoesNotThrow(() -> {
            actionMap.get("addToWSTG").actionPerformed(new ActionEvent(mainPanel, ActionEvent.ACTION_PERFORMED, ""));
        });
    }

    @Test
    void testAllShortcutsRegistered() {
        shortcutsManager.registerGlobalShortcuts(mainPanel);
        ActionMap actionMap = mainPanel.getActionMap();

        // Verify all expected actions are registered
        assertNotNull(actionMap.get("addToWSTG"));
        assertNotNull(actionMap.get("markAsFinding"));
        assertNotNull(actionMap.get("generateEvidence"));
        assertNotNull(actionMap.get("quickNote"));
        assertNotNull(actionMap.get("focusSearch"));
        assertNotNull(actionMap.get("deleteItem"));
        assertNotNull(actionMap.get("deleteItemBackspace"));
    }

    @Test
    void testAddToWSTGActionWithFocus() {
        when(loggerTable.hasFocus()).thenReturn(true);
        when(loggerTable.getSelectedRow()).thenReturn(0);

        shortcutsManager.registerGlobalShortcuts(mainPanel);
        ActionMap actionMap = mainPanel.getActionMap();

        assertDoesNotThrow(() -> {
            actionMap.get("addToWSTG").actionPerformed(new ActionEvent(mainPanel, ActionEvent.ACTION_PERFORMED, ""));
        });

        verify(loggerTable).editCellAt(0, 4);
    }

    @Test
    void testAddToWSTGActionWithoutFocus() {
        when(loggerTable.hasFocus()).thenReturn(false);
        when(loggerTable.isFocusOwner()).thenReturn(false);

        shortcutsManager.registerGlobalShortcuts(mainPanel);
        ActionMap actionMap = mainPanel.getActionMap();

        assertDoesNotThrow(() -> {
            actionMap.get("addToWSTG").actionPerformed(new ActionEvent(mainPanel, ActionEvent.ACTION_PERFORMED, ""));
        });

        verify(loggerTable, never()).editCellAt(anyInt(), anyInt());
    }

    @Test
    void testAddToWSTGActionNoSelection() {
        when(loggerTable.hasFocus()).thenReturn(true);
        when(loggerTable.getSelectedRow()).thenReturn(-1);

        shortcutsManager.registerGlobalShortcuts(mainPanel);
        ActionMap actionMap = mainPanel.getActionMap();

        assertDoesNotThrow(() -> {
            actionMap.get("addToWSTG").actionPerformed(new ActionEvent(mainPanel, ActionEvent.ACTION_PERFORMED, ""));
        });

        verify(loggerTable, never()).editCellAt(anyInt(), anyInt());
    }

    @Test
    void testMarkAsFindingActionWithFocus() {
        when(instanceTable.hasFocus()).thenReturn(true);
        when(instanceTable.getSelectedRow()).thenReturn(0);

        shortcutsManager.registerGlobalShortcuts(mainPanel);
        ActionMap actionMap = mainPanel.getActionMap();

        assertDoesNotThrow(() -> {
            actionMap.get("markAsFinding")
                    .actionPerformed(new ActionEvent(mainPanel, ActionEvent.ACTION_PERFORMED, ""));
        });

        verify(instanceTable).editCellAt(0, 2);
    }

    @Test
    void testMarkAsFindingActionWithoutFocus() {
        when(instanceTable.hasFocus()).thenReturn(false);

        shortcutsManager.registerGlobalShortcuts(mainPanel);
        ActionMap actionMap = mainPanel.getActionMap();

        assertDoesNotThrow(() -> {
            actionMap.get("markAsFinding")
                    .actionPerformed(new ActionEvent(mainPanel, ActionEvent.ACTION_PERFORMED, ""));
        });

        verify(instanceTable, never()).editCellAt(anyInt(), anyInt());
    }

    @Test
    void testGenerateEvidenceAction() {
        JTextPane evidenceBox = new JTextPane();
        when(extenderPanelUI.getEvidenceBox()).thenReturn(evidenceBox);

        shortcutsManager.registerGlobalShortcuts(mainPanel);
        ActionMap actionMap = mainPanel.getActionMap();

        assertDoesNotThrow(() -> {
            actionMap.get("generateEvidence")
                    .actionPerformed(new ActionEvent(mainPanel, ActionEvent.ACTION_PERFORMED, ""));
        });

        verify(extenderPanelUI).getEvidenceBox();
    }

    @Test
    void testQuickNoteAction() {
        JTextPane commentBox = new JTextPane();
        when(extenderPanelUI.getPenTesterCommentBox()).thenReturn(commentBox);

        shortcutsManager.registerGlobalShortcuts(mainPanel);
        ActionMap actionMap = mainPanel.getActionMap();

        assertDoesNotThrow(() -> {
            actionMap.get("quickNote").actionPerformed(new ActionEvent(mainPanel, ActionEvent.ACTION_PERFORMED, ""));
        });

        verify(extenderPanelUI).getPenTesterCommentBox();
    }

    @Test
    void testFocusSearchActionChecklistTab() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Checklist", new JPanel());
        JTextField checklistSearch = new JTextField();

        when(extenderPanelUI.getBottomModulesTabs()).thenReturn(tabs);
        when(extenderPanelUI.getChecklistSearchField()).thenReturn(checklistSearch);

        shortcutsManager.registerGlobalShortcuts(mainPanel);
        ActionMap actionMap = mainPanel.getActionMap();

        assertDoesNotThrow(() -> {
            actionMap.get("focusSearch").actionPerformed(new ActionEvent(mainPanel, ActionEvent.ACTION_PERFORMED, ""));
        });

        verify(extenderPanelUI, atLeastOnce()).getChecklistSearchField();
    }

    @Test
    void testFocusSearchActionLoggerTab() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Logger", new JPanel());
        JTextField loggerSearch = new JTextField();

        when(extenderPanelUI.getBottomModulesTabs()).thenReturn(tabs);
        when(extenderPanelUI.getLoggerSearchField()).thenReturn(loggerSearch);

        shortcutsManager.registerGlobalShortcuts(mainPanel);
        ActionMap actionMap = mainPanel.getActionMap();

        assertDoesNotThrow(() -> {
            actionMap.get("focusSearch").actionPerformed(new ActionEvent(mainPanel, ActionEvent.ACTION_PERFORMED, ""));
        });

        verify(extenderPanelUI, atLeastOnce()).getLoggerSearchField();
    }

    @Test
    void testFocusSearchActionNullTabs() {
        when(extenderPanelUI.getBottomModulesTabs()).thenReturn(null);

        shortcutsManager.registerGlobalShortcuts(mainPanel);
        ActionMap actionMap = mainPanel.getActionMap();

        assertDoesNotThrow(() -> {
            actionMap.get("focusSearch").actionPerformed(new ActionEvent(mainPanel, ActionEvent.ACTION_PERFORMED, ""));
        });
    }

    @Test
    void testDeleteItemActionLoggerFocus() {
        when(loggerTable.hasFocus()).thenReturn(true);
        when(instanceTable.hasFocus()).thenReturn(false);

        shortcutsManager.registerGlobalShortcuts(mainPanel);
        ActionMap actionMap = mainPanel.getActionMap();

        assertDoesNotThrow(() -> {
            actionMap.get("deleteItem").actionPerformed(new ActionEvent(mainPanel, ActionEvent.ACTION_PERFORMED, ""));
        });

        verify(loggerTable).deleteEntry();
        verify(instanceTable, never()).deleteInstance();
    }

    @Test
    void testDeleteItemActionInstanceFocus() {
        when(loggerTable.hasFocus()).thenReturn(false);
        when(instanceTable.hasFocus()).thenReturn(true);

        shortcutsManager.registerGlobalShortcuts(mainPanel);
        ActionMap actionMap = mainPanel.getActionMap();

        assertDoesNotThrow(() -> {
            actionMap.get("deleteItem").actionPerformed(new ActionEvent(mainPanel, ActionEvent.ACTION_PERFORMED, ""));
        });

        verify(instanceTable).deleteInstance();
        verify(loggerTable, never()).deleteEntry();
    }

    @Test
    void testDeleteItemActionNoFocus() {
        when(loggerTable.hasFocus()).thenReturn(false);
        when(instanceTable.hasFocus()).thenReturn(false);

        shortcutsManager.registerGlobalShortcuts(mainPanel);
        ActionMap actionMap = mainPanel.getActionMap();

        assertDoesNotThrow(() -> {
            actionMap.get("deleteItem").actionPerformed(new ActionEvent(mainPanel, ActionEvent.ACTION_PERFORMED, ""));
        });

        verify(loggerTable, never()).deleteEntry();
        verify(instanceTable, never()).deleteInstance();
    }

    @Test
    void testDeleteItemBackspaceAction() {
        when(loggerTable.hasFocus()).thenReturn(true);

        shortcutsManager.registerGlobalShortcuts(mainPanel);
        ActionMap actionMap = mainPanel.getActionMap();

        assertDoesNotThrow(() -> {
            actionMap.get("deleteItemBackspace")
                    .actionPerformed(new ActionEvent(mainPanel, ActionEvent.ACTION_PERFORMED, ""));
        });

        verify(loggerTable).deleteEntry();
    }

    @Test
    void testKeyStrokeCtrlShiftW() {
        shortcutsManager.registerGlobalShortcuts(mainPanel);
        InputMap inputMap = mainPanel.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);

        KeyStroke expected = KeyStroke.getKeyStroke(KeyEvent.VK_W,
                InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK);
        assertEquals("addToWSTG", inputMap.get(expected));
    }

    @Test
    void testKeyStrokeCtrlShiftF() {
        shortcutsManager.registerGlobalShortcuts(mainPanel);
        InputMap inputMap = mainPanel.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);

        KeyStroke expected = KeyStroke.getKeyStroke(KeyEvent.VK_F,
                InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK);
        assertEquals("markAsFinding", inputMap.get(expected));
    }

    @Test
    void testKeyStrokeDelete() {
        shortcutsManager.registerGlobalShortcuts(mainPanel);
        InputMap inputMap = mainPanel.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);

        KeyStroke expected = KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0);
        assertEquals("deleteItem", inputMap.get(expected));
    }
}
