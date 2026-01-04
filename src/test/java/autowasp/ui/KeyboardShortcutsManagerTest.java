package autowasp.ui;

import autowasp.Autowasp;
import autowasp.ExtenderPanelUI;
import autowasp.managers.LoggerManager;
import autowasp.managers.UIManager;
import autowasp.logger.entrytable.LoggerTable;
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

    @BeforeEach
    void setUp() {
        extender = mock(Autowasp.class);
        uiManager = mock(UIManager.class);
        extenderPanelUI = mock(ExtenderPanelUI.class);

        when(extender.getUIManager()).thenReturn(uiManager);
        when(uiManager.getExtenderPanelUI()).thenReturn(extenderPanelUI);

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
        // Mock requirements for actions
        LoggerManager loggerManager = mock(LoggerManager.class);
        LoggerTable loggerTable = mock(LoggerTable.class);
        when(extender.getLoggerManager()).thenReturn(loggerManager);
        when(loggerManager.getLoggerTable()).thenReturn(loggerTable);

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
}
