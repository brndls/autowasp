package autowasp.ui;

import autowasp.Autowasp;
import autowasp.ExtenderPanelUI;
import autowasp.logger.entrytable.LoggerTable;
import autowasp.logger.instancestable.InstanceTable;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

/**
 * Manages keyboard shortcuts for the application.
 */
public class KeyboardShortcutsManager {

    private final Autowasp extender;

    public KeyboardShortcutsManager(Autowasp extender) {
        this.extender = extender;
    }

    /**
     * Registers global shortcuts on the main panel.
     * Use WHEN_ANCESTOR_OF_FOCUSED_COMPONENT to ensure they work when any child has
     * focus.
     */
    public void registerGlobalShortcuts(JComponent mainPanel) {
        InputMap inputMap = mainPanel.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        ActionMap actionMap = mainPanel.getActionMap();

        // Ctrl+Shift+W - Add to WSTG Checklist
        registerShortcut(inputMap, actionMap,
                KeyStroke.getKeyStroke(KeyEvent.VK_W, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK),
                "addToWSTG", this::addToWSTGAction);

        // Ctrl+Shift+F - Mark as Finding
        registerShortcut(inputMap, actionMap,
                KeyStroke.getKeyStroke(KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK),
                "markAsFinding", this::markAsFindingAction);

        // Ctrl+Shift+E - Generate Evidence
        registerShortcut(inputMap, actionMap,
                KeyStroke.getKeyStroke(KeyEvent.VK_E, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK),
                "generateEvidence", this::generateEvidenceAction);

        // Ctrl+Shift+N - Quick Note
        registerShortcut(inputMap, actionMap,
                KeyStroke.getKeyStroke(KeyEvent.VK_N, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK),
                "quickNote", this::quickNoteAction);

        // Ctrl+F - Focus Search (Context Aware)
        registerShortcut(inputMap, actionMap,
                KeyStroke.getKeyStroke(KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK),
                "focusSearch", this::focusSearchAction);

        // Delete - Delete Selected Entry/Instance
        registerShortcut(inputMap, actionMap,
                KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0),
                "deleteItem", this::deleteItemAction);

        // Also support Backspace for delete on Mac sometimes, or ensure standard Delete
        // works
        registerShortcut(inputMap, actionMap,
                KeyStroke.getKeyStroke(KeyEvent.VK_BACK_SPACE, 0),
                "deleteItemBackspace", this::deleteItemAction);
    }

    private void registerShortcut(InputMap inputMap, ActionMap actionMap, KeyStroke keyStroke, String name,
            Runnable action) {
        inputMap.put(keyStroke, name);
        actionMap.put(name, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                action.run();
            }
        });
    }

    private void addToWSTGAction() {
        JTable table = extender.getLoggerManager().getLoggerTable();
        if (table.hasFocus() || table.isFocusOwner()) {
            int row = table.getSelectedRow();
            int col = 4; // Issue column
            if (row != -1) {
                table.editCellAt(row, col);
                if (table.getEditorComponent() != null) {
                    table.getEditorComponent().requestFocusInWindow();
                }
            }
        }
    }

    private void markAsFindingAction() {
        JTable instanceTable = extender.getLoggerManager().getInstanceTable();
        if (instanceTable.hasFocus()) {
            int row = instanceTable.getSelectedRow();
            int col = 2; // Confidence column
            if (row != -1) {
                instanceTable.editCellAt(row, col);
                if (instanceTable.getEditorComponent() != null) {
                    instanceTable.getEditorComponent().requestFocusInWindow();
                }
            }
        }
    }

    private void generateEvidenceAction() {
        extender.getUIManager().getExtenderPanelUI().getEvidenceBox().requestFocusInWindow();
    }

    private void quickNoteAction() {
        extender.getUIManager().getExtenderPanelUI().getPenTesterCommentBox().requestFocusInWindow();
    }

    private void focusSearchAction() {
        // Focus the appropriate search field based on active tab
        ExtenderPanelUI ui = extender.getUIManager().getExtenderPanelUI();
        JTabbedPane tabs = ui.getBottomModulesTabs();

        if (tabs != null) {
            int selectedIndex = tabs.getSelectedIndex();
            String title = tabs.getTitleAt(selectedIndex);

            if (title != null && title.contains("Checklist") && ui.getChecklistSearchField() != null) {
                ui.getChecklistSearchField().requestFocusInWindow();
            } else if (title != null && title.contains("Logger") && ui.getLoggerSearchField() != null) {
                ui.getLoggerSearchField().requestFocusInWindow();
            }
        }
    }

    private void deleteItemAction() {
        LoggerTable loggerTable = extender.getLoggerManager().getLoggerTable();
        InstanceTable instanceTable = extender.getLoggerManager().getInstanceTable();

        if (loggerTable.hasFocus()) {
            loggerTable.deleteEntry();
        } else if (instanceTable.hasFocus()) {
            instanceTable.deleteInstance();
        }
    }
}
