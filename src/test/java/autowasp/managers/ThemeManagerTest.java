package autowasp.managers;

import org.junit.jupiter.api.Test;

import javax.swing.UIManager;
import java.awt.Color;

import static org.junit.jupiter.api.Assertions.*;

class ThemeManagerTest {

    private ThemeManager themeManager;

    @Test
    void testIsDarkMode_WithDarkBackground_ReturnsTrue() {
        // Mock UIManager color for dark mode simulation
        // Note: javax.swing.UIManager is static, so we can't easily mock it without
        // additional tools.
        // However, ThemeManager uses UIManager.getColor("Control").
        // We can set UIManager properties for the test.

        Color originalControl = UIManager.getColor("Control");
        try {
            UIManager.put("Control", new Color(43, 43, 43)); // Dark color
            themeManager = new ThemeManager();
            assertTrue(themeManager.isDarkMode());
            assertEquals(new Color(43, 43, 43), themeManager.getBackgroundColor());
        } finally {
            UIManager.put("Control", originalControl);
        }
    }

    @Test
    void testIsDarkMode_WithLightBackground_ReturnsFalse() {
        Color originalControl = UIManager.getColor("Control");
        try {
            UIManager.put("Control", new Color(240, 240, 240)); // Light color
            themeManager = new ThemeManager();
            assertFalse(themeManager.isDarkMode());
            assertEquals(new Color(255, 255, 255), themeManager.getBackgroundColor());
        } finally {
            UIManager.put("Control", originalControl);
        }
    }

    @Test
    void testColorPalette_ConsistencyCheck() {
        // Test light mode palette
        Color originalControl = UIManager.getColor("Control");
        try {
            UIManager.put("Control", new Color(240, 240, 240));
            themeManager = new ThemeManager();

            assertNotNull(themeManager.getBackgroundColor());
            assertNotNull(themeManager.getForegroundColor());
            assertNotNull(themeManager.getTableHeaderColor());
            assertNotNull(themeManager.getTableSelectionColor());
            assertNotNull(themeManager.getSuccessColor());
            assertNotNull(themeManager.getWarningColor());
            assertNotNull(themeManager.getErrorColor());
            assertNotNull(themeManager.getDefaultFont());
            assertNotNull(themeManager.getMonospaceFont());

        } finally {
            UIManager.put("Control", originalControl);
        }
    }
}
