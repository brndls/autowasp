package autowasp.managers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.UserInterface;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.swing.UIManager;
import java.awt.Color;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class ThemeManagerTest {

    @Mock
    private MontoyaApi api;
    @Mock
    private UserInterface userInterface;

    private ThemeManager themeManager;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(api.userInterface()).thenReturn(userInterface);
    }

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
            themeManager = new ThemeManager(api);
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
            themeManager = new ThemeManager(api);
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
            themeManager = new ThemeManager(api);

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
