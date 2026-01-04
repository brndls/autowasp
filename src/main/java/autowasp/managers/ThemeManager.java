package autowasp.managers;

import burp.api.montoya.MontoyaApi;
import java.awt.Color;
import java.awt.Font;
import java.awt.Component;
import javax.swing.UIManager;

/**
 * Manages the application theme (Light/Dark mode) and provides color palettes.
 */
public class ThemeManager {

    private final MontoyaApi api;
    private Boolean isDarkMode;

    // Light Mode Colors
    private static final Color LIGHT_BACKGROUND = new Color(255, 255, 255);
    private static final Color LIGHT_FOREGROUND = new Color(0, 0, 0);
    private static final Color LIGHT_TABLE_HEADER = new Color(240, 240, 240);
    private static final Color LIGHT_TABLE_SELECTION = new Color(184, 207, 229);

    // Dark Mode Colors (Darcula/IntelliJ style)
    private static final Color DARK_BACKGROUND = new Color(43, 43, 43);
    private static final Color DARK_FOREGROUND = new Color(187, 187, 187);
    private static final Color DARK_TABLE_HEADER = new Color(60, 63, 65);
    private static final Color DARK_TABLE_SELECTION = new Color(75, 110, 175);

    // Shared Colors
    private static final Color SUCCESS_COLOR = new Color(98, 151, 85);
    private static final Color WARNING_COLOR = new Color(204, 120, 50);
    private static final Color ERROR_COLOR = new Color(255, 107, 104);

    public ThemeManager(MontoyaApi api) {
        this.api = api;
        detectTheme();
    }

    /**
     * Detects the current Burp Suite theme.
     * Uses a heuristic approach by checking the background color of standard
     * UIManager properties.
     */
    private void detectTheme() {
        // Method 1: Check UIManager "Control" color luminance
        Color controlColor = UIManager.getColor("Control");
        if (controlColor != null) {
            isDarkMode = calculateLuminance(controlColor) < 0.5;
            return;
        }

        // Method 2: Fallback to Panel.background
        Color panelColor = UIManager.getColor("Panel.background");
        if (panelColor != null) {
            isDarkMode = calculateLuminance(panelColor) < 0.5;
            return;
        }

        // Default to light mode if detection fails
        isDarkMode = false;
    }

    /**
     * Calculates the luminance of a color.
     * Returns a value between 0.0 (dark) and 1.0 (light).
     */
    private double calculateLuminance(Color color) {
        return (0.299 * color.getRed() + 0.587 * color.getGreen() + 0.114 * color.getBlue()) / 255.0;
    }

    public boolean isDarkMode() {
        if (isDarkMode == null) {
            detectTheme();
        }
        return isDarkMode;
    }

    public Color getBackgroundColor() {
        return isDarkMode() ? DARK_BACKGROUND : LIGHT_BACKGROUND;
    }

    public Color getForegroundColor() {
        return isDarkMode() ? DARK_FOREGROUND : LIGHT_FOREGROUND;
    }

    public Color getTableHeaderColor() {
        return isDarkMode() ? DARK_TABLE_HEADER : LIGHT_TABLE_HEADER;
    }

    public Color getTableSelectionColor() {
        return isDarkMode() ? DARK_TABLE_SELECTION : LIGHT_TABLE_SELECTION;
    }

    public Color getSuccessColor() {
        return SUCCESS_COLOR;
    }

    public Color getWarningColor() {
        return WARNING_COLOR;
    }

    public Color getErrorColor() {
        return ERROR_COLOR;
    }

    public Font getDefaultFont() {
        return UIManager.getFont("Label.font");
    }

    public Font getMonospaceFont() {
        return new Font("Monospaced", Font.PLAIN, getDefaultFont().getSize());
    }

    /**
     * Force refresh/redetect theme
     */
    public void refreshTheme() {
        detectTheme();
    }
}
