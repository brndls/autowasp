/*
 * Copyright (c) 2026 Autowasp Contributors
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
import autowasp.managers.UIManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumnModel;
import java.awt.Color;
import java.awt.Component;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AbstractAutowaspTableTest {

    @Mock
    private Autowasp mockExtender;

    @Mock
    private UIManager mockUIManager;

    @Mock
    private autowasp.managers.ThemeManager mockThemeManager;

    private DefaultTableModel tableModel;
    private ConcreteAutowaspTable table;

    // Concrete implementation for testing
    private static class ConcreteAutowaspTable extends AbstractAutowaspTable {
        private static final long serialVersionUID = 1L;

        ConcreteAutowaspTable(javax.swing.table.TableModel tableModel, Autowasp extender) {
            super(tableModel, extender);
        }
    }

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        // Setup mock chain
        when(mockExtender.getUIManager()).thenReturn(mockUIManager);
        when(mockUIManager.getThemeManager()).thenReturn(mockThemeManager);

        // Create table model with some data
        tableModel = new DefaultTableModel(new Object[][] { { "Row 1" }, { "Row 2" }, { "Row 3" } },
                new Object[] { "Column 1" });

        table = new ConcreteAutowaspTable(tableModel, mockExtender);
    }

    @Test
    void shouldApplyThemeOnConstruction() {
        verify(mockThemeManager).applyThemeToTable(table);
    }

    @Test
    void shouldStoreExtenderReference() {
        assertNotNull(table.extender);
        assertEquals(mockExtender, table.extender);
    }

    @Test
    void shouldUseProvidedTableModel() {
        assertEquals(tableModel, table.getModel());
        assertEquals(3, table.getRowCount());
        assertEquals(1, table.getColumnCount());
    }

    @Test
    void shouldApplyAlternateRowColorForEvenRows() {
        // Setup
        Color alternateColor = new Color(240, 240, 240);
        when(mockThemeManager.getAlternateRowColor()).thenReturn(alternateColor);

        // Execute - render row 0 (even)
        Component component = table.prepareRenderer(table.getDefaultRenderer(Object.class), 0, 0);

        // Verify - even rows use default background
        assertEquals(table.getBackground(), component.getBackground());
    }

    @Test
    void shouldApplyAlternateRowColorForOddRows() {
        // Setup
        Color alternateColor = new Color(240, 240, 240);
        when(mockThemeManager.getAlternateRowColor()).thenReturn(alternateColor);

        // Execute - render row 1 (odd)
        Component component = table.prepareRenderer(table.getDefaultRenderer(Object.class), 1, 0);

        // Verify - odd rows use alternate color
        assertEquals(alternateColor, component.getBackground());
    }

    @Test
    void shouldNotChangeBackgroundForSelectedRows() {
        // Setup
        Color alternateColor = new Color(240, 240, 240);
        when(mockThemeManager.getAlternateRowColor()).thenReturn(alternateColor);

        // Select row 1
        table.setRowSelectionInterval(1, 1);

        // Execute - render selected row
        Component component = table.prepareRenderer(table.getDefaultRenderer(Object.class), 1, 0);

        // Verify - selected row keeps selection background (not alternate color)
        assertNotEquals(alternateColor, component.getBackground());
    }

    @Test
    void shouldSetColumnWidthsCorrectly() {
        // Setup - add more columns
        tableModel.addColumn("Column 2");
        tableModel.addColumn("Column 3");

        // Execute
        table.setColumnWidths(100, 200, 150, 300, 200, 400);

        // Verify
        TableColumnModel columnModel = table.getColumnModel();
        assertEquals(100, columnModel.getColumn(0).getPreferredWidth());
        assertEquals(200, columnModel.getColumn(0).getMaxWidth());
        assertEquals(150, columnModel.getColumn(1).getPreferredWidth());
        assertEquals(300, columnModel.getColumn(1).getMaxWidth());
        assertEquals(200, columnModel.getColumn(2).getPreferredWidth());
        assertEquals(400, columnModel.getColumn(2).getMaxWidth());
    }

    @Test
    void shouldHandlePartialColumnWidthsGracefully() {
        // Setup - only 1 column exists
        // Execute - try to set widths for 2 columns
        table.setColumnWidths(100, 200, 150, 300);

        // Verify - only first column is set, no exception thrown
        TableColumnModel columnModel = table.getColumnModel();
        assertEquals(100, columnModel.getColumn(0).getPreferredWidth());
        assertEquals(200, columnModel.getColumn(0).getMaxWidth());
    }

    @Test
    void shouldHandleEmptyColumnWidthsArray() {
        // Execute - empty array
        assertDoesNotThrow(() -> table.setColumnWidths());
    }

    @Test
    void shouldHandleOddNumberOfWidthsGracefully() {
        // Execute - odd number of widths (missing max width for last column)
        assertDoesNotThrow(() -> table.setColumnWidths(100, 200, 150));
    }
}
