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

package autowasp.checklist;

import java.awt.Color;

/**
 * Represents the testing status of a WSTG checklist item.
 */
public enum ChecklistStatus {
    TODO("Todo", Color.GRAY),
    DONE("Done", new Color(0, 153, 0)), // Darker green for better visibility
    FAIL("Fail", new Color(204, 0, 0)), // Darker red
    NA("N/A", new Color(204, 153, 0)); // Darker yellow/orange

    private final String displayValue;
    private final Color color;

    ChecklistStatus(String displayValue, Color color) {
        this.displayValue = displayValue;
        this.color = color;
    }

    public String getDisplayValue() {
        return displayValue;
    }

    public Color getColor() {
        return color;
    }

    @Override
    public String toString() {
        return displayValue;
    }
}
