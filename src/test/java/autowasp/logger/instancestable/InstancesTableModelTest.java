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

package autowasp.logger.instancestable;

import autowasp.http.HTTPRequestResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class InstancesTableModelTest {

    private InstancesTableModel model;
    private List<InstanceEntry> list;

    @BeforeEach
    void setUp() {
        list = new ArrayList<>();
        model = new InstancesTableModel(list);
    }

    @Test
    void testInstanceLimitEnforcement() {
        List<InstanceEntry> newInstances = new ArrayList<>();
        for (int i = 0; i < 1500; i++) {
            newInstances.add(new InstanceEntry(null, "C", "S", (HTTPRequestResponse) null));
        }

        model.addAllInstanceEntry(newInstances);

        // Should be capped at 1000
        assertEquals(1000, model.getRowCount());
        assertEquals(1000, list.size());
    }

    @Test
    void testClearList() {
        list.add(new InstanceEntry(null, "C", "S", (HTTPRequestResponse) null));
        assertEquals(1, model.getRowCount());

        model.clearInstanceEntryList();
        assertEquals(0, model.getRowCount());
        assertEquals(0, list.size());
    }
}
