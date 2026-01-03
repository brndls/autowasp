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
