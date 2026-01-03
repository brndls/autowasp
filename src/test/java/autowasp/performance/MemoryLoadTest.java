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

package autowasp.performance;

import autowasp.http.HTTPRequestResponse;
import autowasp.http.HTTPService;
import autowasp.logger.entrytable.LoggerEntry;
import autowasp.logger.instancestable.InstanceEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Performance test to measure memory usage under load.
 * This test is tagged as "performance" so it can be excluded from regular
 * builds if needed.
 */
@Tag("performance")
class MemoryLoadTest {

    private static final int SMALL_LOAD = 100;
    private static final int MEDIUM_LOAD = 1000;
    private static final int LARGE_LOAD = 5000;
    private static final int STRESS_LOAD = 10000;

    @Test
    void simulateSmallLoad() throws Exception {
        runSimulation(SMALL_LOAD, "Small Load");
    }

    @Test
    void simulateMediumLoad() throws Exception {
        runSimulation(MEDIUM_LOAD, "Medium Load");
    }

    @Test
    void simulateLargeLoad() throws Exception {
        runSimulation(LARGE_LOAD, "Large Load");
    }

    @Test
    void simulateStressLoad() throws Exception {
        runSimulation(STRESS_LOAD, "Stress Load");
    }

    private void runSimulation(int count, String label) throws Exception {
        System.out.println("--- Starting Simulation: " + label + " (" + count + " entries) ---");

        System.gc();
        long beforeMemory = getUsedMemory();

        List<LoggerEntry> loggerList = new ArrayList<>();
        URL url = URI.create("https://example.com/path").toURL();
        HTTPService service = new HTTPService("example.com", 443, true);

        for (int i = 0; i < count; i++) {
            LoggerEntry entry = new LoggerEntry("example.com", "Action " + i, "Vuln " + i, "Issue " + i);

            // Add 1-3 instances per entry
            int instances = (i % 3) + 1;
            for (int j = 0; j < instances; j++) {
                // Simulated unique request/response (approx 10kb total)
                byte[] request = new byte[5000];
                byte[] response = new byte[5000];
                HTTPRequestResponse rr = new HTTPRequestResponse(request, response, service);
                InstanceEntry instance = new InstanceEntry(url, "Certain", "Medium", rr);
                entry.addInstance(instance);
            }
            loggerList.add(entry);

            if (i > 0 && i % 1000 == 0) {
                System.out.println("Added " + i + " entries...");
            }
        }

        System.gc();
        long afterMemory = getUsedMemory();
        long diffMemory = afterMemory - beforeMemory;

        System.out.println("Memory used for " + count + " entries: " + (diffMemory / 1024 / 1024) + " MB");
        System.out.println("Average memory per entry: " + (diffMemory / count / 1024) + " KB");

        // Verify results
        assertEquals(count, loggerList.size());
    }

    private long getUsedMemory() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }
}
