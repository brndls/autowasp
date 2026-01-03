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

package autowasp.utils;

/**
 * Common constants to reduce memory footprint by avoiding duplicate string
 * literals.
 */
public class AutowaspConstants {
    // Severity
    public static final String SEVERITY_HIGH = "High";
    public static final String SEVERITY_MEDIUM = "Medium";
    public static final String SEVERITY_LOW = "Low";
    public static final String SEVERITY_INFO = "Information";

    // Confidence
    public static final String CONFIDENCE_CERTAIN = "Certain";
    public static final String CONFIDENCE_FIRM = "Firm";
    public static final String CONFIDENCE_TENTATIVE = "Tentative";

    // Actions
    public static final String ACTION_BURP_SCANNER = "Burp Scanner";
    public static final String ACTION_MANUAL = "Manual";

    private AutowaspConstants() {
        // Private constructor to prevent instantiation
    }
}
