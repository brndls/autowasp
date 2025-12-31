/*
 * Copyright (c) 2021 Government Technology Agency
 * Copyright (c) 2024 Autowasp Contributors
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

package autowasp.logger.instancesTable;

import autowasp.http.HTTPRequestResponse;

// Montoya API imports
import burp.api.montoya.http.message.HttpRequestResponse;

import java.io.Serializable;
import java.net.URL;

/**
 * Instance Entry - Montoya API
 *
 * Learning Notes - Migration from Legacy API:
 *
 * Legacy API:
 * - IHttpRequestResponse to store request/response
 *
 * Montoya API:
 * - HttpRequestResponse for request/response
 * - Wrapper class is needed to maintain existing table structure
 * which is more portable for serialization
 */
public class InstanceEntry implements Serializable {
    public int id = 0;
    public final URL url;
    public String confidence;
    public String severity;
    public final HTTPRequestResponse requestResponse;
    final boolean falsePositive;

    /**
     * Constructor from HTTPRequestResponse wrapper (for backward compatibility)
     */
    public InstanceEntry(URL url, String confidence, String severity, HTTPRequestResponse requestResponse) {
        this.id = this.id + 1;
        this.url = url;
        this.confidence = confidence;
        this.severity = severity;
        this.requestResponse = requestResponse;
        this.falsePositive = false;
    }

    /**
     * Constructor from Montoya HttpRequestResponse
     */
    public InstanceEntry(URL url, String confidence, String severity, HttpRequestResponse montoyaRequestResponse) {
        this.id = this.id + 1;
        this.url = url;
        this.confidence = confidence;
        this.severity = severity;
        // Konversi ke HTTPRequestResponse wrapper
        this.requestResponse = montoyaRequestResponse != null ? new HTTPRequestResponse(montoyaRequestResponse) : null;
        this.falsePositive = false;
    }

    public void setConfidence(String confidence) {
        this.confidence = confidence;
    }

    public String getConfidence() {
        return this.confidence;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getSeverity() {
        return severity;
    }

    /**
     * Mendapatkan request/response wrapper
     * Replaces getResReq() which returns IHttpRequestResponse
     */
    public HTTPRequestResponse getRequestResponse() {
        return this.requestResponse;
    }

    /**
     * Old getter for backward compatibility
     *
     * @deprecated Use getRequestResponse() for Montoya API
     */
    @Deprecated
    public HTTPRequestResponse getResReq() {
        return this.requestResponse;
    }

    public boolean isRequestResponseNull() {
        return this.requestResponse == null;
    }

    public String getUrl() {
        return url != null ? url.toString() : "";
    }
}
