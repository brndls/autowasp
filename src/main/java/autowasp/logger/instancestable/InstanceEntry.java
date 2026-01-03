/*
 * Copyright (c) 2021 Government Technology Agency
 * Copyright (c) 2024-2026 Autowasp Contributors
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
    private static final long serialVersionUID = 1L;
    private int id = 0;
    private final URL url;
    private String confidence;
    private String severity;
    private final HTTPRequestResponse requestResponse;

    /**
     * Constructor from HTTPRequestResponse wrapper (for backward compatibility)
     */
    public InstanceEntry(URL url, String confidence, String severity, HTTPRequestResponse requestResponse) {
        this.id = this.id + 1;
        this.url = url;
        this.confidence = confidence;
        this.severity = severity;
        this.requestResponse = requestResponse;
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

    public String getUrl() {
        return url != null ? url.toString() : "";
    }

    public int getId() {
        return id;
    }

    public URL getUrlObject() {
        return url;
    }
}
