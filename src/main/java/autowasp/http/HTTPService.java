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

package autowasp.http;

import burp.api.montoya.http.HttpService;

import java.io.Serializable;

/**
 * HTTP Service Wrapper - Montoya API
 *
 * Learning Notes - Migration from Legacy API:
 *
 * Legacy API:
 * - implements IHttpService
 * - Methods: getHost(), getPort(), getProtocol()
 *
 * Montoya API:
 * - HttpService is an existing interface from the Montoya API
 * - Java class is now a simple POJO for data storage
 * - No need to implement interface as Montoya HttpService
 * provides direct access
 *
 * Approach:
 * - Store data from Montoya HttpService into local fields
 * - Provide getter methods for data access
 * - Remains Serializable for persistence
 */
public class HTTPService implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String host;
    private final int port;
    private final boolean secure;

    /**
     * Constructor from Montoya HttpService
     */
    public HTTPService(HttpService httpService) {
        this.host = httpService.host();
        this.port = httpService.port();
        this.secure = httpService.secure();
    }

    /**
     * Manual constructor for special cases
     */
    public HTTPService(String host, int port, boolean secure) {
        this.host = host;
        this.port = port;
        this.secure = secure;
    }

    public String getHost() {
        if (host == null) {
            return "";
        }
        return host;
    }

    public int getPort() {
        return port;
    }

    /**
     * In Montoya API, protocol is determined by the secure flag
     * true = https, false = http
     */
    public String getProtocol() {
        return secure ? "https" : "http";
    }

    public boolean isSecure() {
        return secure;
    }

    @Override
    public String toString() {
        return getProtocol() + "://" + getHost() + ":" + getPort();
    }
}
