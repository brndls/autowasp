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

package autowasp.http;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.io.Serializable;
import autowasp.utils.CompressionUtils;

/**
 * HTTP Request/Response Wrapper - Montoya API
 *
 * Purpose: Serializable wrapper for HttpRequestResponse data.
 * Needed because Montoya's HttpRequestResponse is not serializable,
 * and we need to persist request/response data for project save/load.
 */
public class HTTPRequestResponse implements Serializable {

    private static final long serialVersionUID = 1L;

    private final byte[] requestBytes;
    private final byte[] responseBytes;
    private final String comment;
    private final String highlight;
    private final HTTPService httpService;

    /**
     * Constructor from Montoya HttpRequestResponse
     */
    public HTTPRequestResponse(HttpRequestResponse requestResponse) {
        // Extract request bytes
        HttpRequest request = requestResponse.request();
        if (request != null) {
            this.requestBytes = CompressionUtils.compress(request.toByteArray().getBytes());
            this.httpService = new HTTPService(request.httpService());
        } else {
            this.requestBytes = new byte[] {};
            this.httpService = null;
        }

        // Extract response bytes
        HttpResponse response = requestResponse.response();
        if (response != null) {
            this.responseBytes = CompressionUtils.compress(response.toByteArray().getBytes());
        } else {
            this.responseBytes = new byte[] {};
        }

        // Extract annotations
        if (requestResponse.annotations() != null) {
            this.comment = requestResponse.annotations().notes();
            this.highlight = requestResponse.annotations().highlightColor() != null
                    ? requestResponse.annotations().highlightColor().toString()
                    : "";
        } else {
            this.comment = "";
            this.highlight = "";
        }
    }

    /**
     * Constructor from raw bytes (for backward compatibility)
     */
    public HTTPRequestResponse(byte[] request, byte[] response, HTTPService httpService) {
        this.requestBytes = request != null ? CompressionUtils.compress(request) : new byte[] {};
        this.responseBytes = response != null ? CompressionUtils.compress(response) : new byte[] {};
        this.httpService = httpService;
        this.comment = "";
        this.highlight = "";
    }

    public byte[] getRequest() {
        return requestBytes != null ? CompressionUtils.decompress(requestBytes) : new byte[] {};
    }

    public byte[] getResponse() {
        return responseBytes != null ? CompressionUtils.decompress(responseBytes) : new byte[] {};
    }

    public String getComment() {
        return comment != null ? comment : "";
    }

    public String getHighlight() {
        return highlight != null ? highlight : "";
    }

    public HTTPService getHttpService() {
        return httpService;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        HTTPRequestResponse that = (HTTPRequestResponse) o;
        return java.util.Arrays.equals(requestBytes, that.requestBytes) &&
                java.util.Arrays.equals(responseBytes, that.responseBytes) &&
                java.util.Objects.equals(comment, that.comment) &&
                java.util.Objects.equals(highlight, that.highlight) &&
                java.util.Objects.equals(httpService, that.httpService);
    }

    @Override
    public int hashCode() {
        int result = java.util.Objects.hash(comment, highlight, httpService);
        result = 31 * result + java.util.Arrays.hashCode(requestBytes);
        result = 31 * result + java.util.Arrays.hashCode(responseBytes);
        return result;
    }

    @Override
    public String toString() {
        return "HTTPRequestResponse{" +
                "requestBytes=" + java.util.Arrays.toString(requestBytes) +
                ", responseBytes=" + java.util.Arrays.toString(responseBytes) +
                ", comment='" + comment + '\'' +
                ", highlight='" + highlight + '\'' +
                ", httpService=" + httpService +
                '}';
    }
}
