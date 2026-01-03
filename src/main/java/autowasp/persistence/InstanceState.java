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

package autowasp.persistence;

/**
 * Lightweight DTO for persisting an instance entry.
 */
public record InstanceState(
        String url,
        String confidence,
        String severity,
        byte[] requestBytes,
        byte[] responseBytes,
        String host,
        int port,
        boolean secure) {
    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        InstanceState that = (InstanceState) o;
        return port == that.port &&
                secure == that.secure &&
                java.util.Objects.equals(url, that.url) &&
                java.util.Objects.equals(confidence, that.confidence) &&
                java.util.Objects.equals(severity, that.severity) &&
                java.util.Arrays.equals(requestBytes, that.requestBytes) &&
                java.util.Arrays.equals(responseBytes, that.responseBytes) &&
                java.util.Objects.equals(host, that.host);
    }

    @Override
    public int hashCode() {
        int result = java.util.Objects.hash(url, confidence, severity, host, port, secure);
        result = 31 * result + java.util.Arrays.hashCode(requestBytes);
        result = 31 * result + java.util.Arrays.hashCode(responseBytes);
        return result;
    }

    @Override
    public String toString() {
        return "InstanceState[" +
                "url=" + url +
                ", confidence=" + confidence +
                ", severity=" + severity +
                ", requestBytes=" + java.util.Arrays.toString(requestBytes) +
                ", responseBytes=" + java.util.Arrays.toString(responseBytes) +
                ", host=" + host +
                ", port=" + port +
                ", secure=" + secure +
                "]";
    }
}
