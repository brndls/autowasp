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
 * Catatan Pembelajaran - Migrasi dari Legacy API:
 * 
 * Legacy API:
 * - implements IHttpService
 * - Methods: getHost(), getPort(), getProtocol()
 * 
 * Montoya API:
 * - HttpService adalah interface yang sudah ada
 * - Class ini sekarang menjadi simple POJO untuk menyimpan data
 * - Tidak perlu implement interface karena HttpService di Montoya
 * sudah menyediakan akses langsung
 * 
 * Pendekatan:
 * - Simpan data dari HttpService Montoya ke local fields
 * - Provide getter methods untuk akses data
 * - Tetap Serializable untuk persistensi
 */
public class HTTPService implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String host;
    private final int port;
    private final boolean secure;

    /**
     * Constructor dari Montoya HttpService
     */
    public HTTPService(HttpService httpService) {
        this.host = httpService.host();
        this.port = httpService.port();
        this.secure = httpService.secure();
    }

    /**
     * Constructor manual untuk kasus khusus
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
     * Di Montoya API, protokol ditentukan oleh flag secure
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
