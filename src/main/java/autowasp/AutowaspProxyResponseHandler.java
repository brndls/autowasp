/*
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

package autowasp;

import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

/**
 * Handler untuk Proxy Response - Montoya API
 * 
 * Catatan Pembelajaran - Migrasi dari Legacy API:
 * 
 * Legacy API menggunakan IProxyListener dengan method:
 * - processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage
 * message)
 * 
 * Montoya API memisahkan menjadi dua handler:
 * - ProxyRequestHandler: untuk request yang masuk
 * - ProxyResponseHandler: untuk response yang keluar
 * 
 * Keuntungan Montoya API:
 * 1. Separation of concerns - request dan response terpisah
 * 2. Tipe yang lebih aman - tidak perlu cek messageIsRequest
 * 3. API yang lebih fluent - method chaining
 */
public class AutowaspProxyResponseHandler implements ProxyResponseHandler {

    private final Autowasp extender;

    public AutowaspProxyResponseHandler(Autowasp extender) {
        this.extender = extender;
    }

    /**
     * Dipanggil saat response diterima dari server
     * Menggantikan logika di processProxyMessage() dengan messageIsRequest = false
     */
    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        try {
            // Cek apakah URL dalam scope
            String url = interceptedResponse.initiatingRequest().url();

            if (extender.isInScope(url)) {
                synchronized (extender.trafficLog) {
                    // Klasifikasi traffic menggunakan TrafficLogic
                    extender.trafficLogic.classifyTraffic(interceptedResponse);
                }
            }
        } catch (Exception e) {
            extender.logError(e);
        }

        // Lanjutkan response tanpa modifikasi
        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    /**
     * Dipanggil sebelum response dikirim ke client
     * Bisa digunakan untuk modifikasi response jika diperlukan
     */
    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        // Tidak ada modifikasi, lanjutkan response
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }
}
