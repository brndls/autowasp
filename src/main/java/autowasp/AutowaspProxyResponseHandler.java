/*
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

package autowasp;

import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

/**
 * Handler for Proxy Response - Montoya API
 *
 * Learning Notes - Migration from Legacy API:
 *
 * Legacy API uses IProxyListener with method:
 * - processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage
 * message)
 *
 * Montoya API uses ProxyRequestHandler and ProxyResponseHandler:
 * - ProxyRequestHandler: for incoming requests
 * - ProxyResponseHandler: for outgoing responses
 *
 * Benefits:
 * 1. Separation of concerns - request and response are separated
 * 2. Safer types - no need to check messageIsRequest
 * 3. More fluent API - method chaining
 */
public class AutowaspProxyResponseHandler implements ProxyResponseHandler {

    private final Autowasp extender;

    public AutowaspProxyResponseHandler(Autowasp extender) {
        this.extender = extender;
    }

    /**
     * Called when response is received from server
     * Replaces logic in processProxyMessage() with messageIsRequest = false
     */
    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        try {
            // Cek apakah URL dalam scope
            String url = interceptedResponse.initiatingRequest().url();

            if (extender.isInScope(url)) {
                synchronized (extender.getLoggerManager().getTrafficLog()) {
                    // Classify traffic using TrafficLogic
                    extender.getTrafficLogic().classifyTraffic(interceptedResponse);
                }
            }
        } catch (Exception e) {
            extender.logError(e);
        }

        // Lanjutkan response tanpa modifikasi
        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    /**
     * Called before response is sent to client
     * Can be used to modify response if needed
     */
    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        // Tidak ada modifikasi, lanjutkan response
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }
}
