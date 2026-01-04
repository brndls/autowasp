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

package autowasp.logger;

public class TrafficInstance {

    private boolean isUnencrypted;
    private boolean isBase64;
    private boolean isXContent;
    private boolean isServerInfoLeaked;
    private boolean isServerErrorInfoLeaked;
    private boolean isCorHeaders;
    private boolean isUnauthorisedDisclosure;
    private boolean isXSS;
    private boolean isCGI;
    private boolean isHTTPVerb;

    public TrafficInstance() {
        this.isUnencrypted = false;
        this.isBase64 = false;
        this.isXContent = false;
        this.isServerInfoLeaked = false;
        this.isServerErrorInfoLeaked = false;
        this.isCorHeaders = false;
        this.isUnauthorisedDisclosure = false;
        this.isXSS = false;
        this.isCGI = false;
        this.isHTTPVerb = false;
    }

    public void setUnencrypted(boolean unencrypted) {
        this.isUnencrypted = unencrypted;
    }

    public boolean isUnencrypted() {
        return isUnencrypted;
    }

    public void setBase64(boolean base64) {
        this.isBase64 = base64;
    }

    public boolean isBase64() {
        return isBase64;
    }

    public void setXContent(boolean xContent) {
        this.isXContent = xContent;
    }

    public boolean isXContent() {
        return isXContent;
    }

    public void setServerInfoLeaked(boolean serverInfoLeaked) {
        this.isServerInfoLeaked = serverInfoLeaked;
    }

    public boolean isServerInfoLeaked() {
        return isServerInfoLeaked;
    }

    public void setServerErrorInfoLeaked(boolean serverErrorInfoLeaked) {
        this.isServerErrorInfoLeaked = serverErrorInfoLeaked;
    }

    public boolean isServerErrorInfoLeaked() {
        return isServerErrorInfoLeaked;
    }

    public void setCorHeaders(boolean corHeaders) {
        this.isCorHeaders = corHeaders;
    }

    public boolean isCorHeaders() {
        return isCorHeaders;
    }

    public void setUnauthorisedDisclosure(boolean unauthorisedDisclosure) {
        this.isUnauthorisedDisclosure = unauthorisedDisclosure;
    }

    public boolean isUnauthorisedDisclosure() {
        return isUnauthorisedDisclosure;
    }

    public void setXSS(boolean xss) {
        this.isXSS = xss;
    }

    public boolean isXSS() {
        return isXSS;
    }

    public void setCGI(boolean cgi) {
        this.isCGI = cgi;
    }

    public boolean isCGI() {
        return isCGI;
    }

    public void setHTTPVerb(boolean httpVerb) {
        this.isHTTPVerb = httpVerb;
    }

    public boolean isHTTPVerb() {
        return isHTTPVerb;
    }

    // Legacy setters for compatibility if needed, though better to use standard
    // ones
    public void setUnencrypted() {
        this.isUnencrypted = true;
    }

    public void setServerErrorInfoLeaked() {
        this.isServerErrorInfoLeaked = true;
    }

    public void setServerInfoLeaked() {
        this.isServerErrorInfoLeaked = true;
    }

    public void setCGI() {
        this.isCGI = true;
    }

    public void setBase64() {
        this.isBase64 = true;
    }

    public void setCorHeaders() {
        this.isCorHeaders = true;
    }

    public void setHTTPVerb() {
        this.isHTTPVerb = true;
    }

    public void setXContentHeaders() {
        this.isXContent = true;
    }
}
