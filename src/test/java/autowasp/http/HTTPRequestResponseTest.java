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
package autowasp.http;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ByteArray;
import org.junit.jupiter.api.Test;

import java.io.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link HTTPRequestResponse}.
 * Tests serialization, compression, and data integrity.
 */
class HTTPRequestResponseTest {

    @Test
    void testConstructorFromMontoyaWithFullData() {
        // Arrange
        HttpRequestResponse mockReqResp = mock(HttpRequestResponse.class);
        HttpRequest mockRequest = mock(HttpRequest.class);
        HttpResponse mockResponse = mock(HttpResponse.class);
        Annotations mockAnnotations = mock(Annotations.class);
        burp.api.montoya.http.HttpService mockService = mock(burp.api.montoya.http.HttpService.class);
        ByteArray mockRequestBytes = mock(ByteArray.class);
        ByteArray mockResponseBytes = mock(ByteArray.class);

        when(mockReqResp.request()).thenReturn(mockRequest);
        when(mockReqResp.response()).thenReturn(mockResponse);
        when(mockReqResp.annotations()).thenReturn(mockAnnotations);
        when(mockRequest.toByteArray()).thenReturn(mockRequestBytes);
        when(mockResponse.toByteArray()).thenReturn(mockResponseBytes);
        when(mockRequestBytes.getBytes()).thenReturn("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".getBytes());
        when(mockResponseBytes.getBytes()).thenReturn("HTTP/1.1 200 OK\r\n\r\n".getBytes());
        when(mockRequest.httpService()).thenReturn(mockService);
        when(mockService.host()).thenReturn("example.com");
        when(mockService.port()).thenReturn(443);
        when(mockService.secure()).thenReturn(true);
        when(mockAnnotations.notes()).thenReturn("Test comment");
        when(mockAnnotations.highlightColor()).thenReturn(HighlightColor.RED);

        // Act
        HTTPRequestResponse wrapper = new HTTPRequestResponse(mockReqResp);

        // Assert
        assertNotNull(wrapper.getRequest());
        assertNotNull(wrapper.getResponse());
        assertEquals("Test comment", wrapper.getComment());
        assertEquals("RED", wrapper.getHighlight());
        assertNotNull(wrapper.getHttpService());
        assertEquals("example.com", wrapper.getHttpService().getHost());
    }

    @Test
    void testConstructorFromMontoyaWithNullRequest() {
        // Arrange
        HttpRequestResponse mockReqResp = mock(HttpRequestResponse.class);
        HttpResponse mockResponse = mock(HttpResponse.class);
        ByteArray mockResponseBytes = mock(ByteArray.class);

        when(mockReqResp.request()).thenReturn(null);
        when(mockReqResp.response()).thenReturn(mockResponse);
        when(mockReqResp.annotations()).thenReturn(null);
        when(mockResponse.toByteArray()).thenReturn(mockResponseBytes);
        when(mockResponseBytes.getBytes()).thenReturn("HTTP/1.1 200 OK\r\n\r\n".getBytes());

        // Act
        HTTPRequestResponse wrapper = new HTTPRequestResponse(mockReqResp);

        // Assert
        assertArrayEquals(new byte[] {}, wrapper.getRequest());
        assertNotNull(wrapper.getResponse());
        assertNull(wrapper.getHttpService());
        assertEquals("", wrapper.getComment());
        assertEquals("", wrapper.getHighlight());
    }

    @Test
    void testConstructorFromMontoyaWithNullResponse() {
        // Arrange
        HttpRequestResponse mockReqResp = mock(HttpRequestResponse.class);
        HttpRequest mockRequest = mock(HttpRequest.class);
        burp.api.montoya.http.HttpService mockService = mock(burp.api.montoya.http.HttpService.class);
        ByteArray mockRequestBytes = mock(ByteArray.class);

        when(mockReqResp.request()).thenReturn(mockRequest);
        when(mockReqResp.response()).thenReturn(null);
        when(mockReqResp.annotations()).thenReturn(null);
        when(mockRequest.toByteArray()).thenReturn(mockRequestBytes);
        when(mockRequestBytes.getBytes()).thenReturn("GET / HTTP/1.1\r\n\r\n".getBytes());
        when(mockRequest.httpService()).thenReturn(mockService);
        when(mockService.host()).thenReturn("example.com");
        when(mockService.port()).thenReturn(80);
        when(mockService.secure()).thenReturn(false);

        // Act
        HTTPRequestResponse wrapper = new HTTPRequestResponse(mockReqResp);

        // Assert
        assertNotNull(wrapper.getRequest());
        assertArrayEquals(new byte[] {}, wrapper.getResponse());
        assertNotNull(wrapper.getHttpService());
    }

    @Test
    void testConstructorFromMontoyaWithNullAnnotations() {
        // Arrange
        HttpRequestResponse mockReqResp = mock(HttpRequestResponse.class);
        HttpRequest mockRequest = mock(HttpRequest.class);
        HttpResponse mockResponse = mock(HttpResponse.class);
        burp.api.montoya.http.HttpService mockService = mock(burp.api.montoya.http.HttpService.class);
        ByteArray mockRequestBytes = mock(ByteArray.class);
        ByteArray mockResponseBytes = mock(ByteArray.class);

        when(mockReqResp.request()).thenReturn(mockRequest);
        when(mockReqResp.response()).thenReturn(mockResponse);
        when(mockReqResp.annotations()).thenReturn(null);
        when(mockRequest.toByteArray()).thenReturn(mockRequestBytes);
        when(mockResponse.toByteArray()).thenReturn(mockResponseBytes);
        when(mockRequestBytes.getBytes()).thenReturn("GET / HTTP/1.1\r\n\r\n".getBytes());
        when(mockResponseBytes.getBytes()).thenReturn("HTTP/1.1 200 OK\r\n\r\n".getBytes());
        when(mockRequest.httpService()).thenReturn(mockService);
        when(mockService.host()).thenReturn("example.com");
        when(mockService.port()).thenReturn(443);
        when(mockService.secure()).thenReturn(true);

        // Act
        HTTPRequestResponse wrapper = new HTTPRequestResponse(mockReqResp);

        // Assert
        assertEquals("", wrapper.getComment());
        assertEquals("", wrapper.getHighlight());
    }

    @Test
    void testConstructorFromMontoyaWithNullHighlightColor() {
        // Arrange
        HttpRequestResponse mockReqResp = mock(HttpRequestResponse.class);
        HttpRequest mockRequest = mock(HttpRequest.class);
        HttpResponse mockResponse = mock(HttpResponse.class);
        Annotations mockAnnotations = mock(Annotations.class);
        burp.api.montoya.http.HttpService mockService = mock(burp.api.montoya.http.HttpService.class);
        ByteArray mockRequestBytes = mock(ByteArray.class);
        ByteArray mockResponseBytes = mock(ByteArray.class);

        when(mockReqResp.request()).thenReturn(mockRequest);
        when(mockReqResp.response()).thenReturn(mockResponse);
        when(mockReqResp.annotations()).thenReturn(mockAnnotations);
        when(mockRequest.toByteArray()).thenReturn(mockRequestBytes);
        when(mockResponse.toByteArray()).thenReturn(mockResponseBytes);
        when(mockRequestBytes.getBytes()).thenReturn("GET / HTTP/1.1\r\n\r\n".getBytes());
        when(mockResponseBytes.getBytes()).thenReturn("HTTP/1.1 200 OK\r\n\r\n".getBytes());
        when(mockRequest.httpService()).thenReturn(mockService);
        when(mockService.host()).thenReturn("example.com");
        when(mockService.port()).thenReturn(443);
        when(mockService.secure()).thenReturn(true);
        when(mockAnnotations.notes()).thenReturn("Test");
        when(mockAnnotations.highlightColor()).thenReturn(null);

        // Act
        HTTPRequestResponse wrapper = new HTTPRequestResponse(mockReqResp);

        // Assert
        assertEquals("", wrapper.getHighlight());
    }

    @Test
    void testConstructorFromRawBytes() {
        // Arrange
        byte[] request = "GET / HTTP/1.1\r\n\r\n".getBytes();
        byte[] response = "HTTP/1.1 200 OK\r\n\r\n".getBytes();
        HTTPService service = new HTTPService("example.com", 443, true);

        // Act
        HTTPRequestResponse wrapper = new HTTPRequestResponse(request, response, service);

        // Assert
        assertNotNull(wrapper.getRequest());
        assertNotNull(wrapper.getResponse());
        assertEquals(service, wrapper.getHttpService());
        assertEquals("", wrapper.getComment());
        assertEquals("", wrapper.getHighlight());
    }

    @Test
    void testConstructorFromRawBytesWithNullRequest() {
        // Arrange
        byte[] response = "HTTP/1.1 200 OK\r\n\r\n".getBytes();
        HTTPService service = new HTTPService("example.com", 443, true);

        // Act
        HTTPRequestResponse wrapper = new HTTPRequestResponse(null, response, service);

        // Assert
        assertArrayEquals(new byte[] {}, wrapper.getRequest());
        assertNotNull(wrapper.getResponse());
    }

    @Test
    void testConstructorFromRawBytesWithNullResponse() {
        // Arrange
        byte[] request = "GET / HTTP/1.1\r\n\r\n".getBytes();
        HTTPService service = new HTTPService("example.com", 443, true);

        // Act
        HTTPRequestResponse wrapper = new HTTPRequestResponse(request, null, service);

        // Assert
        assertNotNull(wrapper.getRequest());
        assertArrayEquals(new byte[] {}, wrapper.getResponse());
    }

    @Test
    void testConstructorFromRawBytesWithNullService() {
        // Arrange
        byte[] request = "GET / HTTP/1.1\r\n\r\n".getBytes();
        byte[] response = "HTTP/1.1 200 OK\r\n\r\n".getBytes();

        // Act
        HTTPRequestResponse wrapper = new HTTPRequestResponse(request, response, null);

        // Assert
        assertNotNull(wrapper.getRequest());
        assertNotNull(wrapper.getResponse());
        assertNull(wrapper.getHttpService());
    }

    @Test
    void testCompressionDecompression() {
        // Arrange
        byte[] largeRequest = new byte[10000];
        for (int i = 0; i < largeRequest.length; i++) {
            largeRequest[i] = (byte) (i % 256);
        }
        HTTPService service = new HTTPService("example.com", 443, true);

        // Act
        HTTPRequestResponse wrapper = new HTTPRequestResponse(largeRequest, null, service);
        byte[] decompressed = wrapper.getRequest();

        // Assert
        assertArrayEquals(largeRequest, decompressed);
    }

    @Test
    void testEqualsWithSameObject() {
        // Arrange
        byte[] request = "GET / HTTP/1.1\r\n\r\n".getBytes();
        HTTPService service = new HTTPService("example.com", 443, true);
        HTTPRequestResponse wrapper = new HTTPRequestResponse(request, null, service);

        // Assert
        assertEquals(wrapper, wrapper);
    }

    @Test
    void testEqualsWithEqualObjects() {
        // Arrange
        byte[] request = "GET / HTTP/1.1\r\n\r\n".getBytes();
        HTTPService service = new HTTPService("example.com", 443, true);
        HTTPRequestResponse wrapper1 = new HTTPRequestResponse(request, null, service);
        HTTPRequestResponse wrapper2 = new HTTPRequestResponse(request, null, service);

        // Assert
        assertEquals(wrapper1, wrapper2);
    }

    @Test
    void testEqualsWithDifferentRequest() {
        // Arrange
        byte[] request1 = "GET / HTTP/1.1\r\n\r\n".getBytes();
        byte[] request2 = "POST / HTTP/1.1\r\n\r\n".getBytes();
        HTTPService service = new HTTPService("example.com", 443, true);
        HTTPRequestResponse wrapper1 = new HTTPRequestResponse(request1, null, service);
        HTTPRequestResponse wrapper2 = new HTTPRequestResponse(request2, null, service);

        // Assert
        assertNotEquals(wrapper1, wrapper2);
    }

    @Test
    void testEqualsWithNull() {
        // Arrange
        byte[] request = "GET / HTTP/1.1\r\n\r\n".getBytes();
        HTTPService service = new HTTPService("example.com", 443, true);
        HTTPRequestResponse wrapper = new HTTPRequestResponse(request, null, service);

        // Assert
        assertNotEquals(wrapper, null);
    }

    @Test
    void testEqualsWithDifferentClass() {
        // Arrange
        byte[] request = "GET / HTTP/1.1\r\n\r\n".getBytes();
        HTTPService service = new HTTPService("example.com", 443, true);
        HTTPRequestResponse wrapper = new HTTPRequestResponse(request, null, service);

        // Assert
        assertNotEquals(wrapper, "not an HTTPRequestResponse");
    }

    @Test
    void testHashCodeConsistency() {
        // Arrange
        byte[] request = "GET / HTTP/1.1\r\n\r\n".getBytes();
        HTTPService service = new HTTPService("example.com", 443, true);
        HTTPRequestResponse wrapper = new HTTPRequestResponse(request, null, service);

        // Act
        int hash1 = wrapper.hashCode();
        int hash2 = wrapper.hashCode();

        // Assert
        assertEquals(hash1, hash2);
    }

    @Test
    void testHashCodeEqualityContract() {
        // Arrange
        byte[] request = "GET / HTTP/1.1\r\n\r\n".getBytes();
        HTTPService service = new HTTPService("example.com", 443, true);
        HTTPRequestResponse wrapper1 = new HTTPRequestResponse(request, null, service);
        HTTPRequestResponse wrapper2 = new HTTPRequestResponse(request, null, service);

        // Assert
        assertEquals(wrapper1.hashCode(), wrapper2.hashCode());
    }

    @Test
    void testToString() {
        // Arrange
        byte[] request = "GET".getBytes();
        byte[] response = "OK".getBytes();
        HTTPService service = new HTTPService("example.com", 443, true);
        HTTPRequestResponse wrapper = new HTTPRequestResponse(request, response, service);

        // Act
        String result = wrapper.toString();

        // Assert
        assertTrue(result.contains("HTTPRequestResponse"));
        assertTrue(result.contains("requestBytes"));
        assertTrue(result.contains("responseBytes"));
        assertTrue(result.contains("httpService"));
    }

    @Test
    void testSerialization() throws IOException, ClassNotFoundException {
        // Arrange
        byte[] request = "GET / HTTP/1.1\r\n\r\n".getBytes();
        byte[] response = "HTTP/1.1 200 OK\r\n\r\n".getBytes();
        HTTPService service = new HTTPService("example.com", 443, true);
        HTTPRequestResponse original = new HTTPRequestResponse(request, response, service);

        // Serialize
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(original);
        oos.close();

        // Deserialize
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        HTTPRequestResponse deserialized = (HTTPRequestResponse) ois.readObject();
        ois.close();

        // Assert
        assertEquals(original, deserialized);
        assertArrayEquals(original.getRequest(), deserialized.getRequest());
        assertArrayEquals(original.getResponse(), deserialized.getResponse());
        assertEquals(original.getHttpService(), deserialized.getHttpService());
    }

    @Test
    void testGetRequestWithNullBytes() {
        // Arrange - using reflection or constructor that might set null
        byte[] request = null;
        HTTPService service = new HTTPService("example.com", 443, true);
        HTTPRequestResponse wrapper = new HTTPRequestResponse(request, null, service);

        // Act
        byte[] result = wrapper.getRequest();

        // Assert
        assertArrayEquals(new byte[] {}, result);
    }

    @Test
    void testGetResponseWithNullBytes() {
        // Arrange
        byte[] request = "GET / HTTP/1.1\r\n\r\n".getBytes();
        HTTPService service = new HTTPService("example.com", 443, true);
        HTTPRequestResponse wrapper = new HTTPRequestResponse(request, null, service);

        // Act
        byte[] result = wrapper.getResponse();

        // Assert
        assertArrayEquals(new byte[] {}, result);
    }

    @Test
    void testLargePayloadCompression() {
        // Arrange - 1MB payload
        byte[] largePayload = new byte[1024 * 1024];
        for (int i = 0; i < largePayload.length; i++) {
            largePayload[i] = (byte) 'A'; // Highly compressible
        }
        HTTPService service = new HTTPService("example.com", 443, true);

        // Act
        HTTPRequestResponse wrapper = new HTTPRequestResponse(largePayload, largePayload, service);
        byte[] decompressedRequest = wrapper.getRequest();
        byte[] decompressedResponse = wrapper.getResponse();

        // Assert
        assertArrayEquals(largePayload, decompressedRequest);
        assertArrayEquals(largePayload, decompressedResponse);
    }
}
