package com.vista.security.model;

import burp.IHttpRequestResponse;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Property-based and unit tests for HttpTransaction.
 * 
 * Property 2: Request-Response Association
 * Validates: Requirements 1.2, 10.1, 10.2
 */
public class HttpTransactionTest {
    
    /**
     * Property Test: HttpTransaction immutability
     * 
     * For any HttpTransaction created, all fields should remain unchanged
     * and the object should be immutable (no setters, defensive copies).
     */
    @Test
    public void testHttpTransactionImmutability() {
        // Arrange
        String id = "test-id-123";
        long timestamp = System.currentTimeMillis();
        String method = "POST";
        String url = "https://example.com/api/users";
        String contentType = "application/json";
        int statusCode = 200;
        long responseSize = 1024;
        byte[] request = "POST /api/users HTTP/1.1\r\n".getBytes();
        byte[] response = "HTTP/1.1 200 OK\r\n".getBytes();
        IHttpRequestResponse burpMessage = createMockBurpMessage(request, response);
        
        // Act
        HttpTransaction transaction = new HttpTransaction(
            id, timestamp, method, url, contentType, statusCode, responseSize,
            request, response, burpMessage
        );
        
        // Assert - All fields should match constructor parameters
        assertEquals(id, transaction.getId());
        assertEquals(timestamp, transaction.getTimestamp());
        assertEquals(method, transaction.getMethod());
        assertEquals(url, transaction.getUrl());
        assertEquals(contentType, transaction.getContentType());
        assertEquals(statusCode, transaction.getStatusCode());
        assertEquals(responseSize, transaction.getResponseSize());
        assertArrayEquals(request, transaction.getRequest());
        assertArrayEquals(response, transaction.getResponse());
        assertEquals(burpMessage, transaction.getBurpMessage());
        
        // Assert - Modifying returned arrays should not affect internal state
        byte[] returnedRequest = transaction.getRequest();
        byte[] returnedResponse = transaction.getResponse();
        byte[] originalRequest = returnedRequest.clone();
        byte[] originalResponse = returnedResponse.clone();
        
        // Modify returned arrays
        if (returnedRequest.length > 0) returnedRequest[0] = (byte) 'X';
        if (returnedResponse.length > 0) returnedResponse[0] = (byte) 'X';
        
        // Get arrays again - they should still match originals
        assertArrayEquals(originalRequest, transaction.getRequest());
        assertArrayEquals(originalResponse, transaction.getResponse());
    }
    
    /**
     * Property Test: Request-Response Association
     * 
     * For any HTTP request-response pair captured, retrieving the transaction
     * should return both the request and response correctly associated together.
     * 
     * Validates: Requirements 1.2
     */
    @Test
    public void testRequestResponseAssociation() {
        // Arrange - Create multiple transactions with different request/response pairs
        byte[] request1 = "GET /api/users HTTP/1.1\r\n".getBytes();
        byte[] response1 = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"users\":[]}".getBytes();
        
        byte[] request2 = "POST /api/login HTTP/1.1\r\n".getBytes();
        byte[] response2 = "HTTP/1.1 401 Unauthorized\r\n".getBytes();
        
        IHttpRequestResponse burpMessage1 = createMockBurpMessage(request1, response1);
        IHttpRequestResponse burpMessage2 = createMockBurpMessage(request2, response2);
        
        // Act
        HttpTransaction transaction1 = HttpTransaction.create(
            System.currentTimeMillis(), "GET", "https://example.com/api/users",
            "application/json", 200, response1.length,
            request1, response1, burpMessage1
        );
        
        HttpTransaction transaction2 = HttpTransaction.create(
            System.currentTimeMillis(), "POST", "https://example.com/api/login",
            "application/json", 401, response2.length,
            request2, response2, burpMessage2
        );
        
        // Assert - Each transaction should have its correct request/response pair
        assertArrayEquals(request1, transaction1.getRequest());
        assertArrayEquals(response1, transaction1.getResponse());
        assertEquals(burpMessage1, transaction1.getBurpMessage());
        
        assertArrayEquals(request2, transaction2.getRequest());
        assertArrayEquals(response2, transaction2.getResponse());
        assertEquals(burpMessage2, transaction2.getBurpMessage());
        
        // Assert - Transactions should not be mixed up
        assertFalse(java.util.Arrays.equals(transaction1.getRequest(), transaction2.getRequest()));
        assertFalse(java.util.Arrays.equals(transaction1.getResponse(), transaction2.getResponse()));
    }
    
    /**
     * Test: Null content-type handling
     * 
     * When content-type is null, it should default to "unknown".
     * Validates: Requirements 10.5
     */
    @Test
    public void testNullContentTypeHandling() {
        // Arrange
        byte[] request = "GET / HTTP/1.1\r\n".getBytes();
        byte[] response = "HTTP/1.1 200 OK\r\n".getBytes();
        IHttpRequestResponse burpMessage = createMockBurpMessage(request, response);
        
        // Act
        HttpTransaction transaction = HttpTransaction.create(
            System.currentTimeMillis(), "GET", "https://example.com/",
            null, // null content-type
            200, response.length,
            request, response, burpMessage
        );
        
        // Assert
        assertEquals("unknown", transaction.getContentType());
    }
    
    /**
     * Test: Formatted timestamp
     */
    @Test
    public void testFormattedTimestamp() {
        // Arrange
        long timestamp = System.currentTimeMillis();
        HttpTransaction transaction = createSimpleTransaction(timestamp);
        
        // Act
        String formatted = transaction.getFormattedTimestamp();
        
        // Assert - Should be in HH:mm:ss.SSS format
        assertNotNull(formatted);
        assertTrue(formatted.matches("\\d{2}:\\d{2}:\\d{2}\\.\\d{3}"));
    }
    
    /**
     * Test: Formatted size
     */
    @Test
    public void testFormattedSize() {
        // Test bytes
        HttpTransaction transaction1 = createSimpleTransactionWithSize(512);
        assertEquals("512 B", transaction1.getFormattedSize());
        
        // Test kilobytes
        HttpTransaction transaction2 = createSimpleTransactionWithSize(2048);
        assertEquals("2.0 KB", transaction2.getFormattedSize());
        
        // Test megabytes
        HttpTransaction transaction3 = createSimpleTransactionWithSize(2 * 1024 * 1024);
        assertEquals("2.0 MB", transaction3.getFormattedSize());
    }
    
    /**
     * Test: Equals and hashCode
     */
    @Test
    public void testEqualsAndHashCode() {
        // Arrange
        String id = "same-id";
        HttpTransaction transaction1 = new HttpTransaction(
            id, System.currentTimeMillis(), "GET", "https://example.com/",
            "text/html", 200, 1024,
            new byte[0], new byte[0], null
        );
        
        HttpTransaction transaction2 = new HttpTransaction(
            id, System.currentTimeMillis() + 1000, "POST", "https://different.com/",
            "application/json", 404, 2048,
            new byte[0], new byte[0], null
        );
        
        HttpTransaction transaction3 = new HttpTransaction(
            "different-id", System.currentTimeMillis(), "GET", "https://example.com/",
            "text/html", 200, 1024,
            new byte[0], new byte[0], null
        );
        
        // Assert - Same ID means equal
        assertEquals(transaction1, transaction2);
        assertEquals(transaction1.hashCode(), transaction2.hashCode());
        
        // Assert - Different ID means not equal
        assertNotEquals(transaction1, transaction3);
    }
    
    // Helper methods
    
    private HttpTransaction createSimpleTransaction(long timestamp) {
        return HttpTransaction.create(
            timestamp, "GET", "https://example.com/",
            "text/html", 200, 1024,
            new byte[0], new byte[0], null
        );
    }
    
    private HttpTransaction createSimpleTransactionWithSize(long size) {
        return HttpTransaction.create(
            System.currentTimeMillis(), "GET", "https://example.com/",
            "text/html", 200, size,
            new byte[0], new byte[0], null
        );
    }
    
    private IHttpRequestResponse createMockBurpMessage(byte[] request, byte[] response) {
        return new IHttpRequestResponse() {
            @Override
            public byte[] getRequest() {
                return request;
            }
            
            @Override
            public byte[] getResponse() {
                return response;
            }
        };
    }
}
