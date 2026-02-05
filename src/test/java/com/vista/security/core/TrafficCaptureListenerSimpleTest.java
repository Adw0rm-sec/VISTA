package com.vista.security.core;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;
import com.vista.security.model.HttpTransaction;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Simplified tests for TrafficCaptureListener focusing on core functionality.
 * 
 * Validates: Requirements 1.1, 1.2, 1.4, 7.1, 7.2, 10.3
 */
public class TrafficCaptureListenerSimpleTest {
    
    private TrafficBufferManager bufferManager;
    private TrafficCaptureListener captureListener;
    private SimpleMockCallbacks mockCallbacks;
    
    @BeforeEach
    public void setUp() {
        bufferManager = new TrafficBufferManager(1000);
        mockCallbacks = new SimpleMockCallbacks();
        captureListener = new TrafficCaptureListener(mockCallbacks, bufferManager);
    }
    
    @AfterEach
    public void tearDown() {
        captureListener.shutdown();
    }
    
    /**
     * Test: Pause stops capture
     */
    @Test
    public void testPauseStopsCapture() throws InterruptedException {
        // Arrange
        IHttpRequestResponse mockMessage = createMockMessage();
        
        // Act - Pause
        captureListener.pause();
        assertTrue(captureListener.isPaused());
        
        // Try to capture while paused
        captureListener.captureMessage(mockMessage);
        Thread.sleep(100);
        
        // Assert - No transactions should be captured
        assertEquals(0, bufferManager.size());
    }
    
    /**
     * Test: Resume restarts capture
     */
    @Test
    public void testResumeRestartsCapture() throws InterruptedException {
        // Arrange
        IHttpRequestResponse mockMessage = createMockMessage();
        
        // Act - Pause then resume
        captureListener.pause();
        captureListener.resume();
        assertFalse(captureListener.isPaused());
        
        // Capture message
        captureListener.captureMessage(mockMessage);
        Thread.sleep(200);
        
        // Assert - Transaction should be captured
        assertEquals(1, bufferManager.size());
    }
    
    /**
     * Test: Null callbacks throws exception
     */
    @Test
    public void testNullCallbacksThrowsException() {
        assertThrows(IllegalArgumentException.class, () -> {
            new TrafficCaptureListener(null, bufferManager);
        });
    }
    
    /**
     * Test: Null buffer manager throws exception
     */
    @Test
    public void testNullBufferManagerThrowsException() {
        assertThrows(IllegalArgumentException.class, () -> {
            new TrafficCaptureListener(mockCallbacks, null);
        });
    }
    
    /**
     * Test: Null message handling
     */
    @Test
    public void testNullMessageHandling() throws InterruptedException {
        // Act - Should not throw
        assertDoesNotThrow(() -> {
            captureListener.captureMessage(null);
        });
        
        Thread.sleep(100);
        
        // Assert - No transaction should be added
        assertEquals(0, bufferManager.size());
    }
    
    // Helper methods and simple mock classes
    
    private IHttpRequestResponse createMockMessage() {
        String requestStr = "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        String responseStr = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"result\":\"success\"}";
        
        return new SimpleMockHttpRequestResponse(
            requestStr.getBytes(),
            responseStr.getBytes()
        );
    }
    
    // Minimal mock implementations
    
    private static class SimpleMockCallbacks implements IBurpExtenderCallbacks {
        private final SimpleMockHelpers helpers = new SimpleMockHelpers();
        private final List<IHttpListener> httpListeners = new ArrayList<>();
        
        @Override
        public IExtensionHelpers getHelpers() {
            return helpers;
        }
        
        @Override
        public void printError(String message) {
            System.err.println("Error: " + message);
        }
        
        @Override
        public void printOutput(String message) {
            System.out.println("Output: " + message);
        }
        
        @Override
        public void setExtensionName(String name) {}
        
        @Override
        public void addSuiteTab(burp.ITab tab) {}
        
        @Override
        public void registerContextMenuFactory(burp.IContextMenuFactory factory) {}
        
        @Override
        public void registerHttpListener(IHttpListener listener) {
            httpListeners.add(listener);
        }
        
        @Override
        public void removeHttpListener(IHttpListener listener) {
            httpListeners.remove(listener);
        }
        
        @Override
        public void sendToRepeater(String host, int port, boolean useHttps, byte[] request, String tabCaption) {}
        
        @Override
        public IHttpRequestResponse makeHttpRequest(IHttpService httpService, byte[] request) {
            return null;
        }
    }
    
    private static class SimpleMockHelpers implements IExtensionHelpers {
        @Override
        public IRequestInfo analyzeRequest(byte[] request) {
            return new SimpleMockRequestInfo(request);
        }
        
        @Override
        public IResponseInfo analyzeResponse(byte[] response) {
            return new SimpleMockResponseInfo(response);
        }
    }
    
    private static class SimpleMockRequestInfo implements IRequestInfo {
        private final byte[] request;
        private final List<String> headers;
        
        public SimpleMockRequestInfo(byte[] request) {
            this.request = request;
            String requestStr = new String(request);
            String[] lines = requestStr.split("\r\n");
            
            this.headers = new ArrayList<>();
            for (String line : lines) {
                if (line.isEmpty()) break;
                headers.add(line);
            }
        }
        
        @Override
        public List<String> getHeaders() {
            return headers;
        }
        
        @Override
        public int getBodyOffset() {
            String requestStr = new String(request);
            int index = requestStr.indexOf("\r\n\r\n");
            return index >= 0 ? index + 4 : request.length;
        }
    }
    
    private static class SimpleMockResponseInfo implements IResponseInfo {
        private final byte[] response;
        private final List<String> headers;
        
        public SimpleMockResponseInfo(byte[] response) {
            this.response = response;
            String responseStr = new String(response);
            String[] lines = responseStr.split("\r\n");
            
            this.headers = new ArrayList<>();
            for (String line : lines) {
                if (line.isEmpty()) break;
                headers.add(line);
            }
        }
        
        @Override
        public List<String> getHeaders() {
            return headers;
        }
        
        @Override
        public int getBodyOffset() {
            String responseStr = new String(response);
            int index = responseStr.indexOf("\r\n\r\n");
            return index >= 0 ? index + 4 : response.length;
        }
    }
    
    private static class SimpleMockHttpRequestResponse implements IHttpRequestResponse {
        private byte[] request;
        private byte[] response;
        
        public SimpleMockHttpRequestResponse(byte[] request, byte[] response) {
            this.request = request;
            this.response = response;
        }
        
        @Override
        public byte[] getRequest() {
            return request;
        }
        
        @Override
        public byte[] getResponse() {
            return response;
        }
    }
}
