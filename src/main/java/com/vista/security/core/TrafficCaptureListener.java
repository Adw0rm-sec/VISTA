package com.vista.security.core;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import com.vista.security.model.HttpTransaction;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * TrafficCaptureListener captures HTTP traffic for monitoring.
 * 
 * Features:
 * - Non-blocking capture using background thread pool
 * - Extracts metadata (method, URL, content-type, status, size)
 * - Pause/resume capability
 * - Graceful error handling
 * 
 * Performance:
 * - Metadata extraction < 10ms
 * - Background processing prevents blocking Burp
 * - Bounded thread pool prevents resource exhaustion
 * 
 * Note: This implementation works with Burp Suite Community Edition's simplified API.
 * Traffic is captured manually via context menu or programmatically.
 */
public class TrafficCaptureListener {
    
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final TrafficBufferManager bufferManager;
    private final ExecutorService executor;
    private volatile boolean paused;
    
    /**
     * Creates a new TrafficCaptureListener.
     * 
     * @param callbacks Burp callbacks for API access
     * @param bufferManager Buffer manager to store captured transactions
     */
    public TrafficCaptureListener(IBurpExtenderCallbacks callbacks, 
                                   TrafficBufferManager bufferManager) {
        if (callbacks == null) {
            throw new IllegalArgumentException("callbacks cannot be null");
        }
        if (bufferManager == null) {
            throw new IllegalArgumentException("bufferManager cannot be null");
        }
        
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.bufferManager = bufferManager;
        this.executor = Executors.newFixedThreadPool(2); // Small thread pool for background processing
        this.paused = false;
    }
    
    /**
     * Captures an HTTP message for monitoring.
     * 
     * This method can be called manually (e.g., from context menu) or programmatically.
     * Only processes complete request/response pairs.
     * 
     * @param messageInfo The HTTP message to capture
     */
    public void captureMessage(IHttpRequestResponse messageInfo) {
        // Check if paused
        if (paused) {
            return;
        }
        
        // Process in background to avoid blocking caller
        executor.submit(() -> {
            try {
                HttpTransaction transaction = createTransaction(messageInfo);
                if (transaction != null) {
                    bufferManager.addTransaction(transaction);
                }
            } catch (Exception e) {
                // Log error but don't throw
                callbacks.printError("Error capturing traffic: " + e.getMessage());
            }
        });
    }
    
    /**
     * Pauses traffic capture.
     */
    public void pause() {
        this.paused = true;
    }
    
    /**
     * Resumes traffic capture.
     */
    public void resume() {
        this.paused = false;
    }
    
    /**
     * Checks if capture is currently paused.
     * 
     * @return True if paused, false otherwise
     */
    public boolean isPaused() {
        return paused;
    }
    
    /**
     * Shuts down the background executor.
     * Should be called when the extension is unloaded.
     */
    public void shutdown() {
        executor.shutdown();
    }
    
    /**
     * Creates an HttpTransaction from a Burp message.
     * 
     * @param messageInfo The Burp HTTP message
     * @return The created transaction, or null if parsing fails
     */
    private HttpTransaction createTransaction(IHttpRequestResponse messageInfo) {
        try {
            // Generate unique ID
            String id = UUID.randomUUID().toString();
            
            // Get current timestamp
            long timestamp = System.currentTimeMillis();
            
            // Extract request metadata
            byte[] request = messageInfo.getRequest();
            if (request == null) {
                return null;
            }
            
            IRequestInfo requestInfo = helpers.analyzeRequest(request);
            String method = extractMethod(requestInfo);
            String path = extractUrl(request);
            
            // Build full URL with host information from IHttpService
            String fullUrl = buildFullUrl(messageInfo, path);
            
            // Extract response metadata
            byte[] response = messageInfo.getResponse();
            if (response == null) {
                return null; // Skip incomplete transactions
            }
            
            IResponseInfo responseInfo = helpers.analyzeResponse(response);
            int statusCode = extractStatusCode(responseInfo);
            String contentType = extractContentType(responseInfo);
            long responseSize = response.length - responseInfo.getBodyOffset();
            
            // Create transaction
            return new HttpTransaction(
                id,
                timestamp,
                method,
                fullUrl,
                contentType,
                statusCode,
                responseSize,
                request,
                response,
                messageInfo
            );
            
        } catch (Exception e) {
            callbacks.printError("Error creating transaction: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Builds full URL from IHttpService and path.
     * 
     * @param messageInfo The HTTP message containing service info
     * @param path The request path
     * @return Full URL (e.g., https://example.com:443/api/users)
     */
    private String buildFullUrl(IHttpRequestResponse messageInfo, String path) {
        try {
            burp.IHttpService httpService = messageInfo.getHttpService();
            if (httpService == null) {
                return path;
            }
            
            String protocol = httpService.getProtocol();
            String host = httpService.getHost();
            int port = httpService.getPort();
            
            // Build URL
            StringBuilder url = new StringBuilder();
            url.append(protocol).append("://").append(host);
            
            // Add port if non-standard
            if ((protocol.equals("https") && port != 443) || 
                (protocol.equals("http") && port != 80)) {
                url.append(":").append(port);
            }
            
            // Add path
            if (!path.startsWith("/")) {
                url.append("/");
            }
            url.append(path);
            
            return url.toString();
            
        } catch (Exception e) {
            return path;
        }
    }
    
    /**
     * Extracts the Content-Type header from a response.
     * 
     * @param responseInfo The response info
     * @return The content-type value, or null if not found
     */
    private String extractContentType(IResponseInfo responseInfo) {
        try {
            List<String> headers = responseInfo.getHeaders();
            if (headers == null) {
                return null;
            }
            
            for (String header : headers) {
                if (header.toLowerCase().startsWith("content-type:")) {
                    String value = header.substring(13).trim();
                    // Extract just the MIME type (before semicolon)
                    int semicolon = value.indexOf(';');
                    if (semicolon > 0) {
                        value = value.substring(0, semicolon).trim();
                    }
                    return value;
                }
            }
            
            return null;
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Extracts the HTTP method from request info.
     * 
     * @param requestInfo The request info
     * @return The HTTP method (GET, POST, etc.)
     */
    private String extractMethod(IRequestInfo requestInfo) {
        try {
            List<String> headers = requestInfo.getHeaders();
            if (headers != null && !headers.isEmpty()) {
                String firstLine = headers.get(0);
                String[] parts = firstLine.split(" ");
                if (parts.length > 0) {
                    return parts[0];
                }
            }
            return "GET";
        } catch (Exception e) {
            return "GET";
        }
    }
    
    /**
     * Extracts the status code from response info.
     * 
     * @param responseInfo The response info
     * @return The HTTP status code
     */
    private int extractStatusCode(IResponseInfo responseInfo) {
        try {
            List<String> headers = responseInfo.getHeaders();
            if (headers != null && !headers.isEmpty()) {
                String firstLine = headers.get(0);
                String[] parts = firstLine.split(" ");
                if (parts.length > 1) {
                    return Integer.parseInt(parts[1]);
                }
            }
            return 200;
        } catch (Exception e) {
            return 200;
        }
    }
    
    /**
     * Extracts the full URL from a request.
     * 
     * @param request The HTTP request bytes
     * @return The full URL
     */
    private String extractUrl(byte[] request) {
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(request);
            List<String> headers = requestInfo.getHeaders();
            if (headers != null && !headers.isEmpty()) {
                String firstLine = headers.get(0);
                String[] parts = firstLine.split(" ");
                if (parts.length > 1) {
                    return parts[1];
                }
            }
            return "unknown";
        } catch (Exception e) {
            return "unknown";
        }
    }
}
