package com.vista.security.core;

import burp.IHttpRequestResponse;

import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * Tracks requests sent from Burp Repeater for easy attachment to Interactive Assistant.
 * Maintains a history of recent Repeater requests that users can select from.
 */
public class RepeaterRequestTracker {
    
    private static RepeaterRequestTracker instance;
    private final Deque<RepeaterRequest> recentRequests;
    private static final int MAX_HISTORY = 50; // Keep last 50 requests
    
    private RepeaterRequestTracker() {
        this.recentRequests = new ConcurrentLinkedDeque<>();
    }
    
    public static synchronized RepeaterRequestTracker getInstance() {
        if (instance == null) {
            instance = new RepeaterRequestTracker();
        }
        return instance;
    }
    
    /**
     * Adds a request from Repeater to the history
     */
    public void addRequest(IHttpRequestResponse requestResponse, String url) {
        RepeaterRequest req = new RepeaterRequest(requestResponse, url);
        
        // Add to front of deque
        recentRequests.addFirst(req);
        
        // Remove oldest if exceeds max
        while (recentRequests.size() > MAX_HISTORY) {
            recentRequests.removeLast();
        }
    }
    
    /**
     * Gets all recent requests for display in dropdown
     */
    public List<RepeaterRequest> getRecentRequests() {
        return new ArrayList<>(recentRequests);
    }
    
    /**
     * Gets a specific request by index
     */
    public RepeaterRequest getRequest(int index) {
        if (index < 0 || index >= recentRequests.size()) {
            return null;
        }
        return new ArrayList<>(recentRequests).get(index);
    }
    
    /**
     * Clears all history
     */
    public void clear() {
        recentRequests.clear();
    }
    
    /**
     * Represents a request from Repeater with metadata
     */
    public static class RepeaterRequest {
        private final IHttpRequestResponse requestResponse;
        private final String url;
        private final long timestamp;
        private final String method;
        private final int statusCode;
        
        public RepeaterRequest(IHttpRequestResponse requestResponse, String url) {
            this.requestResponse = requestResponse;
            this.url = url;
            this.timestamp = System.currentTimeMillis();
            
            // Extract method from first line of request
            byte[] request = requestResponse.getRequest();
            if (request != null && request.length > 0) {
                String requestStr = new String(request, 0, Math.min(100, request.length));
                String[] parts = requestStr.split(" ");
                this.method = parts.length > 0 ? parts[0] : "GET";
            } else {
                this.method = "GET";
            }
            
            // Extract status code from response
            byte[] response = requestResponse.getResponse();
            if (response != null && response.length > 12) {
                String statusLine = new String(response, 0, Math.min(50, response.length));
                String[] parts = statusLine.split(" ");
                int code = 0;
                if (parts.length >= 2) {
                    try {
                        code = Integer.parseInt(parts[1]);
                    } catch (NumberFormatException e) {
                        code = 0;
                    }
                }
                this.statusCode = code;
            } else {
                this.statusCode = 0;
            }
        }
        
        public IHttpRequestResponse getRequestResponse() {
            return requestResponse;
        }
        
        public String getUrl() {
            return url;
        }
        
        public long getTimestamp() {
            return timestamp;
        }
        
        public String getMethod() {
            return method;
        }
        
        public int getStatusCode() {
            return statusCode;
        }
        
        /**
         * Gets a display string for dropdown
         */
        public String getDisplayString() {
            SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
            String time = sdf.format(new Date(timestamp));
            
            // Truncate URL if too long
            String displayUrl = url;
            if (displayUrl.length() > 60) {
                displayUrl = displayUrl.substring(0, 57) + "...";
            }
            
            String statusStr = statusCode > 0 ? " [" + statusCode + "]" : "";
            
            return String.format("[%s] %s %s%s", time, method, displayUrl, statusStr);
        }
        
        @Override
        public String toString() {
            return getDisplayString();
        }
    }
}
