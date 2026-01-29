package com.vista.security.model;

/**
 * Represents a single bypass attempt with its results
 */
public class BypassAttempt {
    private final String payload;
    private boolean successful;
    private int statusCode;
    private String response;
    private long responseTime;
    private String failureReason;
    
    public BypassAttempt(String payload) {
        this.payload = payload;
    }
    
    public String getPayload() { return payload; }
    
    public boolean isSuccessful() { return successful; }
    public void setSuccessful(boolean successful) { this.successful = successful; }
    
    public int getStatusCode() { return statusCode; }
    public void setStatusCode(int statusCode) { this.statusCode = statusCode; }
    
    public String getResponse() { return response; }
    public void setResponse(String response) { this.response = response; }
    
    public long getResponseTime() { return responseTime; }
    public void setResponseTime(long responseTime) { this.responseTime = responseTime; }
    
    public String getFailureReason() { return failureReason; }
    public void setFailureReason(String reason) { this.failureReason = reason; }
}
