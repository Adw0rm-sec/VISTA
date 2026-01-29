package com.vista.security.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Contains the complete results of a bypass operation
 */
public class BypassResult {
    private boolean successful;
    private String successfulPayload;
    private String successfulResponse;
    private int totalAttempts;
    private List<BypassAttempt> attempts = new ArrayList<>();
    private long totalTime;
    
    public boolean isSuccessful() { return successful; }
    public void setSuccessful(boolean successful) { this.successful = successful; }
    
    public String getSuccessfulPayload() { return successfulPayload; }
    public void setSuccessfulPayload(String payload) { this.successfulPayload = payload; }
    
    public String getSuccessfulResponse() { return successfulResponse; }
    public void setSuccessfulResponse(String response) { this.successfulResponse = response; }
    
    public int getTotalAttempts() { return totalAttempts; }
    public void setTotalAttempts(int total) { this.totalAttempts = total; }
    
    public List<BypassAttempt> getAttempts() { return attempts; }
    public void addAttempt(BypassAttempt attempt) { this.attempts.add(attempt); }
    
    public long getTotalTime() { return totalTime; }
    public void setTotalTime(long time) { this.totalTime = time; }
    
    public String getSummary() {
        if (successful) {
            return String.format("✓ Bypass found after %d attempts in %dms\nPayload: %s", 
                attempts.size(), totalTime, successfulPayload);
        } else {
            return String.format("✗ No bypass found after %d attempts in %dms", 
                totalAttempts, totalTime);
        }
    }
}
