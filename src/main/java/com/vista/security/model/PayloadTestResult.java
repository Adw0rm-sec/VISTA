package com.vista.security.model;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Represents the result of testing a payload against a target.
 * Used for tracking which payloads work and building success statistics.
 */
public class PayloadTestResult {
    
    private String id;
    private String payloadId;          // Reference to the payload
    private String payloadValue;       // Snapshot of payload value
    private String targetUrl;          // Target URL
    private String parameter;          // Parameter name where payload was used
    private boolean success;           // Whether the payload worked
    private String response;           // Response snippet (first 500 chars)
    private int statusCode;            // HTTP status code
    private long timestamp;            // When the test was performed
    private String notes;              // User notes about the test
    
    public PayloadTestResult(String payloadId, String payloadValue, String targetUrl, 
                            String parameter, boolean success) {
        this.id = UUID.randomUUID().toString();
        this.payloadId = payloadId;
        this.payloadValue = payloadValue;
        this.targetUrl = targetUrl;
        this.parameter = parameter;
        this.success = success;
        this.response = "";
        this.statusCode = 0;
        this.timestamp = System.currentTimeMillis();
        this.notes = "";
    }
    
    // Getters
    public String getId() { return id; }
    public String getPayloadId() { return payloadId; }
    public String getPayloadValue() { return payloadValue; }
    public String getTargetUrl() { return targetUrl; }
    public String getParameter() { return parameter; }
    public boolean isSuccess() { return success; }
    public String getResponse() { return response; }
    public int getStatusCode() { return statusCode; }
    public long getTimestamp() { return timestamp; }
    public String getNotes() { return notes; }
    
    // Setters
    public void setResponse(String response) {
        // Store only first 500 chars to save space
        if (response != null && response.length() > 500) {
            this.response = response.substring(0, 500) + "...";
        } else {
            this.response = response;
        }
    }
    
    public void setStatusCode(int statusCode) { this.statusCode = statusCode; }
    public void setNotes(String notes) { this.notes = notes; }
    
    /**
     * Get formatted timestamp.
     */
    public String getFormattedTimestamp() {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return sdf.format(new Date(timestamp));
    }
    
    /**
     * Get relative time (e.g., "2 hours ago").
     */
    public String getRelativeTime() {
        long diff = System.currentTimeMillis() - timestamp;
        long seconds = diff / 1000;
        long minutes = seconds / 60;
        long hours = minutes / 60;
        long days = hours / 24;
        
        if (days > 0) {
            return days + " day" + (days > 1 ? "s" : "") + " ago";
        } else if (hours > 0) {
            return hours + " hour" + (hours > 1 ? "s" : "") + " ago";
        } else if (minutes > 0) {
            return minutes + " minute" + (minutes > 1 ? "s" : "") + " ago";
        } else {
            return "Just now";
        }
    }
    
    /**
     * Get success indicator emoji.
     */
    public String getSuccessIndicator() {
        return success ? "✓" : "✗";
    }
    
    /**
     * Get display string for this result.
     */
    public String getDisplayString() {
        return String.format("%s %s on %s [%d] - %s",
            getSuccessIndicator(),
            parameter,
            targetUrl,
            statusCode,
            getRelativeTime());
    }
    
    /**
     * Convert to JSON string (manual serialization).
     */
    public String toJson() {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"id\": \"").append(escapeJson(id)).append("\",\n");
        json.append("  \"payloadId\": \"").append(escapeJson(payloadId)).append("\",\n");
        json.append("  \"payloadValue\": \"").append(escapeJson(payloadValue)).append("\",\n");
        json.append("  \"targetUrl\": \"").append(escapeJson(targetUrl)).append("\",\n");
        json.append("  \"parameter\": \"").append(escapeJson(parameter)).append("\",\n");
        json.append("  \"success\": ").append(success).append(",\n");
        json.append("  \"response\": \"").append(escapeJson(response)).append("\",\n");
        json.append("  \"statusCode\": ").append(statusCode).append(",\n");
        json.append("  \"timestamp\": ").append(timestamp).append(",\n");
        json.append("  \"notes\": \"").append(escapeJson(notes)).append("\"\n");
        json.append("}");
        return json.toString();
    }
    
    /**
     * Create from JSON string (manual deserialization).
     */
    public static PayloadTestResult fromJson(String json) {
        String payloadId = extractString(json, "payloadId");
        String payloadValue = extractString(json, "payloadValue");
        String targetUrl = extractString(json, "targetUrl");
        String parameter = extractString(json, "parameter");
        boolean success = extractBoolean(json, "success");
        
        PayloadTestResult result = new PayloadTestResult(payloadId, payloadValue, targetUrl, parameter, success);
        
        result.response = extractString(json, "response");
        result.statusCode = extractInt(json, "statusCode");
        result.timestamp = extractLong(json, "timestamp");
        result.notes = extractString(json, "notes");
        
        return result;
    }
    
    // JSON helper methods
    private static String extractString(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return unescapeJson(matcher.group(1));
        }
        return "";
    }
    
    private static int extractInt(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return Integer.parseInt(matcher.group(1));
        }
        return 0;
    }
    
    private static long extractLong(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return Long.parseLong(matcher.group(1));
        }
        return 0L;
    }
    
    private static boolean extractBoolean(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*(true|false)");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return Boolean.parseBoolean(matcher.group(1));
        }
        return false;
    }
    
    private static String escapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }
    
    private static String unescapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\\"", "\"")
                  .replace("\\\\", "\\")
                  .replace("\\n", "\n")
                  .replace("\\r", "\r")
                  .replace("\\t", "\t");
    }
    
    @Override
    public String toString() {
        return getDisplayString();
    }
}
