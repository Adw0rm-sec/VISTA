package com.vista.security.model;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Represents a single payload in the payload library.
 * Tracks usage statistics and success rate.
 */
public class Payload {
    
    private String id;
    private String value;              // Actual payload string
    private String description;        // Human-readable description
    private List<String> tags;         // Tags for categorization
    private String encoding;           // none, url, base64, double-url, etc.
    private String context;            // html-body, html-attribute, javascript, etc.
    private int successCount;          // Number of successful uses
    private int failureCount;          // Number of failed uses
    private double successRate;        // Calculated success rate (0-100)
    private long lastUsed;             // Timestamp of last use
    private String notes;              // Additional notes
    
    public Payload(String value, String description) {
        this.id = UUID.randomUUID().toString();
        this.value = value;
        this.description = description;
        this.tags = new ArrayList<>();
        this.encoding = "none";
        this.context = "any";
        this.successCount = 0;
        this.failureCount = 0;
        this.successRate = 0.0;
        this.lastUsed = 0;
        this.notes = "";
    }
    
    // Getters
    public String getId() { return id; }
    public String getValue() { return value; }
    public String getDescription() { return description; }
    public List<String> getTags() { return tags; }
    public String getEncoding() { return encoding; }
    public String getContext() { return context; }
    public int getSuccessCount() { return successCount; }
    public int getFailureCount() { return failureCount; }
    public double getSuccessRate() { return successRate; }
    public long getLastUsed() { return lastUsed; }
    public String getNotes() { return notes; }
    
    // Setters
    public void setValue(String value) { this.value = value; }
    public void setDescription(String description) { this.description = description; }
    public void setTags(List<String> tags) { this.tags = tags; }
    public void setEncoding(String encoding) { this.encoding = encoding; }
    public void setContext(String context) { this.context = context; }
    public void setNotes(String notes) { this.notes = notes; }
    public void setSuccessCount(int successCount) { this.successCount = successCount; updateSuccessRate(); }
    public void setFailureCount(int failureCount) { this.failureCount = failureCount; updateSuccessRate(); }
    public void setLastUsed(long lastUsed) { this.lastUsed = lastUsed; }
    
    /**
     * Add a tag to this payload.
     */
    public void addTag(String tag) {
        if (!tags.contains(tag)) {
            tags.add(tag);
        }
    }
    
    /**
     * Record a successful use of this payload.
     */
    public void recordSuccess() {
        successCount++;
        lastUsed = System.currentTimeMillis();
        updateSuccessRate();
    }
    
    /**
     * Record a failed use of this payload.
     */
    public void recordFailure() {
        failureCount++;
        lastUsed = System.currentTimeMillis();
        updateSuccessRate();
    }
    
    /**
     * Update the success rate based on success/failure counts.
     */
    private void updateSuccessRate() {
        int total = successCount + failureCount;
        if (total > 0) {
            successRate = (double) successCount / total * 100.0;
        } else {
            successRate = 0.0;
        }
    }
    
    /**
     * Get total number of uses.
     */
    public int getTotalUses() {
        return successCount + failureCount;
    }
    
    /**
     * Check if this payload has been used.
     */
    public boolean hasBeenUsed() {
        return getTotalUses() > 0;
    }
    
    /**
     * Get a display string for success rate.
     */
    public String getSuccessRateDisplay() {
        if (getTotalUses() == 0) {
            return "Not used";
        }
        return String.format("%.1f%% (%d/%d)", successRate, successCount, getTotalUses());
    }
    
    /**
     * Create a copy of this payload.
     */
    public Payload copy() {
        Payload copy = new Payload(this.value, this.description + " (Copy)");
        copy.tags = new ArrayList<>(this.tags);
        copy.encoding = this.encoding;
        copy.context = this.context;
        copy.notes = this.notes;
        // Don't copy statistics
        return copy;
    }
    
    /**
     * Convert to JSON string (manual serialization).
     */
    public String toJson() {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"id\": \"").append(escapeJson(id)).append("\",\n");
        json.append("  \"value\": \"").append(escapeJson(value)).append("\",\n");
        json.append("  \"description\": \"").append(escapeJson(description)).append("\",\n");
        json.append("  \"tags\": [");
        for (int i = 0; i < tags.size(); i++) {
            json.append("\"").append(escapeJson(tags.get(i))).append("\"");
            if (i < tags.size() - 1) json.append(", ");
        }
        json.append("],\n");
        json.append("  \"encoding\": \"").append(escapeJson(encoding)).append("\",\n");
        json.append("  \"context\": \"").append(escapeJson(context)).append("\",\n");
        json.append("  \"successCount\": ").append(successCount).append(",\n");
        json.append("  \"failureCount\": ").append(failureCount).append(",\n");
        json.append("  \"successRate\": ").append(successRate).append(",\n");
        json.append("  \"lastUsed\": ").append(lastUsed).append(",\n");
        json.append("  \"notes\": \"").append(escapeJson(notes)).append("\"\n");
        json.append("}");
        return json.toString();
    }
    
    /**
     * Create from JSON string (manual deserialization).
     */
    public static Payload fromJson(String json) {
        Payload payload = new Payload("", "");
        
        payload.id = extractString(json, "id");
        payload.value = extractString(json, "value");
        payload.description = extractString(json, "description");
        payload.encoding = extractString(json, "encoding");
        payload.context = extractString(json, "context");
        payload.notes = extractString(json, "notes");
        
        payload.successCount = extractInt(json, "successCount");
        payload.failureCount = extractInt(json, "failureCount");
        payload.successRate = extractDouble(json, "successRate");
        payload.lastUsed = extractLong(json, "lastUsed");
        
        payload.tags = extractArray(json, "tags");
        
        return payload;
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
    
    private static double extractDouble(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*([\\d.]+)");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return Double.parseDouble(matcher.group(1));
        }
        return 0.0;
    }
    
    private static List<String> extractArray(String json, String key) {
        List<String> result = new ArrayList<>();
        Pattern pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*\\[([^\\]]*)\\]");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            String arrayContent = matcher.group(1);
            Pattern itemPattern = Pattern.compile("\"([^\"]*)\"");
            Matcher itemMatcher = itemPattern.matcher(arrayContent);
            while (itemMatcher.find()) {
                result.add(unescapeJson(itemMatcher.group(1)));
            }
        }
        return result;
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
        return value + " (" + getSuccessRateDisplay() + ")";
    }
}
