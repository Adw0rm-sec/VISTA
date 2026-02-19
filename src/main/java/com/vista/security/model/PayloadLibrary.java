package com.vista.security.model;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Represents a collection of payloads organized by category.
 * Can be built-in or custom.
 */
public class PayloadLibrary {
    
    private String id;
    private String name;               // e.g., "XSS - Reflected"
    private String category;           // e.g., "XSS", "SQLi", "SSTI"
    private String subcategory;        // e.g., "Reflected", "Stored", "DOM"
    private List<Payload> payloads;
    private boolean isBuiltIn;
    private String source;             // e.g., "PayloadsAllTheThings", "Custom"
    private String description;
    private List<String> tags;
    
    public PayloadLibrary(String name, String category, String subcategory) {
        this.id = UUID.randomUUID().toString();
        this.name = name;
        this.category = category;
        this.subcategory = subcategory;
        this.payloads = new ArrayList<>();
        this.isBuiltIn = false;
        this.source = "Custom";
        this.description = "";
        this.tags = new ArrayList<>();
    }
    
    // Getters
    public String getId() { return id; }
    public String getName() { return name; }
    public String getCategory() { return category; }
    public String getSubcategory() { return subcategory; }
    public List<Payload> getPayloads() { return payloads; }
    public boolean isBuiltIn() { return isBuiltIn; }
    public String getSource() { return source; }
    public String getDescription() { return description; }
    public List<String> getTags() { return tags; }
    
    // Setters
    public void setName(String name) { this.name = name; }
    public void setCategory(String category) { this.category = category; }
    public void setSubcategory(String subcategory) { this.subcategory = subcategory; }
    public void setBuiltIn(boolean builtIn) { isBuiltIn = builtIn; }
    public void setSource(String source) { this.source = source; }
    public void setDescription(String description) { this.description = description; }
    public void setTags(List<String> tags) { this.tags = tags; }
    
    /**
     * Add a payload to this library.
     */
    public void addPayload(Payload payload) {
        payloads.add(payload);
    }
    
    /**
     * Remove a payload from this library.
     */
    public void removePayload(String payloadId) {
        payloads.removeIf(p -> p.getId().equals(payloadId));
    }
    
    /**
     * Get payload by ID.
     */
    public Payload getPayload(String payloadId) {
        return payloads.stream()
            .filter(p -> p.getId().equals(payloadId))
            .findFirst()
            .orElse(null);
    }
    
    /**
     * Get payloads by context.
     */
    public List<Payload> getPayloadsByContext(String context) {
        return payloads.stream()
            .filter(p -> p.getContext().equals(context) || p.getContext().equals("any"))
            .collect(Collectors.toList());
    }
    
    /**
     * Get payloads sorted by success rate.
     */
    public List<Payload> getPayloadsBySuccessRate() {
        return payloads.stream()
            .sorted((p1, p2) -> Double.compare(p2.getSuccessRate(), p1.getSuccessRate()))
            .collect(Collectors.toList());
    }
    
    /**
     * Get top N payloads by success rate.
     */
    public List<Payload> getTopPayloads(int limit) {
        return getPayloadsBySuccessRate().stream()
            .limit(limit)
            .collect(Collectors.toList());
    }
    
    /**
     * Search payloads by query string.
     */
    public List<Payload> searchPayloads(String query) {
        String lowerQuery = query.toLowerCase();
        return payloads.stream()
            .filter(p -> p.getValue().toLowerCase().contains(lowerQuery) ||
                        p.getDescription().toLowerCase().contains(lowerQuery) ||
                        p.getTags().stream().anyMatch(tag -> tag.toLowerCase().contains(lowerQuery)))
            .collect(Collectors.toList());
    }
    
    /**
     * Get total number of payloads.
     */
    public int getPayloadCount() {
        return payloads.size();
    }
    
    /**
     * Get average success rate across all payloads.
     */
    public double getAverageSuccessRate() {
        if (payloads.isEmpty()) return 0.0;
        
        double sum = payloads.stream()
            .filter(Payload::hasBeenUsed)
            .mapToDouble(Payload::getSuccessRate)
            .sum();
        
        long usedCount = payloads.stream()
            .filter(Payload::hasBeenUsed)
            .count();
        
        return usedCount > 0 ? sum / usedCount : 0.0;
    }
    
    /**
     * Create a copy of this library.
     */
    public PayloadLibrary copy() {
        PayloadLibrary copy = new PayloadLibrary(
            this.name + " (Copy)",
            this.category,
            this.subcategory
        );
        copy.description = this.description;
        copy.tags = new ArrayList<>(this.tags);
        copy.source = "Custom";
        copy.isBuiltIn = false;
        
        // Copy payloads
        for (Payload payload : this.payloads) {
            copy.addPayload(payload.copy());
        }
        
        return copy;
    }
    
    /**
     * Convert to JSON string (manual serialization).
     */
    public String toJson() {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"id\": \"").append(escapeJson(id)).append("\",\n");
        json.append("  \"name\": \"").append(escapeJson(name)).append("\",\n");
        json.append("  \"category\": \"").append(escapeJson(category)).append("\",\n");
        json.append("  \"subcategory\": \"").append(escapeJson(subcategory)).append("\",\n");
        json.append("  \"description\": \"").append(escapeJson(description)).append("\",\n");
        json.append("  \"source\": \"").append(escapeJson(source)).append("\",\n");
        json.append("  \"isBuiltIn\": ").append(isBuiltIn).append(",\n");
        json.append("  \"tags\": [");
        for (int i = 0; i < tags.size(); i++) {
            json.append("\"").append(escapeJson(tags.get(i))).append("\"");
            if (i < tags.size() - 1) json.append(", ");
        }
        json.append("],\n");
        json.append("  \"payloads\": [\n");
        for (int i = 0; i < payloads.size(); i++) {
            String payloadJson = payloads.get(i).toJson();
            // Indent payload JSON
            String[] lines = payloadJson.split("\n");
            for (String line : lines) {
                json.append("    ").append(line).append("\n");
            }
            if (i < payloads.size() - 1) {
                json.append("    ,\n");
            }
        }
        json.append("  ]\n");
        json.append("}");
        return json.toString();
    }
    
    /**
     * Create from JSON string (manual deserialization).
     */
    public static PayloadLibrary fromJson(String json) {
        PayloadLibrary library = new PayloadLibrary("", "", "");
        
        library.id = extractString(json, "id");
        library.name = extractString(json, "name");
        library.category = extractString(json, "category");
        library.subcategory = extractString(json, "subcategory");
        library.description = extractString(json, "description");
        library.source = extractString(json, "source");
        library.isBuiltIn = extractBoolean(json, "isBuiltIn");
        library.tags = extractArray(json, "tags");
        
        // Extract payloads array
        library.payloads = extractPayloads(json);
        
        return library;
    }
    
    // JSON helper methods
    private static String extractString(String json, String key) {
        // Escaped-quote-aware string extraction
        String keyPattern = "\"" + key + "\"\\s*:\\s*\"";
        Pattern pattern = Pattern.compile(keyPattern);
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            int start = matcher.end(); // Position right after the opening quote
            StringBuilder sb = new StringBuilder();
            for (int i = start; i < json.length(); i++) {
                char c = json.charAt(i);
                if (c == '\\' && i + 1 < json.length()) {
                    sb.append(c);
                    sb.append(json.charAt(i + 1));
                    i++;
                } else if (c == '"') {
                    break;
                } else {
                    sb.append(c);
                }
            }
            return unescapeJson(sb.toString());
        }
        return "";
    }
    
    private static boolean extractBoolean(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*(true|false)");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return Boolean.parseBoolean(matcher.group(1));
        }
        return false;
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
    
    private static List<Payload> extractPayloads(String json) {
        List<Payload> payloads = new ArrayList<>();
        
        // Find the payloads array
        Pattern arrayPattern = Pattern.compile("\"payloads\"\\s*:\\s*\\[(.*?)\\]\\s*}", Pattern.DOTALL);
        Matcher arrayMatcher = arrayPattern.matcher(json);
        
        if (arrayMatcher.find()) {
            String payloadsJson = arrayMatcher.group(1);
            
            // Split by payload objects (simple approach - look for }{ pattern)
            int depth = 0;
            StringBuilder currentPayload = new StringBuilder();
            
            for (int i = 0; i < payloadsJson.length(); i++) {
                char c = payloadsJson.charAt(i);
                
                if (c == '{') {
                    depth++;
                    currentPayload.append(c);
                } else if (c == '}') {
                    currentPayload.append(c);
                    depth--;
                    
                    if (depth == 0 && currentPayload.length() > 0) {
                        String payloadJson = currentPayload.toString().trim();
                        if (!payloadJson.isEmpty()) {
                            try {
                                payloads.add(Payload.fromJson(payloadJson));
                            } catch (Exception e) {
                                // Skip malformed payload
                            }
                        }
                        currentPayload = new StringBuilder();
                    }
                } else if (depth > 0) {
                    currentPayload.append(c);
                }
            }
        }
        
        return payloads;
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
        return name + " (" + getPayloadCount() + " payloads)";
    }
}
