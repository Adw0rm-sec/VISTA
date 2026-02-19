package com.vista.security.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Represents a custom AI prompt template with variable substitution.
 * Templates allow users to customize AI behavior for different testing scenarios.
 */
public class PromptTemplate {
    
    private String id;
    private String name;
    private String category;
    private String author;
    private String description;
    private String systemPrompt;
    private String userPrompt;
    private boolean isBuiltIn;
    private boolean isActive;
    private TemplateMode mode;
    
    // AI Configuration Overrides (optional)
    private String modelOverride;
    private Double temperatureOverride;
    private Integer maxTokensOverride;
    
    // Metadata
    private long createdAt;
    private long modifiedAt;
    private int usageCount;
    private List<String> tags;
    
    /**
     * Constructor for creating new templates.
     */
    public PromptTemplate(String name, String category, String author, String description,
                         String systemPrompt, String userPrompt) {
        this(name, category, author, description, systemPrompt, userPrompt, TemplateMode.STANDARD);
    }
    
    /**
     * Constructor for creating new templates with mode.
     */
    public PromptTemplate(String name, String category, String author, String description,
                         String systemPrompt, String userPrompt, TemplateMode mode) {
        this.id = UUID.randomUUID().toString().substring(0, 8);
        this.name = name;
        this.category = category;
        this.author = author;
        this.description = description;
        this.systemPrompt = systemPrompt;
        this.userPrompt = userPrompt;
        this.isBuiltIn = false;
        this.isActive = true;
        this.mode = mode != null ? mode : TemplateMode.STANDARD;
        this.createdAt = System.currentTimeMillis();
        this.modifiedAt = System.currentTimeMillis();
        this.usageCount = 0;
        this.tags = new ArrayList<>();
    }
    
    /**
     * Full constructor for loading from storage.
     */
    public PromptTemplate(String id, String name, String category, String author, String description,
                         String systemPrompt, String userPrompt, boolean isBuiltIn, boolean isActive,
                         String modelOverride, Double temperatureOverride, Integer maxTokensOverride,
                         long createdAt, long modifiedAt, int usageCount, List<String> tags, TemplateMode mode) {
        this.id = id;
        this.name = name;
        this.category = category;
        this.author = author;
        this.description = description;
        this.systemPrompt = systemPrompt;
        this.userPrompt = userPrompt;
        this.isBuiltIn = isBuiltIn;
        this.isActive = isActive;
        this.mode = mode != null ? mode : TemplateMode.STANDARD;
        this.modelOverride = modelOverride;
        this.temperatureOverride = temperatureOverride;
        this.maxTokensOverride = maxTokensOverride;
        this.createdAt = createdAt;
        this.modifiedAt = modifiedAt;
        this.usageCount = usageCount;
        this.tags = tags != null ? tags : new ArrayList<>();
    }
    
    // Getters
    public String getId() { return id; }
    public String getName() { return name; }
    public String getCategory() { return category; }
    public String getAuthor() { return author; }
    public String getDescription() { return description; }
    public String getSystemPrompt() { return systemPrompt; }
    public String getUserPrompt() { return userPrompt; }
    public boolean isBuiltIn() { return isBuiltIn; }
    public boolean isActive() { return isActive; }
    public TemplateMode getMode() { return mode; }
    public String getModelOverride() { return modelOverride; }
    public Double getTemperatureOverride() { return temperatureOverride; }
    public Integer getMaxTokensOverride() { return maxTokensOverride; }
    public long getCreatedAt() { return createdAt; }
    public long getModifiedAt() { return modifiedAt; }
    public int getUsageCount() { return usageCount; }
    public List<String> getTags() { return tags; }
    
    // Setters
    public void setName(String name) { 
        this.name = name; 
        this.modifiedAt = System.currentTimeMillis();
    }
    
    public void setCategory(String category) { 
        this.category = category;
        this.modifiedAt = System.currentTimeMillis();
    }
    
    public void setAuthor(String author) { 
        this.author = author;
        this.modifiedAt = System.currentTimeMillis();
    }
    
    public void setDescription(String description) { 
        this.description = description;
        this.modifiedAt = System.currentTimeMillis();
    }
    
    public void setSystemPrompt(String systemPrompt) { 
        this.systemPrompt = systemPrompt;
        this.modifiedAt = System.currentTimeMillis();
    }
    
    public void setUserPrompt(String userPrompt) { 
        this.userPrompt = userPrompt;
        this.modifiedAt = System.currentTimeMillis();
    }
    
    public void setActive(boolean active) { 
        this.isActive = active;
        this.modifiedAt = System.currentTimeMillis();
    }
    
    public void setModelOverride(String modelOverride) { 
        this.modelOverride = modelOverride;
        this.modifiedAt = System.currentTimeMillis();
    }
    
    public void setTemperatureOverride(Double temperatureOverride) { 
        this.temperatureOverride = temperatureOverride;
        this.modifiedAt = System.currentTimeMillis();
    }
    
    public void setMaxTokensOverride(Integer maxTokensOverride) { 
        this.maxTokensOverride = maxTokensOverride;
        this.modifiedAt = System.currentTimeMillis();
    }
    
    public void setMode(TemplateMode mode) {
        this.mode = mode != null ? mode : TemplateMode.STANDARD;
        this.modifiedAt = System.currentTimeMillis();
    }
    
    public void setTags(List<String> tags) { 
        this.tags = tags;
        this.modifiedAt = System.currentTimeMillis();
    }
    
    public void addTag(String tag) {
        if (!this.tags.contains(tag)) {
            this.tags.add(tag);
            this.modifiedAt = System.currentTimeMillis();
        }
    }
    
    public void removeTag(String tag) {
        this.tags.remove(tag);
        this.modifiedAt = System.currentTimeMillis();
    }
    
    public void incrementUsageCount() {
        this.usageCount++;
        this.modifiedAt = System.currentTimeMillis();
    }
    
    public String getFormattedCreatedAt() {
        return LocalDateTime.ofInstant(
            java.time.Instant.ofEpochMilli(createdAt),
            java.time.ZoneId.systemDefault()
        ).format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"));
    }
    
    public String getFormattedModifiedAt() {
        return LocalDateTime.ofInstant(
            java.time.Instant.ofEpochMilli(modifiedAt),
            java.time.ZoneId.systemDefault()
        ).format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"));
    }
    
    @Override
    public String toString() {
        return name + (isBuiltIn ? " [Built-in]" : "");
    }
    
    /**
     * Create a copy of this template.
     */
    public PromptTemplate copy() {
        PromptTemplate copy = new PromptTemplate(
            name + " (Copy)",
            category,
            author,
            description,
            systemPrompt,
            userPrompt,
            mode
        );
        copy.tags = new ArrayList<>(this.tags);
        copy.modelOverride = this.modelOverride;
        copy.temperatureOverride = this.temperatureOverride;
        copy.maxTokensOverride = this.maxTokensOverride;
        return copy;
    }
    
    /**
     * Convert to JSON string for storage.
     */
    public String toJson() {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"id\": \"").append(escapeJson(id)).append("\",\n");
        json.append("  \"name\": \"").append(escapeJson(name)).append("\",\n");
        json.append("  \"category\": \"").append(escapeJson(category)).append("\",\n");
        json.append("  \"author\": \"").append(escapeJson(author)).append("\",\n");
        json.append("  \"description\": \"").append(escapeJson(description)).append("\",\n");
        json.append("  \"systemPrompt\": \"").append(escapeJson(systemPrompt)).append("\",\n");
        json.append("  \"userPrompt\": \"").append(escapeJson(userPrompt)).append("\",\n");
        json.append("  \"isBuiltIn\": ").append(isBuiltIn).append(",\n");
        json.append("  \"isActive\": ").append(isActive).append(",\n");
        json.append("  \"mode\": \"").append(mode.name()).append("\",\n");
        json.append("  \"modelOverride\": ").append(modelOverride != null ? "\"" + escapeJson(modelOverride) + "\"" : "null").append(",\n");
        json.append("  \"temperatureOverride\": ").append(temperatureOverride).append(",\n");
        json.append("  \"maxTokensOverride\": ").append(maxTokensOverride).append(",\n");
        json.append("  \"createdAt\": ").append(createdAt).append(",\n");
        json.append("  \"modifiedAt\": ").append(modifiedAt).append(",\n");
        json.append("  \"usageCount\": ").append(usageCount).append(",\n");
        json.append("  \"tags\": [");
        for (int i = 0; i < tags.size(); i++) {
            json.append("\"").append(escapeJson(tags.get(i))).append("\"");
            if (i < tags.size() - 1) json.append(", ");
        }
        json.append("]\n");
        json.append("}");
        return json.toString();
    }
    
    /**
     * Parse from JSON string.
     */
    public static PromptTemplate fromJson(String json) {
        try {
            String id = extractJsonString(json, "id");
            String name = extractJsonString(json, "name");
            String category = extractJsonString(json, "category");
            String author = extractJsonString(json, "author");
            String description = extractJsonString(json, "description");
            String systemPrompt = extractJsonString(json, "systemPrompt");
            String userPrompt = extractJsonString(json, "userPrompt");
            boolean isBuiltIn = extractJsonBoolean(json, "isBuiltIn");
            boolean isActive = extractJsonBoolean(json, "isActive");
            String modeStr = extractJsonStringOrNull(json, "mode");
            TemplateMode mode = modeStr != null ? TemplateMode.fromString(modeStr) : TemplateMode.STANDARD;
            String modelOverride = extractJsonStringOrNull(json, "modelOverride");
            Double temperatureOverride = extractJsonDoubleOrNull(json, "temperatureOverride");
            Integer maxTokensOverride = extractJsonIntOrNull(json, "maxTokensOverride");
            long createdAt = extractJsonLong(json, "createdAt");
            long modifiedAt = extractJsonLong(json, "modifiedAt");
            int usageCount = extractJsonInt(json, "usageCount");
            List<String> tags = extractJsonStringArray(json, "tags");
            
            return new PromptTemplate(id, name, category, author, description, systemPrompt, userPrompt,
                isBuiltIn, isActive, modelOverride, temperatureOverride, maxTokensOverride,
                createdAt, modifiedAt, usageCount, tags, mode);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse PromptTemplate from JSON: " + e.getMessage(), e);
        }
    }
    
    // JSON parsing helpers
    private static String extractJsonString(String json, String key) {
        // Escaped-quote-aware string extraction
        String keyPattern = "\"" + key + "\"\\s*:\\s*\"";
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(keyPattern, java.util.regex.Pattern.DOTALL).matcher(json);
        if (m.find()) {
            int start = m.end();
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
    
    private static String extractJsonStringOrNull(String json, String key) {
        // Check for null first
        String nullPattern = "\"" + key + "\"\\s*:\\s*null";
        java.util.regex.Matcher nullM = java.util.regex.Pattern.compile(nullPattern).matcher(json);
        if (nullM.find()) return null;
        
        // Escaped-quote-aware string extraction
        String keyPattern = "\"" + key + "\"\\s*:\\s*\"";
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(keyPattern).matcher(json);
        if (m.find()) {
            int start = m.end();
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
        return null;
    }
    
    private static boolean extractJsonBoolean(String json, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*(true|false)";
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(pattern).matcher(json);
        return m.find() && "true".equals(m.group(1));
    }
    
    private static long extractJsonLong(String json, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*([0-9]+)";
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(pattern).matcher(json);
        return m.find() ? Long.parseLong(m.group(1)) : 0;
    }
    
    private static int extractJsonInt(String json, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*([0-9]+)";
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(pattern).matcher(json);
        return m.find() ? Integer.parseInt(m.group(1)) : 0;
    }
    
    private static Double extractJsonDoubleOrNull(String json, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*(null|([0-9.]+))";
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(pattern).matcher(json);
        if (m.find()) {
            String value = m.group(1);
            return "null".equals(value) ? null : Double.parseDouble(m.group(2));
        }
        return null;
    }
    
    private static Integer extractJsonIntOrNull(String json, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*(null|([0-9]+))";
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(pattern).matcher(json);
        if (m.find()) {
            String value = m.group(1);
            return "null".equals(value) ? null : Integer.parseInt(m.group(2));
        }
        return null;
    }
    
    private static List<String> extractJsonStringArray(String json, String key) {
        List<String> result = new ArrayList<>();
        String pattern = "\"" + key + "\"\\s*:\\s*\\[([^\\]]*)\\]";
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(pattern).matcher(json);
        if (m.find()) {
            String arrayContent = m.group(1);
            if (!arrayContent.trim().isEmpty()) {
                String[] items = arrayContent.split(",");
                for (String item : items) {
                    String cleaned = item.trim().replaceAll("^\"|\"$", "");
                    if (!cleaned.isEmpty()) {
                        result.add(unescapeJson(cleaned));
                    }
                }
            }
        }
        return result;
    }
    
    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
    
    private static String unescapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t")
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
    }
}
