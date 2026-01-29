package com.vista.security.model;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Represents a collection of related HTTP requests.
 * Used for organizing and analyzing similar requests together.
 */
public class RequestCollection {
    
    private String id;
    private String name;
    private String description;
    private List<CollectionItem> items;
    private long created;
    private long modified;
    private List<String> tags;
    
    public RequestCollection(String name, String description) {
        this.id = UUID.randomUUID().toString();
        this.name = name;
        this.description = description;
        this.items = new ArrayList<>();
        this.created = System.currentTimeMillis();
        this.modified = System.currentTimeMillis();
        this.tags = new ArrayList<>();
    }
    
    // Getters
    public String getId() { return id; }
    public String getName() { return name; }
    public String getDescription() { return description; }
    public List<CollectionItem> getItems() { return items; }
    public long getCreated() { return created; }
    public long getModified() { return modified; }
    public List<String> getTags() { return tags; }
    
    // Setters
    public void setName(String name) { 
        this.name = name;
        this.modified = System.currentTimeMillis();
    }
    
    public void setDescription(String description) { 
        this.description = description;
        this.modified = System.currentTimeMillis();
    }
    
    public void setTags(List<String> tags) { this.tags = tags; }
    
    // Item management
    public void addItem(CollectionItem item) {
        items.add(item);
        modified = System.currentTimeMillis();
    }
    
    public void removeItem(String itemId) {
        items.removeIf(item -> item.getId().equals(itemId));
        modified = System.currentTimeMillis();
    }
    
    public CollectionItem getItem(String itemId) {
        return items.stream()
            .filter(item -> item.getId().equals(itemId))
            .findFirst()
            .orElse(null);
    }
    
    public int getItemCount() {
        return items.size();
    }
    
    public int getTestedCount() {
        return (int) items.stream().filter(CollectionItem::isTested).count();
    }
    
    public int getSuccessCount() {
        return (int) items.stream().filter(CollectionItem::isSuccess).count();
    }
    
    // Manual JSON serialization
    public String toJson() {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"id\": \"").append(escapeJson(id)).append("\",\n");
        json.append("  \"name\": \"").append(escapeJson(name)).append("\",\n");
        json.append("  \"description\": \"").append(escapeJson(description)).append("\",\n");
        json.append("  \"created\": ").append(created).append(",\n");
        json.append("  \"modified\": ").append(modified).append(",\n");
        json.append("  \"tags\": [");
        for (int i = 0; i < tags.size(); i++) {
            json.append("\"").append(escapeJson(tags.get(i))).append("\"");
            if (i < tags.size() - 1) json.append(", ");
        }
        json.append("],\n");
        json.append("  \"items\": [\n");
        for (int i = 0; i < items.size(); i++) {
            String itemJson = items.get(i).toJson();
            String[] lines = itemJson.split("\n");
            for (String line : lines) {
                json.append("    ").append(line).append("\n");
            }
            if (i < items.size() - 1) {
                json.append("    ,\n");
            }
        }
        json.append("  ]\n");
        json.append("}");
        return json.toString();
    }
    
    public static RequestCollection fromJson(String json) {
        RequestCollection collection = new RequestCollection("", "");
        
        collection.id = extractString(json, "id");
        collection.name = extractString(json, "name");
        collection.description = extractString(json, "description");
        collection.created = extractLong(json, "created");
        collection.modified = extractLong(json, "modified");
        collection.tags = extractArray(json, "tags");
        collection.items = extractItems(json);
        
        return collection;
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
    
    private static long extractLong(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return Long.parseLong(matcher.group(1));
        }
        return 0L;
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
    
    private static List<CollectionItem> extractItems(String json) {
        List<CollectionItem> items = new ArrayList<>();
        
        Pattern arrayPattern = Pattern.compile("\"items\"\\s*:\\s*\\[(.*?)\\]\\s*}", Pattern.DOTALL);
        Matcher arrayMatcher = arrayPattern.matcher(json);
        
        if (arrayMatcher.find()) {
            String itemsJson = arrayMatcher.group(1);
            
            int depth = 0;
            StringBuilder currentItem = new StringBuilder();
            
            for (int i = 0; i < itemsJson.length(); i++) {
                char c = itemsJson.charAt(i);
                
                if (c == '{') {
                    depth++;
                    currentItem.append(c);
                } else if (c == '}') {
                    currentItem.append(c);
                    depth--;
                    
                    if (depth == 0 && currentItem.length() > 0) {
                        String itemJson = currentItem.toString().trim();
                        if (!itemJson.isEmpty()) {
                            try {
                                items.add(CollectionItem.fromJson(itemJson));
                            } catch (Exception e) {
                                // Skip malformed item
                            }
                        }
                        currentItem = new StringBuilder();
                    }
                } else if (depth > 0) {
                    currentItem.append(c);
                }
            }
        }
        
        return items;
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
        return name + " (" + items.size() + " requests)";
    }
}
