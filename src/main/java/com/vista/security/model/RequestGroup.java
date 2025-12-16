package com.vista.security.model;

import burp.IHttpRequestResponse;

import java.awt.Color;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Represents a group of related requests with custom name and color.
 * Allows users to organize requests by feature, endpoint, or test scenario.
 */
public class RequestGroup {
    
    private final String id;
    private String name;
    private Color color;
    private final List<IHttpRequestResponse> requests;
    private String description;
    private boolean expanded;
    
    // Predefined colors for quick selection
    public static final Color[] PRESET_COLORS = {
        new Color(231, 76, 60),    // Red
        new Color(230, 126, 34),   // Orange
        new Color(241, 196, 15),   // Yellow
        new Color(46, 204, 113),   // Green
        new Color(52, 152, 219),   // Blue
        new Color(155, 89, 182),   // Purple
        new Color(149, 165, 166),  // Gray
        new Color(52, 73, 94),     // Dark Blue
        new Color(26, 188, 156),   // Teal
        new Color(236, 240, 241),  // Light Gray
    };
    
    public static final String[] COLOR_NAMES = {
        "Red", "Orange", "Yellow", "Green", "Blue", 
        "Purple", "Gray", "Dark Blue", "Teal", "Light"
    };
    
    public RequestGroup(String name, Color color) {
        this.id = UUID.randomUUID().toString().substring(0, 8);
        this.name = name;
        this.color = color;
        this.requests = new ArrayList<>();
        this.expanded = true;
    }
    
    public RequestGroup(String name, int colorIndex) {
        this(name, PRESET_COLORS[colorIndex % PRESET_COLORS.length]);
    }
    
    // Getters and setters
    public String getId() { return id; }
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public Color getColor() { return color; }
    public void setColor(Color color) { this.color = color; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public boolean isExpanded() { return expanded; }
    public void setExpanded(boolean expanded) { this.expanded = expanded; }
    
    public List<IHttpRequestResponse> getRequests() { return requests; }
    
    public void addRequest(IHttpRequestResponse request) {
        if (!requests.contains(request)) {
            requests.add(request);
        }
    }
    
    public void removeRequest(IHttpRequestResponse request) {
        requests.remove(request);
    }
    
    public boolean containsRequest(IHttpRequestResponse request) {
        return requests.contains(request);
    }
    
    public int getRequestCount() {
        return requests.size();
    }
    
    public void clear() {
        requests.clear();
    }
    
    /**
     * Get a contrasting text color for this group's background.
     */
    public Color getTextColor() {
        // Calculate luminance
        double luminance = (0.299 * color.getRed() + 0.587 * color.getGreen() + 0.114 * color.getBlue()) / 255;
        return luminance > 0.5 ? Color.BLACK : Color.WHITE;
    }
    
    /**
     * Get a lighter version of the color for backgrounds.
     */
    public Color getLightColor() {
        return new Color(
            Math.min(255, color.getRed() + 40),
            Math.min(255, color.getGreen() + 40),
            Math.min(255, color.getBlue() + 40),
            80 // Semi-transparent
        );
    }
    
    @Override
    public String toString() {
        return name + " (" + requests.size() + ")";
    }
    
    @Override
    public boolean equals(Object obj) {
        if (obj instanceof RequestGroup other) {
            return this.id.equals(other.id);
        }
        return false;
    }
    
    @Override
    public int hashCode() {
        return id.hashCode();
    }
    
    /**
     * Serialize group to JSON-like string for persistence.
     */
    public String toJson() {
        return String.format("{\"id\":\"%s\",\"name\":\"%s\",\"color\":\"%d,%d,%d\",\"desc\":\"%s\"}",
            id, escape(name), color.getRed(), color.getGreen(), color.getBlue(),
            description != null ? escape(description) : "");
    }
    
    /**
     * Create group from JSON-like string.
     */
    public static RequestGroup fromJson(String json) {
        try {
            String name = extractValue(json, "name");
            String colorStr = extractValue(json, "color");
            String[] rgb = colorStr.split(",");
            Color color = new Color(
                Integer.parseInt(rgb[0]),
                Integer.parseInt(rgb[1]),
                Integer.parseInt(rgb[2])
            );
            RequestGroup group = new RequestGroup(name, color);
            group.description = extractValue(json, "desc");
            return group;
        } catch (Exception e) {
            return null;
        }
    }
    
    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
    
    private static String extractValue(String json, String key) {
        String pattern = "\"" + key + "\":\"";
        int start = json.indexOf(pattern);
        if (start < 0) return "";
        start += pattern.length();
        int end = json.indexOf("\"", start);
        if (end < 0) return "";
        return json.substring(start, end).replace("\\n", "\n").replace("\\\"", "\"");
    }
}
