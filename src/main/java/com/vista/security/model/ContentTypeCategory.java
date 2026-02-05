package com.vista.security.model;

/**
 * Enumeration of content type categories for filtering HTTP traffic.
 * Each category can match based on Content-Type header or URL file extension.
 */
public enum ContentTypeCategory {
    JAVASCRIPT("JavaScript", "application/javascript", "text/javascript", ".js"),
    XML("XML", "application/xml", "text/xml", ".xml"),
    JSON("JSON", "application/json", ".json"),
    CSS("CSS", "text/css", ".css"),
    IMAGES("Images", "image/", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp"),
    FONTS("Fonts", "font/", "application/font", ".woff", ".woff2", ".ttf", ".otf", ".eot");
    
    private final String displayName;
    private final String[] patterns;
    
    ContentTypeCategory(String displayName, String... patterns) {
        this.displayName = displayName;
        this.patterns = patterns;
    }
    
    /**
     * Returns the display name for UI.
     */
    public String getDisplayName() {
        return displayName;
    }
    
    /**
     * Checks if this category matches the given content-type header and URL.
     * 
     * @param contentType Content-Type header value (can be null)
     * @param url Request URL (can be null)
     * @return true if matches, false otherwise
     */
    public boolean matches(String contentType, String url) {
        if (contentType == null && url == null) {
            return false;
        }
        
        // Check Content-Type header
        if (contentType != null) {
            String lowerContentType = contentType.toLowerCase();
            for (String pattern : patterns) {
                if (!pattern.startsWith(".") && lowerContentType.contains(pattern.toLowerCase())) {
                    return true;
                }
            }
        }
        
        // Check URL file extension
        if (url != null) {
            String lowerUrl = url.toLowerCase();
            for (String pattern : patterns) {
                if (pattern.startsWith(".") && lowerUrl.endsWith(pattern)) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Returns all patterns for this category.
     */
    public String[] getPatterns() {
        return patterns.clone();
    }
}
