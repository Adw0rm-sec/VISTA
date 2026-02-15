package com.vista.security.model;

/**
 * Template mode indicating the level of expertise and detail.
 * 
 * STANDARD mode provides basic guidance (~150 tokens) suitable for common scenarios.
 * EXPERT mode provides comprehensive expertise (~500 tokens) with PortSwigger/OWASP
 * knowledge, bypass techniques, and troubleshooting guidance.
 */
public enum TemplateMode {
    /**
     * Standard templates with basic guidance (~150 tokens).
     * Fast, cost-effective, suitable for common scenarios.
     * Success rate: ~30%, Cost: $0.001/query
     */
    STANDARD("Standard", "📋", "Basic guidance for common scenarios"),
    
    /**
     * Expert templates with comprehensive expertise (~500 tokens).
     * Includes PortSwigger/OWASP knowledge, bypass techniques,
     * troubleshooting, and real-world examples.
     * Success rate: ~70%+, Cost: $0.003/query
     */
    EXPERT("Expert", "⭐", "Comprehensive expertise with PortSwigger knowledge");
    
    private final String displayName;
    private final String icon;
    private final String description;
    
    TemplateMode(String displayName, String icon, String description) {
        this.displayName = displayName;
        this.icon = icon;
        this.description = description;
    }
    
    /**
     * Get the display name for UI.
     */
    public String getDisplayName() {
        return displayName;
    }
    
    /**
     * Get the icon for UI display.
     */
    public String getIcon() {
        return icon;
    }
    
    /**
     * Get the description of this mode.
     */
    public String getDescription() {
        return description;
    }
    
    /**
     * Parse mode from string (case-insensitive).
     */
    public static TemplateMode fromString(String str) {
        if (str == null) return STANDARD;
        
        for (TemplateMode mode : values()) {
            if (mode.name().equalsIgnoreCase(str) || 
                mode.displayName.equalsIgnoreCase(str)) {
                return mode;
            }
        }
        return STANDARD;
    }
}
