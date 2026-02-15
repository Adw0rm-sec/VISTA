package com.vista.security.model;

/**
 * Categories for Traffic Monitor findings.
 * Used to group findings hierarchically in the UI.
 */
public enum FindingCategory {
    CREDENTIALS("Credentials", "🔑", "Hardcoded passwords, API keys, tokens, secrets"),
    INFO_DISCLOSURE("Information Disclosure", "ℹ️", "Private IPs, internal paths, version info"),
    HIDDEN_PARAMS("Hidden Parameters", "👁️", "Hidden form fields, disabled fields, debug params"),
    ENCODED_DATA("Encoded Data", "🔐", "Base64, JWT, Hex encoded sensitive data"),
    COMMENTED_DATA("Commented Data", "💬", "Secrets in HTML/JS/SQL comments"),
    GENERAL("General", "📋", "Other security findings");
    
    private final String displayName;
    private final String icon;
    private final String description;
    
    FindingCategory(String displayName, String icon, String description) {
        this.displayName = displayName;
        this.icon = icon;
        this.description = description;
    }
    
    public String getDisplayName() {
        return displayName;
    }
    
    public String getIcon() {
        return icon;
    }
    
    public String getDescription() {
        return description;
    }
    
    public String getDisplayNameWithIcon() {
        return icon + " " + displayName;
    }
    
    @Override
    public String toString() {
        return displayName;
    }
    
    /**
     * Parse category from string (case-insensitive).
     */
    public static FindingCategory fromString(String str) {
        if (str == null) return GENERAL;
        
        String normalized = str.toUpperCase().replace(" ", "_").replace("-", "_");
        
        try {
            return FindingCategory.valueOf(normalized);
        } catch (IllegalArgumentException e) {
            // Try matching display name
            for (FindingCategory cat : values()) {
                if (cat.displayName.equalsIgnoreCase(str)) {
                    return cat;
                }
            }
            return GENERAL;
        }
    }
}
