package com.vista.security.model;

/**
 * Specific types of findings within each category.
 */
public enum FindingType {
    // Credentials
    API_KEY("API Key", FindingCategory.CREDENTIALS),
    PASSWORD("Password", FindingCategory.CREDENTIALS),
    USERNAME("Username", FindingCategory.CREDENTIALS),
    ACCESS_TOKEN("Access Token", FindingCategory.CREDENTIALS),
    SECRET_KEY("Secret Key", FindingCategory.CREDENTIALS),
    
    // Information Disclosure
    PRIVATE_IP("Private IP Address", FindingCategory.INFO_DISCLOSURE),
    INTERNAL_HOSTNAME("Internal Hostname", FindingCategory.INFO_DISCLOSURE),
    FILE_PATH("File Path", FindingCategory.INFO_DISCLOSURE),
    VERSION_INFO("Version Information", FindingCategory.INFO_DISCLOSURE),
    STACK_TRACE("Stack Trace", FindingCategory.INFO_DISCLOSURE),
    
    // Hidden Parameters
    HIDDEN_FIELD("Hidden Form Field", FindingCategory.HIDDEN_PARAMS),
    DISABLED_FIELD_URL("Disabled Field with URL", FindingCategory.HIDDEN_PARAMS),
    DEBUG_PARAMETER("Debug Parameter", FindingCategory.HIDDEN_PARAMS),
    ADMIN_FLAG("Admin Flag", FindingCategory.HIDDEN_PARAMS),
    
    // Encoded Data
    BASE64_SECRET("Base64 Encoded Secret", FindingCategory.ENCODED_DATA),
    JWT_TOKEN("JWT Token", FindingCategory.ENCODED_DATA),
    HEX_ENCODED("Hex Encoded Data", FindingCategory.ENCODED_DATA),
    URL_ENCODED_SECRET("URL Encoded Secret", FindingCategory.ENCODED_DATA),
    
    // Commented Data
    HTML_COMMENT_SECRET("HTML Comment Secret", FindingCategory.COMMENTED_DATA),
    JS_COMMENT_SECRET("JavaScript Comment Secret", FindingCategory.COMMENTED_DATA),
    SQL_COMMENT_DATA("SQL Comment Data", FindingCategory.COMMENTED_DATA),
    
    // General
    OTHER("Other Finding", FindingCategory.GENERAL);
    
    private final String displayName;
    private final FindingCategory category;
    
    FindingType(String displayName, FindingCategory category) {
        this.displayName = displayName;
        this.category = category;
    }
    
    public String getDisplayName() {
        return displayName;
    }
    
    public FindingCategory getCategory() {
        return category;
    }
    
    @Override
    public String toString() {
        return displayName;
    }
    
    /**
     * Parse type from string (case-insensitive).
     */
    public static FindingType fromString(String str) {
        if (str == null) return OTHER;
        
        String normalized = str.toUpperCase()
            .replace(" ", "_")
            .replace("-", "_")
            .replace("/", "_");
        
        try {
            return FindingType.valueOf(normalized);
        } catch (IllegalArgumentException e) {
            // Try matching display name
            for (FindingType type : values()) {
                if (type.displayName.equalsIgnoreCase(str)) {
                    return type;
                }
            }
            return OTHER;
        }
    }
}
