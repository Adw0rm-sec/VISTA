package com.vista.security.model;

import java.util.UUID;

/**
 * TrafficFinding represents an intelligent security finding discovered
 * through automated analysis of HTTP traffic.
 * 
 * Enhanced to support hierarchical display with:
 * - Domain grouping
 * - Category grouping (Credentials, Info Disclosure, etc.)
 * - Specific finding types (API Key, Private IP, etc.)
 * - Decoded data for encoded findings
 */
public class TrafficFinding {
    
    private final String id;
    private final String type; // SECRET, HIDDEN_URL, PARAMETER, SENSITIVE_DATA, TOKEN, DEBUG_CODE
    private final String severity; // CRITICAL, HIGH, MEDIUM, LOW, INFO
    private final String title;
    private final String description;
    private final String evidence; // The actual finding (code snippet, URL, etc.)
    private final HttpTransaction sourceTransaction;
    private final long timestamp;
    private final String category; // JavaScript, JSON Response, HTML Response, Request, Header
    private final String detectionEngine; // Pattern or AI
    
    // Enhanced fields for hierarchical display
    private final FindingCategory findingCategory; // Credentials, Info Disclosure, etc.
    private final FindingType findingType; // API Key, Private IP, etc.
    private final String location; // Response Body, Request Header, JavaScript, etc.
    private final String decodedData; // Decoded content if applicable
    private final String encodingType; // Base64, JWT, Hex, URL
    private final String domain; // Domain for grouping
    
    // New fields for enhanced UI
    private String affectedParameter; // Specific parameter/field name
    private String detailedDescription; // Full 2-3 sentence description
    private String impact; // Impact assessment
    private String remediation; // How to fix
    
    /**
     * Creates a new TrafficFinding with enhanced hierarchical fields.
     * 
     * @param type The type of finding
     * @param severity The severity level
     * @param title The finding title
     * @param description The finding description
     * @param evidence The evidence (code snippet, URL, etc.)
     * @param sourceTransaction The source HTTP transaction
     * @param category The category (JavaScript, JSON, etc.)
     * @param detectionEngine The detection engine (Pattern or AI)
     * @param findingCategory The finding category for grouping
     * @param findingType The specific finding type
     * @param location The location in request/response
     * @param decodedData Decoded content if applicable
     * @param encodingType The encoding type if applicable
     */
    public TrafficFinding(String type, String severity, String title, String description,
                         String evidence, HttpTransaction sourceTransaction, String category,
                         String detectionEngine, FindingCategory findingCategory, 
                         FindingType findingType, String location, String decodedData, 
                         String encodingType) {
        this.id = UUID.randomUUID().toString();
        this.type = type;
        this.severity = severity;
        this.title = title;
        this.description = description;
        this.evidence = evidence;
        this.sourceTransaction = sourceTransaction;
        this.timestamp = System.currentTimeMillis();
        this.category = category;
        this.detectionEngine = detectionEngine;
        this.findingCategory = findingCategory != null ? findingCategory : FindingCategory.GENERAL;
        this.findingType = findingType != null ? findingType : FindingType.OTHER;
        this.location = location != null ? location : "Unknown";
        this.decodedData = decodedData;
        this.encodingType = encodingType;
        this.domain = extractDomain(sourceTransaction.getUrl());
    }
    
    /**
     * Creates a new TrafficFinding with enhanced fields (no encoding).
     */
    public TrafficFinding(String type, String severity, String title, String description,
                         String evidence, HttpTransaction sourceTransaction, String category,
                         String detectionEngine, FindingCategory findingCategory, 
                         FindingType findingType, String location) {
        this(type, severity, title, description, evidence, sourceTransaction, category,
             detectionEngine, findingCategory, findingType, location, null, null);
    }
    
    /**
     * Creates a new TrafficFinding with detection engine.
     * For backward compatibility with existing code.
     */
    public TrafficFinding(String type, String severity, String title, String description,
                         String evidence, HttpTransaction sourceTransaction, String category,
                         String detectionEngine) {
        this(type, severity, title, description, evidence, sourceTransaction, category,
             detectionEngine, FindingCategory.GENERAL, FindingType.OTHER, "Unknown", null, null);
    }
    
    /**
     * Creates a new TrafficFinding with default Pattern detection engine.
     * For backward compatibility.
     * 
     * @param type The type of finding
     * @param severity The severity level
     * @param title The finding title
     * @param description The finding description
     * @param evidence The evidence (code snippet, URL, etc.)
     * @param sourceTransaction The source HTTP transaction
     * @param category The category (JavaScript, JSON, etc.)
     */
    public TrafficFinding(String type, String severity, String title, String description,
                         String evidence, HttpTransaction sourceTransaction, String category) {
        this(type, severity, title, description, evidence, sourceTransaction, category, "Pattern",
             FindingCategory.GENERAL, FindingType.OTHER, "Unknown", null, null);
    }
    
    // Getters
    
    public String getId() {
        return id;
    }
    
    public String getType() {
        return type;
    }
    
    public String getSeverity() {
        return severity;
    }
    
    public String getTitle() {
        return title;
    }
    
    public String getDescription() {
        return description;
    }
    
    public String getEvidence() {
        return evidence;
    }
    
    public HttpTransaction getSourceTransaction() {
        return sourceTransaction;
    }
    
    public long getTimestamp() {
        return timestamp;
    }
    
    public String getCategory() {
        return category;
    }
    
    public String getDetectionEngine() {
        return detectionEngine;
    }
    
    public FindingCategory getFindingCategory() {
        return findingCategory;
    }
    
    public FindingType getFindingType() {
        return findingType;
    }
    
    public String getLocation() {
        return location;
    }
    
    public String getDecodedData() {
        return decodedData;
    }
    
    public String getEncodingType() {
        return encodingType;
    }
    
    public String getDomain() {
        return domain;
    }
    
    public boolean hasDecodedData() {
        return decodedData != null && !decodedData.isEmpty();
    }
    
    public String getAffectedParameter() {
        return affectedParameter;
    }
    
    public void setAffectedParameter(String affectedParameter) {
        this.affectedParameter = affectedParameter;
    }
    
    public String getDetailedDescription() {
        return detailedDescription;
    }
    
    public void setDetailedDescription(String detailedDescription) {
        this.detailedDescription = detailedDescription;
    }
    
    public String getImpact() {
        return impact;
    }
    
    public void setImpact(String impact) {
        this.impact = impact;
    }
    
    public String getRemediation() {
        return remediation;
    }
    
    public void setRemediation(String remediation) {
        this.remediation = remediation;
    }
    
    /**
     * Gets a formatted timestamp string.
     * 
     * @return Formatted timestamp
     */
    public String getFormattedTimestamp() {
        return new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
            .format(new java.util.Date(timestamp));
    }
    
    /**
     * Gets the severity as a numeric value for sorting.
     * 
     * @return Numeric severity (higher = more severe)
     */
    public int getSeverityValue() {
        switch (severity.toUpperCase()) {
            case "CRITICAL": return 5;
            case "HIGH": return 4;
            case "MEDIUM": return 3;
            case "LOW": return 2;
            case "INFO": return 1;
            default: return 0;
        }
    }
    
    /**
     * Extracts domain from URL.
     * 
     * @param url The URL
     * @return The domain
     */
    private String extractDomain(String url) {
        try {
            java.net.URL u = new java.net.URL(url);
            return u.getHost();
        } catch (Exception e) {
            return "unknown";
        }
    }
    
    /**
     * Converts this TrafficFinding to an ExploitFinding for integration
     * with existing FindingsManager.
     * 
     * @return ExploitFinding instance
     */
    public ExploitFinding toExploitFinding() {
        HttpTransaction tx = sourceTransaction;
        
        return new ExploitFinding(
            extractHost(tx.getUrl()),           // host
            extractEndpoint(tx.getUrl()),       // endpoint
            tx.getMethod(),                     // method
            type,                               // parameter (using type as parameter)
            "TRAFFIC_ANALYSIS",                 // exploitType
            evidence,                           // payload (using evidence as payload)
            title,                              // indicator
            tx.getStatusCode(),                 // statusCode
            (int) tx.getResponseSize(),         // responseLength
            0L,                                 // responseTime (not tracked)
            tx.getRequest(),                    // request
            tx.getResponse()                    // response
        );
    }
    
    /**
     * Extracts host from URL.
     * 
     * @param url The URL
     * @return The host
     */
    private String extractHost(String url) {
        try {
            java.net.URL u = new java.net.URL(url);
            return u.getHost();
        } catch (Exception e) {
            return "unknown";
        }
    }
    
    /**
     * Extracts endpoint from URL.
     * 
     * @param url The URL
     * @return The endpoint path
     */
    private String extractEndpoint(String url) {
        try {
            java.net.URL u = new java.net.URL(url);
            return u.getPath();
        } catch (Exception e) {
            return "/";
        }
    }
    
    @Override
    public String toString() {
        return String.format("[%s] %s - %s: %s",
            severity, category, title, evidence.substring(0, Math.min(50, evidence.length())));
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        TrafficFinding other = (TrafficFinding) obj;
        return id.equals(other.id);
    }
    
    @Override
    public int hashCode() {
        return id.hashCode();
    }
}
