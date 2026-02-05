package com.vista.security.model;

import java.util.UUID;

/**
 * TrafficFinding represents an intelligent security finding discovered
 * through automated analysis of HTTP traffic.
 * 
 * Findings can be:
 * - Secrets (API keys, passwords, tokens)
 * - Hidden URLs and endpoints
 * - Hidden parameters
 * - Sensitive data exposure
 * - Security misconfigurations
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
    
    /**
     * Creates a new TrafficFinding.
     * 
     * @param type The type of finding
     * @param severity The severity level
     * @param title The finding title
     * @param description The finding description
     * @param evidence The evidence (code snippet, URL, etc.)
     * @param sourceTransaction The source HTTP transaction
     * @param category The category (JavaScript, JSON, etc.)
     * @param detectionEngine The detection engine (Pattern or AI)
     */
    public TrafficFinding(String type, String severity, String title, String description,
                         String evidence, HttpTransaction sourceTransaction, String category,
                         String detectionEngine) {
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
        this(type, severity, title, description, evidence, sourceTransaction, category, "Pattern");
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
