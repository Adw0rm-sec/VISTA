package com.vista.security.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Holds comprehensive response analysis results
 */
public class ResponseAnalysis {
    
    public int statusCode;
    public Map<String, String> headers;
    public Map<String, String> securityHeaders;
    public String body;
    public String contentType;
    public int contentLength;
    public List<String> errorMessages = new ArrayList<>();
    public List<String> sensitiveData = new ArrayList<>();
    public int reflectionCount;
    public long responseTime;
    
    /**
     * Generates formatted summary for AI prompt
     */
    public String toFormattedString() {
        StringBuilder sb = new StringBuilder();
        
        sb.append("=== DEEP RESPONSE ANALYSIS ===\n\n");
        
        // Status
        sb.append("Status: ").append(statusCode).append(" ").append(getStatusDescription()).append("\n");
        sb.append("Content-Type: ").append(contentType).append("\n");
        sb.append("Content-Length: ").append(contentLength).append(" bytes\n");
        if (responseTime > 0) {
            sb.append("Response Time: ").append(responseTime).append("ms");
            if (responseTime > 3000) {
                sb.append(" (SLOW - potential for timing attacks)");
            }
            sb.append("\n");
        }
        sb.append("\n");
        
        // Security headers
        sb.append("Security Headers Analysis:\n");
        if (securityHeaders != null && !securityHeaders.isEmpty()) {
            for (Map.Entry<String, String> entry : securityHeaders.entrySet()) {
                sb.append("  ").append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
            }
        } else {
            sb.append("  (No security headers analyzed)\n");
        }
        sb.append("\n");
        
        // Error messages
        if (!errorMessages.isEmpty()) {
            sb.append("⚠️ ERROR MESSAGES DETECTED:\n");
            for (String error : errorMessages) {
                sb.append("  • ").append(error).append("\n");
            }
            sb.append("  → These errors may reveal internal implementation details\n\n");
        }
        
        // Sensitive data
        if (!sensitiveData.isEmpty()) {
            sb.append("⚠️ SENSITIVE DATA DETECTED:\n");
            for (String data : sensitiveData) {
                sb.append("  • ").append(data).append("\n");
            }
            sb.append("  → This data should not be exposed in responses\n\n");
        }
        
        // Reflection info
        if (reflectionCount > 0) {
            sb.append("Reflection Points: ").append(reflectionCount).append(" potential reflection(s) detected\n");
            sb.append("  → Use ReflectionAnalyzer for detailed context analysis\n\n");
        }
        
        // Security assessment
        sb.append("Security Assessment:\n");
        int issues = countSecurityIssues();
        if (issues == 0) {
            sb.append("  ✓ No obvious security issues detected\n");
        } else {
            sb.append("  ⚠️ ").append(issues).append(" potential security issue(s) found\n");
            if (!errorMessages.isEmpty()) {
                sb.append("  - Information disclosure via error messages\n");
            }
            if (!sensitiveData.isEmpty()) {
                sb.append("  - Sensitive data exposure\n");
            }
            if (securityHeaders != null) {
                long missingHeaders = securityHeaders.values().stream()
                    .filter(v -> v.startsWith("✗")).count();
                if (missingHeaders > 0) {
                    sb.append("  - ").append(missingHeaders).append(" security header(s) missing\n");
                }
            }
        }
        
        return sb.toString();
    }
    
    /**
     * Generates concise summary for UI display
     */
    public String toSummary() {
        int issues = countSecurityIssues();
        return String.format("Status: %d | %d bytes | %d issue(s)", 
            statusCode, contentLength, issues);
    }
    
    private String getStatusDescription() {
        if (statusCode >= 200 && statusCode < 300) return "OK";
        if (statusCode >= 300 && statusCode < 400) return "Redirect";
        if (statusCode >= 400 && statusCode < 500) return "Client Error";
        if (statusCode >= 500) return "Server Error";
        return "Unknown";
    }
    
    private int countSecurityIssues() {
        int count = 0;
        
        if (!errorMessages.isEmpty()) count += errorMessages.size();
        if (!sensitiveData.isEmpty()) count += sensitiveData.size();
        
        if (securityHeaders != null) {
            count += (int) securityHeaders.values().stream()
                .filter(v -> v.startsWith("✗") || v.startsWith("⚠️")).count();
        }
        
        return count;
    }
}
