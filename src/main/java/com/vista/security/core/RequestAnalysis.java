package com.vista.security.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Holds comprehensive request analysis results
 */
public class RequestAnalysis {
    
    public String method;
    public String url;
    public String path;
    public List<DeepRequestAnalyzer.ParameterInfo> parameters = new ArrayList<>();
    public Map<String, String> headers;
    public String authentication;
    public String technology;
    public String endpointType;
    public int riskScore;
    public List<String> predictedVulnerabilities = new ArrayList<>();
    public List<String> recommendations = new ArrayList<>();
    
    /**
     * Generates formatted summary for AI prompt
     */
    public String toFormattedString() {
        StringBuilder sb = new StringBuilder();
        
        sb.append("=== DEEP REQUEST ANALYSIS ===\n\n");
        
        // Basic info
        sb.append("Endpoint: ").append(path).append(" (").append(endpointType).append(")\n");
        sb.append("Method: ").append(method).append("\n");
        sb.append("Full URL: ").append(url).append("\n\n");
        
        // Parameters
        sb.append("Parameters (").append(parameters.size()).append(" found):\n");
        if (parameters.isEmpty()) {
            sb.append("  (No parameters)\n");
        } else {
            for (DeepRequestAnalyzer.ParameterInfo param : parameters) {
                sb.append(param.toString()).append("\n");
            }
        }
        sb.append("\n");
        
        // Important headers
        sb.append("Key Headers:\n");
        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                String key = entry.getKey();
                if (isImportantHeader(key)) {
                    sb.append("  - ").append(key).append(": ").append(truncate(entry.getValue(), 60)).append("\n");
                }
            }
        }
        sb.append("\n");
        
        // Authentication
        sb.append("Authentication: ").append(authentication).append("\n");
        if (authentication.contains("Cookie") && headers != null) {
            String cookie = headers.get("Cookie");
            if (cookie != null) {
                sb.append("  Cookie Details: ").append(analyzeCookie(cookie)).append("\n");
            }
        }
        sb.append("\n");
        
        // Technology
        sb.append("Technology Stack: ").append(technology).append("\n\n");
        
        // Risk assessment
        sb.append("Risk Score: ").append(riskScore).append("/10 ");
        if (riskScore >= 7) {
            sb.append("(HIGH RISK ⚠️)");
        } else if (riskScore >= 4) {
            sb.append("(MEDIUM RISK)");
        } else {
            sb.append("(LOW RISK)");
        }
        sb.append("\n\n");
        
        // Predicted vulnerabilities
        sb.append("Predicted Vulnerabilities:\n");
        if (predictedVulnerabilities.isEmpty()) {
            sb.append("  (None predicted)\n");
        } else {
            for (String vuln : predictedVulnerabilities) {
                sb.append("  • ").append(vuln).append("\n");
            }
        }
        sb.append("\n");
        
        // Recommendations
        sb.append("Testing Recommendations:\n");
        if (recommendations.isEmpty()) {
            sb.append("  (No specific recommendations)\n");
        } else {
            for (int i = 0; i < recommendations.size(); i++) {
                sb.append("  ").append(i + 1).append(". ").append(recommendations.get(i)).append("\n");
            }
        }
        
        return sb.toString();
    }
    
    /**
     * Generates concise summary for UI display
     */
    public String toSummary() {
        return String.format("%s %s | %d params | Risk: %d/10 | %s", 
            method, path, parameters.size(), riskScore, endpointType);
    }
    
    private boolean isImportantHeader(String header) {
        String lower = header.toLowerCase();
        return lower.equals("host") || 
               lower.equals("user-agent") ||
               lower.equals("content-type") ||
               lower.equals("cookie") ||
               lower.equals("authorization") ||
               lower.startsWith("x-") ||
               lower.contains("api");
    }
    
    private String analyzeCookie(String cookie) {
        StringBuilder analysis = new StringBuilder();
        
        if (cookie.toLowerCase().contains("httponly")) {
            analysis.append("✓ HttpOnly ");
        } else {
            analysis.append("✗ No HttpOnly (VULNERABLE to XSS) ");
        }
        
        if (cookie.toLowerCase().contains("secure")) {
            analysis.append("✓ Secure ");
        } else {
            analysis.append("✗ No Secure flag ");
        }
        
        if (cookie.toLowerCase().contains("samesite")) {
            analysis.append("✓ SameSite ");
        } else {
            analysis.append("✗ No SameSite (VULNERABLE to CSRF) ");
        }
        
        return analysis.toString();
    }
    
    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
