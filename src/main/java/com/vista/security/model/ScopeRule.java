package com.vista.security.model;

import java.util.regex.Pattern;

/**
 * Represents a scope rule for filtering traffic.
 * Supports wildcard patterns like *.example.com
 */
public class ScopeRule {
    private final String pattern;
    private final Pattern regex;
    private final boolean enabled;
    
    public ScopeRule(String pattern) {
        this(pattern, true);
    }
    
    public ScopeRule(String pattern, boolean enabled) {
        this.pattern = pattern;
        this.enabled = enabled;
        this.regex = compilePattern(pattern);
    }
    
    private Pattern compilePattern(String pattern) {
        // Convert wildcard pattern to regex
        // *.example.com -> matches any subdomain of example.com
        // example.com -> matches example.com and its subdomains
        String regexPattern = pattern
            .replace(".", "\\.")
            .replace("*", "[^/]*");
        
        // Pattern should match the domain part of the URL only
        // Format: https?://[subdomain.]domain.com[/path]
        return Pattern.compile(regexPattern, Pattern.CASE_INSENSITIVE);
    }
    
    public boolean matches(String url) {
        if (!enabled) {
            return false;
        }
        
        // Extract host from URL
        String host = extractHost(url);
        if (host == null || host.isEmpty()) {
            return false;
        }
        
        // Check if host matches the pattern
        // For pattern "example.com", match:
        // - example.com
        // - www.example.com
        // - api.example.com
        // But NOT:
        // - google.com
        // - notexample.com
        
        String patternStr = pattern.toLowerCase();
        String hostLower = host.toLowerCase();
        
        // If pattern has wildcard
        if (patternStr.startsWith("*.")) {
            String domain = patternStr.substring(2); // Remove *.
            // Match if host ends with .domain or is exactly domain
            return hostLower.equals(domain) || hostLower.endsWith("." + domain);
        } else {
            // No wildcard - match exact domain or any subdomain
            return hostLower.equals(patternStr) || hostLower.endsWith("." + patternStr);
        }
    }
    
    /**
     * Extract host from URL.
     */
    private String extractHost(String url) {
        try {
            // Handle URLs with protocol
            if (url.startsWith("http://") || url.startsWith("https://")) {
                int start = url.indexOf("://") + 3;
                int end = url.indexOf('/', start);
                if (end == -1) {
                    end = url.indexOf('?', start);
                }
                if (end == -1) {
                    end = url.length();
                }
                String hostPort = url.substring(start, end);
                // Remove port if present
                int colonIndex = hostPort.indexOf(':');
                return colonIndex > 0 ? hostPort.substring(0, colonIndex) : hostPort;
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }
    
    public String getPattern() {
        return pattern;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    @Override
    public String toString() {
        return pattern + (enabled ? "" : " (disabled)");
    }
}
