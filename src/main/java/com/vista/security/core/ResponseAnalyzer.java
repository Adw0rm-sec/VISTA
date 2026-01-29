package com.vista.security.core;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Response Analyzer - Provides comprehensive response analysis for AI
 * Extracts error messages, sensitive data, security headers, and timing info
 */
public class ResponseAnalyzer {
    
    private final IExtensionHelpers helpers;
    
    // Patterns for detection
    private static final Pattern SQL_ERROR = Pattern.compile(
        "(SQL syntax|mysql_|ORA-\\d+|PostgreSQL|SQLite|SQLSTATE|syntax error|database error)",
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern STACK_TRACE = Pattern.compile(
        "(at [a-zA-Z0-9.]+\\([^)]+\\)|Exception in thread|Traceback|\\s+File \")",
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern EMAIL = Pattern.compile(
        "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
    );
    
    private static final Pattern IP_ADDRESS = Pattern.compile(
        "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
    );
    
    private static final Pattern INTERNAL_PATH = Pattern.compile(
        "([C-Z]:\\\\|/var/|/home/|/usr/|/opt/)[^\\s<>\"']+",
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern API_KEY = Pattern.compile(
        "(api[_-]?key|apikey|access[_-]?token|secret[_-]?key)[\"']?\\s*[:=]\\s*[\"']?([a-zA-Z0-9_-]{20,})",
        Pattern.CASE_INSENSITIVE
    );
    
    public ResponseAnalyzer(IExtensionHelpers helpers) {
        this.helpers = helpers;
    }
    
    /**
     * Performs deep analysis of an HTTP response
     */
    public ResponseAnalysis analyze(IHttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.getResponse() == null) {
            return new ResponseAnalysis();
        }
        
        byte[] response = requestResponse.getResponse();
        String responseStr = new String(response, java.nio.charset.StandardCharsets.UTF_8);
        
        ResponseAnalysis analysis = new ResponseAnalysis();
        
        // Parse status line
        String[] lines = responseStr.split("\r?\n");
        if (lines.length > 0) {
            String[] statusLine = lines[0].split(" ");
            if (statusLine.length >= 2) {
                try {
                    analysis.statusCode = Integer.parseInt(statusLine[1]);
                } catch (NumberFormatException e) {
                    analysis.statusCode = 0;
                }
            }
        }
        
        // Parse headers
        analysis.headers = parseHeaders(lines);
        
        // Extract body
        int bodyStart = responseStr.indexOf("\r\n\r\n");
        if (bodyStart > 0 && bodyStart + 4 < responseStr.length()) {
            analysis.body = responseStr.substring(bodyStart + 4);
        }
        
        // Security headers analysis
        analysis.securityHeaders = analyzeSecurityHeaders(analysis.headers);
        
        // Error message detection
        analysis.errorMessages = detectErrorMessages(responseStr);
        
        // Sensitive data detection
        analysis.sensitiveData = detectSensitiveData(responseStr);
        
        // Response timing (if available)
        analysis.responseTime = 0; // Would need to track this separately
        
        // Content analysis
        analysis.contentType = analysis.headers.getOrDefault("Content-Type", "Unknown");
        analysis.contentLength = analysis.body != null ? analysis.body.length() : 0;
        
        // Reflection detection (enhanced)
        analysis.reflectionCount = countReflections(analysis.body);
        
        return analysis;
    }
    
    /**
     * Parses headers from response lines
     */
    private Map<String, String> parseHeaders(String[] lines) {
        Map<String, String> headers = new LinkedHashMap<>();
        
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.trim().isEmpty()) break; // End of headers
            
            int colonIndex = line.indexOf(':');
            if (colonIndex > 0) {
                String name = line.substring(0, colonIndex).trim();
                String value = line.substring(colonIndex + 1).trim();
                headers.put(name, value);
            }
        }
        
        return headers;
    }
    
    /**
     * Analyzes security headers
     */
    private Map<String, String> analyzeSecurityHeaders(Map<String, String> headers) {
        Map<String, String> security = new LinkedHashMap<>();
        
        // Check for important security headers
        checkHeader(security, headers, "X-Frame-Options", "Prevents clickjacking");
        checkHeader(security, headers, "Content-Security-Policy", "Prevents XSS and injection");
        checkHeader(security, headers, "X-Content-Type-Options", "Prevents MIME sniffing");
        checkHeader(security, headers, "Strict-Transport-Security", "Enforces HTTPS");
        checkHeader(security, headers, "X-XSS-Protection", "Browser XSS filter");
        checkHeader(security, headers, "Referrer-Policy", "Controls referrer information");
        checkHeader(security, headers, "Permissions-Policy", "Controls browser features");
        
        // Check for problematic headers
        if (headers.containsKey("Server")) {
            security.put("Server", "⚠️ Server version disclosed: " + headers.get("Server"));
        }
        if (headers.containsKey("X-Powered-By")) {
            security.put("X-Powered-By", "⚠️ Technology disclosed: " + headers.get("X-Powered-By"));
        }
        if (headers.containsKey("X-AspNet-Version")) {
            security.put("X-AspNet-Version", "⚠️ ASP.NET version disclosed");
        }
        
        // Check CORS
        if (headers.containsKey("Access-Control-Allow-Origin")) {
            String origin = headers.get("Access-Control-Allow-Origin");
            if (origin.equals("*")) {
                security.put("CORS", "⚠️ Wildcard CORS - allows any origin");
            } else {
                security.put("CORS", "✓ CORS configured: " + origin);
            }
        }
        
        return security;
    }
    
    /**
     * Detects error messages in response
     */
    private List<String> detectErrorMessages(String response) {
        List<String> errors = new ArrayList<>();
        Set<String> found = new HashSet<>(); // Avoid duplicates
        
        // SQL errors
        Matcher sqlMatcher = SQL_ERROR.matcher(response);
        while (sqlMatcher.find()) {
            String error = extractContext(response, sqlMatcher.start(), 100);
            if (found.add(error)) {
                errors.add("SQL Error: " + error);
            }
        }
        
        // Stack traces
        Matcher stackMatcher = STACK_TRACE.matcher(response);
        while (stackMatcher.find()) {
            String trace = extractContext(response, stackMatcher.start(), 150);
            if (found.add(trace)) {
                errors.add("Stack Trace: " + trace);
            }
        }
        
        // Generic error patterns
        if (response.contains("Warning:") || response.contains("Fatal error:")) {
            errors.add("PHP Error detected in response");
        }
        if (response.contains("Exception") && response.contains("at line")) {
            errors.add("Application Exception detected");
        }
        
        return errors;
    }
    
    /**
     * Detects sensitive data in response
     */
    private List<String> detectSensitiveData(String response) {
        List<String> sensitive = new ArrayList<>();
        Set<String> found = new HashSet<>();
        
        // Email addresses
        Matcher emailMatcher = EMAIL.matcher(response);
        int emailCount = 0;
        while (emailMatcher.find() && emailCount < 5) {
            String email = emailMatcher.group();
            if (found.add(email) && !isCommonEmail(email)) {
                sensitive.add("Email: " + email);
                emailCount++;
            }
        }
        
        // IP addresses (internal)
        Matcher ipMatcher = IP_ADDRESS.matcher(response);
        int ipCount = 0;
        while (ipMatcher.find() && ipCount < 5) {
            String ip = ipMatcher.group();
            if (found.add(ip) && isInternalIP(ip)) {
                sensitive.add("Internal IP: " + ip);
                ipCount++;
            }
        }
        
        // Internal paths
        Matcher pathMatcher = INTERNAL_PATH.matcher(response);
        int pathCount = 0;
        while (pathMatcher.find() && pathCount < 3) {
            String path = pathMatcher.group();
            if (found.add(path)) {
                sensitive.add("Internal Path: " + path);
                pathCount++;
            }
        }
        
        // API keys
        Matcher apiMatcher = API_KEY.matcher(response);
        while (apiMatcher.find()) {
            String key = apiMatcher.group(2);
            if (key != null && key.length() >= 20) {
                sensitive.add("Potential API Key: " + key.substring(0, 10) + "...");
            }
        }
        
        // AWS keys
        if (response.contains("AKIA")) {
            sensitive.add("⚠️ Potential AWS Access Key detected");
        }
        
        return sensitive;
    }
    
    /**
     * Counts reflection points in response
     */
    private int countReflections(String body) {
        if (body == null) return 0;
        
        // This is a simple count - actual reflection analysis is done by ReflectionAnalyzer
        // Just count potential reflection indicators
        int count = 0;
        
        // Common reflection patterns
        String[] patterns = {"<script>", "onerror=", "onclick=", "javascript:", "eval("};
        for (String pattern : patterns) {
            int index = 0;
            while ((index = body.indexOf(pattern, index)) != -1) {
                count++;
                index += pattern.length();
            }
        }
        
        return count;
    }
    
    // Helper methods
    
    private void checkHeader(Map<String, String> security, Map<String, String> headers, 
                            String headerName, String description) {
        if (headers.containsKey(headerName)) {
            security.put(headerName, "✓ Present: " + description);
        } else {
            security.put(headerName, "✗ Missing: " + description);
        }
    }
    
    private String extractContext(String text, int position, int length) {
        int start = Math.max(0, position - 20);
        int end = Math.min(text.length(), position + length);
        String context = text.substring(start, end);
        return context.replaceAll("\\s+", " ").trim();
    }
    
    private boolean isCommonEmail(String email) {
        String lower = email.toLowerCase();
        return lower.contains("example.com") || 
               lower.contains("test.com") ||
               lower.contains("localhost");
    }
    
    private boolean isInternalIP(String ip) {
        return ip.startsWith("10.") || 
               ip.startsWith("192.168.") ||
               ip.startsWith("172.16.") ||
               ip.startsWith("127.");
    }
}
