package com.vista.security.core;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import java.net.URL;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deep Request Analyzer - Provides comprehensive request analysis for AI
 * Extracts parameters, headers, authentication, technology stack, and risk scoring
 */
public class DeepRequestAnalyzer {
    
    private final IExtensionHelpers helpers;
    
    public DeepRequestAnalyzer(IExtensionHelpers helpers) {
        this.helpers = helpers;
    }
    
    /**
     * Performs deep analysis of an HTTP request
     */
    public RequestAnalysis analyze(IHttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.getRequest() == null) {
            return new RequestAnalysis();
        }
        
        byte[] request = requestResponse.getRequest();
        String requestStr = new String(request, java.nio.charset.StandardCharsets.UTF_8);
        
        RequestAnalysis analysis = new RequestAnalysis();
        
        // Parse request line
        String[] lines = requestStr.split("\r?\n");
        if (lines.length > 0) {
            String[] requestLine = lines[0].split(" ");
            if (requestLine.length >= 2) {
                analysis.method = requestLine[0];
                analysis.path = requestLine[1];
                
                // Extract URL
                try {
                    if (requestResponse.getHttpService() != null) {
                        String protocol = requestResponse.getHttpService().getProtocol();
                        String host = requestResponse.getHttpService().getHost();
                        analysis.url = protocol + "://" + host + analysis.path;
                    } else {
                        analysis.url = analysis.path;
                    }
                } catch (Exception e) {
                    analysis.url = analysis.path;
                }
            }
        }
        
        // Parse headers
        analysis.headers = parseHeaders(lines);
        
        // Extract parameters
        analysis.parameters = extractAllParameters(requestStr, analysis.method, analysis.headers);
        
        // Detect authentication
        analysis.authentication = detectAuthentication(analysis.headers, analysis.parameters);
        
        // Detect technology
        analysis.technology = detectTechnology(analysis.headers, requestStr);
        
        // Classify endpoint
        analysis.endpointType = classifyEndpoint(analysis.path, analysis.parameters);
        
        // Score risk
        analysis.riskScore = calculateRiskScore(analysis);
        
        // Predict vulnerabilities
        analysis.predictedVulnerabilities = predictVulnerabilities(analysis);
        
        // Generate recommendations
        analysis.recommendations = generateRecommendations(analysis);
        
        return analysis;
    }
    
    /**
     * Parses headers from request lines
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
     * Extracts ALL parameters from request (URL, POST, JSON, XML, multipart)
     */
    private List<ParameterInfo> extractAllParameters(String requestStr, String method, Map<String, String> headers) {
        List<ParameterInfo> params = new ArrayList<>();
        
        // Extract URL parameters
        extractUrlParameters(requestStr, params);
        
        // Extract body parameters (POST, PUT, PATCH)
        if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
            String contentType = headers.getOrDefault("Content-Type", "");
            extractBodyParameters(requestStr, contentType, params);
        }
        
        // Extract cookie parameters
        String cookie = headers.get("Cookie");
        if (cookie != null) {
            extractCookieParameters(cookie, params);
        }
        
        return params;
    }
    
    /**
     * Extracts parameters from URL query string
     */
    private void extractUrlParameters(String requestStr, List<ParameterInfo> params) {
        try {
            String[] lines = requestStr.split("\r?\n");
            if (lines.length > 0) {
                String requestLine = lines[0];
                int queryStart = requestLine.indexOf('?');
                if (queryStart > 0) {
                    int queryEnd = requestLine.indexOf(' ', queryStart);
                    if (queryEnd < 0) queryEnd = requestLine.length();
                    
                    String queryString = requestLine.substring(queryStart + 1, queryEnd);
                    String[] pairs = queryString.split("&");
                    
                    for (String pair : pairs) {
                        int eqIndex = pair.indexOf('=');
                        if (eqIndex > 0) {
                            ParameterInfo info = new ParameterInfo();
                            info.name = urlDecode(pair.substring(0, eqIndex));
                            info.value = urlDecode(pair.substring(eqIndex + 1));
                            info.type = "URL";
                            info.location = "Query String";
                            info.riskLevel = assessParameterRisk(info);
                            params.add(info);
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Ignore parsing errors
        }
    }
    
    /**
     * Extracts parameters from request body
     */
    private void extractBodyParameters(String requestStr, String contentType, List<ParameterInfo> params) {
        int bodyStart = requestStr.indexOf("\r\n\r\n");
        if (bodyStart < 0) return;
        
        String body = requestStr.substring(bodyStart + 4);
        if (body.trim().isEmpty()) return;
        
        if (contentType.contains("application/json")) {
            extractJsonParameters(body, params);
        } else if (contentType.contains("application/xml") || contentType.contains("text/xml")) {
            extractXmlParameters(body, params);
        } else if (contentType.contains("multipart/form-data")) {
            extractMultipartParameters(body, params);
        } else if (contentType.contains("application/x-www-form-urlencoded")) {
            extractFormParameters(body, params);
        } else {
            // Try to detect format automatically
            String trimmed = body.trim();
            if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                extractJsonParameters(body, params);
            } else if (trimmed.startsWith("<")) {
                extractXmlParameters(body, params);
            } else if (trimmed.contains("=") && trimmed.contains("&")) {
                extractFormParameters(body, params);
            }
        }
    }
    
    /**
     * Extracts parameters from JSON body
     */
    private void extractJsonParameters(String body, List<ParameterInfo> params) {
        try {
            // Simple JSON parsing using regex (handles nested objects at first level)
            Pattern pattern = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"?([^,}\"\\]]+)\"?");
            Matcher matcher = pattern.matcher(body);
            
            while (matcher.find()) {
                ParameterInfo info = new ParameterInfo();
                info.name = matcher.group(1);
                info.value = matcher.group(2).trim();
                info.type = "JSON";
                info.location = "Body";
                info.riskLevel = assessParameterRisk(info);
                params.add(info);
            }
        } catch (Exception e) {
            // Ignore JSON parsing errors
        }
    }
    
    /**
     * Extracts parameters from XML body
     */
    private void extractXmlParameters(String body, List<ParameterInfo> params) {
        try {
            // Simple XML parsing using regex
            Pattern pattern = Pattern.compile("<([^/>\\s]+)>([^<]+)</\\1>");
            Matcher matcher = pattern.matcher(body);
            
            while (matcher.find()) {
                ParameterInfo info = new ParameterInfo();
                info.name = matcher.group(1);
                info.value = matcher.group(2).trim();
                info.type = "XML";
                info.location = "Body";
                info.riskLevel = assessParameterRisk(info);
                params.add(info);
            }
        } catch (Exception e) {
            // Ignore XML parsing errors
        }
    }
    
    /**
     * Extracts parameters from multipart form data
     */
    private void extractMultipartParameters(String body, List<ParameterInfo> params) {
        try {
            // Parse multipart boundaries
            Pattern pattern = Pattern.compile("name=\"([^\"]+)\"[\\s\\S]*?\\r\\n\\r\\n([^\\r\\n-]+)");
            Matcher matcher = pattern.matcher(body);
            
            while (matcher.find()) {
                ParameterInfo info = new ParameterInfo();
                info.name = matcher.group(1);
                info.value = matcher.group(2).trim();
                info.type = "Multipart";
                info.location = "Body";
                info.riskLevel = assessParameterRisk(info);
                params.add(info);
            }
        } catch (Exception e) {
            // Ignore multipart parsing errors
        }
    }
    
    /**
     * Extracts parameters from form-encoded body
     */
    private void extractFormParameters(String body, List<ParameterInfo> params) {
        try {
            String[] pairs = body.split("&");
            for (String pair : pairs) {
                int eqIndex = pair.indexOf('=');
                if (eqIndex > 0) {
                    ParameterInfo info = new ParameterInfo();
                    info.name = urlDecode(pair.substring(0, eqIndex));
                    info.value = urlDecode(pair.substring(eqIndex + 1));
                    info.type = "Form";
                    info.location = "Body";
                    info.riskLevel = assessParameterRisk(info);
                    params.add(info);
                }
            }
        } catch (Exception e) {
            // Ignore form parsing errors
        }
    }
    
    /**
     * Extracts parameters from cookies
     */
    private void extractCookieParameters(String cookie, List<ParameterInfo> params) {
        try {
            String[] pairs = cookie.split(";");
            for (String pair : pairs) {
                int eqIndex = pair.indexOf('=');
                if (eqIndex > 0) {
                    ParameterInfo info = new ParameterInfo();
                    info.name = pair.substring(0, eqIndex).trim();
                    info.value = pair.substring(eqIndex + 1).trim();
                    info.type = "Cookie";
                    info.location = "Cookie";
                    info.riskLevel = assessParameterRisk(info);
                    params.add(info);
                }
            }
        } catch (Exception e) {
            // Ignore cookie parsing errors
        }
    }
    
    /**
     * Simple URL decoder
     */
    private String urlDecode(String s) {
        try {
            return java.net.URLDecoder.decode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }
    
    
    /**
     * Analyzes request headers (kept for compatibility but now uses parsed headers)
     */
    private Map<String, String> analyzeHeaders(List<String> headers) {
        Map<String, String> headerMap = new LinkedHashMap<>();
        
        for (String header : headers) {
            if (header.contains(":")) {
                String[] parts = header.split(":", 2);
                if (parts.length == 2) {
                    headerMap.put(parts[0].trim(), parts[1].trim());
                }
            }
        }
        
        return headerMap;
    }
    
    /**
     * Detects authentication method
     */
    private String detectAuthentication(Map<String, String> headers, List<ParameterInfo> params) {
        // Check Authorization header
        String auth = headers.get("Authorization");
        if (auth != null) {
            String lower = auth.toLowerCase();
            if (lower.startsWith("bearer")) return "Bearer Token (JWT/OAuth)";
            if (lower.startsWith("basic")) return "Basic Authentication";
            if (lower.startsWith("digest")) return "Digest Authentication";
            return "Custom Authorization Header";
        }
        
        // Check Cookie header
        String cookie = headers.get("Cookie");
        if (cookie != null) {
            String lower = cookie.toLowerCase();
            if (lower.contains("session") || lower.contains("sess") || lower.contains("token")) {
                return "Session-based (Cookie)";
            }
        }
        
        // Check API key headers
        if (headers.containsKey("X-API-Key") || headers.containsKey("API-Key") || headers.containsKey("Api-Key")) {
            return "API Key (Header)";
        }
        
        // Check for API key in parameters
        for (ParameterInfo param : params) {
            String lower = param.name.toLowerCase();
            if (lower.contains("api") && lower.contains("key")) {
                return "API Key (Parameter)";
            }
            if (lower.equals("token") || lower.equals("access_token")) {
                return "Token-based (Parameter)";
            }
        }
        
        return "None detected";
    }
    
    /**
     * Detects technology stack
     */
    private String detectTechnology(Map<String, String> headers, String requestStr) {
        StringBuilder tech = new StringBuilder();
        
        // Server detection
        String server = headers.get("Server");
        if (server != null) {
            tech.append("Server: ").append(server).append("; ");
        }
        
        // Framework detection
        String powered = headers.get("X-Powered-By");
        if (powered != null) {
            tech.append("Framework: ").append(powered).append("; ");
        }
        
        // ASP.NET detection
        if (headers.containsKey("X-AspNet-Version") || headers.containsKey("X-AspNetMvc-Version")) {
            tech.append("ASP.NET; ");
        }
        
        // Path-based detection
        if (requestStr.contains(".php")) tech.append("PHP; ");
        if (requestStr.contains(".jsp")) tech.append("JSP/Java; ");
        if (requestStr.contains(".asp")) tech.append("ASP; ");
        if (requestStr.contains("/api/")) tech.append("REST API; ");
        
        return tech.length() > 0 ? tech.toString() : "Unknown";
    }
    
    /**
     * Classifies endpoint type
     */
    private String classifyEndpoint(String path, List<ParameterInfo> params) {
        String lower = path.toLowerCase();
        
        if (lower.contains("login") || lower.contains("signin") || lower.contains("auth")) {
            return "Authentication";
        }
        if (lower.contains("register") || lower.contains("signup")) {
            return "Registration";
        }
        if (lower.contains("search") || hasParameter(params, "q", "query", "search")) {
            return "Search";
        }
        if (lower.contains("upload") || lower.contains("file")) {
            return "File Upload";
        }
        if (lower.contains("api/")) {
            return "API Endpoint";
        }
        if (lower.contains("admin")) {
            return "Admin Panel";
        }
        if (lower.contains("profile") || lower.contains("user")) {
            return "User Profile";
        }
        if (lower.contains("payment") || lower.contains("checkout")) {
            return "Payment";
        }
        if (lower.contains("download")) {
            return "File Download";
        }
        
        return "General";
    }
    
    /**
     * Calculates risk score (0-10)
     */
    private int calculateRiskScore(RequestAnalysis analysis) {
        int score = 0;
        
        // High-risk endpoints
        if (analysis.endpointType.equals("Authentication")) score += 2;
        if (analysis.endpointType.equals("File Upload")) score += 3;
        if (analysis.endpointType.equals("Admin Panel")) score += 3;
        if (analysis.endpointType.equals("API Endpoint")) score += 1;
        
        // High-risk parameters
        for (ParameterInfo param : analysis.parameters) {
            if (param.riskLevel.equals("HIGH")) score += 2;
            else if (param.riskLevel.equals("MEDIUM")) score += 1;
        }
        
        // Lack of authentication
        if (analysis.authentication.equals("None detected")) score += 2;
        
        // Many parameters = more attack surface
        if (analysis.parameters.size() > 5) score += 1;
        
        return Math.min(score, 10);
    }
    
    /**
     * Predicts likely vulnerabilities
     */
    private List<String> predictVulnerabilities(RequestAnalysis analysis) {
        List<String> vulns = new ArrayList<>();
        
        // Based on endpoint type
        switch (analysis.endpointType) {
            case "Authentication":
                vulns.add("SQL Injection (login bypass)");
                vulns.add("Brute Force");
                vulns.add("Credential Stuffing");
                break;
            case "Search":
                vulns.add("XSS (reflected)");
                vulns.add("SQL Injection");
                vulns.add("SSRF (if fetching external resources)");
                break;
            case "File Upload":
                vulns.add("Unrestricted File Upload");
                vulns.add("Path Traversal");
                vulns.add("XXE (if XML processing)");
                break;
            case "API Endpoint":
                vulns.add("IDOR (Insecure Direct Object Reference)");
                vulns.add("Mass Assignment");
                vulns.add("API Rate Limiting bypass");
                break;
            case "Admin Panel":
                vulns.add("Authorization bypass");
                vulns.add("Privilege Escalation");
                vulns.add("CSRF");
                break;
        }
        
        // Based on parameters
        for (ParameterInfo param : analysis.parameters) {
            String lower = param.name.toLowerCase();
            if (lower.contains("id") || lower.contains("user")) {
                if (!vulns.contains("IDOR (Insecure Direct Object Reference)")) {
                    vulns.add("IDOR (Insecure Direct Object Reference)");
                }
            }
            if (lower.contains("url") || lower.contains("link") || lower.contains("redirect")) {
                if (!vulns.contains("Open Redirect")) {
                    vulns.add("Open Redirect");
                }
                if (!vulns.contains("SSRF")) {
                    vulns.add("SSRF");
                }
            }
            if (lower.contains("file") || lower.contains("path")) {
                if (!vulns.contains("Path Traversal")) {
                    vulns.add("Path Traversal");
                }
            }
            if (lower.contains("cmd") || lower.contains("command") || lower.contains("exec")) {
                if (!vulns.contains("Command Injection")) {
                    vulns.add("Command Injection");
                }
            }
        }
        
        // Generic vulnerabilities
        if (!vulns.contains("XSS (reflected)") && analysis.parameters.size() > 0) {
            vulns.add("XSS (reflected)");
        }
        
        return vulns;
    }
    
    /**
     * Generates testing recommendations
     */
    private List<String> generateRecommendations(RequestAnalysis analysis) {
        List<String> recommendations = new ArrayList<>();
        
        // Priority recommendations based on risk
        if (analysis.riskScore >= 7) {
            recommendations.add("HIGH PRIORITY: This endpoint has high risk - test thoroughly");
        }
        
        // Specific recommendations
        for (ParameterInfo param : analysis.parameters) {
            if (param.riskLevel.equals("HIGH")) {
                recommendations.add("Test parameter '" + param.name + "' for injection attacks");
            }
        }
        
        if (analysis.authentication.equals("None detected")) {
            recommendations.add("No authentication detected - check for authorization bypass");
        }
        
        if (analysis.endpointType.equals("File Upload")) {
            recommendations.add("Test file upload restrictions (type, size, content)");
        }
        
        if (analysis.endpointType.equals("Search")) {
            recommendations.add("Test search parameter for XSS and SQL injection");
        }
        
        return recommendations;
    }
    
    /**
     * Assesses risk level of a parameter
     */
    private String assessParameterRisk(ParameterInfo param) {
        String lower = param.name.toLowerCase();
        
        // High risk parameters
        if (lower.contains("id") || lower.equals("user") || lower.equals("admin")) return "HIGH";
        if (lower.contains("url") || lower.contains("redirect") || lower.contains("link")) return "HIGH";
        if (lower.contains("file") || lower.contains("path")) return "HIGH";
        if (lower.contains("cmd") || lower.contains("command") || lower.contains("exec")) return "HIGH";
        if (lower.contains("sql") || lower.contains("query")) return "HIGH";
        
        // Medium risk parameters
        if (lower.contains("search") || lower.equals("q")) return "MEDIUM";
        if (lower.contains("name") || lower.contains("email")) return "MEDIUM";
        if (lower.contains("message") || lower.contains("comment")) return "MEDIUM";
        
        return "LOW";
    }
    
    private boolean hasParameter(List<ParameterInfo> params, String... names) {
        for (ParameterInfo param : params) {
            for (String name : names) {
                if (param.name.equalsIgnoreCase(name)) return true;
            }
        }
        return false;
    }
    
    /**
     * Parameter information
     */
    public static class ParameterInfo {
        public String name;
        public String value;
        public String type;
        public String location;
        public String riskLevel;
        
        @Override
        public String toString() {
            return String.format("  - %s: \"%s\" (%s, %s, %s RISK)", 
                name, truncate(value, 50), type, location, riskLevel);
        }
        
        private String truncate(String s, int max) {
            if (s == null) return "";
            return s.length() > max ? s.substring(0, max) + "..." : s;
        }
    }
}
