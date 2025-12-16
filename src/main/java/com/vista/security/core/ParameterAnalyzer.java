package com.vista.security.core;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Analyzes HTTP requests to extract and categorize parameters.
 * Provides security-focused insights for each parameter.
 */
public final class ParameterAnalyzer {
    
    private ParameterAnalyzer() {
        // Utility class - prevent instantiation
    }
    
    /**
     * Extract all parameters from a request in a simple format.
     */
    public static String extractSummary(IExtensionHelpers helpers, IHttpRequestResponse message) {
        if (message == null || message.getRequest() == null) return "(no request)";
        
        String requestText = HttpMessageParser.requestToText(helpers, message.getRequest());
        Map<String, List<Parameter>> parameters = parseAllParameters(requestText);
        
        if (parameters.isEmpty()) {
            return "No parameters detected.\n\nCheck for:\n- JSON body\n- XML body\n- Path parameters\n- Custom headers";
        }
        
        StringBuilder sb = new StringBuilder();
        sb.append("=== PARAMETERS ===\n\n");
        
        for (Map.Entry<String, List<Parameter>> entry : parameters.entrySet()) {
            sb.append(entry.getKey()).append(":\n");
            for (Parameter param : entry.getValue()) {
                sb.append("  • ").append(param.name).append(" = ")
                  .append(truncate(param.value, 100)).append("\n");
            }
            sb.append("\n");
        }
        
        return sb.toString();
    }
    
    /**
     * Extract parameters with detailed security analysis.
     */
    public static String extractDetailed(IExtensionHelpers helpers, IHttpRequestResponse message) {
        if (message == null || message.getRequest() == null) return "(no request)";
        
        String requestText = HttpMessageParser.requestToText(helpers, message.getRequest());
        String[] lines = requestText.split("\\r?\\n");
        
        StringBuilder sb = new StringBuilder();
        sb.append("=== DETAILED PARAMETER ANALYSIS ===\n\n");
        
        // Request line
        if (lines.length > 0) {
            sb.append("Request: ").append(lines[0]).append("\n\n");
        }
        
        // Parse all parameters
        Map<String, List<Parameter>> parameters = parseAllParameters(requestText);
        
        if (!parameters.isEmpty()) {
            sb.append("--- Parameters by Location ---\n");
            for (Map.Entry<String, List<Parameter>> entry : parameters.entrySet()) {
                sb.append("\n").append(entry.getKey()).append(":\n");
                for (Parameter param : entry.getValue()) {
                    sb.append("  • ").append(param.name).append("\n");
                    sb.append("    Value: ").append(truncate(param.value, 200)).append("\n");
                    sb.append("    Suggested Tests: ").append(suggestSecurityTests(param)).append("\n");
                }
            }
            sb.append("\n");
        }
        
        // Security-relevant headers
        sb.append("--- Security-Relevant Headers ---\n");
        for (String line : lines) {
            String lower = line.toLowerCase();
            if (lower.startsWith("authorization:") || lower.startsWith("cookie:") ||
                lower.startsWith("x-") || lower.startsWith("content-type:") ||
                lower.startsWith("origin:") || lower.startsWith("referer:")) {
                sb.append("  ").append(line).append("\n");
            }
        }
        
        // Body analysis
        String body = extractBody(requestText);
        if (!body.isBlank()) {
            sb.append("\n--- Body Analysis ---\n");
            if (body.trim().startsWith("{") || body.trim().startsWith("[")) {
                sb.append("Format: JSON\n");
                sb.append("Potential Tests: JSON injection, type juggling, prototype pollution\n");
                List<String> jsonKeys = extractJsonKeys(body);
                if (!jsonKeys.isEmpty()) {
                    sb.append("Keys: ").append(String.join(", ", jsonKeys)).append("\n");
                }
            } else if (body.trim().startsWith("<")) {
                sb.append("Format: XML\n");
                sb.append("Potential Tests: XXE, XPath injection, XML injection\n");
            } else {
                sb.append("Format: Form data or other\n");
            }
            sb.append("Size: ").append(body.length()).append(" bytes\n");
        }
        
        return sb.toString();
    }

    /**
     * Detect the most likely vulnerability type based on request characteristics.
     */
    public static String detectLikelyVulnerability(IExtensionHelpers helpers, IHttpRequestResponse message) {
        if (message == null || message.getRequest() == null) return null;
        
        String requestText = HttpMessageParser.requestToText(helpers, message.getRequest());
        String lower = requestText.toLowerCase();
        
        // URL/redirect parameters suggest SSRF
        if (lower.contains("url=") || lower.contains("redirect=") || lower.contains("next=") ||
            lower.contains("return=") || lower.contains("callback=") || lower.contains("dest=")) {
            return "SSRF";
        }
        
        // ID parameters suggest IDOR
        if (lower.contains("id=") || lower.contains("user_id=") || lower.contains("account=") ||
            lower.contains("profile=") || lower.contains("order=") || lower.contains("userid=")) {
            return "IDOR";
        }
        
        // Search/query parameters suggest SQLi
        if (lower.contains("search=") || lower.contains("query=") || lower.contains("q=") ||
            lower.contains("filter=") || lower.contains("sort=") || lower.contains("order_by=")) {
            return "SQL Injection";
        }
        
        // Text input parameters suggest XSS
        if (lower.contains("name=") || lower.contains("comment=") || lower.contains("message=") ||
            lower.contains("title=") || lower.contains("body=") || lower.contains("text=")) {
            return "XSS";
        }
        
        // POST without CSRF token suggests CSRF
        String method = HttpMessageParser.extractMethod(requestText);
        if ("POST".equals(method) && !lower.contains("csrf") && !lower.contains("token") && !lower.contains("_token")) {
            return "CSRF";
        }
        
        // File/path parameters suggest LFI/RFI
        if (lower.contains("file=") || lower.contains("path=") || lower.contains("document=") ||
            lower.contains("template=") || lower.contains("include=") || lower.contains("page=")) {
            return "File Upload";
        }
        
        // XML content suggests XXE
        if (lower.contains("xml") || lower.contains("<!doctype") || lower.contains("<!entity")) {
            return "XXE";
        }
        
        // Command-like parameters suggest Command Injection
        if (lower.contains("cmd=") || lower.contains("exec=") || lower.contains("command=") ||
            lower.contains("ping=") || lower.contains("host=")) {
            return "Command Injection";
        }
        
        return null;
    }
    
    // ==================== Private Helper Methods ====================
    
    private static Map<String, List<Parameter>> parseAllParameters(String requestText) {
        Map<String, List<Parameter>> result = new LinkedHashMap<>();
        String[] lines = requestText.split("\\r?\\n");
        
        if (lines.length == 0) return result;
        
        // URL query parameters
        String firstLine = lines[0];
        int queryStart = firstLine.indexOf('?');
        int pathEnd = firstLine.lastIndexOf(" HTTP");
        if (queryStart > 0 && pathEnd > queryStart) {
            String query = firstLine.substring(queryStart + 1, pathEnd);
            List<Parameter> urlParams = parseQueryString(query);
            if (!urlParams.isEmpty()) {
                result.put("URL Query", urlParams);
            }
        }
        
        // Path parameters (IDs in URL path)
        if (pathEnd > 0) {
            String path = firstLine.substring(firstLine.indexOf(' ') + 1, pathEnd);
            if (queryStart > 0) path = path.substring(0, path.indexOf('?'));
            List<Parameter> pathParams = extractPathParameters(path);
            if (!pathParams.isEmpty()) {
                result.put("Path Parameters", pathParams);
            }
        }
        
        // Cookies
        for (String line : lines) {
            if (line.toLowerCase().startsWith("cookie:")) {
                String cookieValue = line.substring(7).trim();
                List<Parameter> cookies = parseCookies(cookieValue);
                if (!cookies.isEmpty()) {
                    result.put("Cookies", cookies);
                }
                break;
            }
        }
        
        // Body parameters
        String body = extractBody(requestText);
        if (!body.isBlank()) {
            String contentType = HttpMessageParser.extractHeader(requestText, "Content-Type");
            contentType = contentType != null ? contentType.toLowerCase() : "";
            
            if (contentType.contains("json") || body.trim().startsWith("{") || body.trim().startsWith("[")) {
                List<Parameter> jsonParams = parseJsonParameters(body);
                if (!jsonParams.isEmpty()) {
                    result.put("JSON Body", jsonParams);
                }
            } else if (contentType.contains("xml") || body.trim().startsWith("<")) {
                List<Parameter> xmlParams = parseXmlParameters(body);
                if (!xmlParams.isEmpty()) {
                    result.put("XML Body", xmlParams);
                }
            } else {
                List<Parameter> formParams = parseQueryString(body);
                if (!formParams.isEmpty()) {
                    result.put("Form Body", formParams);
                }
            }
        }
        
        return result;
    }
    
    private static String extractBody(String requestText) {
        int bodyStart = requestText.indexOf("\r\n\r\n");
        if (bodyStart > 0) return requestText.substring(bodyStart + 4);
        bodyStart = requestText.indexOf("\n\n");
        if (bodyStart > 0) return requestText.substring(bodyStart + 2);
        return "";
    }
    
    private static List<Parameter> parseQueryString(String query) {
        List<Parameter> params = new ArrayList<>();
        if (query == null || query.isBlank()) return params;
        
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                String name = urlDecode(pair.substring(0, eq));
                String value = eq < pair.length() - 1 ? urlDecode(pair.substring(eq + 1)) : "";
                params.add(new Parameter(name, value, ParameterType.QUERY));
            } else if (!pair.isBlank()) {
                params.add(new Parameter(urlDecode(pair), "", ParameterType.QUERY));
            }
        }
        return params;
    }
    
    private static List<Parameter> parseCookies(String cookieHeader) {
        List<Parameter> cookies = new ArrayList<>();
        String[] parts = cookieHeader.split(";");
        for (String part : parts) {
            part = part.trim();
            int eq = part.indexOf('=');
            if (eq > 0) {
                String name = part.substring(0, eq).trim();
                String value = eq < part.length() - 1 ? part.substring(eq + 1).trim() : "";
                cookies.add(new Parameter(name, value, ParameterType.COOKIE));
            }
        }
        return cookies;
    }
    
    private static List<Parameter> extractPathParameters(String path) {
        List<Parameter> params = new ArrayList<>();
        String[] segments = path.split("/");
        for (int i = 0; i < segments.length; i++) {
            String seg = segments[i];
            // Detect numeric IDs, UUIDs, or MongoDB ObjectIds
            if (seg.matches("\\d+") || seg.matches("[a-f0-9-]{36}") || seg.matches("[a-f0-9]{24}")) {
                String context = i > 0 ? segments[i - 1] : "path";
                params.add(new Parameter(context + "_id", seg, ParameterType.PATH));
            }
        }
        return params;
    }
    
    private static List<Parameter> parseJsonParameters(String json) {
        List<Parameter> params = new ArrayList<>();
        Pattern pattern = Pattern.compile("\"([^\"]+)\"\\s*:\\s*(\"[^\"]*\"|\\d+|true|false|null|\\{|\\[)");
        Matcher matcher = pattern.matcher(json);
        while (matcher.find()) {
            String key = matcher.group(1);
            String value = matcher.group(2);
            if (value.startsWith("\"") && value.endsWith("\"")) {
                value = value.substring(1, value.length() - 1);
            }
            params.add(new Parameter(key, truncate(value, 200), ParameterType.JSON));
        }
        return params;
    }
    
    private static List<String> extractJsonKeys(String json) {
        List<String> keys = new ArrayList<>();
        Pattern pattern = Pattern.compile("\"([^\"]+)\"\\s*:");
        Matcher matcher = pattern.matcher(json);
        while (matcher.find() && keys.size() < 20) {
            keys.add(matcher.group(1));
        }
        return keys;
    }
    
    private static List<Parameter> parseXmlParameters(String xml) {
        List<Parameter> params = new ArrayList<>();
        Pattern pattern = Pattern.compile("<([a-zA-Z][a-zA-Z0-9_-]*)(?:\\s[^>]*)?>([^<]*)</\\1>");
        Matcher matcher = pattern.matcher(xml);
        while (matcher.find()) {
            String tag = matcher.group(1);
            String value = matcher.group(2).trim();
            if (!value.isEmpty()) {
                params.add(new Parameter(tag, truncate(value, 200), ParameterType.XML));
            }
        }
        return params;
    }
    
    private static String suggestSecurityTests(Parameter param) {
        String lower = param.name.toLowerCase();
        List<String> tests = new ArrayList<>();
        
        if (lower.contains("id") || lower.contains("num") || lower.matches(".*\\d+.*")) {
            tests.add("IDOR");
        }
        if (lower.contains("url") || lower.contains("link") || lower.contains("path") || 
            lower.contains("redirect") || lower.contains("return") || lower.contains("next")) {
            tests.add("SSRF/Open Redirect");
        }
        if (lower.contains("search") || lower.contains("query") || lower.contains("filter") || 
            lower.contains("sort") || lower.contains("order")) {
            tests.add("SQL Injection");
        }
        if (lower.contains("name") || lower.contains("comment") || lower.contains("text") || 
            lower.contains("message") || lower.contains("title")) {
            tests.add("XSS");
        }
        if (lower.contains("file") || lower.contains("template") || lower.contains("include") ||
            lower.contains("page") || lower.contains("doc")) {
            tests.add("LFI/RFI");
        }
        if (lower.contains("cmd") || lower.contains("exec") || lower.contains("command") || 
            lower.contains("run") || lower.contains("ping")) {
            tests.add("Command Injection");
        }
        if (lower.contains("email") || lower.contains("mail")) {
            tests.add("Email Header Injection");
        }
        if (lower.contains("token") || lower.contains("jwt") || lower.contains("session")) {
            tests.add("Token Manipulation");
        }
        
        // Value-based suggestions
        if (param.value != null && !param.value.isEmpty()) {
            if (param.value.matches("\\d+")) tests.add("Integer Manipulation");
            if (param.value.contains("@")) tests.add("Email Injection");
            if (param.value.startsWith("http") || param.value.startsWith("//")) tests.add("URL Manipulation");
            if (param.value.contains("..") || param.value.contains("/") || param.value.contains("\\")) tests.add("Path Traversal");
            if (param.value.startsWith("ey")) tests.add("JWT Tampering");
        }
        
        return tests.isEmpty() ? "General Fuzzing" : String.join(", ", tests);
    }
    
    private static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }
    
    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
    
    // ==================== Inner Classes ====================
    
    public enum ParameterType {
        QUERY, PATH, COOKIE, JSON, XML, FORM
    }
    
    public static class Parameter {
        public final String name;
        public final String value;
        public final ParameterType type;
        
        public Parameter(String name, String value, ParameterType type) {
            this.name = name;
            this.value = value;
            this.type = type;
        }
    }
}
