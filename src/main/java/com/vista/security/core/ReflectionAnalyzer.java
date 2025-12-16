package com.vista.security.core;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Analyzes HTTP responses to detect parameter reflections.
 * Identifies where user input appears in responses, useful for XSS/injection testing.
 */
public final class ReflectionAnalyzer {
    
    private ReflectionAnalyzer() {}
    
    // Minimum length for a value to be considered for reflection analysis
    private static final int MIN_VALUE_LENGTH = 3;
    
    // Maximum reflections to track per parameter
    private static final int MAX_REFLECTIONS_PER_PARAM = 10;

    /**
     * Result of reflection analysis.
     */
    public static class ReflectionResult {
        public final List<ReflectedParameter> reflections = new ArrayList<>();
        public final int totalReflections;
        public String summary;
        
        public ReflectionResult(int total) {
            this.totalReflections = total;
        }
        
        public boolean hasReflections() {
            return !reflections.isEmpty();
        }
    }
    
    /**
     * A parameter that was found reflected in the response.
     */
    public static class ReflectedParameter {
        public final String name;
        public final String value;
        public final String source; // URL, Body, Cookie, Header
        public final List<ReflectionContext> contexts = new ArrayList<>();
        public final RiskLevel risk;
        
        public ReflectedParameter(String name, String value, String source, RiskLevel risk) {
            this.name = name;
            this.value = value;
            this.source = source;
            this.risk = risk;
        }
    }
    
    /**
     * Context where a reflection was found.
     */
    public static class ReflectionContext {
        public final ContextType type;
        public final int position;
        public final String snippet; // Surrounding text
        public final boolean isEncoded;
        
        public ReflectionContext(ContextType type, int position, String snippet, boolean isEncoded) {
            this.type = type;
            this.position = position;
            this.snippet = snippet;
            this.isEncoded = isEncoded;
        }
    }
    
    public enum ContextType {
        HTML_BODY,           // Inside HTML content
        HTML_ATTRIBUTE,      // Inside an HTML attribute
        HTML_ATTRIBUTE_UNQUOTED, // Unquoted attribute value
        JAVASCRIPT,          // Inside <script> or JS context
        JAVASCRIPT_STRING,   // Inside a JS string
        CSS,                 // Inside <style> or CSS
        URL,                 // Inside href, src, etc.
        JSON,                // Inside JSON response
        XML,                 // Inside XML
        HEADER,              // In response header
        COMMENT,             // Inside HTML/JS comment
        UNKNOWN
    }
    
    public enum RiskLevel {
        CRITICAL,  // Direct reflection in dangerous context (unquoted attr, JS)
        HIGH,      // Reflection in exploitable context
        MEDIUM,    // Reflection with some encoding
        LOW,       // Heavily encoded or safe context
        INFO       // Reflection detected but likely safe
    }

    /**
     * Analyze request/response for parameter reflections.
     */
    public static ReflectionResult analyze(IExtensionHelpers helpers, IHttpRequestResponse message) {
        if (message == null || message.getRequest() == null || message.getResponse() == null) {
            return new ReflectionResult(0);
        }
        
        String requestText = HttpMessageParser.requestToText(helpers, message.getRequest());
        String responseText = HttpMessageParser.responseToText(helpers, message.getResponse());
        
        // Extract all parameters from request
        Map<String, ParameterInfo> parameters = extractAllParameters(requestText);
        
        // Find reflections in response
        List<ReflectedParameter> reflections = new ArrayList<>();
        int totalCount = 0;
        
        for (Map.Entry<String, ParameterInfo> entry : parameters.entrySet()) {
            String name = entry.getKey();
            ParameterInfo param = entry.getValue();
            
            if (param.value.length() < MIN_VALUE_LENGTH) continue;
            
            List<ReflectionContext> contexts = findReflections(param.value, responseText);
            
            if (!contexts.isEmpty()) {
                totalCount += contexts.size();
                RiskLevel risk = assessRisk(contexts);
                ReflectedParameter rp = new ReflectedParameter(name, param.value, param.source, risk);
                
                // Limit contexts per parameter
                for (int i = 0; i < Math.min(contexts.size(), MAX_REFLECTIONS_PER_PARAM); i++) {
                    rp.contexts.add(contexts.get(i));
                }
                
                reflections.add(rp);
            }
        }
        
        // Sort by risk level
        reflections.sort((a, b) -> a.risk.ordinal() - b.risk.ordinal());
        
        ReflectionResult result = new ReflectionResult(totalCount);
        result.reflections.addAll(reflections);
        result.summary = generateSummary(result);
        
        return result;
    }

    private static class ParameterInfo {
        String value;
        String source;
        
        ParameterInfo(String value, String source) {
            this.value = value;
            this.source = source;
        }
    }
    
    private static Map<String, ParameterInfo> extractAllParameters(String requestText) {
        Map<String, ParameterInfo> params = new LinkedHashMap<>();
        String[] lines = requestText.split("\\r?\\n");
        
        if (lines.length == 0) return params;
        
        // URL parameters
        String firstLine = lines[0];
        int queryStart = firstLine.indexOf('?');
        int pathEnd = firstLine.lastIndexOf(" HTTP");
        if (queryStart > 0 && pathEnd > queryStart) {
            String query = firstLine.substring(queryStart + 1, pathEnd);
            parseQueryParams(query, "URL", params);
        }
        
        // Cookie parameters
        for (String line : lines) {
            if (line.toLowerCase().startsWith("cookie:")) {
                String cookies = line.substring(7).trim();
                for (String cookie : cookies.split(";")) {
                    cookie = cookie.trim();
                    int eq = cookie.indexOf('=');
                    if (eq > 0) {
                        String name = cookie.substring(0, eq).trim();
                        String value = urlDecode(cookie.substring(eq + 1).trim());
                        params.put(name, new ParameterInfo(value, "Cookie"));
                    }
                }
                break;
            }
        }
        
        // Body parameters
        String body = extractBody(requestText);
        if (!body.isBlank()) {
            String contentType = HttpMessageParser.extractHeader(requestText, "Content-Type");
            contentType = contentType != null ? contentType.toLowerCase() : "";
            
            if (contentType.contains("json")) {
                parseJsonParams(body, params);
            } else if (contentType.contains("xml")) {
                parseXmlParams(body, params);
            } else {
                parseQueryParams(body, "Body", params);
            }
        }
        
        return params;
    }
    
    private static void parseQueryParams(String query, String source, Map<String, ParameterInfo> params) {
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                String name = urlDecode(pair.substring(0, eq));
                String value = urlDecode(pair.substring(eq + 1));
                params.put(name, new ParameterInfo(value, source));
            }
        }
    }
    
    private static void parseJsonParams(String json, Map<String, ParameterInfo> params) {
        Pattern pattern = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(json);
        while (matcher.find()) {
            params.put(matcher.group(1), new ParameterInfo(matcher.group(2), "JSON Body"));
        }
    }
    
    private static void parseXmlParams(String xml, Map<String, ParameterInfo> params) {
        Pattern pattern = Pattern.compile("<([a-zA-Z][a-zA-Z0-9_-]*)>([^<]+)</\\1>");
        Matcher matcher = pattern.matcher(xml);
        while (matcher.find()) {
            params.put(matcher.group(1), new ParameterInfo(matcher.group(2).trim(), "XML Body"));
        }
    }
    
    private static List<ReflectionContext> findReflections(String value, String responseText) {
        List<ReflectionContext> contexts = new ArrayList<>();
        
        // Search for exact match
        findValueInResponse(value, responseText, false, contexts);
        
        // Search for URL-encoded version
        String urlEncoded = urlEncode(value);
        if (!urlEncoded.equals(value)) {
            findValueInResponse(urlEncoded, responseText, true, contexts);
        }
        
        // Search for HTML-encoded version
        String htmlEncoded = htmlEncode(value);
        if (!htmlEncoded.equals(value)) {
            findValueInResponse(htmlEncoded, responseText, true, contexts);
        }
        
        return contexts;
    }
    
    private static void findValueInResponse(String value, String responseText, boolean isEncoded, 
                                           List<ReflectionContext> contexts) {
        int index = 0;
        String lowerResponse = responseText.toLowerCase();
        String lowerValue = value.toLowerCase();
        
        while ((index = lowerResponse.indexOf(lowerValue, index)) != -1) {
            if (contexts.size() >= MAX_REFLECTIONS_PER_PARAM * 2) break;
            
            ContextType type = determineContext(responseText, index);
            String snippet = extractSnippet(responseText, index, value.length());
            
            contexts.add(new ReflectionContext(type, index, snippet, isEncoded));
            index += value.length();
        }
    }
    
    private static ContextType determineContext(String response, int position) {
        // Look backwards to determine context
        String before = response.substring(Math.max(0, position - 200), position);
        String lowerBefore = before.toLowerCase();
        
        // Check if in response headers (before double newline)
        int headerEnd = response.indexOf("\r\n\r\n");
        if (headerEnd < 0) headerEnd = response.indexOf("\n\n");
        if (position < headerEnd) {
            return ContextType.HEADER;
        }
        
        // Check for script context
        int lastScriptOpen = lowerBefore.lastIndexOf("<script");
        int lastScriptClose = lowerBefore.lastIndexOf("</script");
        if (lastScriptOpen > lastScriptClose) {
            // Inside script tag
            if (isInString(before)) {
                return ContextType.JAVASCRIPT_STRING;
            }
            return ContextType.JAVASCRIPT;
        }
        
        // Check for style context
        int lastStyleOpen = lowerBefore.lastIndexOf("<style");
        int lastStyleClose = lowerBefore.lastIndexOf("</style");
        if (lastStyleOpen > lastStyleClose) {
            return ContextType.CSS;
        }
        
        // Check for comment
        int lastCommentOpen = lowerBefore.lastIndexOf("<!--");
        int lastCommentClose = lowerBefore.lastIndexOf("-->");
        if (lastCommentOpen > lastCommentClose) {
            return ContextType.COMMENT;
        }
        
        // Check for HTML attribute
        int lastTagOpen = lowerBefore.lastIndexOf('<');
        int lastTagClose = lowerBefore.lastIndexOf('>');
        if (lastTagOpen > lastTagClose) {
            // Inside a tag
            if (lowerBefore.contains("href=") || lowerBefore.contains("src=") || 
                lowerBefore.contains("action=") || lowerBefore.contains("url(")) {
                return ContextType.URL;
            }
            
            // Check if in quoted attribute
            int lastQuote = Math.max(lowerBefore.lastIndexOf('"'), lowerBefore.lastIndexOf('\''));
            int lastEquals = lowerBefore.lastIndexOf('=');
            if (lastEquals > lastQuote) {
                return ContextType.HTML_ATTRIBUTE_UNQUOTED;
            }
            return ContextType.HTML_ATTRIBUTE;
        }
        
        // Check content type for JSON/XML
        String contentType = HttpMessageParser.extractHeader(response, "Content-Type");
        if (contentType != null) {
            if (contentType.contains("json")) return ContextType.JSON;
            if (contentType.contains("xml")) return ContextType.XML;
        }
        
        return ContextType.HTML_BODY;
    }
    
    private static boolean isInString(String text) {
        int singleQuotes = 0, doubleQuotes = 0;
        boolean escaped = false;
        
        for (char c : text.toCharArray()) {
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '\'') singleQuotes++;
            if (c == '"') doubleQuotes++;
        }
        
        return (singleQuotes % 2 == 1) || (doubleQuotes % 2 == 1);
    }
    
    private static RiskLevel assessRisk(List<ReflectionContext> contexts) {
        RiskLevel highest = RiskLevel.INFO;
        
        for (ReflectionContext ctx : contexts) {
            RiskLevel risk = switch (ctx.type) {
                case HTML_ATTRIBUTE_UNQUOTED -> RiskLevel.CRITICAL;
                case JAVASCRIPT, JAVASCRIPT_STRING -> ctx.isEncoded ? RiskLevel.MEDIUM : RiskLevel.CRITICAL;
                case URL -> RiskLevel.HIGH;
                case HTML_ATTRIBUTE -> ctx.isEncoded ? RiskLevel.MEDIUM : RiskLevel.HIGH;
                case HTML_BODY -> ctx.isEncoded ? RiskLevel.LOW : RiskLevel.MEDIUM;
                case CSS -> RiskLevel.MEDIUM;
                case JSON, XML -> RiskLevel.MEDIUM;
                case HEADER -> RiskLevel.HIGH;
                case COMMENT -> RiskLevel.LOW;
                default -> RiskLevel.INFO;
            };
            
            if (risk.ordinal() < highest.ordinal()) {
                highest = risk;
            }
        }
        
        return highest;
    }
    
    private static String extractSnippet(String text, int position, int valueLength) {
        int start = Math.max(0, position - 30);
        int end = Math.min(text.length(), position + valueLength + 30);
        String snippet = text.substring(start, end);
        
        // Clean up for display
        snippet = snippet.replace("\r", "").replace("\n", " ");
        if (start > 0) snippet = "..." + snippet;
        if (end < text.length()) snippet = snippet + "...";
        
        return snippet;
    }
    
    private static String extractBody(String requestText) {
        int bodyStart = requestText.indexOf("\r\n\r\n");
        if (bodyStart > 0) return requestText.substring(bodyStart + 4);
        bodyStart = requestText.indexOf("\n\n");
        if (bodyStart > 0) return requestText.substring(bodyStart + 2);
        return "";
    }
    
    private static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }
    
    private static String urlEncode(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (Character.isLetterOrDigit(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                sb.append(c);
            } else {
                sb.append(String.format("%%%02X", (int) c));
            }
        }
        return sb.toString();
    }
    
    private static String htmlEncode(String s) {
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");
    }
    
    private static String generateSummary(ReflectionResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== REFLECTION ANALYSIS ===\n\n");
        
        if (result.reflections.isEmpty()) {
            sb.append("No parameter reflections detected in response.\n");
            return sb.toString();
        }
        
        sb.append("Found ").append(result.totalReflections).append(" reflection(s) in ")
          .append(result.reflections.size()).append(" parameter(s):\n\n");
        
        for (ReflectedParameter rp : result.reflections) {
            String riskIcon = switch (rp.risk) {
                case CRITICAL -> "🔴";
                case HIGH -> "🟠";
                case MEDIUM -> "🟡";
                case LOW -> "🟢";
                default -> "⚪";
            };
            
            sb.append(riskIcon).append(" ").append(rp.name).append(" [").append(rp.source).append("]\n");
            sb.append("   Value: ").append(truncate(rp.value, 40)).append("\n");
            sb.append("   Risk: ").append(rp.risk).append("\n");
            sb.append("   Contexts:\n");
            
            for (ReflectionContext ctx : rp.contexts) {
                sb.append("     • ").append(ctx.type);
                if (ctx.isEncoded) sb.append(" (encoded)");
                sb.append("\n");
                sb.append("       ").append(truncate(ctx.snippet, 60)).append("\n");
            }
            sb.append("\n");
        }
        
        return sb.toString();
    }
    
    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
