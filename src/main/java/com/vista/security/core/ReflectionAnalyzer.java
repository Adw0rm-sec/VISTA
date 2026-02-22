package com.vista.security.core;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Analyzes HTTP responses to identify where and how parameters are reflected.
 * This helps AI provide context-aware testing suggestions without requiring
 * users to manually test for reflection points.
 */
public class ReflectionAnalyzer {
    
    private final IExtensionHelpers helpers;
    
    public ReflectionAnalyzer(IExtensionHelpers helpers) {
        this.helpers = helpers;
    }
    
    /**
     * Analyzes request/response pair to find parameter reflections
     */
    public ReflectionAnalysis analyze(IHttpRequestResponse requestResponse) {
        ReflectionAnalysis analysis = new ReflectionAnalysis();
        
        if (requestResponse == null || requestResponse.getResponse() == null) {
            return analysis;
        }
        
        byte[] request = requestResponse.getRequest();
        byte[] response = requestResponse.getResponse();
        
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        IResponseInfo responseInfo = helpers.analyzeResponse(response);
        
        // Get response body
        int bodyOffset = responseInfo.getBodyOffset();
        String responseBody = new String(response, bodyOffset, response.length - bodyOffset, StandardCharsets.ISO_8859_1);
        
        // Get response headers as string
        String responseHeaders = String.join("\n", responseInfo.getHeaders());
        
        // Extract parameters from request manually
        Map<String, String> parameters = extractParameters(request, requestInfo);
        
        // Analyze each parameter
        for (Map.Entry<String, String> param : parameters.entrySet()) {
            String paramName = param.getKey();
            String paramValue = param.getValue();
            
            if (paramValue == null || paramValue.isEmpty()) {
                continue;
            }
            
            ReflectionPoint reflection = analyzeParameterReflection(
                paramName, paramValue, responseBody, responseHeaders
            );
            
            if (reflection != null) {
                analysis.addReflection(reflection);
            }
        }
        
        return analysis;
    }
    
    /**
     * Extracts parameters from request (GET, POST, JSON)
     */
    private Map<String, String> extractParameters(byte[] request, IRequestInfo requestInfo) {
        Map<String, String> parameters = new HashMap<>();
        
        String requestStr = new String(request, StandardCharsets.ISO_8859_1);
        
        // Extract from URL query string
        String firstLine = requestInfo.getHeaders().get(0);
        if (firstLine.contains("?")) {
            String queryString = firstLine.substring(firstLine.indexOf("?") + 1);
            if (queryString.contains(" ")) {
                queryString = queryString.substring(0, queryString.indexOf(" "));
            }
            parseQueryString(queryString, parameters);
        }
        
        // Extract from POST body
        int bodyOffset = requestInfo.getBodyOffset();
        if (bodyOffset < request.length) {
            String body = new String(request, bodyOffset, request.length - bodyOffset, StandardCharsets.ISO_8859_1);
            
            // Check if it's form data
            if (requestStr.toLowerCase().contains("content-type: application/x-www-form-urlencoded")) {
                parseQueryString(body, parameters);
            }
            // Check if it's JSON
            else if (requestStr.toLowerCase().contains("content-type: application/json")) {
                parseJsonParameters(body, parameters);
            }
        }
        
        return parameters;
    }
    
    private void parseQueryString(String queryString, Map<String, String> parameters) {
        String[] pairs = queryString.split("&");
        for (String pair : pairs) {
            String[] keyValue = pair.split("=", 2);
            if (keyValue.length == 2) {
                parameters.put(urlDecode(keyValue[0]), urlDecode(keyValue[1]));
            }
        }
    }
    
    private void parseJsonParameters(String json, Map<String, String> parameters) {
        // Simple JSON parsing for key-value pairs
        Pattern pattern = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(json);
        while (matcher.find()) {
            parameters.put(matcher.group(1), matcher.group(2));
        }
    }
    
    private String urlDecode(String str) {
        try {
            return java.net.URLDecoder.decode(str, "UTF-8");
        } catch (Exception e) {
            return str;
        }
    }
    
    /**
     * Analyzes how a specific parameter value is reflected in the response.
     * Checks for exact matches, HTML-encoded variants, and significant substrings
     * so that partially-encoded reflections (e.g. &#039;;alert(12345);/&#039;) are detected.
     */
    private ReflectionPoint analyzeParameterReflection(String paramName, String paramValue, 
                                                       String responseBody, String responseHeaders) {
        
        // Build all variants of the value to check
        String htmlEncoded = htmlEncode(paramValue);
        String urlEncoded = urlEncode(paramValue);
        
        // Also build "mixed" HTML-encoded version using numeric entities for quotes
        // (many apps encode ' as &#039; or &#x27; but leave other chars raw)
        String numericEntityEncoded = paramValue
            .replace("'", "&#039;")
            .replace("\"", "&#034;")
            .replace("<", "&lt;")
            .replace(">", "&gt;");
        String hexEntityEncoded = paramValue
            .replace("'", "&#x27;")
            .replace("\"", "&#x22;")
            .replace("<", "&lt;")
            .replace(">", "&gt;");
        
        // Extract "core" alphanumeric substrings from the value (e.g., "alert(12345)" from "';alert(12345);//")
        // This catches reflections where only special chars are encoded/stripped
        List<String> coreSubstrings = extractCoreSubstrings(paramValue);
        
        // Check if ANY variant appears in response
        boolean foundInBody = responseBody.contains(paramValue)
            || responseBody.contains(htmlEncoded)
            || responseBody.contains(numericEntityEncoded)
            || responseBody.contains(hexEntityEncoded);
        boolean foundInHeaders = responseHeaders.contains(paramValue)
            || responseHeaders.contains(urlEncoded);
        
        // Also check core substrings (minimum 4 chars to avoid false positives)
        boolean coreFound = false;
        String matchedCore = null;
        if (!foundInBody) {
            for (String core : coreSubstrings) {
                if (core.length() >= 4 && responseBody.contains(core)) {
                    coreFound = true;
                    matchedCore = core;
                    foundInBody = true;
                    break;
                }
            }
        }
        
        if (!foundInBody && !foundInHeaders) {
            return null;
        }
        
        ReflectionPoint reflection = new ReflectionPoint(paramName, paramValue);
        
        // Check reflection in headers
        if (foundInHeaders) {
            reflection.setReflectedInHeaders(true);
            reflection.addLocation("HTTP Headers");
        }
        
        // Analyze reflection context in body — try all matching variants
        if (responseBody.contains(paramValue)) {
            // Exact match (best case)
            analyzeReflectionContext(paramValue, responseBody, reflection);
        } else if (responseBody.contains(numericEntityEncoded)) {
            // HTML numeric entity encoded (e.g., &#039; for ')
            analyzeReflectionContext(numericEntityEncoded, responseBody, reflection);
            reflection.addLocation("HTML Entity Encoded (&#039; style)");
        } else if (responseBody.contains(hexEntityEncoded)) {
            // HTML hex entity encoded (e.g., &#x27; for ')
            analyzeReflectionContext(hexEntityEncoded, responseBody, reflection);
            reflection.addLocation("HTML Entity Encoded (&#x27; style)");
        } else if (responseBody.contains(htmlEncoded)) {
            // Full HTML entity encoded
            analyzeReflectionContext(htmlEncoded, responseBody, reflection);
            reflection.addLocation("HTML Entity Encoded (&amp; style)");
        } else if (coreFound && matchedCore != null) {
            // Core substring match — partial reflection
            analyzeReflectionContext(matchedCore, responseBody, reflection);
            reflection.addLocation("Partial reflection (core: " + matchedCore + ")");
        }
        
        return reflection;
    }
    
    /**
     * Extracts significant alphanumeric substrings from a payload value.
     * For example, from "';alert(12345);//" extracts ["alert(12345)", "alert", "12345"].
     * This helps detect reflections where only special characters are encoded/stripped.
     */
    private List<String> extractCoreSubstrings(String value) {
        List<String> cores = new ArrayList<>();
        
        // Extract contiguous alphanumeric+parentheses substrings
        java.util.regex.Matcher m = Pattern.compile("[a-zA-Z0-9()_]{4,}").matcher(value);
        while (m.find()) {
            cores.add(m.group());
        }
        
        // Also try the value with only leading/trailing special chars stripped
        String stripped = value.replaceAll("^[^a-zA-Z0-9]+", "").replaceAll("[^a-zA-Z0-9]+$", "");
        if (stripped.length() >= 4 && !cores.contains(stripped)) {
            cores.add(0, stripped); // Higher priority
        }
        
        return cores;
    }
    
    /**
     * Analyzes the context where parameter is reflected (HTML, JavaScript, etc.)
     */
    private void analyzeReflectionContext(String value, String responseBody, ReflectionPoint reflection) {
        
        // Find all occurrences
        List<Integer> positions = findAllOccurrences(responseBody, value);
        
        for (int pos : positions) {
            String context = extractContext(responseBody, pos, value.length());
            ReflectionContext ctx = determineContext(context, value);
            
            reflection.addContext(ctx);
            reflection.addLocation(ctx.getDescription());
        }
    }
    
    /**
     * Finds all positions where value appears in response
     */
    private List<Integer> findAllOccurrences(String text, String value) {
        List<Integer> positions = new ArrayList<>();
        int index = 0;
        
        while ((index = text.indexOf(value, index)) != -1) {
            positions.add(index);
            index += value.length();
        }
        
        return positions;
    }
    
    /**
     * Extracts surrounding context (100 chars before and after)
     */
    private String extractContext(String text, int position, int valueLength) {
        int start = Math.max(0, position - 100);
        int end = Math.min(text.length(), position + valueLength + 100);
        return text.substring(start, end);
    }
    
    /**
     * Determines the reflection context type
     */
    private ReflectionContext determineContext(String context, String value) {
        ReflectionContext ctx = new ReflectionContext();
        ctx.setContext(context);
        ctx.setValue(value);
        
        // Check for HTML encoding
        String encodedValue = htmlEncode(value);
        if (context.contains(encodedValue)) {
            ctx.setEncoded(true);
            ctx.setEncodingType("HTML Entity Encoding");
        }
        
        // Check for URL encoding
        String urlEncodedValue = urlEncode(value);
        if (context.contains(urlEncodedValue)) {
            ctx.setEncoded(true);
            ctx.setEncodingType("URL Encoding");
        }
        
        // Determine context type
        if (isInHtmlTag(context, value)) {
            ctx.setContextType("HTML Tag");
            ctx.setDescription("Inside HTML tag: " + extractTagName(context));
            ctx.setExploitable(!ctx.isEncoded());
        } else if (isInHtmlAttribute(context, value)) {
            ctx.setContextType("HTML Attribute");
            ctx.setDescription("Inside HTML attribute: " + extractAttributeContext(context));
            ctx.setExploitable(!ctx.isEncoded() || canBreakOutOfAttribute(context));
        } else if (isInScriptTag(context, value)) {
            ctx.setContextType("JavaScript");
            ctx.setDescription("Inside <script> tag");
            ctx.setExploitable(true); // Often exploitable even with some encoding
        } else if (isInJavaScriptString(context, value)) {
            ctx.setContextType("JavaScript String");
            ctx.setDescription("Inside JavaScript string literal");
            ctx.setExploitable(canBreakOutOfString(context, value));
        } else if (isInHtmlComment(context, value)) {
            ctx.setContextType("HTML Comment");
            ctx.setDescription("Inside HTML comment <!-- -->");
            ctx.setExploitable(canBreakOutOfComment(context));
        } else if (isInStyle(context, value)) {
            ctx.setContextType("CSS/Style");
            ctx.setDescription("Inside <style> tag or style attribute");
            ctx.setExploitable(true);
        } else {
            ctx.setContextType("HTML Body");
            ctx.setDescription("In HTML body text");
            ctx.setExploitable(!ctx.isEncoded());
        }
        
        return ctx;
    }
    
    // Context detection helpers
    
    private boolean isInHtmlTag(String context, String value) {
        int valuePos = context.indexOf(value);
        if (valuePos == -1) return false;
        
        int lastOpenTag = context.lastIndexOf('<', valuePos);
        int lastCloseTag = context.lastIndexOf('>', valuePos);
        
        return lastOpenTag > lastCloseTag;
    }
    
    private boolean isInHtmlAttribute(String context, String value) {
        int valuePos = context.indexOf(value);
        if (valuePos == -1) return false;
        
        // Check if between = and space/> after a tag
        int lastEquals = context.lastIndexOf('=', valuePos);
        int lastOpenTag = context.lastIndexOf('<', valuePos);
        int lastCloseTag = context.lastIndexOf('>', valuePos);
        
        return lastEquals > lastOpenTag && lastOpenTag > lastCloseTag;
    }
    
    private boolean isInScriptTag(String context, String value) {
        String lowerContext = context.toLowerCase();
        int valuePos = lowerContext.indexOf(value.toLowerCase());
        if (valuePos == -1) return false;
        
        int lastScriptOpen = lowerContext.lastIndexOf("<script", valuePos);
        int lastScriptClose = lowerContext.lastIndexOf("</script>", valuePos);
        
        return lastScriptOpen > lastScriptClose;
    }
    
    private boolean isInJavaScriptString(String context, String value) {
        int valuePos = context.indexOf(value);
        if (valuePos == -1) return false;
        
        // Check if between quotes
        int lastSingleQuote = context.lastIndexOf('\'', valuePos);
        int lastDoubleQuote = context.lastIndexOf('"', valuePos);
        int lastBacktick = context.lastIndexOf('`', valuePos);
        
        int nextSingleQuote = context.indexOf('\'', valuePos + value.length());
        int nextDoubleQuote = context.indexOf('"', valuePos + value.length());
        int nextBacktick = context.indexOf('`', valuePos + value.length());
        
        return (lastSingleQuote != -1 && nextSingleQuote != -1) ||
               (lastDoubleQuote != -1 && nextDoubleQuote != -1) ||
               (lastBacktick != -1 && nextBacktick != -1);
    }
    
    private boolean isInHtmlComment(String context, String value) {
        int valuePos = context.indexOf(value);
        if (valuePos == -1) return false;
        
        int lastCommentOpen = context.lastIndexOf("<!--", valuePos);
        int lastCommentClose = context.lastIndexOf("-->", valuePos);
        
        return lastCommentOpen > lastCommentClose;
    }
    
    private boolean isInStyle(String context, String value) {
        String lowerContext = context.toLowerCase();
        int valuePos = lowerContext.indexOf(value.toLowerCase());
        if (valuePos == -1) return false;
        
        int lastStyleOpen = lowerContext.lastIndexOf("<style", valuePos);
        int lastStyleClose = lowerContext.lastIndexOf("</style>", valuePos);
        
        return lastStyleOpen > lastStyleClose || lowerContext.contains("style=");
    }
    
    private boolean canBreakOutOfAttribute(String context) {
        // Check if quotes are not filtered
        return !context.contains("&quot;") && !context.contains("&#");
    }
    
    private boolean canBreakOutOfString(String context, String value) {
        // Check if quotes and backslashes are not escaped
        return !context.contains("\\\"") && !context.contains("\\'");
    }
    
    private boolean canBreakOutOfComment(String context) {
        // Check if --> is not filtered
        return true; // Usually possible
    }
    
    private String extractTagName(String context) {
        Pattern pattern = Pattern.compile("<(\\w+)");
        Matcher matcher = pattern.matcher(context);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "unknown";
    }
    
    private String extractAttributeContext(String context) {
        Pattern pattern = Pattern.compile("(\\w+)\\s*=");
        Matcher matcher = pattern.matcher(context);
        if (matcher.find()) {
            return matcher.group(1) + " attribute";
        }
        return "unknown attribute";
    }
    
    // Encoding helpers
    
    private String htmlEncode(String str) {
        return str.replace("&", "&amp;")
                  .replace("<", "&lt;")
                  .replace(">", "&gt;")
                  .replace("\"", "&quot;")
                  .replace("'", "&#x27;");
    }
    
    private String urlEncode(String str) {
        StringBuilder result = new StringBuilder();
        for (char c : str.toCharArray()) {
            if (c == '<' || c == '>' || c == '"' || c == '\'' || c == '&' || c == ' ') {
                result.append(String.format("%%%02X", (int) c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
    
    // Data classes
    
    public static class ReflectionAnalysis {
        private final List<ReflectionPoint> reflections = new ArrayList<>();
        
        public void addReflection(ReflectionPoint reflection) {
            reflections.add(reflection);
        }
        
        public List<ReflectionPoint> getReflections() {
            return reflections;
        }
        
        public boolean hasReflections() {
            return !reflections.isEmpty();
        }
        
        public String getSummary() {
            if (reflections.isEmpty()) {
                return "No parameter reflections detected in response (checked exact, HTML-encoded, and partial matches).";
            }
            
            StringBuilder summary = new StringBuilder();
            summary.append("REFLECTION ANALYSIS (").append(reflections.size()).append(" parameter(s) reflected):\n\n");
            
            for (ReflectionPoint reflection : reflections) {
                summary.append("⚡ Parameter: ").append(reflection.getParameterName()).append("\n");
                summary.append("   Injected Value: ").append(reflection.getParameterValue()).append("\n");
                summary.append("   Reflected in: ").append(String.join(", ", reflection.getLocations())).append("\n");
                
                for (ReflectionContext ctx : reflection.getContexts()) {
                    summary.append("   → Context: ").append(ctx.getContextType()).append("\n");
                    summary.append("     Location: ").append(ctx.getDescription()).append("\n");
                    summary.append("     Encoded: ").append(ctx.isEncoded() ? "Yes (" + ctx.getEncodingType() + ")" : "No (RAW reflection!)").append("\n");
                    summary.append("     Exploitable: ").append(ctx.isExploitable() ? "✓ YES — breakout likely possible" : "✗ Unlikely — encoding prevents breakout").append("\n");
                    // Include a snippet of the surrounding context so AI can see exactly what's around the reflection
                    if (ctx.getContext() != null && !ctx.getContext().isEmpty()) {
                        String snippet = ctx.getContext();
                        if (snippet.length() > 300) snippet = snippet.substring(0, 300) + "...";
                        summary.append("     Surrounding HTML: ").append(snippet).append("\n");
                    }
                }
                summary.append("\n");
            }
            
            return summary.toString();
        }
    }
    
    public static class ReflectionPoint {
        private final String parameterName;
        private final String parameterValue;
        private boolean reflectedInHeaders = false;
        private final List<String> locations = new ArrayList<>();
        private final List<ReflectionContext> contexts = new ArrayList<>();
        
        public ReflectionPoint(String parameterName, String parameterValue) {
            this.parameterName = parameterName;
            this.parameterValue = parameterValue;
        }
        
        public String getParameterName() { return parameterName; }
        public String getParameterValue() { return parameterValue; }
        public boolean isReflectedInHeaders() { return reflectedInHeaders; }
        public void setReflectedInHeaders(boolean reflected) { this.reflectedInHeaders = reflected; }
        public List<String> getLocations() { return locations; }
        public void addLocation(String location) { 
            if (!locations.contains(location)) {
                locations.add(location);
            }
        }
        public List<ReflectionContext> getContexts() { return contexts; }
        public void addContext(ReflectionContext context) { contexts.add(context); }
    }
    
    public static class ReflectionContext {
        private String contextType;
        private String description;
        private String context;
        private String value;
        private boolean encoded = false;
        private String encodingType;
        private boolean exploitable = false;
        
        public String getContextType() { return contextType; }
        public void setContextType(String contextType) { this.contextType = contextType; }
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
        public String getContext() { return context; }
        public void setContext(String context) { this.context = context; }
        public String getValue() { return value; }
        public void setValue(String value) { this.value = value; }
        public boolean isEncoded() { return encoded; }
        public void setEncoded(boolean encoded) { this.encoded = encoded; }
        public String getEncodingType() { return encodingType; }
        public void setEncodingType(String encodingType) { this.encodingType = encodingType; }
        public boolean isExploitable() { return exploitable; }
        public void setExploitable(boolean exploitable) { this.exploitable = exploitable; }
    }
}
