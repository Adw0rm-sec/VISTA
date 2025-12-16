package com.vista.security.core;

import burp.IExtensionHelpers;
import burp.IRequestInfo;
import burp.IResponseInfo;

import java.nio.charset.StandardCharsets;

/**
 * Utility class for parsing and formatting HTTP messages.
 * Provides methods to convert Burp's byte arrays to readable text
 * and prepare content for AI analysis.
 */
public final class HttpMessageParser {
    
    private HttpMessageParser() {
        // Utility class - prevent instantiation
    }
    
    /**
     * Convert a raw HTTP request to readable text.
     * @param helpers Burp extension helpers
     * @param request Raw request bytes
     * @return Formatted request string
     */
    public static String requestToText(IExtensionHelpers helpers, byte[] request) {
        if (request == null) return "(no request)";
        
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        int bodyOffset = requestInfo.getBodyOffset();
        
        String headers = String.join("\r\n", requestInfo.getHeaders());
        String body = new String(request, bodyOffset, request.length - bodyOffset, StandardCharsets.ISO_8859_1);
        
        return headers + "\r\n\r\n" + body;
    }
    
    /**
     * Convert a raw HTTP response to readable text.
     * @param helpers Burp extension helpers
     * @param response Raw response bytes
     * @return Formatted response string
     */
    public static String responseToText(IExtensionHelpers helpers, byte[] response) {
        if (response == null) return "(no response)";
        
        IResponseInfo responseInfo = helpers.analyzeResponse(response);
        int bodyOffset = responseInfo.getBodyOffset();
        
        String headers = String.join("\r\n", responseInfo.getHeaders());
        String body = new String(response, bodyOffset, response.length - bodyOffset, StandardCharsets.ISO_8859_1);
        
        return headers + "\r\n\r\n" + body;
    }
    
    /**
     * Prepare HTTP content for AI analysis by optionally stripping
     * sensitive headers and truncating to a maximum length.
     * 
     * @param rawContent The raw HTTP content
     * @param stripSensitiveHeaders Whether to remove Authorization, Cookie, etc.
     * @param maxCharacters Maximum characters to include
     * @return Sanitized content ready for AI
     */
    public static String prepareForAI(String rawContent, boolean stripSensitiveHeaders, int maxCharacters) {
        if (rawContent == null) return "";
        
        String[] parts = rawContent.split("\r?\n\r?\n", 2);
        String headers = parts.length > 0 ? parts[0] : "";
        String body = parts.length > 1 ? parts[1] : "";
        
        if (stripSensitiveHeaders) {
            headers = removeSensitiveHeaders(headers);
        }
        
        String combined = headers + "\n\n" + body;
        
        if (combined.length() > maxCharacters) {
            combined = combined.substring(0, maxCharacters) + "\n...[truncated]...";
        }
        
        return combined;
    }
    
    /**
     * Extract the HTTP method from a request.
     * @param requestText The request as text
     * @return The HTTP method (GET, POST, etc.)
     */
    public static String extractMethod(String requestText) {
        if (requestText == null || requestText.isBlank()) return "UNKNOWN";
        String[] lines = requestText.split("\\r?\\n");
        if (lines.length == 0) return "UNKNOWN";
        String[] parts = lines[0].split(" ");
        return parts.length > 0 ? parts[0] : "UNKNOWN";
    }
    
    /**
     * Extract the request path from a request.
     * @param requestText The request as text
     * @return The request path
     */
    public static String extractPath(String requestText) {
        if (requestText == null || requestText.isBlank()) return "/";
        String[] lines = requestText.split("\\r?\\n");
        if (lines.length == 0) return "/";
        String[] parts = lines[0].split(" ");
        return parts.length > 1 ? parts[1] : "/";
    }
    
    /**
     * Extract a specific header value from HTTP content.
     * @param httpContent The HTTP content
     * @param headerName The header name (case-insensitive)
     * @return The header value or null if not found
     */
    public static String extractHeader(String httpContent, String headerName) {
        if (httpContent == null || headerName == null) return null;
        
        String[] lines = httpContent.split("\\r?\\n");
        String lowerName = headerName.toLowerCase() + ":";
        
        for (String line : lines) {
            if (line.toLowerCase().startsWith(lowerName)) {
                return line.substring(lowerName.length()).trim();
            }
        }
        return null;
    }
    
    private static String removeSensitiveHeaders(String headers) {
        String[] sensitiveHeaders = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"};
        String[] lines = headers.split("\\r?\\n");
        StringBuilder result = new StringBuilder();
        
        for (String line : lines) {
            String lowerLine = line.toLowerCase();
            boolean isSensitive = false;
            
            for (String sensitive : sensitiveHeaders) {
                if (lowerLine.startsWith(sensitive + ":")) {
                    isSensitive = true;
                    break;
                }
            }
            
            if (!isSensitive) {
                result.append(line).append("\n");
            }
        }
        
        return result.toString().trim();
    }
}
