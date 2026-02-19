package com.vista.security.model;

import burp.IHttpRequestResponse;

import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Immutable data model representing a single HTTP request/response transaction.
 * Captures metadata and raw bytes for efficient storage and later analysis.
 */
public class HttpTransaction {
    private final String id;
    private final long timestamp;
    private final String method;
    private final String url;
    private final String contentType;
    private final int statusCode;
    private final long responseSize;
    private final byte[] request;
    private final byte[] response;
    private final IHttpRequestResponse burpMessage;
    
    /**
     * Creates a new HTTP transaction.
     * 
     * @param id Unique identifier (UUID)
     * @param timestamp Capture time in milliseconds
     * @param method HTTP method (GET, POST, etc.)
     * @param url Full URL
     * @param contentType Content-Type header value (or "unknown")
     * @param statusCode HTTP status code
     * @param responseSize Response body size in bytes
     * @param request Raw request bytes
     * @param response Raw response bytes
     * @param burpMessage Original Burp message for integration
     */
    public HttpTransaction(String id, long timestamp, String method, String url,
                          String contentType, int statusCode, long responseSize,
                          byte[] request, byte[] response, 
                          IHttpRequestResponse burpMessage) {
        this.id = id;
        this.timestamp = timestamp;
        this.method = method;
        this.url = url;
        this.contentType = contentType != null ? contentType : "unknown";
        this.statusCode = statusCode;
        this.responseSize = responseSize;
        this.request = request;
        this.response = response;
        this.burpMessage = burpMessage;
    }
    
    /**
     * Creates a new HTTP transaction with auto-generated ID.
     */
    public static HttpTransaction create(long timestamp, String method, String url,
                                        String contentType, int statusCode, long responseSize,
                                        byte[] request, byte[] response,
                                        IHttpRequestResponse burpMessage) {
        return new HttpTransaction(
            UUID.randomUUID().toString(),
            timestamp,
            method,
            url,
            contentType,
            statusCode,
            responseSize,
            request,
            response,
            burpMessage
        );
    }
    
    // Getters
    
    public String getId() {
        return id;
    }
    
    public long getTimestamp() {
        return timestamp;
    }
    
    public String getMethod() {
        return method;
    }
    
    public String getUrl() {
        return url;
    }
    
    public String getContentType() {
        return contentType;
    }
    
    public int getStatusCode() {
        return statusCode;
    }
    
    public long getResponseSize() {
        return responseSize;
    }
    
    public byte[] getRequest() {
        return request;
    }
    
    public byte[] getResponse() {
        return response;
    }
    
    public IHttpRequestResponse getBurpMessage() {
        return burpMessage;
    }
    
    // Utility methods
    
    /**
     * Returns formatted timestamp for UI display (HH:mm:ss.SSS).
     */
    public String getFormattedTimestamp() {
        return new SimpleDateFormat("HH:mm:ss.SSS").format(new Date(timestamp));
    }
    
    /**
     * Returns formatted response size for UI display (B, KB, MB).
     */
    public String getFormattedSize() {
        if (responseSize < 1024) {
            return responseSize + " B";
        } else if (responseSize < 1024 * 1024) {
            return String.format("%.1f KB", responseSize / 1024.0);
        } else {
            return String.format("%.1f MB", responseSize / (1024.0 * 1024.0));
        }
    }
    
    /**
     * Extracts hostname from URL.
     */
    public String getHost() {
        try {
            String urlToProcess = url;
            
            // Handle URLs with protocol
            if (urlToProcess.startsWith("http://") || urlToProcess.startsWith("https://")) {
                int start = urlToProcess.indexOf("://") + 3;
                int end = urlToProcess.indexOf("/", start);
                if (end == -1) {
                    end = urlToProcess.length();
                }
                // Remove port if present
                String hostWithPort = urlToProcess.substring(start, end);
                int colonIndex = hostWithPort.indexOf(":");
                return colonIndex > 0 ? hostWithPort.substring(0, colonIndex) : hostWithPort;
            }
            
            // Handle URLs without protocol (just domain/path)
            if (!urlToProcess.contains("://")) {
                int slashIndex = urlToProcess.indexOf("/");
                if (slashIndex > 0) {
                    String hostWithPort = urlToProcess.substring(0, slashIndex);
                    int colonIndex = hostWithPort.indexOf(":");
                    return colonIndex > 0 ? hostWithPort.substring(0, colonIndex) : hostWithPort;
                } else {
                    // Just a hostname
                    int colonIndex = urlToProcess.indexOf(":");
                    return colonIndex > 0 ? urlToProcess.substring(0, colonIndex) : urlToProcess;
                }
            }
            
            return "unknown";
        } catch (Exception e) {
            return "unknown";
        }
    }
    
    /**
     * Checks if URL has query parameters.
     */
    public boolean hasParams() {
        return url.contains("?");
    }
    
    /**
     * Gets file extension from URL.
     */
    public String getExtension() {
        try {
            int queryIndex = url.indexOf("?");
            String path = queryIndex > 0 ? url.substring(0, queryIndex) : url;
            int lastDot = path.lastIndexOf(".");
            int lastSlash = path.lastIndexOf("/");
            
            if (lastDot > lastSlash && lastDot < path.length() - 1) {
                return path.substring(lastDot + 1);
            }
            return "";
        } catch (Exception e) {
            return "";
        }
    }
    
    /**
     * Extracts page title from HTML response.
     */
    public String getTitle() {
        if (response == null || !contentType.contains("html")) {
            return "";
        }
        
        try {
            String html = new String(response);
            int titleStart = html.toLowerCase().indexOf("<title>");
            if (titleStart == -1) {
                return "";
            }
            titleStart += 7;
            int titleEnd = html.toLowerCase().indexOf("</title>", titleStart);
            if (titleEnd == -1) {
                return "";
            }
            String title = html.substring(titleStart, titleEnd).trim();
            return title.length() > 50 ? title.substring(0, 50) + "..." : title;
        } catch (Exception e) {
            return "";
        }
    }
    
    /**
     * Gets short MIME type for display.
     */
    public String getShortMimeType() {
        if (contentType == null || contentType.equals("unknown")) {
            return "";
        }
        
        // Extract main type
        int semicolon = contentType.indexOf(";");
        String mimeType = semicolon > 0 ? contentType.substring(0, semicolon) : contentType;
        
        // Shorten common types
        if (mimeType.equals("text/html")) return "HTML";
        if (mimeType.equals("application/json")) return "JSON";
        if (mimeType.equals("application/javascript")) return "JS";
        if (mimeType.equals("text/javascript")) return "JS";
        if (mimeType.equals("text/css")) return "CSS";
        if (mimeType.equals("image/png")) return "PNG";
        if (mimeType.equals("image/jpeg")) return "JPEG";
        if (mimeType.equals("image/gif")) return "GIF";
        if (mimeType.equals("application/xml")) return "XML";
        if (mimeType.equals("text/xml")) return "XML";
        
        return mimeType;
    }
    
    /**
     * Serializes this HttpTransaction to a JSON string for persistence.
     * byte[] fields are Base64-encoded. IHttpRequestResponse is not serialized.
     */
    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"id\": ").append(jsonString(id)).append(",\n");
        sb.append("  \"timestamp\": ").append(timestamp).append(",\n");
        sb.append("  \"method\": ").append(jsonString(method)).append(",\n");
        sb.append("  \"url\": ").append(jsonString(url)).append(",\n");
        sb.append("  \"contentType\": ").append(jsonString(contentType)).append(",\n");
        sb.append("  \"statusCode\": ").append(statusCode).append(",\n");
        sb.append("  \"responseSize\": ").append(responseSize).append(",\n");
        sb.append("  \"request\": ").append(request != null ? jsonString(Base64.getEncoder().encodeToString(request)) : "null").append(",\n");
        sb.append("  \"response\": ").append(response != null ? jsonString(Base64.getEncoder().encodeToString(response)) : "null").append("\n");
        sb.append("}");
        return sb.toString();
    }
    
    /**
     * Deserializes an HttpTransaction from a JSON string.
     * Returns null if parsing fails.
     */
    public static HttpTransaction fromJson(String json) {
        try {
            Map<String, String> fields = parseJsonObject(json);
            if (fields == null || !fields.containsKey("id")) return null;
            
            String id = fields.get("id");
            long timestamp = Long.parseLong(fields.getOrDefault("timestamp", "0"));
            String method = fields.getOrDefault("method", "GET");
            String url = fields.getOrDefault("url", "");
            String contentType = fields.getOrDefault("contentType", "unknown");
            int statusCode = Integer.parseInt(fields.getOrDefault("statusCode", "0"));
            long responseSize = Long.parseLong(fields.getOrDefault("responseSize", "0"));
            
            byte[] request = null;
            String reqB64 = fields.get("request");
            if (reqB64 != null && !reqB64.equals("null") && !reqB64.isEmpty()) {
                request = Base64.getDecoder().decode(reqB64);
            }
            
            byte[] response = null;
            String respB64 = fields.get("response");
            if (respB64 != null && !respB64.equals("null") && !respB64.isEmpty()) {
                response = Base64.getDecoder().decode(respB64);
            }
            
            return new HttpTransaction(id, timestamp, method, url, contentType,
                    statusCode, responseSize, request, response, null);
        } catch (Exception e) {
            System.err.println("[VISTA] Error deserializing HttpTransaction: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Escapes a string for JSON output.
     */
    private static String jsonString(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\")
                       .replace("\"", "\\\"")
                       .replace("\n", "\\n")
                       .replace("\r", "\\r")
                       .replace("\t", "\\t") + "\"";
    }
    
    /**
     * Parses a flat JSON object into a Map of key-value pairs.
     * Hand-rolled parser for simple JSON (no nested objects except null values).
     */
    static Map<String, String> parseJsonObject(String json) {
        if (json == null || json.trim().isEmpty()) return null;
        Map<String, String> map = new LinkedHashMap<>();
        json = json.trim();
        if (json.startsWith("{")) json = json.substring(1);
        if (json.endsWith("}")) json = json.substring(0, json.length() - 1);
        
        int i = 0;
        while (i < json.length()) {
            // Find key
            int keyStart = json.indexOf('"', i);
            if (keyStart < 0) break;
            int keyEnd = json.indexOf('"', keyStart + 1);
            if (keyEnd < 0) break;
            String key = json.substring(keyStart + 1, keyEnd);
            
            // Find colon
            int colon = json.indexOf(':', keyEnd + 1);
            if (colon < 0) break;
            
            // Find value
            int valueStart = colon + 1;
            while (valueStart < json.length() && json.charAt(valueStart) == ' ') valueStart++;
            
            if (valueStart >= json.length()) break;
            
            String value;
            int nextPos;
            
            if (json.charAt(valueStart) == '"') {
                // String value - handle escaped quotes
                StringBuilder sb = new StringBuilder();
                int vi = valueStart + 1;
                while (vi < json.length()) {
                    char c = json.charAt(vi);
                    if (c == '\\' && vi + 1 < json.length()) {
                        char next = json.charAt(vi + 1);
                        switch (next) {
                            case '"': sb.append('"'); break;
                            case '\\': sb.append('\\'); break;
                            case 'n': sb.append('\n'); break;
                            case 'r': sb.append('\r'); break;
                            case 't': sb.append('\t'); break;
                            default: sb.append('\\').append(next); break;
                        }
                        vi += 2;
                    } else if (c == '"') {
                        break;
                    } else {
                        sb.append(c);
                        vi++;
                    }
                }
                value = sb.toString();
                nextPos = vi + 1;
            } else if (json.substring(valueStart).startsWith("null")) {
                value = null;
                nextPos = valueStart + 4;
            } else if (json.substring(valueStart).startsWith("true")) {
                value = "true";
                nextPos = valueStart + 4;
            } else if (json.substring(valueStart).startsWith("false")) {
                value = "false";
                nextPos = valueStart + 5;
            } else if (json.charAt(valueStart) == '{') {
                // Nested object - find matching brace
                int depth = 1;
                int vi = valueStart + 1;
                while (vi < json.length() && depth > 0) {
                    if (json.charAt(vi) == '{') depth++;
                    else if (json.charAt(vi) == '}') depth--;
                    vi++;
                }
                value = json.substring(valueStart, vi);
                nextPos = vi;
            } else {
                // Number value
                int end = valueStart;
                while (end < json.length() && json.charAt(end) != ',' && json.charAt(end) != '}' && json.charAt(end) != '\n') {
                    end++;
                }
                value = json.substring(valueStart, end).trim();
                nextPos = end;
            }
            
            map.put(key, value);
            
            // Skip to next field
            i = nextPos;
            while (i < json.length() && (json.charAt(i) == ',' || json.charAt(i) == ' ' || json.charAt(i) == '\n' || json.charAt(i) == '\r')) {
                i++;
            }
        }
        
        return map;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof HttpTransaction)) return false;
        HttpTransaction that = (HttpTransaction) o;
        return id.equals(that.id);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
    
    @Override
    public String toString() {
        return "HttpTransaction{" +
                "id='" + id + '\'' +
                ", method='" + method + '\'' +
                ", url='" + url + '\'' +
                ", statusCode=" + statusCode +
                ", contentType='" + contentType + '\'' +
                '}';
    }
}
