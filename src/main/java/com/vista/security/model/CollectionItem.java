package com.vista.security.model;

import burp.IHttpRequestResponse;
import burp.IHttpService;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Represents a single HTTP request/response in a collection.
 */
public class CollectionItem {
    
    private String id;
    private byte[] request;
    private byte[] response;
    private String url;
    private String method;
    private int statusCode;
    private String host;
    private int port;
    private String protocol;
    private String notes;
    private boolean tested;
    private boolean success;
    private long timestamp;
    
    public CollectionItem(IHttpRequestResponse requestResponse) {
        this.id = UUID.randomUUID().toString();
        this.request = requestResponse.getRequest();
        this.response = requestResponse.getResponse();
        this.timestamp = System.currentTimeMillis();
        this.tested = false;
        this.success = false;
        this.notes = "";
        
        // Extract metadata
        if (requestResponse.getHttpService() != null) {
            IHttpService service = requestResponse.getHttpService();
            this.host = service.getHost();
            this.port = service.getPort();
            this.protocol = service.getProtocol();
        }
        
        // Parse request for method and URL
        if (request != null && request.length > 0) {
            String requestStr = new String(request);
            String[] lines = requestStr.split("\n");
            if (lines.length > 0) {
                String[] parts = lines[0].split(" ");
                if (parts.length >= 2) {
                    this.method = parts[0];
                    this.url = parts[1];
                }
            }
        }
        
        // Parse response for status code
        if (response != null && response.length > 0) {
            String responseStr = new String(response);
            String[] lines = responseStr.split("\n");
            if (lines.length > 0) {
                String[] parts = lines[0].split(" ");
                if (parts.length >= 2) {
                    try {
                        this.statusCode = Integer.parseInt(parts[1]);
                    } catch (NumberFormatException e) {
                        this.statusCode = 0;
                    }
                }
            }
        }
    }
    
    // Constructor for deserialization
    private CollectionItem() {
        this.id = UUID.randomUUID().toString();
        this.timestamp = System.currentTimeMillis();
    }
    
    // Getters
    public String getId() { return id; }
    public byte[] getRequest() { return request; }
    public byte[] getResponse() { return response; }
    public String getUrl() { return url; }
    public String getMethod() { return method; }
    public int getStatusCode() { return statusCode; }
    public String getHost() { return host; }
    public int getPort() { return port; }
    public String getProtocol() { return protocol; }
    public String getNotes() { return notes; }
    public boolean isTested() { return tested; }
    public boolean isSuccess() { return success; }
    public long getTimestamp() { return timestamp; }
    
    // Setters
    public void setNotes(String notes) { this.notes = notes; }
    public void setTested(boolean tested) { this.tested = tested; }
    public void setSuccess(boolean success) { this.success = success; }
    
    // Get full URL
    public String getFullUrl() {
        if (host != null && url != null) {
            return protocol + "://" + host + (port != 80 && port != 443 ? ":" + port : "") + url;
        }
        return url != null ? url : "";
    }
    
    // Manual JSON serialization
    public String toJson() {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"id\": \"").append(escapeJson(id)).append("\",\n");
        json.append("  \"request\": \"").append(Base64.getEncoder().encodeToString(request != null ? request : new byte[0])).append("\",\n");
        json.append("  \"response\": \"").append(Base64.getEncoder().encodeToString(response != null ? response : new byte[0])).append("\",\n");
        json.append("  \"url\": \"").append(escapeJson(url)).append("\",\n");
        json.append("  \"method\": \"").append(escapeJson(method)).append("\",\n");
        json.append("  \"statusCode\": ").append(statusCode).append(",\n");
        json.append("  \"host\": \"").append(escapeJson(host)).append("\",\n");
        json.append("  \"port\": ").append(port).append(",\n");
        json.append("  \"protocol\": \"").append(escapeJson(protocol)).append("\",\n");
        json.append("  \"notes\": \"").append(escapeJson(notes)).append("\",\n");
        json.append("  \"tested\": ").append(tested).append(",\n");
        json.append("  \"success\": ").append(success).append(",\n");
        json.append("  \"timestamp\": ").append(timestamp).append("\n");
        json.append("}");
        return json.toString();
    }
    
    public static CollectionItem fromJson(String json) {
        CollectionItem item = new CollectionItem();
        
        item.id = extractString(json, "id");
        item.url = extractString(json, "url");
        item.method = extractString(json, "method");
        item.host = extractString(json, "host");
        item.protocol = extractString(json, "protocol");
        item.notes = extractString(json, "notes");
        
        item.statusCode = extractInt(json, "statusCode");
        item.port = extractInt(json, "port");
        item.timestamp = extractLong(json, "timestamp");
        
        item.tested = extractBoolean(json, "tested");
        item.success = extractBoolean(json, "success");
        
        // Decode Base64 request/response
        String requestB64 = extractString(json, "request");
        if (!requestB64.isEmpty()) {
            try {
                item.request = Base64.getDecoder().decode(requestB64);
            } catch (Exception e) {
                item.request = new byte[0];
            }
        }
        
        String responseB64 = extractString(json, "response");
        if (!responseB64.isEmpty()) {
            try {
                item.response = Base64.getDecoder().decode(responseB64);
            } catch (Exception e) {
                item.response = new byte[0];
            }
        }
        
        return item;
    }
    
    // JSON helper methods
    private static String extractString(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return unescapeJson(matcher.group(1));
        }
        return "";
    }
    
    private static int extractInt(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return Integer.parseInt(matcher.group(1));
        }
        return 0;
    }
    
    private static long extractLong(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return Long.parseLong(matcher.group(1));
        }
        return 0L;
    }
    
    private static boolean extractBoolean(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*(true|false)");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return Boolean.parseBoolean(matcher.group(1));
        }
        return false;
    }
    
    private static String escapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }
    
    private static String unescapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\\"", "\"")
                  .replace("\\\\", "\\")
                  .replace("\\n", "\n")
                  .replace("\\r", "\r")
                  .replace("\\t", "\t");
    }
    
    @Override
    public String toString() {
        return method + " " + url + " (" + statusCode + ")";
    }
}
