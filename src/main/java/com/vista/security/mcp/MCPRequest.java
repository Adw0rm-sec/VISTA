package com.vista.security.mcp;

import java.util.Map;

/**
 * Represents a JSON-RPC 2.0 request for MCP protocol.
 */
public class MCPRequest {
    private final String jsonrpc = "2.0";
    private final String method;
    private final Map<String, Object> params;
    private final Object id;

    public MCPRequest(String method, Map<String, Object> params, Object id) {
        this.method = method;
        this.params = params;
        this.id = id;
    }

    public String getJsonrpc() {
        return jsonrpc;
    }

    public String getMethod() {
        return method;
    }

    public Map<String, Object> getParams() {
        return params;
    }

    public Object getId() {
        return id;
    }

    /**
     * Convert to JSON string manually (no external dependencies).
     */
    public String toJson() {
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"jsonrpc\":\"").append(jsonrpc).append("\",");
        json.append("\"method\":\"").append(escapeJson(method)).append("\",");
        
        if (params != null && !params.isEmpty()) {
            json.append("\"params\":");
            json.append(mapToJson(params));
            json.append(",");
        }
        
        json.append("\"id\":");
        if (id instanceof String) {
            json.append("\"").append(escapeJson((String) id)).append("\"");
        } else {
            json.append(id);
        }
        
        json.append("}");
        return json.toString();
    }

    private String mapToJson(Map<String, Object> map) {
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!first) json.append(",");
            first = false;
            json.append("\"").append(escapeJson(entry.getKey())).append("\":");
            json.append(valueToJson(entry.getValue()));
        }
        json.append("}");
        return json.toString();
    }

    private String valueToJson(Object value) {
        if (value == null) {
            return "null";
        } else if (value instanceof String) {
            return "\"" + escapeJson((String) value) + "\"";
        } else if (value instanceof Number || value instanceof Boolean) {
            return value.toString();
        } else if (value instanceof Map) {
            return mapToJson((Map<String, Object>) value);
        } else {
            return "\"" + escapeJson(value.toString()) + "\"";
        }
    }

    private String escapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }
}
