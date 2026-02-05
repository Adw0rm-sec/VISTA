package com.vista.security.mcp;

import java.util.Map;

/**
 * Represents a JSON-RPC 2.0 response from MCP server.
 */
public class MCPResponse {
    private String jsonrpc;
    private Object id;
    private Map<String, Object> result;
    private MCPError error;

    public MCPResponse() {
    }

    public String getJsonrpc() {
        return jsonrpc;
    }

    public void setJsonrpc(String jsonrpc) {
        this.jsonrpc = jsonrpc;
    }

    public Object getId() {
        return id;
    }

    public void setId(Object id) {
        this.id = id;
    }

    public Map<String, Object> getResult() {
        return result;
    }

    public void setResult(Map<String, Object> result) {
        this.result = result;
    }

    public MCPError getError() {
        return error;
    }

    public void setError(MCPError error) {
        this.error = error;
    }

    public boolean hasError() {
        return error != null;
    }

    public boolean isSuccess() {
        return result != null && error == null;
    }

    public static class MCPError {
        private int code;
        private String message;
        private Object data;

        public MCPError() {
        }

        public int getCode() {
            return code;
        }

        public void setCode(int code) {
            this.code = code;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }

        public Object getData() {
            return data;
        }

        public void setData(Object data) {
            this.data = data;
        }

        @Override
        public String toString() {
            return "MCPError{code=" + code + ", message='" + message + "'}";
        }
    }
}
