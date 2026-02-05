package com.vista.security.mcp;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Client for connecting to Burp Suite MCP Server.
 * Implements MCP protocol over HTTP/SSE transport.
 */
public class BurpMCPClient {
    private final String serverUrl;
    private final HttpClient httpClient;
    private final AtomicLong requestIdCounter;
    private String sessionId;
    private boolean initialized;
    private List<MCPTool> availableTools;

    public BurpMCPClient(String serverUrl) {
        this.serverUrl = serverUrl.endsWith("/") ? serverUrl.substring(0, serverUrl.length() - 1) : serverUrl;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        this.requestIdCounter = new AtomicLong(1);
        this.initialized = false;
        this.availableTools = new ArrayList<>();
    }

    /**
     * Test connection to MCP server.
     */
    public boolean testConnection() {
        try {
            // Try base URL first
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(serverUrl))
                    .timeout(Duration.ofSeconds(5))
                    .header("Accept", "application/json, text/event-stream")
                    .GET()
                    .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            // 200 = OK, 405 = Method Not Allowed (GET not supported, but server is there)
            // 404 = Try /sse endpoint
            if (response.statusCode() == 200 || response.statusCode() == 405) {
                return true;
            }
            
            // If base URL fails, try /sse endpoint
            if (response.statusCode() == 404 && !serverUrl.endsWith("/sse")) {
                String sseUrl = serverUrl + "/sse";
                HttpRequest sseRequest = HttpRequest.newBuilder()
                        .uri(URI.create(sseUrl))
                        .timeout(Duration.ofSeconds(5))
                        .header("Accept", "application/json, text/event-stream")
                        .GET()
                        .build();
                
                HttpResponse<String> sseResponse = httpClient.send(sseRequest, HttpResponse.BodyHandlers.ofString());
                return sseResponse.statusCode() == 200 || sseResponse.statusCode() == 405;
            }
            
            return false;
        } catch (java.net.ConnectException e) {
            System.err.println("MCP Connection failed: Server not reachable at " + serverUrl);
            System.err.println("Make sure Burp MCP Server extension is installed and enabled");
            return false;
        } catch (java.net.http.HttpTimeoutException e) {
            System.err.println("MCP Connection timeout: Server took too long to respond");
            return false;
        } catch (Exception e) {
            System.err.println("MCP Connection error: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            return false;
        }
    }

    /**
     * Initialize MCP session.
     */
    public boolean initialize() throws IOException, InterruptedException {
        if (initialized) {
            return true;
        }

        Map<String, Object> params = new HashMap<>();
        params.put("protocolVersion", "2024-11-05");
        
        Map<String, Object> clientInfo = new HashMap<>();
        clientInfo.put("name", "VISTA");
        clientInfo.put("version", "2.9.0");
        params.put("clientInfo", clientInfo);
        
        Map<String, Object> capabilities = new HashMap<>();
        capabilities.put("tools", new HashMap<>());
        params.put("capabilities", capabilities);

        MCPRequest request = new MCPRequest("initialize", params, requestIdCounter.getAndIncrement());
        MCPResponse response = sendRequest(request);

        if (response.isSuccess()) {
            initialized = true;
            
            // Extract session ID if provided
            // Note: Session ID would be in response headers, but for simplicity we'll handle it later
            
            // Send initialized notification
            sendNotification("notifications/initialized");
            
            return true;
        }

        return false;
    }

    /**
     * List available tools from MCP server.
     */
    public List<MCPTool> listTools() throws IOException, InterruptedException {
        if (!initialized && !initialize()) {
            throw new IOException("Failed to initialize MCP session");
        }

        MCPRequest request = new MCPRequest("tools/list", new HashMap<>(), requestIdCounter.getAndIncrement());
        MCPResponse response = sendRequest(request);

        if (response.isSuccess()) {
            Map<String, Object> result = response.getResult();
            Object toolsObj = result.get("tools");
            
            if (toolsObj instanceof List) {
                List<MCPTool> tools = new ArrayList<>();
                List<?> toolsList = (List<?>) toolsObj;
                
                for (Object toolObj : toolsList) {
                    if (toolObj instanceof Map) {
                        Map<?, ?> toolMap = (Map<?, ?>) toolObj;
                        MCPTool tool = new MCPTool();
                        tool.setName((String) toolMap.get("name"));
                        tool.setDescription((String) toolMap.get("description"));
                        tool.setInputSchema((Map<String, Object>) toolMap.get("inputSchema"));
                        tools.add(tool);
                    }
                }
                
                this.availableTools = tools;
                return tools;
            }
        }

        return new ArrayList<>();
    }

    /**
     * Call a tool on the MCP server.
     */
    public Map<String, Object> callTool(String toolName, Map<String, Object> arguments) 
            throws IOException, InterruptedException {
        if (!initialized && !initialize()) {
            throw new IOException("Failed to initialize MCP session");
        }

        Map<String, Object> params = new HashMap<>();
        params.put("name", toolName);
        params.put("arguments", arguments != null ? arguments : new HashMap<>());

        MCPRequest request = new MCPRequest("tools/call", params, requestIdCounter.getAndIncrement());
        MCPResponse response = sendRequest(request);

        if (response.isSuccess()) {
            return response.getResult();
        } else if (response.hasError()) {
            throw new IOException("Tool call failed: " + response.getError());
        }

        return new HashMap<>();
    }

    /**
     * Get proxy history from Burp.
     */
    public List<Map<String, Object>> getProxyHistory(int limit) throws IOException, InterruptedException {
        Map<String, Object> args = new HashMap<>();
        if (limit > 0) {
            args.put("limit", limit);
        }
        
        Map<String, Object> result = callTool("proxy_http_history", args);
        Object itemsObj = result.get("items");
        
        if (itemsObj instanceof List) {
            List<Map<String, Object>> items = new ArrayList<>();
            for (Object item : (List<?>) itemsObj) {
                if (item instanceof Map) {
                    items.add((Map<String, Object>) item);
                }
            }
            return items;
        }
        
        return new ArrayList<>();
    }

    /**
     * Search proxy history with regex pattern.
     */
    public List<Map<String, Object>> searchProxyHistory(String pattern, int limit) 
            throws IOException, InterruptedException {
        Map<String, Object> args = new HashMap<>();
        args.put("pattern", pattern);
        if (limit > 0) {
            args.put("limit", limit);
        }
        
        Map<String, Object> result = callTool("proxy_http_history_regex", args);
        Object itemsObj = result.get("items");
        
        if (itemsObj instanceof List) {
            List<Map<String, Object>> items = new ArrayList<>();
            for (Object item : (List<?>) itemsObj) {
                if (item instanceof Map) {
                    items.add((Map<String, Object>) item);
                }
            }
            return items;
        }
        
        return new ArrayList<>();
    }

    /**
     * Get details of a specific proxy history item.
     */
    public Map<String, Object> getProxyHistoryItem(int itemId) throws IOException, InterruptedException {
        Map<String, Object> args = new HashMap<>();
        args.put("id", itemId);
        
        return callTool("proxy_http_history_item", args);
    }

    /**
     * Get current target scope.
     */
    public List<String> getScope() throws IOException, InterruptedException {
        Map<String, Object> result = callTool("scope_list", new HashMap<>());
        Object scopeObj = result.get("scope");
        
        if (scopeObj instanceof List) {
            List<String> scope = new ArrayList<>();
            for (Object item : (List<?>) scopeObj) {
                if (item instanceof String) {
                    scope.add((String) item);
                }
            }
            return scope;
        }
        
        return new ArrayList<>();
    }

    /**
     * Get site map entries.
     */
    public List<String> getSiteMap() throws IOException, InterruptedException {
        Map<String, Object> result = callTool("sitemap_list", new HashMap<>());
        Object urlsObj = result.get("urls");
        
        if (urlsObj instanceof List) {
            List<String> urls = new ArrayList<>();
            for (Object item : (List<?>) urlsObj) {
                if (item instanceof String) {
                    urls.add((String) item);
                }
            }
            return urls;
        }
        
        return new ArrayList<>();
    }

    /**
     * Send a JSON-RPC request to the MCP server.
     */
    private MCPResponse sendRequest(MCPRequest request) throws IOException, InterruptedException {
        String jsonBody = request.toJson();
        
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(serverUrl))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();

        HttpResponse<String> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

        if (httpResponse.statusCode() != 200) {
            throw new IOException("HTTP error: " + httpResponse.statusCode());
        }

        String responseBody = httpResponse.body();
        return parseResponse(responseBody);
    }

    /**
     * Send a notification (no response expected).
     */
    private void sendNotification(String method) {
        try {
            Map<String, Object> notification = new HashMap<>();
            notification.put("jsonrpc", "2.0");
            notification.put("method", method);
            
            String jsonBody = new MCPRequest(method, new HashMap<>(), null).toJson()
                    .replace(",\"id\":null", ""); // Remove id field for notifications
            
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(serverUrl))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();

            httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            // Notifications are fire-and-forget
        }
    }

    /**
     * Parse JSON-RPC response.
     */
    private MCPResponse parseResponse(String json) {
        MCPResponse response = new MCPResponse();
        
        try {
            Map<String, Object> parsed = SimpleJsonParser.parseObject(json);
            
            response.setJsonrpc((String) parsed.get("jsonrpc"));
            response.setId(parsed.get("id"));
            
            if (parsed.containsKey("result")) {
                response.setResult((Map<String, Object>) parsed.get("result"));
            }
            
            if (parsed.containsKey("error")) {
                Map<?, ?> errorMap = (Map<?, ?>) parsed.get("error");
                MCPResponse.MCPError error = new MCPResponse.MCPError();
                
                Object codeObj = errorMap.get("code");
                if (codeObj instanceof Number) {
                    error.setCode(((Number) codeObj).intValue());
                }
                
                error.setMessage((String) errorMap.get("message"));
                error.setData(errorMap.get("data"));
                response.setError(error);
            }
        } catch (Exception e) {
            MCPResponse.MCPError error = new MCPResponse.MCPError();
            error.setCode(-32700);
            error.setMessage("Parse error: " + e.getMessage());
            response.setError(error);
        }
        
        return response;
    }

    public boolean isInitialized() {
        return initialized;
    }

    public List<MCPTool> getAvailableTools() {
        return new ArrayList<>(availableTools);
    }

    public String getServerUrl() {
        return serverUrl;
    }
}
