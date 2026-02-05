package com.vista.security.core;

import com.vista.security.mcp.BurpMCPClient;
import com.vista.security.mcp.MCPTool;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * Manages MCP configuration and client lifecycle.
 */
public class MCPConfigManager {
    private static final String CONFIG_DIR = System.getProperty("user.home") + File.separator + ".vista";
    private static final String CONFIG_FILE = "mcp-config.properties";
    private static final String DEFAULT_MCP_URL = "http://127.0.0.1:9876";
    
    private BurpMCPClient mcpClient;
    private boolean enabled;
    private String serverUrl;
    private Properties config;

    public MCPConfigManager() {
        this.config = new Properties();
        loadConfig();
        
        if (enabled && serverUrl != null && !serverUrl.isEmpty()) {
            try {
                initializeClient();
            } catch (Exception e) {
                System.err.println("Failed to initialize MCP client: " + e.getMessage());
            }
        }
    }

    /**
     * Load configuration from file.
     */
    private void loadConfig() {
        try {
            Path configPath = Paths.get(CONFIG_DIR, CONFIG_FILE);
            
            if (Files.exists(configPath)) {
                try (InputStream input = Files.newInputStream(configPath)) {
                    config.load(input);
                }
                
                enabled = Boolean.parseBoolean(config.getProperty("mcp.enabled", "false"));
                serverUrl = config.getProperty("mcp.server.url", DEFAULT_MCP_URL);
            } else {
                // Default configuration
                enabled = false;
                serverUrl = DEFAULT_MCP_URL;
            }
        } catch (IOException e) {
            System.err.println("Failed to load MCP config: " + e.getMessage());
            enabled = false;
            serverUrl = DEFAULT_MCP_URL;
        }
    }

    /**
     * Save configuration to file.
     */
    public void saveConfig() {
        try {
            Path configDir = Paths.get(CONFIG_DIR);
            if (!Files.exists(configDir)) {
                Files.createDirectories(configDir);
            }
            
            config.setProperty("mcp.enabled", String.valueOf(enabled));
            config.setProperty("mcp.server.url", serverUrl);
            
            Path configPath = Paths.get(CONFIG_DIR, CONFIG_FILE);
            try (OutputStream output = Files.newOutputStream(configPath)) {
                config.store(output, "VISTA MCP Configuration");
            }
        } catch (IOException e) {
            System.err.println("Failed to save MCP config: " + e.getMessage());
        }
    }

    /**
     * Initialize MCP client.
     */
    private void initializeClient() throws Exception {
        if (mcpClient != null) {
            return;
        }
        
        mcpClient = new BurpMCPClient(serverUrl);
        
        if (!mcpClient.testConnection()) {
            throw new IOException("Cannot connect to MCP server at " + serverUrl);
        }
        
        if (!mcpClient.initialize()) {
            throw new IOException("Failed to initialize MCP session");
        }
        
        // Load available tools
        mcpClient.listTools();
    }

    /**
     * Test connection to MCP server.
     */
    public boolean testConnection(String url) {
        try {
            BurpMCPClient testClient = new BurpMCPClient(url);
            boolean connected = testClient.testConnection();
            
            if (!connected) {
                System.err.println("MCP test connection failed for URL: " + url);
                System.err.println("Troubleshooting steps:");
                System.err.println("1. Check if Burp MCP Server extension is installed (Extensions tab)");
                System.err.println("2. Verify MCP server is enabled (MCP tab in Burp)");
                System.err.println("3. Confirm server URL is correct (default: http://127.0.0.1:9876)");
                System.err.println("4. Try accessing " + url + " in a web browser");
            }
            
            return connected;
        } catch (Exception e) {
            System.err.println("MCP test connection exception: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Enable MCP integration.
     */
    public void enable(String url) throws Exception {
        this.serverUrl = url;
        this.enabled = true;
        
        // Test and initialize
        initializeClient();
        
        saveConfig();
    }

    /**
     * Disable MCP integration.
     */
    public void disable() {
        this.enabled = false;
        this.mcpClient = null;
        saveConfig();
    }

    /**
     * Get MCP client (null if not enabled or not initialized).
     */
    public BurpMCPClient getClient() {
        if (!enabled || mcpClient == null) {
            return null;
        }
        
        if (!mcpClient.isInitialized()) {
            try {
                initializeClient();
            } catch (Exception e) {
                System.err.println("Failed to reinitialize MCP client: " + e.getMessage());
                return null;
            }
        }
        
        return mcpClient;
    }

    /**
     * Get available MCP tools.
     */
    public List<MCPTool> getAvailableTools() {
        BurpMCPClient client = getClient();
        if (client != null) {
            return client.getAvailableTools();
        }
        return new ArrayList<>();
    }

    /**
     * Query proxy history from Burp MCP.
     */
    public List<Map<String, Object>> queryProxyHistory(int limit) {
        BurpMCPClient client = getClient();
        if (client != null) {
            try {
                return client.getProxyHistory(limit);
            } catch (Exception e) {
                System.err.println("Failed to query proxy history: " + e.getMessage());
            }
        }
        return new ArrayList<>();
    }

    /**
     * Search proxy history with pattern.
     */
    public List<Map<String, Object>> searchProxyHistory(String pattern, int limit) {
        BurpMCPClient client = getClient();
        if (client != null) {
            try {
                return client.searchProxyHistory(pattern, limit);
            } catch (Exception e) {
                System.err.println("Failed to search proxy history: " + e.getMessage());
            }
        }
        return new ArrayList<>();
    }

    /**
     * Get Burp target scope.
     */
    public List<String> getScope() {
        BurpMCPClient client = getClient();
        if (client != null) {
            try {
                return client.getScope();
            } catch (Exception e) {
                System.err.println("Failed to get scope: " + e.getMessage());
            }
        }
        return new ArrayList<>();
    }

    /**
     * Get site map.
     */
    public List<String> getSiteMap() {
        BurpMCPClient client = getClient();
        if (client != null) {
            try {
                return client.getSiteMap();
            } catch (Exception e) {
                System.err.println("Failed to get site map: " + e.getMessage());
            }
        }
        return new ArrayList<>();
    }

    public boolean isEnabled() {
        return enabled;
    }

    public String getServerUrl() {
        return serverUrl;
    }

    public void setServerUrl(String serverUrl) {
        this.serverUrl = serverUrl;
    }
}
