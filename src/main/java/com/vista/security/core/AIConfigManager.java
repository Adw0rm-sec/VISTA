package com.vista.security.core;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.function.Consumer;

/**
 * Centralized AI Configuration Manager.
 * Singleton that manages AI settings across all VISTA components.
 * Persists configuration to disk and notifies listeners of changes.
 */
public class AIConfigManager {
    
    private static AIConfigManager instance;
    private static final String CONFIG_FILE = System.getProperty("user.home") + "/.vista-ai-config.json";
    
    // Configuration
    private String provider = "OpenAI";
    private String openaiApiKey = "";
    private String azureApiKey = "";
    private String model = "gpt-4o-mini";
    private String endpoint = "";
    private String deployment = "";
    private String openRouterApiKey = "";
    private String openRouterModel = "deepseek/deepseek-r1-0528:free";
    private double temperature = 0.3; // Lower default for cost efficiency
    private int maxTokens = 2000; // Limit response tokens
    private int timeout = 60000; // Request timeout in milliseconds (60 seconds)
    
    // Listeners for config changes
    private final List<Consumer<AIConfigManager>> listeners = new ArrayList<>();
    
    private AIConfigManager() {
        load();
    }
    
    public static synchronized AIConfigManager getInstance() {
        if (instance == null) {
            instance = new AIConfigManager();
        }
        return instance;
    }
    
    // Getters
    public String getProvider() { return provider; }
    public String getOpenAIApiKey() { return openaiApiKey; }
    public String getAzureApiKey() { return azureApiKey; }
    public String getModel() { return model; }
    public String getEndpoint() { return endpoint; }
    public String getDeployment() { return deployment; }
    public String getOpenRouterApiKey() { return openRouterApiKey; }
    public String getOpenRouterModel() { return openRouterModel; }
    public double getTemperature() { return temperature; }
    public int getMaxTokens() { return maxTokens; }
    public int getTimeout() { return timeout; }
    
    // Legacy getter for backward compatibility
    @Deprecated
    public String getApiKey() { 
        if ("Azure AI".equalsIgnoreCase(provider)) {
            return azureApiKey;
        } else if ("OpenRouter".equalsIgnoreCase(provider)) {
            return openRouterApiKey;
        } else {
            return openaiApiKey;
        }
    }
    
    // Setters with auto-save
    public void setProvider(String provider) { 
        this.provider = provider; 
        save();
        notifyListeners();
    }
    
    public void setOpenAIApiKey(String openaiApiKey) { 
        this.openaiApiKey = (openaiApiKey != null) ? openaiApiKey.trim() : ""; 
        save();
        notifyListeners();
    }
    
    public void setAzureApiKey(String azureApiKey) { 
        this.azureApiKey = (azureApiKey != null) ? azureApiKey.trim() : ""; 
        save();
        notifyListeners();
    }
    
    public void setModel(String model) { 
        this.model = model; 
        save();
        notifyListeners();
    }
    
    public void setEndpoint(String endpoint) { 
        this.endpoint = endpoint; 
        save();
        notifyListeners();
    }
    
    public void setDeployment(String deployment) { 
        this.deployment = deployment; 
        save();
        notifyListeners();
    }
    
    public void setOpenRouterApiKey(String openRouterApiKey) { 
        this.openRouterApiKey = (openRouterApiKey != null) ? openRouterApiKey.trim() : ""; 
        save();
        notifyListeners();
    }
    
    public void setOpenRouterModel(String openRouterModel) { 
        this.openRouterModel = openRouterModel; 
        save();
        notifyListeners();
    }
    
    public void setTemperature(double temperature) { 
        this.temperature = temperature; 
        save();
        notifyListeners();
    }
    
    public void setMaxTokens(int maxTokens) { 
        this.maxTokens = maxTokens; 
        save();
        notifyListeners();
    }
    
    // Legacy setter for backward compatibility
    @Deprecated
    public void setApiKey(String apiKey) { 
        if ("Azure AI".equalsIgnoreCase(provider)) {
            this.azureApiKey = apiKey;
        } else if ("OpenRouter".equalsIgnoreCase(provider)) {
            this.openRouterApiKey = apiKey;
        } else {
            this.openaiApiKey = apiKey;
        }
        save();
        notifyListeners();
    }
    
    /**
     * Bulk update configuration.
     */
    public void updateConfig(String provider, String openaiApiKey, String azureApiKey, String model, 
                            String endpoint, String deployment, String openRouterApiKey,
                            String openRouterModel, double temperature) {
        this.provider = provider;
        this.openaiApiKey = (openaiApiKey != null) ? openaiApiKey.trim() : "";
        this.azureApiKey = (azureApiKey != null) ? azureApiKey.trim() : "";
        this.model = model;
        this.endpoint = endpoint;
        this.deployment = deployment;
        this.openRouterApiKey = (openRouterApiKey != null) ? openRouterApiKey.trim() : "";
        this.openRouterModel = openRouterModel;
        this.temperature = temperature;
        save();
        notifyListeners();
    }
    
    /**
     * Check if AI is properly configured.
     */
    public boolean isConfigured() {
        if ("Azure AI".equalsIgnoreCase(provider)) {
            return azureApiKey != null && !azureApiKey.isBlank()
                && endpoint != null && !endpoint.isBlank() 
                && deployment != null && !deployment.isBlank();
        } else if ("OpenRouter".equalsIgnoreCase(provider)) {
            return openRouterApiKey != null && !openRouterApiKey.isBlank()
                && openRouterModel != null && !openRouterModel.isBlank();
        } else {
            return openaiApiKey != null && !openaiApiKey.isBlank();
        }
    }
    
    /**
     * Get configuration status message.
     */
    public String getStatusMessage() {
        if (!isConfigured()) {
            if ("Azure AI".equalsIgnoreCase(provider)) {
                if (azureApiKey == null || azureApiKey.isBlank()) return "Azure API key not configured";
                if (endpoint == null || endpoint.isBlank()) return "Azure endpoint not configured";
                if (deployment == null || deployment.isBlank()) return "Azure deployment not configured";
            } else if ("OpenRouter".equalsIgnoreCase(provider)) {
                if (openRouterApiKey == null || openRouterApiKey.isBlank()) return "OpenRouter API key not configured";
                if (openRouterModel == null || openRouterModel.isBlank()) return "OpenRouter model not configured";
            } else {
                if (openaiApiKey == null || openaiApiKey.isBlank()) return "OpenAI API key not configured";
            }
            return "Configuration incomplete";
        }
        return "✓ " + provider + " configured";
    }
    
    /**
     * Add listener for configuration changes.
     */
    public void addListener(Consumer<AIConfigManager> listener) {
        listeners.add(listener);
    }
    
    /**
     * Remove listener.
     */
    public void removeListener(Consumer<AIConfigManager> listener) {
        listeners.remove(listener);
    }
    
    private void notifyListeners() {
        for (Consumer<AIConfigManager> listener : listeners) {
            try {
                listener.accept(this);
            } catch (Exception ignored) {}
        }
    }
    
    /**
     * Save configuration to disk.
     */
    private void save() {
        try {
            StringBuilder json = new StringBuilder();
            json.append("{\n");
            json.append("  \"provider\": \"").append(escapeJson(provider)).append("\",\n");
            json.append("  \"openaiApiKey\": \"").append(escapeJson(openaiApiKey)).append("\",\n");
            json.append("  \"azureApiKey\": \"").append(escapeJson(azureApiKey)).append("\",\n");
            json.append("  \"model\": \"").append(escapeJson(model)).append("\",\n");
            json.append("  \"endpoint\": \"").append(escapeJson(endpoint)).append("\",\n");
            json.append("  \"deployment\": \"").append(escapeJson(deployment)).append("\",\n");
            json.append("  \"openRouterApiKey\": \"").append(escapeJson(openRouterApiKey)).append("\",\n");
            json.append("  \"openRouterModel\": \"").append(escapeJson(openRouterModel)).append("\",\n");
            json.append("  \"temperature\": ").append(temperature).append(",\n");
            json.append("  \"maxTokens\": ").append(maxTokens).append("\n");
            json.append("}");
            
            Files.writeString(Path.of(CONFIG_FILE), json.toString());
        } catch (Exception e) {
            System.err.println("Failed to save AI config: " + e.getMessage());
        }
    }
    
    /**
     * Load configuration from disk.
     */
    private void load() {
        try {
            Path path = Path.of(CONFIG_FILE);
            if (!Files.exists(path)) return;
            
            String content = Files.readString(path);
            
            provider = extractJsonString(content, "provider", "OpenAI");
            openaiApiKey = extractJsonString(content, "openaiApiKey", "");
            azureApiKey = extractJsonString(content, "azureApiKey", "");
            model = extractJsonString(content, "model", "gpt-4o-mini");
            endpoint = extractJsonString(content, "endpoint", "");
            deployment = extractJsonString(content, "deployment", "");
            openRouterApiKey = extractJsonString(content, "openRouterApiKey", "");
            openRouterModel = extractJsonString(content, "openRouterModel", "deepseek/deepseek-r1-0528:free");
            temperature = extractJsonDouble(content, "temperature", 0.3);
            maxTokens = extractJsonInt(content, "maxTokens", 2000);
            
            // Backward compatibility: if old "apiKey" field exists, migrate it
            String legacyApiKey = extractJsonString(content, "apiKey", null);
            if (legacyApiKey != null && !legacyApiKey.isBlank()) {
                if (openaiApiKey.isBlank()) openaiApiKey = legacyApiKey;
                if (azureApiKey.isBlank()) azureApiKey = legacyApiKey;
            }
            
        } catch (Exception e) {
            System.err.println("Failed to load AI config: " + e.getMessage());
        }
    }
    
    private String extractJsonString(String json, String key, String defaultValue) {
        String pattern = "\"" + key + "\"\\s*:\\s*\"([^\"]*)\"";
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(pattern).matcher(json);
        return m.find() ? unescapeJson(m.group(1)) : defaultValue;
    }
    
    private double extractJsonDouble(String json, String key, double defaultValue) {
        String pattern = "\"" + key + "\"\\s*:\\s*([0-9.]+)";
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(pattern).matcher(json);
        return m.find() ? Double.parseDouble(m.group(1)) : defaultValue;
    }
    
    private int extractJsonInt(String json, String key, int defaultValue) {
        String pattern = "\"" + key + "\"\\s*:\\s*([0-9]+)";
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(pattern).matcher(json);
        return m.find() ? Integer.parseInt(m.group(1)) : defaultValue;
    }
    
    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
    
    private String unescapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\n", "\n").replace("\\\"", "\"").replace("\\\\", "\\");
    }
}
