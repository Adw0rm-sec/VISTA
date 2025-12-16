package com.vista.security.service;

/**
 * Common interface for AI service providers.
 * Implementations handle communication with different AI backends.
 */
public interface AIService {
    
    /**
     * Test the connection to the AI service.
     * @return Status message indicating success or failure details
     * @throws Exception if connection fails
     */
    String testConnection() throws Exception;
    
    /**
     * Send a prompt to the AI service and get a response.
     * @param systemPrompt The system context/instructions
     * @param userPrompt The user's question or request
     * @return The AI's response
     * @throws Exception if the request fails
     */
    String ask(String systemPrompt, String userPrompt) throws Exception;
    
    /**
     * Configuration holder for AI service settings.
     */
    abstract class Configuration {
        protected String apiKey;
        protected double temperature = 0.7;
        
        public String getApiKey() { return apiKey; }
        public void setApiKey(String apiKey) { this.apiKey = apiKey; }
        public double getTemperature() { return temperature; }
        public void setTemperature(double temperature) { this.temperature = temperature; }
        
        public abstract boolean isValid();
    }
}
