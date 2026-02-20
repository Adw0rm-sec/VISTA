package com.vista.security.service;

import com.vista.security.model.ChatMessage;
import java.util.List;

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
     * Send a prompt to the AI service with template tracking.
     * @param systemPrompt The system context/instructions
     * @param userPrompt The user's question or request
     * @param templateName The name of the template being used (null if direct)
     * @return The AI's response
     * @throws Exception if the request fails
     */
    default String ask(String systemPrompt, String userPrompt, String templateName) throws Exception {
        return ask(systemPrompt, userPrompt);
    }
    
    /**
     * Send a prompt to the AI service with template and HTTP context tracking.
     * @param systemPrompt The system context/instructions
     * @param userPrompt The user's question or request
     * @param templateName The name of the template being used (null if direct)
     * @param httpRequest The HTTP request being analyzed (null if not applicable)
     * @param httpResponse The HTTP response being analyzed (null if not applicable)
     * @return The AI's response
     * @throws Exception if the request fails
     */
    default String ask(String systemPrompt, String userPrompt, String templateName, 
                      String httpRequest, String httpResponse) throws Exception {
        return ask(systemPrompt, userPrompt, templateName);
    }
    
    /**
     * Send a message with full conversation history.
     * This is more efficient as it doesn't repeat the system prompt every time.
     * @param messages The conversation history (system, user, assistant messages)
     * @return The AI's response
     * @throws Exception if the request fails
     */
    default String askWithHistory(List<ChatMessage> messages) throws Exception {
        // Default implementation: extract last system and user message
        // Implementations should override this for proper conversation support
        String systemPrompt = messages.stream()
            .filter(m -> m.getRole() == ChatMessage.Role.SYSTEM)
            .reduce((first, second) -> second) // Get last system message
            .map(ChatMessage::getContent)
            .orElse("");
        
        String userPrompt = messages.stream()
            .filter(m -> m.getRole() == ChatMessage.Role.USER)
            .reduce((first, second) -> second) // Get last user message
            .map(ChatMessage::getContent)
            .orElse("");
        
        return ask(systemPrompt, userPrompt);
    }
    
    /**
     * Send a message with full conversation history and template tracking.
     * @param messages The conversation history (system, user, assistant messages)
     * @param templateName The name of the template being used (null if direct)
     * @return The AI's response
     * @throws Exception if the request fails
     */
    default String askWithHistory(List<ChatMessage> messages, String templateName) throws Exception {
        return askWithHistory(messages);
    }
    
    /**
     * Send a message with full conversation history, template, and HTTP context tracking.
     * @param messages The conversation history (system, user, assistant messages)
     * @param templateName The name of the template being used (null if direct)
     * @param httpRequest The HTTP request being analyzed (null if not applicable)
     * @param httpResponse The HTTP response being analyzed (null if not applicable)
     * @return The AI's response
     * @throws Exception if the request fails
     */
    default String askWithHistory(List<ChatMessage> messages, String templateName,
                                  String httpRequest, String httpResponse) throws Exception {
        return askWithHistory(messages, templateName);
    }
    
    /**
     * Configuration holder for AI service settings.
     */
    abstract class Configuration {
        protected String apiKey;
        protected double temperature = 0.7;
        protected int maxTokens = 2000;
        
        public String getApiKey() { return apiKey; }
        public void setApiKey(String apiKey) { this.apiKey = apiKey; }
        public double getTemperature() { return temperature; }
        public void setTemperature(double temperature) { this.temperature = temperature; }
        public int getMaxTokens() { return maxTokens; }
        public void setMaxTokens(int maxTokens) { this.maxTokens = maxTokens; }
        
        public abstract boolean isValid();
    }
}
