package com.vista.security.core;

import burp.IBurpExtenderCallbacks;
import com.vista.security.model.ChatMessage;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Comprehensive logging utility for AI requests.
 * Tracks all data sent to AI providers including token estimates, templates used, and full payloads.
 * Useful for debugging template usage and monitoring API costs.
 */
public class AIRequestLogger {
    
    private static final AtomicLong requestCounter = new AtomicLong(0);
    private static final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
    private static boolean enabled = true;
    private static boolean logFullPayload = true;  // Changed to true by default
    private static IBurpExtenderCallbacks callbacks = null;
    
    /**
     * Set the Burp callbacks for logging output.
     * This should be called during extension initialization.
     */
    public static void setCallbacks(IBurpExtenderCallbacks callbacks) {
        AIRequestLogger.callbacks = callbacks;
    }
    
    /**
     * Enable or disable AI request logging.
     */
    public static void setEnabled(boolean enabled) {
        AIRequestLogger.enabled = enabled;
    }
    
    /**
     * Enable or disable full payload logging (can be verbose).
     */
    public static void setLogFullPayload(boolean logFullPayload) {
        AIRequestLogger.logFullPayload = logFullPayload;
    }
    
    /**
     * Log a simple AI request (system + user prompt).
     */
    public static void logRequest(String provider, String model, String systemPrompt, String userPrompt, String templateName) {
        logRequest(provider, model, systemPrompt, userPrompt, templateName, null, null);
    }
    
    /**
     * Log a simple AI request with HTTP request/response context.
     */
    public static void logRequest(String provider, String model, String systemPrompt, String userPrompt, 
                                  String templateName, String httpRequest, String httpResponse) {
        if (!enabled) return;
        
        long requestId = requestCounter.incrementAndGet();
        String timestamp = dateFormat.format(new Date());
        
        int systemTokens = estimateTokens(systemPrompt);
        int userTokens = estimateTokens(userPrompt);
        int totalTokens = systemTokens + userTokens;
        
        StringBuilder log = new StringBuilder();
        log.append("\n");
        log.append("═══════════════════════════════════════════════════════════════════════════════\n");
        log.append("AI REQUEST LOG #").append(requestId).append("\n");
        log.append("═══════════════════════════════════════════════════════════════════════════════\n");
        log.append("Timestamp:       ").append(timestamp).append("\n");
        log.append("Provider:        ").append(provider).append("\n");
        log.append("Model:           ").append(model).append("\n");
        log.append("Template:        ").append(templateName != null ? templateName : "None (Direct)").append("\n");
        log.append("───────────────────────────────────────────────────────────────────────────────\n");
        log.append("TOKEN ANALYSIS\n");
        log.append("───────────────────────────────────────────────────────────────────────────────\n");
        log.append("System Prompt:   ").append(systemTokens).append(" tokens (~").append(systemPrompt.length()).append(" chars)\n");
        log.append("User Prompt:     ").append(userTokens).append(" tokens (~").append(userPrompt.length()).append(" chars)\n");
        log.append("Total Input:     ").append(totalTokens).append(" tokens\n");
        
        // Log HTTP Request/Response if provided
        if (httpRequest != null || httpResponse != null) {
            log.append("───────────────────────────────────────────────────────────────────────────────\n");
            log.append("HTTP TRAFFIC BEING ANALYZED\n");
            log.append("───────────────────────────────────────────────────────────────────────────────\n");
            
            if (httpRequest != null) {
                log.append("Request Size:    ").append(httpRequest.length()).append(" bytes\n");
                log.append("Request Preview: ").append(getFirstLine(httpRequest)).append("\n");
            }
            
            if (httpResponse != null) {
                log.append("Response Size:   ").append(httpResponse.length()).append(" bytes\n");
                log.append("Response Preview: ").append(getFirstLine(httpResponse)).append("\n");
            }
        }
        
        log.append("───────────────────────────────────────────────────────────────────────────────\n");
        
        // Always log prompts for debugging
        log.append("SYSTEM PROMPT\n");
        log.append("───────────────────────────────────────────────────────────────────────────────\n");
        log.append(systemPrompt).append("\n");
        log.append("───────────────────────────────────────────────────────────────────────────────\n");
        log.append("USER PROMPT\n");
        log.append("───────────────────────────────────────────────────────────────────────────────\n");
        log.append(userPrompt).append("\n");
        log.append("───────────────────────────────────────────────────────────────────────────────\n");
        
        log.append("═══════════════════════════════════════════════════════════════════════════════\n");
        
        // Output to Burp extension output or fallback to System.out
        if (callbacks != null) {
            callbacks.printOutput(log.toString());
        } else {
            System.out.println(log.toString());
        }
    }
    
    /**
     * Log an AI request with conversation history.
     */
    public static void logRequestWithHistory(String provider, String model, List<ChatMessage> messages, String templateName) {
        logRequestWithHistory(provider, model, messages, templateName, null, null);
    }
    
    /**
     * Log an AI request with conversation history and HTTP context.
     */
    public static void logRequestWithHistory(String provider, String model, List<ChatMessage> messages, 
                                            String templateName, String httpRequest, String httpResponse) {
        if (!enabled) return;
        
        long requestId = requestCounter.incrementAndGet();
        String timestamp = dateFormat.format(new Date());
        
        int totalTokens = 0;
        int systemTokens = 0;
        int userTokens = 0;
        int assistantTokens = 0;
        int messageCount = messages.size();
        
        for (ChatMessage msg : messages) {
            int tokens = estimateTokens(msg.getContent());
            totalTokens += tokens;
            
            switch (msg.getRole()) {
                case SYSTEM -> systemTokens += tokens;
                case USER -> userTokens += tokens;
                case ASSISTANT -> assistantTokens += tokens;
            }
        }
        
        StringBuilder log = new StringBuilder();
        log.append("\n");
        log.append("═══════════════════════════════════════════════════════════════════════════════\n");
        log.append("AI REQUEST LOG #").append(requestId).append(" (WITH HISTORY)\n");
        log.append("═══════════════════════════════════════════════════════════════════════════════\n");
        log.append("Timestamp:       ").append(timestamp).append("\n");
        log.append("Provider:        ").append(provider).append("\n");
        log.append("Model:           ").append(model).append("\n");
        log.append("Template:        ").append(templateName != null ? templateName : "None (Direct)").append("\n");
        log.append("Message Count:   ").append(messageCount).append("\n");
        log.append("───────────────────────────────────────────────────────────────────────────────\n");
        log.append("TOKEN ANALYSIS\n");
        log.append("───────────────────────────────────────────────────────────────────────────────\n");
        log.append("System Messages: ").append(systemTokens).append(" tokens\n");
        log.append("User Messages:   ").append(userTokens).append(" tokens\n");
        log.append("Assistant Msgs:  ").append(assistantTokens).append(" tokens\n");
        log.append("Total Input:     ").append(totalTokens).append(" tokens\n");
        
        // Log HTTP Request/Response if provided
        if (httpRequest != null || httpResponse != null) {
            log.append("───────────────────────────────────────────────────────────────────────────────\n");
            log.append("HTTP TRAFFIC BEING ANALYZED\n");
            log.append("───────────────────────────────────────────────────────────────────────────────\n");
            
            if (httpRequest != null) {
                log.append("Request Size:    ").append(httpRequest.length()).append(" bytes\n");
                log.append("Request Preview: ").append(getFirstLine(httpRequest)).append("\n");
            }
            
            if (httpResponse != null) {
                log.append("Response Size:   ").append(httpResponse.length()).append(" bytes\n");
                log.append("Response Preview: ").append(getFirstLine(httpResponse)).append("\n");
            }
        }
        
        log.append("───────────────────────────────────────────────────────────────────────────────\n");
        
        // Always log conversation history for debugging
        log.append("CONVERSATION HISTORY\n");
        log.append("───────────────────────────────────────────────────────────────────────────────\n");
        
        for (int i = 0; i < messages.size(); i++) {
            ChatMessage msg = messages.get(i);
            int tokens = estimateTokens(msg.getContent());
            
            log.append("[").append(i + 1).append("/").append(messageCount).append("] ");
            log.append(msg.getRole()).append(" (").append(tokens).append(" tokens)\n");
            log.append("───────────────────────────────────────────────────────────────────────────────\n");
            log.append(msg.getContent()).append("\n");
            
            if (i < messages.size() - 1) {
                log.append("───────────────────────────────────────────────────────────────────────────────\n");
            }
        }
        
        log.append("═══════════════════════════════════════════════════════════════════════════════\n");
        
        // Output to Burp extension output or fallback to System.out
        if (callbacks != null) {
            callbacks.printOutput(log.toString());
        } else {
            System.out.println(log.toString());
        }
    }
    
    /**
     * Log the response from AI.
     */
    public static void logResponse(String provider, String response, long durationMs) {
        if (!enabled) return;
        
        int responseTokens = estimateTokens(response);
        
        StringBuilder log = new StringBuilder();
        log.append("\n");
        log.append("───────────────────────────────────────────────────────────────────────────────\n");
        log.append("AI RESPONSE\n");
        log.append("───────────────────────────────────────────────────────────────────────────────\n");
        log.append("Provider:        ").append(provider).append("\n");
        log.append("Duration:        ").append(durationMs).append(" ms\n");
        log.append("Response Tokens: ").append(responseTokens).append(" tokens (~").append(response.length()).append(" chars)\n");
        log.append("───────────────────────────────────────────────────────────────────────────────\n");
        
        // Always log response content for debugging
        log.append("RESPONSE CONTENT\n");
        log.append("───────────────────────────────────────────────────────────────────────────────\n");
        log.append(response).append("\n");
        
        log.append("═══════════════════════════════════════════════════════════════════════════════\n");
        
        // Output to Burp extension output or fallback to System.out
        if (callbacks != null) {
            callbacks.printOutput(log.toString());
        } else {
            System.out.println(log.toString());
        }
    }
    
    /**
     * Log an error during AI request.
     */
    public static void logError(String provider, String operation, Exception error) {
        if (!enabled) return;
        
        String timestamp = dateFormat.format(new Date());
        
        StringBuilder log = new StringBuilder();
        log.append("\n");
        log.append("═══════════════════════════════════════════════════════════════════════════════\n");
        log.append("AI REQUEST ERROR\n");
        log.append("═══════════════════════════════════════════════════════════════════════════════\n");
        log.append("Timestamp:       ").append(timestamp).append("\n");
        log.append("Provider:        ").append(provider).append("\n");
        log.append("Operation:       ").append(operation).append("\n");
        log.append("Error Type:      ").append(error.getClass().getSimpleName()).append("\n");
        log.append("Error Message:   ").append(error.getMessage()).append("\n");
        log.append("───────────────────────────────────────────────────────────────────────────────\n");
        log.append("STACK TRACE\n");
        log.append("───────────────────────────────────────────────────────────────────────────────\n");
        
        StringWriter sw = new StringWriter();
        error.printStackTrace(new PrintWriter(sw));
        log.append(sw.toString());
        
        log.append("═══════════════════════════════════════════════════════════════════════════════\n");
        
        // Output to Burp extension error output or fallback to System.err
        if (callbacks != null) {
            callbacks.printError(log.toString());
        } else {
            System.err.println(log.toString());
        }
    }
    
    /**
     * Estimate token count for a given text.
     * Uses a simple approximation: ~4 characters per token for English text.
     * This is a rough estimate; actual tokenization varies by model.
     */
    private static int estimateTokens(String text) {
        if (text == null || text.isEmpty()) {
            return 0;
        }
        
        // Basic estimation: 4 chars per token on average
        // Add extra tokens for special characters and formatting
        int charCount = text.length();
        int wordCount = text.split("\\s+").length;
        
        // More accurate estimation considering:
        // - Average word length
        // - Special characters
        // - Code/JSON formatting
        return Math.max(charCount / 4, wordCount);
    }
    
    /**
     * Get statistics summary.
     */
    public static String getStatistics() {
        return String.format("Total AI requests logged: %d", requestCounter.get());
    }
    
    /**
     * Get the first line of text (for preview).
     */
    private static String getFirstLine(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        
        int newlineIndex = text.indexOf('\n');
        if (newlineIndex > 0) {
            String firstLine = text.substring(0, newlineIndex).trim();
            return firstLine.length() > 100 ? firstLine.substring(0, 100) + "..." : firstLine;
        }
        
        return text.length() > 100 ? text.substring(0, 100) + "..." : text;
    }
}
