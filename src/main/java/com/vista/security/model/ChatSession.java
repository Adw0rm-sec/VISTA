package com.vista.security.model;

import burp.IHttpRequestResponse;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Represents a conversation session with the AI.
 * Each session maintains its own conversation history and system prompt.
 */
public class ChatSession {
    
    private final String sessionId;
    private final LocalDateTime createdAt;
    private final String initialRequestUrl; // The request that started this session
    private String currentSystemPrompt;     // Current system prompt (can change with template)
    private final List<ChatMessage> messages;
    private boolean active;
    private LocalDateTime lastActivityAt;
    private IHttpRequestResponse requestResponse; // Store the request/response for this session
    private final List<IHttpRequestResponse> attachedRequests; // Interactive assistant attached requests
    private final List<TestingStep> testingSteps; // Session-specific testing history
    
    public ChatSession(String initialRequestUrl, String systemPrompt) {
        this.sessionId = generateSessionId();
        this.createdAt = LocalDateTime.now();
        this.lastActivityAt = LocalDateTime.now();
        this.initialRequestUrl = initialRequestUrl;
        this.currentSystemPrompt = systemPrompt;
        this.messages = new ArrayList<>();
        this.attachedRequests = new ArrayList<>();
        this.testingSteps = new ArrayList<>();
        this.active = true;
        
        // Add initial system message
        if (systemPrompt != null && !systemPrompt.isBlank()) {
            addMessage(new ChatMessage(ChatMessage.Role.SYSTEM, systemPrompt));
        }
    }
    
    private static String generateSessionId() {
        return "session_" + System.currentTimeMillis() + "_" + (int)(Math.random() * 10000);
    }
    
    /**
     * Add a message to this session.
     */
    public synchronized void addMessage(ChatMessage message) {
        messages.add(message);
        lastActivityAt = LocalDateTime.now();
    }
    
    /**
     * Add a user message with optional request reference.
     */
    public synchronized void addUserMessage(String content, String requestReference) {
        addMessage(new ChatMessage(ChatMessage.Role.USER, content, requestReference));
    }
    
    /**
     * Add an assistant response.
     */
    public synchronized void addAssistantMessage(String content) {
        addMessage(new ChatMessage(ChatMessage.Role.ASSISTANT, content));
    }
    
    /**
     * Update the system prompt (when template changes).
     * This adds a new system message to the conversation.
     */
    public synchronized void updateSystemPrompt(String newSystemPrompt) {
        this.currentSystemPrompt = newSystemPrompt;
        addMessage(new ChatMessage(ChatMessage.Role.SYSTEM, newSystemPrompt));
    }
    
    /**
     * Get all messages in this session.
     */
    public List<ChatMessage> getMessages() {
        return Collections.unmodifiableList(messages);
    }
    
    /**
     * Get only user and assistant messages (excluding system).
     */
    public List<ChatMessage> getConversationMessages() {
        return messages.stream()
            .filter(m -> m.getRole() != ChatMessage.Role.SYSTEM)
            .toList();
    }
    
    /**
     * Get the current system prompt.
     */
    public String getCurrentSystemPrompt() {
        return currentSystemPrompt;
    }
    
    /**
     * Check if this is the first user message (no previous user/assistant messages).
     */
    public boolean isFirstUserMessage() {
        return messages.stream()
            .noneMatch(m -> m.getRole() == ChatMessage.Role.USER || 
                           m.getRole() == ChatMessage.Role.ASSISTANT);
    }
    
    /**
     * Get the number of exchanges (user-assistant pairs).
     */
    public int getExchangeCount() {
        return (int) messages.stream()
            .filter(m -> m.getRole() == ChatMessage.Role.ASSISTANT)
            .count();
    }
    
    /**
     * Get a summary title for this session (first 50 chars of first user message).
     */
    public String getSessionTitle() {
        return messages.stream()
            .filter(m -> m.getRole() == ChatMessage.Role.USER)
            .findFirst()
            .map(m -> {
                String content = m.getContent();
                if (content.length() > 50) {
                    return content.substring(0, 47) + "...";
                }
                return content;
            })
            .orElse("New Session");
    }
    
    // Getters
    public String getSessionId() { return sessionId; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getLastActivityAt() { return lastActivityAt; }
    public String getInitialRequestUrl() { return initialRequestUrl; }
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
    public IHttpRequestResponse getRequestResponse() { return requestResponse; }
    public void setRequestResponse(IHttpRequestResponse requestResponse) { 
        this.requestResponse = requestResponse; 
    }
    
    /**
     * Get attached requests for this session (from interactive assistant).
     */
    public List<IHttpRequestResponse> getAttachedRequests() {
        return Collections.unmodifiableList(attachedRequests);
    }
    
    /**
     * Add an attached request to this session.
     */
    public void addAttachedRequest(IHttpRequestResponse request) {
        attachedRequests.add(request);
        lastActivityAt = LocalDateTime.now();
    }
    
    /**
     * Clear attached requests for this session.
     */
    public void clearAttachedRequests() {
        attachedRequests.clear();
    }
    
    /**
     * Get count of attached requests.
     */
    public int getAttachedRequestCount() {
        return attachedRequests.size();
    }
    
    /**
     * Get testing steps for this session.
     */
    public List<TestingStep> getTestingSteps() {
        return Collections.unmodifiableList(testingSteps);
    }
    
    /**
     * Add a testing step to this session.
     */
    public void addTestingStep(TestingStep step) {
        testingSteps.add(step);
        lastActivityAt = LocalDateTime.now();
    }
    
    /**
     * Clear testing steps for this session.
     */
    public void clearTestingSteps() {
        testingSteps.clear();
    }
    
    /**
     * Get count of testing steps.
     */
    public int getTestingStepCount() {
        return testingSteps.size();
    }
    
    /**
     * TestingStep inner class for session-specific testing history.
     */
    public static class TestingStep {
        public final String stepName;
        public final String request;
        public final String response;
        public final String observation;
        
        public TestingStep(String stepName, String request, String response, String observation) {
            this.stepName = stepName;
            this.request = request;
            this.response = response;
            this.observation = observation;
        }
    }
    
    @Override
    public String toString() {
        return String.format("Session[%s] - %d messages - %s", 
            sessionId, messages.size(), getSessionTitle());
    }
}
