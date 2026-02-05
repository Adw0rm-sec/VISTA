package com.vista.security.model;

import java.time.LocalDateTime;

/**
 * Represents a single message in a chat session.
 * Can be from system, user, or assistant.
 */
public class ChatMessage {
    
    public enum Role {
        SYSTEM,    // System prompt (instructions)
        USER,      // User's message
        ASSISTANT  // AI's response
    }
    
    private final String id;
    private final Role role;
    private final String content;
    private final LocalDateTime timestamp;
    private final String requestReference; // Optional: URL or request ID this message refers to
    
    public ChatMessage(Role role, String content) {
        this(role, content, null);
    }
    
    public ChatMessage(Role role, String content, String requestReference) {
        this.id = generateId();
        this.role = role;
        this.content = content;
        this.timestamp = LocalDateTime.now();
        this.requestReference = requestReference;
    }
    
    private static String generateId() {
        return "msg_" + System.currentTimeMillis() + "_" + (int)(Math.random() * 10000);
    }
    
    // Getters
    public String getId() { return id; }
    public Role getRole() { return role; }
    public String getContent() { return content; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public String getRequestReference() { return requestReference; }
    
    public boolean hasRequestReference() {
        return requestReference != null && !requestReference.isBlank();
    }
    
    @Override
    public String toString() {
        return String.format("[%s] %s: %s", 
            timestamp.toString(), 
            role, 
            content.substring(0, Math.min(50, content.length())));
    }
}
