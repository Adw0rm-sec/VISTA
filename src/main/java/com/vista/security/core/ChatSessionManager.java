package com.vista.security.core;

import com.vista.security.model.ChatMessage;
import com.vista.security.model.ChatSession;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages multiple parallel chat sessions with AI.
 * Each request from Repeater/Proxy creates a new session.
 * Sessions maintain their own conversation history and system prompts.
 */
public class ChatSessionManager {
    
    private static ChatSessionManager instance;
    
    private final Map<String, ChatSession> sessions;
    private String activeSessionId;
    private final int maxSessions;
    private final int sessionTimeoutMinutes;
    
    private ChatSessionManager() {
        this.sessions = new ConcurrentHashMap<>();
        this.maxSessions = 50; // Maximum parallel sessions
        this.sessionTimeoutMinutes = 60; // Auto-cleanup after 1 hour of inactivity
    }
    
    public static synchronized ChatSessionManager getInstance() {
        if (instance == null) {
            instance = new ChatSessionManager();
        }
        return instance;
    }
    
    /**
     * Create a new chat session.
     * @param requestUrl The URL/identifier of the request that started this session
     * @param systemPrompt The initial system prompt (from template)
     * @return The new session
     */
    public ChatSession createSession(String requestUrl, String systemPrompt) {
        // Cleanup old sessions if needed
        cleanupInactiveSessions();
        
        // Create new session
        ChatSession session = new ChatSession(requestUrl, systemPrompt);
        sessions.put(session.getSessionId(), session);
        activeSessionId = session.getSessionId();
        
        return session;
    }
    
    /**
     * Get a session by ID.
     */
    public ChatSession getSession(String sessionId) {
        return sessions.get(sessionId);
    }
    
    /**
     * Get the currently active session.
     */
    public ChatSession getActiveSession() {
        if (activeSessionId == null) {
            return null;
        }
        return sessions.get(activeSessionId);
    }
    
    /**
     * Set the active session.
     */
    public void setActiveSession(String sessionId) {
        if (sessions.containsKey(sessionId)) {
            this.activeSessionId = sessionId;
        }
    }
    
    /**
     * Get all sessions, sorted by last activity (most recent first).
     */
    public List<ChatSession> getAllSessions() {
        List<ChatSession> sessionList = new ArrayList<>(sessions.values());
        sessionList.sort((s1, s2) -> s2.getLastActivityAt().compareTo(s1.getLastActivityAt()));
        return sessionList;
    }
    
    /**
     * Get active sessions (not marked as inactive).
     */
    public List<ChatSession> getActiveSessions() {
        return sessions.values().stream()
            .filter(ChatSession::isActive)
            .sorted((s1, s2) -> s2.getLastActivityAt().compareTo(s1.getLastActivityAt()))
            .toList();
    }
    
    /**
     * Close a session (mark as inactive).
     */
    public void closeSession(String sessionId) {
        ChatSession session = sessions.get(sessionId);
        if (session != null) {
            session.setActive(false);
            if (sessionId.equals(activeSessionId)) {
                activeSessionId = null;
            }
        }
    }
    
    /**
     * Delete a session permanently.
     */
    public void deleteSession(String sessionId) {
        sessions.remove(sessionId);
        if (sessionId.equals(activeSessionId)) {
            activeSessionId = null;
        }
    }
    
    /**
     * Clear all sessions.
     */
    public void clearAllSessions() {
        sessions.clear();
        activeSessionId = null;
    }
    
    /**
     * Cleanup inactive sessions (older than timeout).
     */
    private void cleanupInactiveSessions() {
        LocalDateTime cutoff = LocalDateTime.now().minus(sessionTimeoutMinutes, ChronoUnit.MINUTES);
        
        List<String> toRemove = new ArrayList<>();
        for (Map.Entry<String, ChatSession> entry : sessions.entrySet()) {
            ChatSession session = entry.getValue();
            if (!session.isActive() && session.getLastActivityAt().isBefore(cutoff)) {
                toRemove.add(entry.getKey());
            }
        }
        
        toRemove.forEach(sessions::remove);
        
        // If we still have too many sessions, remove oldest inactive ones
        if (sessions.size() > maxSessions) {
            List<ChatSession> inactiveSessions = sessions.values().stream()
                .filter(s -> !s.isActive())
                .sorted(Comparator.comparing(ChatSession::getLastActivityAt))
                .toList();
            
            int toDelete = sessions.size() - maxSessions;
            for (int i = 0; i < Math.min(toDelete, inactiveSessions.size()); i++) {
                sessions.remove(inactiveSessions.get(i).getSessionId());
            }
        }
    }
    
    /**
     * Get statistics about sessions.
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalSessions", sessions.size());
        stats.put("activeSessions", getActiveSessions().size());
        stats.put("totalMessages", sessions.values().stream()
            .mapToInt(s -> s.getMessages().size())
            .sum());
        return stats;
    }
}
