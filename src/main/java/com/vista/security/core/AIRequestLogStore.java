package com.vista.security.core;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Singleton store for all AI request/response records.
 * Captures every AI call made by VISTA (AI Advisor + Traffic Monitor) with:
 * - Full system prompt, user prompt, and AI response
 * - Provider, model, template name
 * - Timing, token estimates
 * - Source (which component made the call)
 * 
 * Used by AIRequestLogPanel to give users full transparency into
 * what data is being sent to AI and what responses are received.
 */
public class AIRequestLogStore {
    
    private static final AIRequestLogStore INSTANCE = new AIRequestLogStore();
    private static final int MAX_ENTRIES = 500;
    
    private final CopyOnWriteArrayList<AIRequestRecord> records = new CopyOnWriteArrayList<>();
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();
    
    private AIRequestLogStore() {}
    
    public static AIRequestLogStore getInstance() {
        return INSTANCE;
    }
    
    /**
     * Log an AI request with all details.
     */
    public AIRequestRecord logRequest(String source, String provider, String model,
                                       String templateName, String systemPrompt,
                                       String userPrompt) {
        AIRequestRecord record = new AIRequestRecord();
        record.id = records.size() + 1;
        record.timestamp = LocalDateTime.now();
        record.source = source;
        record.provider = provider;
        record.model = model;
        record.templateName = templateName;
        record.systemPrompt = systemPrompt != null ? systemPrompt : "";
        record.userPrompt = userPrompt != null ? userPrompt : "";
        record.systemPromptTokens = estimateTokens(record.systemPrompt);
        record.userPromptTokens = estimateTokens(record.userPrompt);
        record.status = "⏳ Pending";
        record.startTimeMs = System.currentTimeMillis();
        
        records.add(record);
        
        // Trim old entries
        while (records.size() > MAX_ENTRIES) {
            records.remove(0);
        }
        
        notifyListeners();
        return record;
    }
    
    /**
     * Update a record with the AI response.
     */
    public void logResponse(AIRequestRecord record, String response) {
        if (record == null) return;
        record.response = response != null ? response : "";
        record.responseTokens = estimateTokens(record.response);
        record.durationMs = System.currentTimeMillis() - record.startTimeMs;
        record.status = "✅ Success";
        notifyListeners();
    }
    
    /**
     * Update a record with an error.
     */
    public void logError(AIRequestRecord record, String error) {
        if (record == null) return;
        record.response = "ERROR: " + (error != null ? error : "Unknown error");
        record.durationMs = System.currentTimeMillis() - record.startTimeMs;
        record.status = "❌ Error";
        notifyListeners();
    }
    
    /**
     * Get all records (newest first).
     */
    public List<AIRequestRecord> getRecords() {
        List<AIRequestRecord> reversed = new ArrayList<>(records);
        Collections.reverse(reversed);
        return reversed;
    }
    
    /**
     * Get record count.
     */
    public int size() {
        return records.size();
    }
    
    /**
     * Clear all records.
     */
    public void clear() {
        records.clear();
        notifyListeners();
    }
    
    /**
     * Register a listener for new records.
     */
    public void addListener(Listener listener) {
        listeners.add(listener);
    }
    
    private void notifyListeners() {
        for (Listener l : listeners) {
            try {
                l.onRecordUpdated();
            } catch (Exception ignored) {}
        }
    }
    
    private static int estimateTokens(String text) {
        if (text == null || text.isEmpty()) return 0;
        return text.length() / 4; // Rough estimate: ~4 chars per token
    }
    
    /**
     * Listener interface for record updates.
     */
    public interface Listener {
        void onRecordUpdated();
    }
    
    /**
     * Data class for a single AI request/response record.
     */
    public static class AIRequestRecord {
        public int id;
        public LocalDateTime timestamp;
        public String source;        // "AI Advisor", "Traffic Monitor JS", "Traffic Monitor HTML"
        public String provider;      // "OpenAI", "Azure AI", "OpenRouter"
        public String model;
        public String templateName;  // Template used or "Direct"
        public String systemPrompt;
        public String userPrompt;
        public String response;
        public String status;        // "⏳ Pending", "✅ Success", "❌ Error"
        public int systemPromptTokens;
        public int userPromptTokens;
        public int responseTokens;
        public long durationMs;
        public long startTimeMs;
        
        private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("HH:mm:ss");
        
        public String getFormattedTime() {
            return timestamp != null ? timestamp.format(FMT) : "";
        }
        
        public String getFormattedDuration() {
            if (durationMs <= 0) return "...";
            if (durationMs < 1000) return durationMs + "ms";
            return String.format("%.1fs", durationMs / 1000.0);
        }
        
        public int getTotalTokens() {
            return systemPromptTokens + userPromptTokens + responseTokens;
        }
    }
}
