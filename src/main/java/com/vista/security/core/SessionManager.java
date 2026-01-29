package com.vista.security.core;

import com.vista.security.ui.TestingSuggestionsPanel;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Manages session data persistence across Burp restarts.
 * Saves conversation history, testing steps, and other session data.
 */
public class SessionManager {
    
    private static SessionManager instance;
    private final String sessionDir;
    private final String conversationFile;
    private final String testingStepsFile;
    private final String sessionMetadataFile;
    
    private boolean initialized;
    
    private SessionManager() {
        String homeDir = System.getProperty("user.home");
        this.sessionDir = homeDir + File.separator + ".vista" + File.separator + "sessions";
        this.conversationFile = sessionDir + File.separator + "conversation_history.json";
        this.testingStepsFile = sessionDir + File.separator + "testing_steps.json";
        this.sessionMetadataFile = sessionDir + File.separator + "session_metadata.json";
        this.initialized = false;
    }
    
    public static synchronized SessionManager getInstance() {
        if (instance == null) {
            instance = new SessionManager();
        }
        return instance;
    }
    
    /**
     * Initialize the session manager.
     */
    public void initialize() {
        if (initialized) return;
        
        try {
            Files.createDirectories(Paths.get(sessionDir));
            initialized = true;
        } catch (Exception e) {
            System.err.println("Failed to initialize SessionManager: " + e.getMessage());
        }
    }
    
    // ========== Conversation History ==========
    
    /**
     * Save conversation history to disk.
     */
    public void saveConversationHistory(List<TestingSuggestionsPanel.ConversationMessage> history) {
        if (!initialized) initialize();
        
        try {
            StringBuilder json = new StringBuilder();
            json.append("[\n");
            
            for (int i = 0; i < history.size(); i++) {
                TestingSuggestionsPanel.ConversationMessage msg = history.get(i);
                json.append("  {\n");
                json.append("    \"role\": \"").append(escapeJson(msg.role)).append("\",\n");
                json.append("    \"content\": \"").append(escapeJson(msg.content)).append("\"\n");
                json.append("  }");
                if (i < history.size() - 1) {
                    json.append(",");
                }
                json.append("\n");
            }
            
            json.append("]");
            
            Files.write(Paths.get(conversationFile), json.toString().getBytes());
        } catch (Exception e) {
            System.err.println("Failed to save conversation history: " + e.getMessage());
        }
    }
    
    /**
     * Load conversation history from disk.
     */
    public List<TestingSuggestionsPanel.ConversationMessage> loadConversationHistory() {
        List<TestingSuggestionsPanel.ConversationMessage> history = new ArrayList<>();
        
        File file = new File(conversationFile);
        if (!file.exists()) return history;
        
        try {
            String json = new String(Files.readAllBytes(file.toPath()));
            
            // Parse JSON array
            int depth = 0;
            StringBuilder currentMsg = new StringBuilder();
            
            for (int i = 0; i < json.length(); i++) {
                char c = json.charAt(i);
                
                if (c == '{') {
                    depth++;
                    currentMsg.append(c);
                } else if (c == '}') {
                    currentMsg.append(c);
                    depth--;
                    
                    if (depth == 0 && currentMsg.length() > 0) {
                        String msgJson = currentMsg.toString().trim();
                        if (!msgJson.isEmpty()) {
                            try {
                                String role = extractString(msgJson, "role");
                                String content = extractString(msgJson, "content");
                                
                                history.add(new TestingSuggestionsPanel.ConversationMessage(role, content));
                            } catch (Exception e) {
                                // Skip malformed message
                            }
                        }
                        currentMsg = new StringBuilder();
                    }
                } else if (depth > 0) {
                    currentMsg.append(c);
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to load conversation history: " + e.getMessage());
        }
        
        return history;
    }
    
    /**
     * Clear conversation history.
     */
    public void clearConversationHistory() {
        try {
            Files.deleteIfExists(Paths.get(conversationFile));
        } catch (Exception e) {
            System.err.println("Failed to clear conversation history: " + e.getMessage());
        }
    }
    
    // ========== Testing Steps ==========
    
    /**
     * Save testing steps to disk.
     */
    public void saveTestingSteps(List<TestingSuggestionsPanel.TestingStep> steps) {
        if (!initialized) initialize();
        
        try {
            StringBuilder json = new StringBuilder();
            json.append("[\n");
            
            for (int i = 0; i < steps.size(); i++) {
                TestingSuggestionsPanel.TestingStep step = steps.get(i);
                json.append("  {\n");
                json.append("    \"stepName\": \"").append(escapeJson(step.stepName)).append("\",\n");
                json.append("    \"request\": \"").append(escapeJson(step.request)).append("\",\n");
                json.append("    \"response\": \"").append(escapeJson(step.response)).append("\",\n");
                json.append("    \"observation\": \"").append(escapeJson(step.observation)).append("\"\n");
                json.append("  }");
                if (i < steps.size() - 1) {
                    json.append(",");
                }
                json.append("\n");
            }
            
            json.append("]");
            
            Files.write(Paths.get(testingStepsFile), json.toString().getBytes());
        } catch (Exception e) {
            System.err.println("Failed to save testing steps: " + e.getMessage());
        }
    }
    
    /**
     * Load testing steps from disk.
     */
    public List<TestingSuggestionsPanel.TestingStep> loadTestingSteps() {
        List<TestingSuggestionsPanel.TestingStep> steps = new ArrayList<>();
        
        File file = new File(testingStepsFile);
        if (!file.exists()) return steps;
        
        try {
            String json = new String(Files.readAllBytes(file.toPath()));
            
            // Parse JSON array
            int depth = 0;
            StringBuilder currentStep = new StringBuilder();
            
            for (int i = 0; i < json.length(); i++) {
                char c = json.charAt(i);
                
                if (c == '{') {
                    depth++;
                    currentStep.append(c);
                } else if (c == '}') {
                    currentStep.append(c);
                    depth--;
                    
                    if (depth == 0 && currentStep.length() > 0) {
                        String stepJson = currentStep.toString().trim();
                        if (!stepJson.isEmpty()) {
                            try {
                                String stepName = extractString(stepJson, "stepName");
                                String request = extractString(stepJson, "request");
                                String response = extractString(stepJson, "response");
                                String observation = extractString(stepJson, "observation");
                                
                                steps.add(new TestingSuggestionsPanel.TestingStep(stepName, request, response, observation));
                            } catch (Exception e) {
                                // Skip malformed step
                            }
                        }
                        currentStep = new StringBuilder();
                    }
                } else if (depth > 0) {
                    currentStep.append(c);
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to load testing steps: " + e.getMessage());
        }
        
        return steps;
    }
    
    /**
     * Clear testing steps.
     */
    public void clearTestingSteps() {
        try {
            Files.deleteIfExists(Paths.get(testingStepsFile));
        } catch (Exception e) {
            System.err.println("Failed to clear testing steps: " + e.getMessage());
        }
    }
    
    // ========== Session Metadata ==========
    
    /**
     * Save session metadata (last active time, session count, etc.).
     */
    public void saveSessionMetadata(Map<String, String> metadata) {
        if (!initialized) initialize();
        
        try {
            StringBuilder json = new StringBuilder();
            json.append("{\n");
            
            int i = 0;
            for (Map.Entry<String, String> entry : metadata.entrySet()) {
                json.append("  \"").append(escapeJson(entry.getKey())).append("\": \"")
                    .append(escapeJson(entry.getValue())).append("\"");
                if (i < metadata.size() - 1) {
                    json.append(",");
                }
                json.append("\n");
                i++;
            }
            
            json.append("}");
            
            Files.write(Paths.get(sessionMetadataFile), json.toString().getBytes());
        } catch (Exception e) {
            System.err.println("Failed to save session metadata: " + e.getMessage());
        }
    }
    
    /**
     * Load session metadata.
     */
    public Map<String, String> loadSessionMetadata() {
        Map<String, String> metadata = new HashMap<>();
        
        File file = new File(sessionMetadataFile);
        if (!file.exists()) return metadata;
        
        try {
            String json = new String(Files.readAllBytes(file.toPath()));
            
            // Simple key-value extraction
            Pattern pattern = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"([^\"]*)\"");
            Matcher matcher = pattern.matcher(json);
            
            while (matcher.find()) {
                String key = unescapeJson(matcher.group(1));
                String value = unescapeJson(matcher.group(2));
                metadata.put(key, value);
            }
        } catch (Exception e) {
            System.err.println("Failed to load session metadata: " + e.getMessage());
        }
        
        return metadata;
    }
    
    // ========== Session Statistics ==========
    
    /**
     * Get session statistics.
     */
    public Map<String, Integer> getSessionStats() {
        Map<String, Integer> stats = new HashMap<>();
        
        stats.put("conversationMessages", loadConversationHistory().size());
        stats.put("testingSteps", loadTestingSteps().size());
        
        return stats;
    }
    
    /**
     * Clear all session data.
     */
    public void clearAllSessionData() {
        clearConversationHistory();
        clearTestingSteps();
        
        try {
            Files.deleteIfExists(Paths.get(sessionMetadataFile));
        } catch (Exception e) {
            System.err.println("Failed to clear session metadata: " + e.getMessage());
        }
    }
    
    // ========== Helper Methods ==========
    
    private String extractString(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return unescapeJson(matcher.group(1));
        }
        return "";
    }
    
    private long extractLong(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return Long.parseLong(matcher.group(1));
        }
        return System.currentTimeMillis();
    }
    
    private String escapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }
    
    private String unescapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\\"", "\"")
                  .replace("\\\\", "\\")
                  .replace("\\n", "\n")
                  .replace("\\r", "\r")
                  .replace("\\t", "\t");
    }
    
    public boolean isInitialized() {
        return initialized;
    }
}
