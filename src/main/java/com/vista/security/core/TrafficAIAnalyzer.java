package com.vista.security.core;

import burp.IBurpExtenderCallbacks;
import com.vista.security.model.HttpTransaction;
import com.vista.security.model.PromptTemplate;
import com.vista.security.service.AIService;
import com.vista.security.service.AzureAIService;
import com.vista.security.service.OpenAIService;
import com.vista.security.service.OpenRouterService;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AI-based analyzer for HTTP traffic.
 * Analyzes JavaScript and HTML files for hidden parameters, endpoints, secrets.
 * Only analyzes in-scope domains when scope is enabled.
 */
public class TrafficAIAnalyzer {
    
    private final IBurpExtenderCallbacks callbacks;
    private final ScopeManager scopeManager;
    private final PromptTemplateManager templateManager;
    private final AIConfigManager aiConfig;
    private final ExecutorService executor;
    
    private boolean enabled = false;
    private String selectedTemplateId = null;
    
    // Listeners for findings
    private final List<FindingListener> listeners = new ArrayList<>();
    
    // Statistics
    private int totalAnalyzed = 0;
    private int totalFindings = 0;
    
    public TrafficAIAnalyzer(IBurpExtenderCallbacks callbacks, ScopeManager scopeManager) {
        this.callbacks = callbacks;
        this.scopeManager = scopeManager;
        this.templateManager = PromptTemplateManager.getInstance();
        this.aiConfig = AIConfigManager.getInstance();
        this.executor = Executors.newSingleThreadExecutor();
        
        // Ensure traffic analysis templates exist
        ensureTrafficTemplates();
    }
    
    /**
     * Enable or disable AI analysis.
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        callbacks.printOutput("[Traffic AI] Analysis " + (enabled ? "enabled" : "disabled"));
    }
    
    /**
     * Check if AI analysis is enabled.
     */
    public boolean isEnabled() {
        return enabled;
    }
    
    /**
     * Set the prompt template to use for analysis.
     */
    public void setTemplate(String templateId) {
        this.selectedTemplateId = templateId;
    }
    
    /**
     * Get the current template ID.
     */
    public String getTemplateId() {
        return selectedTemplateId;
    }
    
    /**
     * Add a finding listener.
     */
    public void addListener(FindingListener listener) {
        listeners.add(listener);
    }
    
    /**
     * Remove a finding listener.
     */
    public void removeListener(FindingListener listener) {
        listeners.remove(listener);
    }
    
    /**
     * Analyze a transaction if conditions are met.
     */
    public void analyzeTransaction(HttpTransaction transaction) {
        // Check if analysis should run
        if (!shouldAnalyze(transaction)) {
            return;
        }
        
        // Analyze asynchronously
        executor.submit(() -> {
            try {
                performAnalysis(transaction);
            } catch (Exception e) {
                callbacks.printError("[Traffic AI] Analysis error: " + e.getMessage());
            }
        });
    }
    
    /**
     * Check if a transaction should be analyzed.
     */
    private boolean shouldAnalyze(HttpTransaction transaction) {
        // 1. AI analysis must be enabled
        if (!enabled) {
            return false;
        }
        
        // 2. AI must be configured
        if (!aiConfig.isConfigured()) {
            callbacks.printOutput("[Traffic AI] Skipping - AI not configured");
            return false;
        }
        
        // 3. Scope must be enabled
        if (!scopeManager.isScopeEnabled()) {
            callbacks.printOutput("[Traffic AI] Skipping - Scope not enabled");
            return false;
        }
        
        // 4. Domain must have at least one scope rule
        if (scopeManager.size() == 0) {
            callbacks.printOutput("[Traffic AI] Skipping - No domains in scope");
            return false;
        }
        
        // 5. URL must be in scope
        if (!scopeManager.isInScope(transaction.getUrl())) {
            return false; // Silently skip out-of-scope
        }
        
        // 6. Content type must be analyzable
        if (!isAnalyzableContentType(transaction.getContentType())) {
            return false; // Silently skip non-analyzable types
        }
        
        // 7. Response size must be reasonable (< 500KB)
        if (transaction.getResponseSize() > 500 * 1024) {
            callbacks.printOutput("[Traffic AI] Skipping - Response too large: " + transaction.getUrl());
            return false;
        }
        
        return true;
    }
    
    /**
     * Check if content type is analyzable.
     */
    private boolean isAnalyzableContentType(String contentType) {
        if (contentType == null) {
            return false;
        }
        
        String lower = contentType.toLowerCase();
        return lower.contains("javascript") || 
               lower.contains("text/html") ||
               lower.contains("application/json");
    }
    
    /**
     * Perform AI analysis on a transaction.
     */
    private void performAnalysis(HttpTransaction transaction) {
        try {
            callbacks.printOutput("[Traffic AI] Analyzing: " + transaction.getUrl());
            
            // Get AI service
            AIService aiService = getAIService();
            if (aiService == null) {
                callbacks.printError("[Traffic AI] Failed to create AI service");
                return;
            }
            
            // Get template
            PromptTemplate template = getTemplate(transaction);
            if (template == null) {
                callbacks.printError("[Traffic AI] No template available");
                return;
            }
            
            // Build context
            VariableContext context = buildContext(transaction);
            
            // Process template
            String prompt = templateManager.processTemplate(template, context);
            
            // Split into system and user prompts
            String[] parts = prompt.split("\n\n", 2);
            String systemPrompt = parts.length > 0 ? parts[0] : "";
            String userPrompt = parts.length > 1 ? parts[1] : prompt;
            
            // Call AI
            String response = aiService.ask(systemPrompt, userPrompt);
            
            // Parse findings
            List<TrafficFinding> findings = parseFindings(response, transaction);
            
            // Update statistics
            totalAnalyzed++;
            totalFindings += findings.size();
            
            // Notify listeners
            for (TrafficFinding finding : findings) {
                notifyFinding(finding);
            }
            
            callbacks.printOutput("[Traffic AI] Found " + findings.size() + " findings in: " + transaction.getUrl());
            
        } catch (Exception e) {
            callbacks.printError("[Traffic AI] Analysis failed: " + e.getMessage());
            e.printStackTrace(new java.io.PrintWriter(new java.io.StringWriter()));
        }
    }
    
    /**
     * Get AI service based on configuration.
     */
    private AIService getAIService() {
        String provider = aiConfig.getProvider();
        
        if ("Azure AI".equalsIgnoreCase(provider)) {
            AzureAIService.Configuration config = new AzureAIService.Configuration();
            config.setApiKey(aiConfig.getAzureApiKey());
            config.setEndpoint(aiConfig.getEndpoint());
            config.setDeploymentName(aiConfig.getDeployment());
            config.setTemperature(aiConfig.getTemperature());
            return new AzureAIService(config);
        } else if ("OpenRouter".equalsIgnoreCase(provider)) {
            OpenRouterService.Configuration config = new OpenRouterService.Configuration();
            config.setApiKey(aiConfig.getOpenRouterApiKey());
            config.setModel(aiConfig.getOpenRouterModel());
            config.setTemperature(aiConfig.getTemperature());
            return new OpenRouterService(config);
        } else {
            OpenAIService.Configuration config = new OpenAIService.Configuration();
            config.setApiKey(aiConfig.getOpenAIApiKey());
            config.setModel(aiConfig.getModel());
            config.setTemperature(aiConfig.getTemperature());
            return new OpenAIService(config);
        }
    }
    
    /**
     * Get template for analysis.
     */
    private PromptTemplate getTemplate(HttpTransaction transaction) {
        // If user selected a template, use it
        if (selectedTemplateId != null) {
            PromptTemplate template = templateManager.getTemplate(selectedTemplateId);
            if (template != null) {
                return template;
            }
        }
        
        // Otherwise, select based on content type
        String contentType = transaction.getContentType();
        if (contentType != null) {
            if (contentType.toLowerCase().contains("javascript")) {
                return templateManager.getTemplateByName("Traffic - JavaScript Analysis");
            } else if (contentType.toLowerCase().contains("html")) {
                return templateManager.getTemplateByName("Traffic - HTML Analysis");
            }
        }
        
        // Default to JavaScript template
        return templateManager.getTemplateByName("Traffic - JavaScript Analysis");
    }
    
    /**
     * Build variable context for template processing.
     */
    private VariableContext buildContext(HttpTransaction transaction) {
        // Create a simple map-based context for traffic analysis
        // We'll use custom variables since we don't have full request/response objects
        java.util.Map<String, String> variables = new java.util.HashMap<>();
        
        // Basic info
        variables.put("URL", transaction.getUrl());
        variables.put("METHOD", transaction.getMethod());
        variables.put("STATUS", String.valueOf(transaction.getStatusCode()));
        variables.put("CONTENT_TYPE", transaction.getContentType() != null ? transaction.getContentType() : "");
        variables.put("SIZE", String.valueOf(transaction.getResponseSize()));
        
        // Response content
        String responseBody = extractResponseBody(transaction.getResponse());
        variables.put("CONTENT", responseBody);
        variables.put("RESPONSE_BODY", responseBody);
        
        // Create a simple context wrapper
        return new SimpleVariableContext(variables);
    }
    
    /**
     * Simple variable context for traffic analysis.
     */
    private static class SimpleVariableContext extends VariableContext {
        private final java.util.Map<String, String> variables;
        
        public SimpleVariableContext(java.util.Map<String, String> variables) {
            super(null, null, null, null, null, null, null, null);
            this.variables = variables;
        }
        
        @Override
        public String getVariable(String varName) {
            return variables.getOrDefault(varName, super.getVariable(varName));
        }
    }
    
    /**
     * Extract response body from full response.
     */
    private String extractResponseBody(byte[] response) {
        if (response == null || response.length == 0) {
            return "";
        }
        
        String responseStr = new String(response);
        int bodyStart = responseStr.indexOf("\r\n\r\n");
        if (bodyStart > 0) {
            return responseStr.substring(bodyStart + 4);
        }
        
        return responseStr;
    }
    
    /**
     * Parse AI response into structured findings.
     */
    private List<TrafficFinding> parseFindings(String aiResponse, HttpTransaction transaction) {
        List<TrafficFinding> findings = new ArrayList<>();
        
        // Parse findings from AI response
        // Expected format:
        // - Type: [TYPE]
        // - Severity: [SEVERITY]
        // - Evidence: [EVIDENCE]
        // - Description: [DESCRIPTION]
        
        Pattern pattern = Pattern.compile(
            "- Type:\\s*\\[?([A-Z_]+)\\]?\\s*\n" +
            "- Severity:\\s*\\[?([A-Z]+)\\]?\\s*\n" +
            "- Evidence:\\s*\\[?([^\\]]+)\\]?\\s*\n" +
            "- Description:\\s*\\[?([^\\]]+)\\]?",
            Pattern.CASE_INSENSITIVE
        );
        
        Matcher matcher = pattern.matcher(aiResponse);
        while (matcher.find()) {
            String type = matcher.group(1).trim();
            String severity = matcher.group(2).trim();
            String evidence = matcher.group(3).trim();
            String description = matcher.group(4).trim();
            
            TrafficFinding finding = new TrafficFinding(
                transaction.getUrl(),
                type,
                severity,
                evidence,
                description,
                System.currentTimeMillis()
            );
            
            findings.add(finding);
        }
        
        // If no structured findings found, create a general finding
        if (findings.isEmpty() && aiResponse.length() > 50) {
            TrafficFinding finding = new TrafficFinding(
                transaction.getUrl(),
                "GENERAL",
                "INFO",
                aiResponse.substring(0, Math.min(200, aiResponse.length())),
                "AI analysis completed",
                System.currentTimeMillis()
            );
            findings.add(finding);
        }
        
        return findings;
    }
    
    /**
     * Notify listeners of a new finding.
     */
    private void notifyFinding(TrafficFinding finding) {
        for (FindingListener listener : listeners) {
            try {
                listener.onFinding(finding);
            } catch (Exception e) {
                callbacks.printError("[Traffic AI] Listener error: " + e.getMessage());
            }
        }
    }
    
    /**
     * Get analysis statistics.
     */
    public String getStatistics() {
        return String.format("Analyzed: %d | Findings: %d", totalAnalyzed, totalFindings);
    }
    
    /**
     * Ensure traffic analysis templates exist.
     */
    private void ensureTrafficTemplates() {
        // Check if unified bug bounty template exists
        if (templateManager.getTemplateByName("Traffic - Bug Bounty Hunter") == null) {
            // Templates will be created by PromptTemplateManager
            callbacks.printOutput("[Traffic AI] Creating unified bug bounty analysis template");
        }
    }
    
    /**
     * Shutdown the analyzer.
     */
    public void shutdown() {
        executor.shutdown();
    }
    
    /**
     * Listener interface for findings.
     */
    public interface FindingListener {
        void onFinding(TrafficFinding finding);
    }
    
    /**
     * Traffic finding model with grouping support.
     */
    public static class TrafficFinding {
        private final String url;
        private final String type;
        private final String severity;
        private final String evidence;
        private final String description;
        private final long timestamp;
        private int count = 1; // For grouping duplicate findings
        private final List<String> urls = new ArrayList<>(); // URLs where this finding appears
        
        public TrafficFinding(String url, String type, String severity, 
                            String evidence, String description, long timestamp) {
            this.url = url;
            this.type = type;
            this.severity = severity;
            this.evidence = evidence;
            this.description = description;
            this.timestamp = timestamp;
            this.urls.add(url);
        }
        
        public String getUrl() { return url; }
        public String getType() { return type; }
        public String getSeverity() { return severity; }
        public String getEvidence() { return evidence; }
        public String getDescription() { return description; }
        public long getTimestamp() { return timestamp; }
        public int getCount() { return count; }
        public List<String> getUrls() { return new ArrayList<>(urls); }
        
        public String getFormattedTime() {
            java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("HH:mm:ss");
            return sdf.format(new java.util.Date(timestamp));
        }
        
        /**
         * Check if this finding is similar to another (for grouping).
         */
        public boolean isSimilarTo(TrafficFinding other) {
            // Same type and severity
            if (!this.type.equals(other.type) || !this.severity.equals(other.severity)) {
                return false;
            }
            
            // Similar evidence (normalize and compare)
            String thisEvidence = normalizeEvidence(this.evidence);
            String otherEvidence = normalizeEvidence(other.evidence);
            
            // If evidence is very similar (>80% match), consider them the same
            double similarity = calculateSimilarity(thisEvidence, otherEvidence);
            return similarity > 0.8;
        }
        
        /**
         * Merge another finding into this one (for grouping).
         */
        public void mergeWith(TrafficFinding other) {
            this.count++;
            if (!this.urls.contains(other.url)) {
                this.urls.add(other.url);
            }
        }
        
        /**
         * Normalize evidence for comparison.
         */
        private String normalizeEvidence(String evidence) {
            return evidence.toLowerCase()
                .replaceAll("\\s+", " ")
                .replaceAll("[\"']", "")
                .trim();
        }
        
        /**
         * Calculate similarity between two strings (0.0 to 1.0).
         */
        private double calculateSimilarity(String s1, String s2) {
            if (s1.equals(s2)) return 1.0;
            
            int maxLen = Math.max(s1.length(), s2.length());
            if (maxLen == 0) return 1.0;
            
            int distance = levenshteinDistance(s1, s2);
            return 1.0 - ((double) distance / maxLen);
        }
        
        /**
         * Calculate Levenshtein distance between two strings.
         */
        private int levenshteinDistance(String s1, String s2) {
            int[][] dp = new int[s1.length() + 1][s2.length() + 1];
            
            for (int i = 0; i <= s1.length(); i++) {
                dp[i][0] = i;
            }
            for (int j = 0; j <= s2.length(); j++) {
                dp[0][j] = j;
            }
            
            for (int i = 1; i <= s1.length(); i++) {
                for (int j = 1; j <= s2.length(); j++) {
                    int cost = s1.charAt(i - 1) == s2.charAt(j - 1) ? 0 : 1;
                    dp[i][j] = Math.min(Math.min(
                        dp[i - 1][j] + 1,      // deletion
                        dp[i][j - 1] + 1),     // insertion
                        dp[i - 1][j - 1] + cost // substitution
                    );
                }
            }
            
            return dp[s1.length()][s2.length()];
        }
    }
}
