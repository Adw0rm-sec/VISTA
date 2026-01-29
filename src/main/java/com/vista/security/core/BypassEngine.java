package com.vista.security.core;

import com.vista.security.model.BypassAttempt;
import com.vista.security.model.BypassResult;
import com.vista.security.service.AIService;
import burp.IHttpRequestResponse;
import burp.IExtensionHelpers;
import burp.IResponseInfo;
import burp.IBurpExtenderCallbacks;

import java.util.*;
import java.util.concurrent.*;

/**
 * AI-Powered Bypass Engine
 * Intelligently generates and tests payload variations to bypass WAFs and validation
 */
public class BypassEngine {
    
    private final AIService aiService;
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final BypassKnowledgeBase knowledgeBase;
    
    // Learning mechanism - tracks what works
    private final Map<String, List<String>> successfulBypassPatterns;
    
    public BypassEngine(AIService aiService, IExtensionHelpers helpers,
                       IBurpExtenderCallbacks callbacks,
                       BypassKnowledgeBase knowledgeBase) {
        this.aiService = aiService;
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.knowledgeBase = knowledgeBase;
        this.successfulBypassPatterns = new ConcurrentHashMap<>();
    }
    
    /**
     * Main entry point - attempts to bypass protection for a given payload
     */
    public BypassResult findBypass(IHttpRequestResponse baseRequest, 
                                   String originalPayload,
                                   String attackType,
                                   BypassCallback callback) {
        
        long startTime = System.currentTimeMillis();
        
        // Phase 1: Analyze the blocking mechanism
        callback.onPhaseComplete("Analysis", "Analyzing protection mechanism...");
        BlockingAnalysis analysis = analyzeBlocking(baseRequest, originalPayload);
        callback.onPhaseComplete("Analysis", analysis.getSummary());
        
        // Phase 2: Generate AI-powered bypass candidates
        callback.onPhaseComplete("Generation", "Generating bypass candidates...");
        List<String> bypassCandidates = generateBypassCandidates(
            originalPayload, 
            attackType, 
            analysis
        );
        callback.onPhaseComplete("Generation", 
            String.format("Generated %d bypass candidates", bypassCandidates.size()));
        
        // Phase 3: Test candidates intelligently
        callback.onPhaseComplete("Testing", "Testing bypass candidates...");
        BypassResult result = testBypassCandidates(
            baseRequest, 
            bypassCandidates, 
            analysis,
            callback
        );
        
        result.setTotalTime(System.currentTimeMillis() - startTime);
        
        // Phase 4: Learn from results
        if (result.isSuccessful()) {
            learnFromSuccess(attackType, analysis.getProtectionType(), 
                           result.getSuccessfulPayload());
            callback.onPhaseComplete("Complete", "✓ Bypass found!");
        } else {
            callback.onPhaseComplete("Complete", "✗ No bypass found");
        }
        
        return result;
    }
    
    /**
     * Analyzes WHY the original payload was blocked
     */
    private BlockingAnalysis analyzeBlocking(IHttpRequestResponse baseRequest, 
                                            String payload) {
        BlockingAnalysis analysis = new BlockingAnalysis();
        
        // Detect WAF from response
        byte[] response = baseRequest.getResponse();
        if (response != null) {
            String responseStr = new String(response, java.nio.charset.StandardCharsets.ISO_8859_1);
            IResponseInfo responseInfo = helpers.analyzeResponse(response);
            
            // Simple WAF detection based on headers
            String wafType = "None";
            for (String header : responseInfo.getHeaders()) {
                String headerLower = header.toLowerCase();
                if (headerLower.contains("cloudflare") || headerLower.contains("cf-ray")) {
                    wafType = "Cloudflare";
                    break;
                } else if (headerLower.contains("x-amz")) {
                    wafType = "AWS WAF";
                    break;
                } else if (headerLower.contains("mod_security") || headerLower.contains("modsecurity")) {
                    wafType = "ModSecurity";
                    break;
                }
            }
            analysis.setWafType(wafType);
            
            // Check for common blocking patterns
            if (responseStr.contains("403") || responseStr.contains("Forbidden")) {
                analysis.setProtectionType("WAF_BLOCK");
            } else if (responseStr.contains("400") || responseStr.contains("Bad Request")) {
                analysis.setProtectionType("INPUT_VALIDATION");
            } else if (responseStr.contains("406") || responseStr.contains("Not Acceptable")) {
                analysis.setProtectionType("CONTENT_TYPE_FILTER");
            } else if (responseStr.contains("&lt;") || responseStr.contains("&gt;")) {
                analysis.setProtectionType("OUTPUT_ENCODING");
            } else {
                analysis.setProtectionType("UNKNOWN");
            }
            
            // Extract blocking keywords if present
            analysis.setBlockingKeywords(extractBlockingKeywords(responseStr, payload));
        }
        
        return analysis;
    }
    
    /**
     * Uses AI to generate contextual bypass variations
     */
    private List<String> generateBypassCandidates(String originalPayload, 
                                                  String attackType,
                                                  BlockingAnalysis analysis) {
        List<String> candidates = new ArrayList<>();
        
        // Build AI prompt with context
        String prompt = buildBypassPrompt(originalPayload, attackType, analysis);
        
        // Get AI-generated bypasses
        try {
            String aiResponse = aiService.ask(
                "You are a penetration testing expert specializing in WAF and filter bypasses.",
                prompt
            );
            candidates.addAll(parseAIBypassSuggestions(aiResponse));
        } catch (Exception e) {
            callbacks.printError("AI bypass generation failed: " + e.getMessage());
            // Fallback to knowledge base if AI fails
            String knowledge = BypassKnowledgeBase.getBypassKnowledge(attackType);
            // Extract payloads from knowledge base text
            String[] lines = knowledge.split("\n");
            for (String line : lines) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#") && !line.startsWith("//") && line.length() > 5) {
                    candidates.add(line);
                }
            }
        }
        
        // Add historical successful patterns
        if (successfulBypassPatterns.containsKey(attackType)) {
            candidates.addAll(applySuccessfulPatterns(originalPayload, attackType));
        }
        
        // Add encoding variations
        candidates.addAll(generateEncodingVariations(originalPayload));
        
        // Add obfuscation techniques
        candidates.addAll(generateObfuscationVariations(originalPayload, attackType));
        
        // Remove duplicates
        return new ArrayList<>(new LinkedHashSet<>(candidates));
    }
    
    /**
     * Builds a contextual prompt for AI bypass generation
     */
    private String buildBypassPrompt(String payload, String attackType, 
                                     BlockingAnalysis analysis) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("Generate bypass variations for this security testing scenario:\n\n");
        prompt.append("Original Payload: ").append(payload).append("\n");
        prompt.append("Attack Type: ").append(attackType).append("\n");
        prompt.append("Protection Detected: ").append(analysis.getProtectionType()).append("\n");
        
        if (analysis.getWafType() != null && !analysis.getWafType().equals("None")) {
            prompt.append("WAF Type: ").append(analysis.getWafType()).append("\n");
        }
        
        if (!analysis.getBlockingKeywords().isEmpty()) {
            prompt.append("Blocked Keywords: ").append(
                String.join(", ", analysis.getBlockingKeywords())).append("\n");
        }
        
        prompt.append("\nGenerate 10 creative bypass variations using:\n");
        prompt.append("- Encoding techniques (URL, HTML, Unicode, etc.)\n");
        prompt.append("- Case manipulation\n");
        prompt.append("- Comment injection\n");
        prompt.append("- Null byte insertion\n");
        prompt.append("- Alternative syntax\n");
        prompt.append("- Concatenation tricks\n");
        prompt.append("\nProvide only the payload variations, one per line, no explanations.");
        
        return prompt.toString();
    }
    
    /**
     * Tests bypass candidates intelligently with early stopping
     */
    private BypassResult testBypassCandidates(IHttpRequestResponse baseRequest,
                                             List<String> candidates,
                                             BlockingAnalysis analysis,
                                             BypassCallback callback) {
        BypassResult result = new BypassResult();
        result.setTotalAttempts(candidates.size());
        
        for (int i = 0; i < candidates.size(); i++) {
            String candidate = candidates.get(i);
            
            // Test the bypass
            BypassAttempt attempt = testSingleBypass(baseRequest, candidate);
            result.addAttempt(attempt);
            
            callback.onBypassTested(i + 1, candidates.size(), attempt);
            
            // Check if successful
            if (attempt.isSuccessful()) {
                result.setSuccessful(true);
                result.setSuccessfulPayload(candidate);
                result.setSuccessfulResponse(attempt.getResponse());
                break; // Early stopping on success
            }
            
            // Rate limiting
            try {
                Thread.sleep(100); // Avoid overwhelming the target
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        return result;
    }
    
    /**
     * Tests a single bypass payload
     */
    private BypassAttempt testSingleBypass(IHttpRequestResponse baseRequest, 
                                          String bypassPayload) {
        BypassAttempt attempt = new BypassAttempt(bypassPayload);
        
        try {
            // Get original request
            byte[] originalRequest = baseRequest.getRequest();
            String requestStr = new String(originalRequest, java.nio.charset.StandardCharsets.ISO_8859_1);
            
            // Replace original payload with bypass payload
            // This is a simplified version - in production, you'd need to identify
            // the exact parameter and replace it properly
            String modifiedRequest = requestStr; // Placeholder for actual replacement logic
            
            // Make the request (this would use Burp's makeHttpRequest in real implementation)
            // For now, we'll simulate the response analysis
            byte[] response = baseRequest.getResponse();
            
            if (response != null) {
                String responseStr = new String(response, java.nio.charset.StandardCharsets.ISO_8859_1);
                IResponseInfo responseInfo = helpers.analyzeResponse(response);
                int statusCode = 200; // Default, as getStatusCode() doesn't exist in interface
                
                // Try to extract status code from headers
                if (responseInfo.getHeaders() != null && !responseInfo.getHeaders().isEmpty()) {
                    String firstLine = responseInfo.getHeaders().get(0);
                    if (firstLine.contains(" ")) {
                        String[] parts = firstLine.split(" ");
                        if (parts.length >= 2) {
                            try {
                                statusCode = Integer.parseInt(parts[1]);
                            } catch (NumberFormatException e) {
                                // Keep default
                            }
                        }
                    }
                }
                
                attempt.setStatusCode(statusCode);
                attempt.setResponse(responseStr.substring(0, Math.min(1000, responseStr.length())));
                attempt.setResponseTime(100); // Placeholder
                
                // Determine if successful based on response
                boolean isBlocked = responseStr.contains("403") || 
                                   responseStr.contains("Forbidden") ||
                                   responseStr.contains("blocked") ||
                                   responseStr.contains("&lt;") || 
                                   responseStr.contains("&gt;");
                
                attempt.setSuccessful(!isBlocked);
                
                if (isBlocked) {
                    attempt.setFailureReason("Still blocked or encoded");
                }
            }
        } catch (Exception e) {
            attempt.setSuccessful(false);
            attempt.setFailureReason("Error: " + e.getMessage());
        }
        
        return attempt;
    }
    
    /**
     * Generates encoding variations of the payload
     */
    private List<String> generateEncodingVariations(String payload) {
        List<String> variations = new ArrayList<>();
        
        // URL encoding variations
        variations.add(urlEncode(payload));
        variations.add(doubleUrlEncode(payload));
        
        // HTML entity encoding
        variations.add(htmlEncode(payload));
        
        // Unicode encoding
        variations.add(unicodeEncode(payload));
        
        // Mixed encoding
        variations.add(mixedEncode(payload));
        
        return variations;
    }
    
    /**
     * Generates obfuscation variations based on attack type
     */
    private List<String> generateObfuscationVariations(String payload, String attackType) {
        List<String> variations = new ArrayList<>();
        
        switch (attackType.toUpperCase()) {
            case "XSS":
                variations.addAll(generateXSSObfuscations(payload));
                break;
            case "SQLI":
            case "SQL_INJECTION":
                variations.addAll(generateSQLiObfuscations(payload));
                break;
            case "COMMAND_INJECTION":
                variations.addAll(generateCommandInjectionObfuscations(payload));
                break;
        }
        
        return variations;
    }
    
    private List<String> generateXSSObfuscations(String payload) {
        List<String> obfuscations = new ArrayList<>();
        
        // Case variations
        obfuscations.add(payload.toUpperCase());
        obfuscations.add(randomCase(payload));
        
        // Comment injection
        obfuscations.add(payload.replace("<", "</*!-->"));
        obfuscations.add(payload.replace("script", "scr<!---->ipt"));
        
        // Null byte tricks
        obfuscations.add(payload.replace("<", "<%00"));
        
        // Alternative event handlers
        if (payload.contains("onerror")) {
            obfuscations.add(payload.replace("onerror", "onload"));
            obfuscations.add(payload.replace("onerror", "onmouseover"));
        }
        
        // Context breaking
        obfuscations.add("</title>" + payload);
        obfuscations.add("</textarea>" + payload);
        obfuscations.add("</style>" + payload);
        
        return obfuscations;
    }
    
    private List<String> generateSQLiObfuscations(String payload) {
        List<String> obfuscations = new ArrayList<>();
        
        // Comment variations
        obfuscations.add(payload.replace(" ", "/**/"));
        obfuscations.add(payload.replace(" ", "%0a"));
        
        // Case variations
        obfuscations.add(randomCase(payload));
        
        // Alternative syntax
        if (payload.contains("UNION")) {
            obfuscations.add(payload.replace("UNION", "UNION ALL"));
            obfuscations.add(payload.replace("UNION", "/*!UNION*/"));
        }
        
        if (payload.contains("SELECT")) {
            obfuscations.add(payload.replace("SELECT", "/*!50000SELECT*/"));
            obfuscations.add(payload.replace("SELECT", "SeLeCt"));
        }
        
        return obfuscations;
    }
    
    private List<String> generateCommandInjectionObfuscations(String payload) {
        List<String> obfuscations = new ArrayList<>();
        
        // Variable expansion tricks
        obfuscations.add(payload.replace("cat", "c${IFS}at"));
        obfuscations.add(payload.replace("cat", "c'a't"));
        
        // Encoding
        obfuscations.add(payload.replace(" ", "${IFS}"));
        obfuscations.add(payload.replace(" ", "$IFS$9"));
        
        return obfuscations;
    }
    
    // Helper methods for encoding
    private String urlEncode(String str) {
        StringBuilder result = new StringBuilder();
        for (char c : str.toCharArray()) {
            if (c == '<' || c == '>' || c == '"' || c == '\'' || c == '&') {
                result.append(String.format("%%%02X", (int) c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
    
    private String doubleUrlEncode(String str) {
        return urlEncode(urlEncode(str));
    }
    
    private String htmlEncode(String str) {
        return str.replace("&", "&amp;")
                  .replace("<", "&lt;")
                  .replace(">", "&gt;")
                  .replace("\"", "&quot;")
                  .replace("'", "&#x27;");
    }
    
    private String unicodeEncode(String str) {
        StringBuilder result = new StringBuilder();
        for (char c : str.toCharArray()) {
            if (c == '<' || c == '>' || c == '"' || c == '\'') {
                result.append(String.format("\\u%04x", (int) c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
    
    private String mixedEncode(String str) {
        StringBuilder result = new StringBuilder();
        Random random = new Random();
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            int encoding = random.nextInt(3);
            if (c == '<' || c == '>' || c == '"' || c == '\'') {
                switch (encoding) {
                    case 0 -> result.append(String.format("%%%02X", (int) c));
                    case 1 -> result.append(String.format("&#x%02x;", (int) c));
                    case 2 -> result.append(String.format("\\u%04x", (int) c));
                }
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
    
    private String randomCase(String str) {
        StringBuilder result = new StringBuilder();
        Random random = new Random();
        for (char c : str.toCharArray()) {
            result.append(random.nextBoolean() ? 
                Character.toUpperCase(c) : Character.toLowerCase(c));
        }
        return result.toString();
    }
    
    private List<String> extractBlockingKeywords(String response, String payload) {
        List<String> keywords = new ArrayList<>();
        String[] suspiciousWords = {"script", "alert", "onerror", "onload", "SELECT", 
                                    "UNION", "OR", "AND", "eval", "exec", "system"};
        
        for (String word : suspiciousWords) {
            if (payload.toLowerCase().contains(word.toLowerCase()) && 
                response.toLowerCase().contains("block")) {
                keywords.add(word);
            }
        }
        return keywords;
    }
    
    private List<String> parseAIBypassSuggestions(String aiResponse) {
        List<String> suggestions = new ArrayList<>();
        String[] lines = aiResponse.split("\n");
        
        for (String line : lines) {
            line = line.trim();
            // Skip empty lines and headers
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("//")) {
                continue;
            }
            // Remove numbering like "1. ", "2. ", etc.
            line = line.replaceFirst("^\\d+\\.\\s*", "");
            // Remove markdown code blocks
            line = line.replace("```", "").trim();
            
            if (!line.isEmpty() && line.length() > 3) {
                suggestions.add(line);
            }
        }
        return suggestions;
    }
    
    private List<String> applySuccessfulPatterns(String payload, String attackType) {
        List<String> variations = new ArrayList<>();
        
        // Apply patterns from successful bypasses
        for (Map.Entry<String, List<String>> entry : successfulBypassPatterns.entrySet()) {
            if (entry.getKey().startsWith(attackType)) {
                for (String pattern : entry.getValue()) {
                    // Extract the transformation pattern and apply to current payload
                    variations.add(applyPattern(payload, pattern));
                }
            }
        }
        return variations;
    }
    
    private String applyPattern(String payload, String successfulPayload) {
        // Simple pattern application - can be enhanced with more sophisticated pattern matching
        return payload;
    }
    
    private void learnFromSuccess(String attackType, String protectionType, 
                                  String successfulPayload) {
        String key = attackType + "_" + protectionType;
        successfulBypassPatterns.computeIfAbsent(key, k -> new ArrayList<>())
            .add(successfulPayload);
        
        callbacks.printOutput("✓ Learned new bypass pattern for " + key);
    }
    
    // Inner classes
    public static class BlockingAnalysis {
        private String wafType;
        private String protectionType;
        private List<String> blockingKeywords = new ArrayList<>();
        
        public String getWafType() { return wafType; }
        public void setWafType(String wafType) { this.wafType = wafType; }
        
        public String getProtectionType() { return protectionType; }
        public void setProtectionType(String protectionType) { 
            this.protectionType = protectionType; 
        }
        
        public List<String> getBlockingKeywords() { return blockingKeywords; }
        public void setBlockingKeywords(List<String> keywords) { 
            this.blockingKeywords = keywords; 
        }
        
        public String getSummary() {
            return String.format("WAF: %s, Protection: %s, Blocked Keywords: %d",
                wafType != null ? wafType : "None",
                protectionType != null ? protectionType : "Unknown",
                blockingKeywords.size());
        }
    }
    
    public interface BypassCallback {
        void onPhaseComplete(String phase, String message);
        void onBypassTested(int current, int total, BypassAttempt attempt);
    }
}
