package com.vista.security.core;

import com.vista.security.model.HttpTransaction;
import com.vista.security.model.TrafficFinding;
import com.vista.security.service.AIService;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * IntelligentTrafficAnalyzer uses AI to automatically analyze HTTP traffic
 * and extract security-relevant intelligence.
 * 
 * Analysis Capabilities:
 * - JavaScript files: API keys, secrets, hidden URLs, debug code
 * - API responses: Hidden parameters, undocumented endpoints
 * - Request/Response: Sensitive data exposure, tokens, credentials
 * - Pattern detection: API keys, JWTs, connection strings, IPs
 * 
 * This enables proactive security testing by automatically discovering
 * issues as users browse through applications.
 */
public class IntelligentTrafficAnalyzer {
    
    private final AIService aiService;
    private final FindingsManager findingsManager;
    private com.vista.security.core.ScopeManager scopeManager; // For AI cost control
    
    // File extensions to EXCLUDE from AI analysis (to save costs)
    private static final String[] AI_EXCLUDED_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",  // Images
        ".css", ".woff", ".woff2", ".ttf", ".eot",                  // Styles/Fonts
        ".mp4", ".webm", ".mp3", ".wav",                            // Media
        ".pdf", ".zip", ".tar", ".gz",                              // Documents/Archives
        ".xml", ".txt", ".csv"                                      // Data files
    };
    
    // False positive filters - URLs to ignore
    private static final String[] FALSE_POSITIVE_DOMAINS = {
        "w3.org",
        "xmlsoap.org",
        "schemas.microsoft.com",
        "schemas.xmlsoap.org",
        "www.w3.org",
        "xmlns.com",
        "apache.org/xml",
        "openxmlformats.org",
        "purl.org",
        "dublincore.org"
    };
    
    private static final String[] FALSE_POSITIVE_PATTERNS = {
        "xmlns:",
        "xsi:",
        "xsd:",
        "schema",
        ".xsd",
        ".dtd"
    };
    
    // Pattern matchers for quick detection
    private static final Pattern API_KEY_PATTERN = Pattern.compile(
        "(api[_-]?key|apikey|api[_-]?secret|access[_-]?token)\\s*[:=]\\s*['\"]([a-zA-Z0-9_\\-]{20,})['\"]",
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern AWS_KEY_PATTERN = Pattern.compile(
        "AKIA[0-9A-Z]{16}"
    );
    
    private static final Pattern JWT_PATTERN = Pattern.compile(
        "eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+"
    );
    
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
        "(password|passwd|pwd)\\s*[:=]\\s*['\"]([^'\"]{3,})['\"]",
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern URL_PATTERN = Pattern.compile(
        "https?://[a-zA-Z0-9.-]+(?:/[^\\s'\")]*)?",
        Pattern.CASE_INSENSITIVE
    );
    
    /**
     * Creates a new IntelligentTrafficAnalyzer.
     * 
     * @param aiService AI service for intelligent analysis
     * @param findingsManager Findings manager to store discovered issues
     */
    public IntelligentTrafficAnalyzer(AIService aiService, FindingsManager findingsManager) {
        if (aiService == null) {
            throw new IllegalArgumentException("aiService cannot be null");
        }
        if (findingsManager == null) {
            throw new IllegalArgumentException("findingsManager cannot be null");
        }
        
        this.aiService = aiService;
        this.findingsManager = findingsManager;
        this.scopeManager = null; // Will be set later
    }
    
    /**
     * Sets the scope manager for AI cost control.
     * AI analysis will ONLY run on in-scope URLs when scope is enabled.
     * 
     * @param scopeManager The scope manager
     */
    public void setScopeManager(com.vista.security.core.ScopeManager scopeManager) {
        this.scopeManager = scopeManager;
    }
    
    /**
     * Checks if AI analysis should be used for this URL.
     * AI analysis ONLY runs when:
     * 1. Scope is enabled AND has domains defined AND URL is in scope
     * 
     * This ensures users don't get charged for AI unless they explicitly
     * define what they want to analyze.
     * 
     * @param url The URL to check
     * @return True if AI should be used, false otherwise
     */
    private boolean shouldUseAI(String url) {
        // If scope manager not set, DO NOT allow AI (safety first)
        if (scopeManager == null) {
            System.out.println("[Traffic Monitor] 💰 AI DISABLED (scope manager not configured)");
            return false;
        }
        
        // AI ONLY runs when scope is enabled
        if (!scopeManager.isScopeEnabled()) {
            System.out.println("[Traffic Monitor] 💰 AI DISABLED (scope not enabled - add domains and enable scope to use AI)");
            return false;
        }
        
        // AI ONLY runs when scope has domains defined
        if (scopeManager.size() == 0) {
            System.out.println("[Traffic Monitor] 💰 AI DISABLED (no domains in scope - add domains to use AI)");
            return false;
        }
        
        // Check if URL is in scope
        boolean inScope = scopeManager.isInScope(url);
        if (!inScope) {
            System.out.println("[Traffic Monitor] 💰 AI SKIPPED (out of scope): " + url);
        }
        return inScope;
    }
    
    /**
     * Checks if file extension should be excluded from AI analysis.
     * 
     * @param url The URL to check
     * @return True if should be excluded, false otherwise
     */
    private boolean isAIExcludedExtension(String url) {
        String lowerUrl = url.toLowerCase();
        for (String ext : AI_EXCLUDED_EXTENSIONS) {
            if (lowerUrl.endsWith(ext)) {
                System.out.println("[Traffic Monitor] 💰 AI SKIPPED (excluded extension " + ext + "): " + url);
                return true;
            }
        }
        return false;
    }
    
    /**
     * Checks if a URL is a false positive (CDN, schema, etc.).
     * 
     * @param url The URL to check
     * @return True if it's a false positive, false otherwise
     */
    private boolean isFalsePositive(String url) {
        if (url == null || url.isEmpty()) {
            return true;
        }
        
        String lowerUrl = url.toLowerCase();
        
        // Check against false positive domains
        for (String domain : FALSE_POSITIVE_DOMAINS) {
            if (lowerUrl.contains(domain)) {
                System.out.println("[Traffic Monitor] Filtered false positive (domain): " + url);
                return true;
            }
        }
        
        // Check against false positive patterns
        for (String pattern : FALSE_POSITIVE_PATTERNS) {
            if (lowerUrl.contains(pattern)) {
                System.out.println("[Traffic Monitor] Filtered false positive (pattern): " + url);
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Analyzes a batch of HTTP transactions for security issues.
     * 
     * @param transactions The transactions to analyze
     * @return List of discovered findings
     */
    public List<TrafficFinding> analyzeBatch(List<HttpTransaction> transactions) {
        List<TrafficFinding> allFindings = new ArrayList<>();
        
        for (HttpTransaction transaction : transactions) {
            try {
                String url = transaction.getUrl();
                
                // Skip false positives
                if (isFalsePositive(url)) {
                    System.out.println("[Traffic Monitor] Skipping false positive transaction: " + url);
                    continue;
                }
                
                // CRITICAL: Check scope BEFORE any analysis
                // Pattern detection: Always runs (free)
                // AI analysis: Only when scope is enabled + in scope
                
                // Pattern detection runs for ALL traffic (no scope required)
                List<TrafficFinding> findings = analyzeTransaction(transaction);
                
                // Filter findings based on scope (if enabled)
                if (scopeManager != null && scopeManager.isScopeEnabled() && scopeManager.size() > 0) {
                    // Scope is enabled - only keep in-scope findings
                    if (!scopeManager.isInScope(url)) {
                        System.out.println("[Traffic Monitor] ⏭️ SKIPPING out-of-scope findings for: " + url);
                        continue; // Skip out-of-scope findings
                    } else {
                        System.out.println("[Traffic Monitor] ✅ URL is IN SCOPE, keeping findings: " + url);
                    }
                }
                
                // Check for duplicate findings before adding
                for (TrafficFinding finding : findings) {
                    if (!isDuplicateFinding(finding, allFindings)) {
                        allFindings.add(finding);
                        // Store NEW finding in manager immediately
                        findingsManager.addFinding(finding.toExploitFinding());
                    } else {
                        System.out.println("[Traffic Monitor] 🔄 Skipping duplicate finding: " + finding.getTitle());
                    }
                }
                
            } catch (Exception e) {
                System.err.println("Error analyzing transaction: " + e.getMessage());
            }
        }
        
        return allFindings;
    }
    
    /**
     * Analyzes a single HTTP transaction.
     * 
     * @param transaction The transaction to analyze
     * @return List of discovered findings
     */
    public List<TrafficFinding> analyzeTransaction(HttpTransaction transaction) {
        List<TrafficFinding> findings = new ArrayList<>();
        
        // Determine content type and route to appropriate analyzer
        String contentType = transaction.getContentType();
        String url = transaction.getUrl();
        
        System.out.println("[Traffic Monitor] 📋 Content-Type: " + contentType + " | URL: " + url);
        
        if (contentType != null) {
            if (contentType.contains("javascript") || url.endsWith(".js")) {
                System.out.println("[Traffic Monitor] 📜 Detected JavaScript file, starting analysis...");
                findings.addAll(analyzeJavaScript(transaction));
            } else if (contentType.contains("json")) {
                System.out.println("[Traffic Monitor] 📊 Detected JSON response, starting analysis...");
                findings.addAll(analyzeJsonResponse(transaction));
            } else if (contentType.contains("html")) {
                System.out.println("[Traffic Monitor] 🌐 Detected HTML response, starting analysis...");
                findings.addAll(analyzeHtmlResponse(transaction));
            } else {
                System.out.println("[Traffic Monitor] 📄 Other content type, running pattern detection...");
                findings.addAll(analyzeForPatterns(transaction));
            }
        } else {
            System.out.println("[Traffic Monitor] ❓ No content type, running pattern detection...");
            findings.addAll(analyzeForPatterns(transaction));
        }
        
        // Always analyze for common patterns
        findings.addAll(analyzeForPatterns(transaction));
        
        // Analyze headers
        findings.addAll(analyzeHeaders(transaction));
        
        return findings;
    }
    
    /**
     * Analyzes JavaScript files for secrets and hidden URLs.
     * 
     * @param transaction The transaction containing JavaScript
     * @return List of findings
     */
    private List<TrafficFinding> analyzeJavaScript(HttpTransaction transaction) {
        List<TrafficFinding> findings = new ArrayList<>();
        
        try {
            byte[] response = transaction.getResponse();
            if (response == null || response.length == 0) {
                System.out.println("[Traffic Monitor] ⚠️ JavaScript file has no response body");
                return findings;
            }
            
            String jsContent = new String(response);
            System.out.println("[Traffic Monitor] 📏 JavaScript size: " + jsContent.length() + " bytes");
            
            // Quick pattern-based detection first (ALWAYS runs - FREE)
            System.out.println("[Traffic Monitor] 🔍 Running pattern-based detection (FREE)...");
            List<TrafficFinding> patternFindings = detectPatternsInContent(transaction, jsContent, "JavaScript");
            findings.addAll(patternFindings);
            System.out.println("[Traffic Monitor] 🔍 Pattern detection found: " + patternFindings.size() + " findings");
            
            // AI analysis - ONLY if conditions are met (COSTS MONEY)
            if (jsContent.length() < 500_000) { // 500KB limit
                // Check if AI should be used (scope + extension filters)
                if (!shouldUseAI(transaction.getUrl())) {
                    System.out.println("[Traffic Monitor] 💰 AI analysis DISABLED (scope filter)");
                } else if (isAIExcludedExtension(transaction.getUrl())) {
                    System.out.println("[Traffic Monitor] 💰 AI analysis DISABLED (excluded extension)");
                } else {
                    System.out.println("[Traffic Monitor] 🤖 JavaScript size OK for AI analysis, proceeding...");
                    List<TrafficFinding> aiFindings = analyzeJavaScriptWithAI(transaction, jsContent);
                    findings.addAll(aiFindings);
                }
            } else {
                System.out.println("[Traffic Monitor] ⚠️ JavaScript too large (" + jsContent.length() + " bytes), skipping AI analysis");
            }
            
        } catch (Exception e) {
            System.err.println("[Traffic Monitor] ❌ Error analyzing JavaScript: " + e.getMessage());
            e.printStackTrace();
        }
        
        return findings;
    }
    
    /**
     * Uses AI to deeply analyze JavaScript for security issues.
     * 
     * @param transaction The transaction
     * @param jsContent The JavaScript content
     * @return List of findings
     */
    private List<TrafficFinding> analyzeJavaScriptWithAI(HttpTransaction transaction, String jsContent) {
        List<TrafficFinding> findings = new ArrayList<>();
        
        try {
            // Truncate if too long (AI has token limits)
            String content = jsContent.length() > 10000 
                ? jsContent.substring(0, 10000) + "\n... [truncated]"
                : jsContent;
            
            String systemPrompt = "You are a security analyst specializing in finding vulnerabilities in JavaScript code.";
            String userPrompt = buildJavaScriptAnalysisPrompt(transaction, content);
            
            System.out.println("[Traffic Monitor] Calling AI for deep JavaScript analysis: " + transaction.getUrl());
            
            // Call AI service for deep analysis
            String aiResponse = aiService.ask(systemPrompt, userPrompt);
            
            // Parse AI response and extract findings
            if (aiResponse != null && !aiResponse.trim().isEmpty()) {
                System.out.println("[Traffic Monitor] AI analysis complete, parsing findings...");
                findings.addAll(parseAIFindings(transaction, aiResponse));
                System.out.println("[Traffic Monitor] AI found " + findings.size() + " additional findings");
            } else {
                System.out.println("[Traffic Monitor] AI returned empty response (AI may not be configured)");
            }
            
        } catch (Exception e) {
            // AI analysis failed, but pattern-based detection still works
            System.err.println("AI JavaScript analysis failed (pattern detection still active): " + e.getMessage());
        }
        
        return findings;
    }
    
    /**
     * Analyzes JSON responses for hidden parameters and endpoints.
     * 
     * @param transaction The transaction
     * @return List of findings
     */
    private List<TrafficFinding> analyzeJsonResponse(HttpTransaction transaction) {
        List<TrafficFinding> findings = new ArrayList<>();
        
        try {
            byte[] response = transaction.getResponse();
            if (response == null) {
                return findings;
            }
            
            String jsonContent = new String(response);
            
            // Look for interesting patterns in JSON
            findings.addAll(detectPatternsInContent(transaction, jsonContent, "JSON Response"));
            
            // Look for hidden parameters (keys that might be interesting)
            findings.addAll(extractHiddenParameters(transaction, jsonContent));
            
        } catch (Exception e) {
            System.err.println("Error analyzing JSON: " + e.getMessage());
        }
        
        return findings;
    }
    
    /**
     * Analyzes HTML responses for hidden forms and endpoints.
     * 
     * @param transaction The transaction
     * @return List of findings
     */
    private List<TrafficFinding> analyzeHtmlResponse(HttpTransaction transaction) {
        List<TrafficFinding> findings = new ArrayList<>();
        
        try {
            byte[] response = transaction.getResponse();
            if (response == null) {
                return findings;
            }
            
            String htmlContent = new String(response);
            
            // Look for hidden form fields
            Pattern hiddenFieldPattern = Pattern.compile(
                "<input[^>]*type=['\"]hidden['\"][^>]*name=['\"]([^'\"]+)['\"][^>]*value=['\"]([^'\"]+)['\"]",
                Pattern.CASE_INSENSITIVE
            );
            
            Matcher matcher = hiddenFieldPattern.matcher(htmlContent);
            while (matcher.find()) {
                String fieldName = matcher.group(1);
                String fieldValue = matcher.group(2);
                
                // Check if value looks sensitive
                if (fieldValue.length() > 10 && !fieldValue.matches("\\d+")) {
                    findings.add(new TrafficFinding(
                        "HIDDEN_PARAMETER",
                        "MEDIUM",
                        "Hidden Form Field: " + fieldName,
                        "Found hidden form field with non-trivial value",
                        "Field: " + fieldName + " = " + fieldValue,
                        transaction,
                        "HTML Response"
                    ));
                }
            }
            
        } catch (Exception e) {
            System.err.println("Error analyzing HTML: " + e.getMessage());
        }
        
        return findings;
    }
    
    /**
     * Analyzes request/response headers for sensitive information.
     * 
     * @param transaction The transaction
     * @return List of findings
     */
    private List<TrafficFinding> analyzeHeaders(HttpTransaction transaction) {
        List<TrafficFinding> findings = new ArrayList<>();
        
        // This would analyze headers from the raw request/response bytes
        // For now, placeholder
        
        return findings;
    }
    
    /**
     * Detects common security patterns in content.
     * 
     * @param transaction The transaction
     * @param content The content to analyze
     * @param category The category (JavaScript, JSON, etc.)
     * @return List of findings
     */
    private List<TrafficFinding> detectPatternsInContent(HttpTransaction transaction, 
                                                         String content, 
                                                         String category) {
        List<TrafficFinding> findings = new ArrayList<>();
        
        // API Keys
        Matcher apiKeyMatcher = API_KEY_PATTERN.matcher(content);
        while (apiKeyMatcher.find()) {
            findings.add(new TrafficFinding(
                "SECRET",
                "HIGH",
                "Potential API Key Found",
                "Found what appears to be an API key in " + category,
                apiKeyMatcher.group(0),
                transaction,
                category
            ));
        }
        
        // AWS Keys
        Matcher awsMatcher = AWS_KEY_PATTERN.matcher(content);
        while (awsMatcher.find()) {
            findings.add(new TrafficFinding(
                "SECRET",
                "CRITICAL",
                "AWS Access Key Found",
                "Found AWS access key in " + category,
                awsMatcher.group(0),
                transaction,
                category
            ));
        }
        
        // JWT Tokens
        Matcher jwtMatcher = JWT_PATTERN.matcher(content);
        while (jwtMatcher.find()) {
            findings.add(new TrafficFinding(
                "TOKEN",
                "MEDIUM",
                "JWT Token Found",
                "Found JWT token in " + category,
                jwtMatcher.group(0).substring(0, Math.min(50, jwtMatcher.group(0).length())) + "...",
                transaction,
                category
            ));
        }
        
        // Passwords
        Matcher passwordMatcher = PASSWORD_PATTERN.matcher(content);
        while (passwordMatcher.find()) {
            findings.add(new TrafficFinding(
                "SECRET",
                "HIGH",
                "Hardcoded Password Found",
                "Found hardcoded password in " + category,
                passwordMatcher.group(1) + " = [REDACTED]",
                transaction,
                category
            ));
        }
        
        // URLs (potential hidden endpoints)
        Matcher urlMatcher = URL_PATTERN.matcher(content);
        while (urlMatcher.find()) {
            String url = urlMatcher.group(0);
            
            // Skip false positives
            if (isFalsePositive(url)) {
                System.out.println("[Traffic Monitor] Filtered false positive URL in content: " + url);
                continue;
            }
            
            // Only report if it's not the same domain
            if (!url.contains(transaction.getUrl())) {
                findings.add(new TrafficFinding(
                    "HIDDEN_URL",
                    "INFO",
                    "External URL Found",
                    "Found reference to external URL in " + category,
                    url,
                    transaction,
                    category
                ));
            }
        }
        
        return findings;
    }
    
    /**
     * Analyzes content for common security patterns.
     * 
     * @param transaction The transaction
     * @return List of findings
     */
    private List<TrafficFinding> analyzeForPatterns(HttpTransaction transaction) {
        List<TrafficFinding> findings = new ArrayList<>();
        
        byte[] response = transaction.getResponse();
        if (response == null) {
            return findings;
        }
        
        String content = new String(response);
        findings.addAll(detectPatternsInContent(transaction, content, "Response"));
        
        return findings;
    }
    
    /**
     * Extracts hidden parameters from JSON responses.
     * 
     * @param transaction The transaction
     * @param jsonContent The JSON content
     * @return List of findings
     */
    private List<TrafficFinding> extractHiddenParameters(HttpTransaction transaction, String jsonContent) {
        List<TrafficFinding> findings = new ArrayList<>();
        
        // Look for interesting parameter names
        String[] interestingParams = {
            "admin", "debug", "internal", "secret", "token", "key", 
            "password", "credential", "auth", "session", "id"
        };
        
        for (String param : interestingParams) {
            Pattern pattern = Pattern.compile(
                "\"(" + param + "[^\"]*?)\"\\s*:\\s*\"?([^,}\"]+)\"?",
                Pattern.CASE_INSENSITIVE
            );
            
            Matcher matcher = pattern.matcher(jsonContent);
            if (matcher.find()) {
                findings.add(new TrafficFinding(
                    "PARAMETER",
                    "LOW",
                    "Interesting Parameter: " + matcher.group(1),
                    "Found potentially interesting parameter in JSON response",
                    matcher.group(1) + " = " + matcher.group(2),
                    transaction,
                    "JSON Response"
                ));
            }
        }
        
        return findings;
    }
    
    /**
     * Builds the AI analysis prompt for JavaScript.
     * 
     * @param transaction The transaction
     * @param jsContent The JavaScript content
     * @return The prompt string
     */
    private String buildJavaScriptAnalysisPrompt(HttpTransaction transaction, String jsContent) {
        return String.format(
            "Analyze this JavaScript file for security issues:\n\n" +
            "URL: %s\n" +
            "Content-Type: %s\n" +
            "Size: %d bytes\n\n" +
            "JavaScript Code:\n%s\n\n" +
            "Find and report:\n" +
            "1. Hardcoded API keys, secrets, passwords\n" +
            "2. Hidden API endpoints and URLs\n" +
            "3. Sensitive comments or debug code\n" +
            "4. Development/staging URLs\n" +
            "5. Authentication tokens\n" +
            "6. Any security-sensitive information\n\n" +
            "Format each finding as:\n" +
            "- Type: [SECRET|HIDDEN_URL|DEBUG_CODE]\n" +
            "- Severity: [CRITICAL|HIGH|MEDIUM|LOW]\n" +
            "- Evidence: [exact code snippet]\n" +
            "- Description: [brief explanation]",
            transaction.getUrl(),
            transaction.getContentType(),
            jsContent.length(),
            jsContent
        );
    }
    
    /**
     * Parses AI response to extract findings.
     * 
     * @param transaction The transaction
     * @param aiResponse The AI response text
     * @return List of findings
     */
    private List<TrafficFinding> parseAIFindings(HttpTransaction transaction, String aiResponse) {
        List<TrafficFinding> findings = new ArrayList<>();
        
        try {
            // Simple parsing - look for structured findings in AI response
            String[] lines = aiResponse.split("\n");
            String currentType = null;
            String currentSeverity = null;
            String currentEvidence = null;
            String currentDescription = null;
            
            for (String line : lines) {
                line = line.trim();
                
                if (line.startsWith("- Type:") || line.startsWith("Type:")) {
                    // Save previous finding if complete
                    if (currentType != null && currentSeverity != null) {
                        findings.add(new TrafficFinding(
                            currentType,
                            currentSeverity,
                            "AI-Detected: " + currentType,
                            currentDescription != null ? currentDescription : "Security issue found by AI analysis",
                            currentEvidence != null ? currentEvidence : "See AI response",
                            transaction,
                            "AI Analysis",
                            "AI"  // Mark as AI detection
                        ));
                    }
                    
                    // Start new finding
                    currentType = extractValue(line);
                    currentSeverity = null;
                    currentEvidence = null;
                    currentDescription = null;
                    
                } else if (line.startsWith("- Severity:") || line.startsWith("Severity:")) {
                    currentSeverity = extractValue(line);
                    
                } else if (line.startsWith("- Evidence:") || line.startsWith("Evidence:")) {
                    currentEvidence = extractValue(line);
                    
                } else if (line.startsWith("- Description:") || line.startsWith("Description:")) {
                    currentDescription = extractValue(line);
                }
            }
            
            // Save last finding
            if (currentType != null && currentSeverity != null) {
                findings.add(new TrafficFinding(
                    currentType,
                    currentSeverity,
                    "AI-Detected: " + currentType,
                    currentDescription != null ? currentDescription : "Security issue found by AI analysis",
                    currentEvidence != null ? currentEvidence : "See AI response",
                    transaction,
                    "AI Analysis",
                    "AI"  // Mark as AI detection
                ));
            }
            
        } catch (Exception e) {
            System.err.println("Error parsing AI findings: " + e.getMessage());
        }
        
        return findings;
    }
    
    /**
     * Checks if a finding is a duplicate based on evidence.
     * 
     * @param newFinding The new finding to check
     * @param existingFindings List of existing findings
     * @return True if duplicate, false otherwise
     */
    private boolean isDuplicateFinding(TrafficFinding newFinding, List<TrafficFinding> existingFindings) {
        String newEvidence = newFinding.getEvidence();
        String newType = newFinding.getType();
        
        for (TrafficFinding existing : existingFindings) {
            // Same type and same evidence = duplicate
            if (existing.getType().equals(newType) && 
                existing.getEvidence().equals(newEvidence)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Extracts value from a line like "- Type: SECRET" or "Severity: HIGH".
     * 
     * @param line The line to parse
     * @return The extracted value
     */
    private String extractValue(String line) {
        int colonIndex = line.indexOf(':');
        if (colonIndex > 0 && colonIndex < line.length() - 1) {
            return line.substring(colonIndex + 1).trim();
        }
        return "";
    }
}
