package com.vista.security.core;

import com.vista.security.model.HttpTransaction;
import com.vista.security.model.TrafficFinding;
import com.vista.security.service.AIService;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * IntelligentTrafficAnalyzer - AI-ONLY MODE with Enhanced Prompts and URL Deduplication
 * Version: 2.10.5-final
 * 
 * Features:
 * - AI-only analysis (no pattern detection)
 * - Enhanced security prompts for comprehensive detection
 * - URL deduplication to avoid repetitive analysis (bounded LRU cache to prevent memory leaks)
 * - AI request/response logging
 * - Validation for "None Detected" and missing evidence
 * - Content-type filtering (HTML/JavaScript only)
 * - Scope-based AI cost control
 */
public class IntelligentTrafficAnalyzer {
    
    private static final int MAX_ANALYZED_URLS = 10000; // Cap to prevent unbounded memory growth
    
    private final AIService aiService;
    private final FindingsManager findingsManager;
    private com.vista.security.core.ScopeManager scopeManager;
    // Bounded LRU set - automatically evicts oldest entries when full to prevent memory leaks
    private final Set<String> analyzedUrls = Collections.synchronizedSet(
        Collections.newSetFromMap(new java.util.LinkedHashMap<String, Boolean>(MAX_ANALYZED_URLS, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(java.util.Map.Entry<String, Boolean> eldest) {
                return size() > MAX_ANALYZED_URLS;
            }
        })
    );
    
    
    // Default unified template - sent as system prompt for ALL HTTP traffic analysis (JS, HTML, etc.)
    // Users can customize this via the UI. This single template defines:
    //   - AI's role and expertise
    //   - What to look for and what to skip
    //   - Response format rules
    private static final String DEFAULT_TEMPLATE = 
        "You are an expert application security analyst specializing in web vulnerability assessment. " +
        "Your role is to analyze HTTP traffic (HTML pages, JavaScript files, API responses) for real security vulnerabilities.\n\n" +
        "EXPERTISE:\n" +
        "- OWASP Top 10 vulnerabilities\n" +
        "- Client-side security issues (XSS, DOM manipulation, prototype pollution)\n" +
        "- Sensitive data exposure (API keys, credentials, tokens, PII)\n" +
        "- Security misconfigurations (missing headers, debug info, verbose errors)\n" +
        "- Information disclosure (internal IPs, stack traces, server details)\n\n" +
        "WHAT TO LOOK FOR:\n" +
        "1. API_KEY: Actual API keys (AKIA*, AIza*, sk_live_*, api_key=\"xxx\")\n" +
        "   ✅ Report: const API_KEY = \"AIzaSyC_YU1YQKR4YoafqU...\"\n" +
        "   ❌ Skip: const apiUrl = \"https://api.example.com\"\n" +
        "2. CREDENTIAL: Hardcoded passwords, database credentials\n" +
        "   ✅ Report: password: \"admin123\" or <!-- password: secret -->\n" +
        "   ❌ Skip: passwordField.value (no actual password)\n" +
        "3. PRIVATE_IP: Internal IPs (10.x.x.x, 192.168.x.x, 172.16-31.x.x)\n" +
        "   ✅ Report: const server = \"192.168.1.100\"\n" +
        "   ❌ Skip: public IP like \"8.8.8.8\"\n" +
        "4. TOKEN: JWT tokens (eyJ...), session tokens, auth tokens with actual values\n" +
        "   ✅ Report: const jwt = \"eyJhbGciOiJIUzI1NiIs...\"\n" +
        "   ❌ Skip: getToken() (function call, no actual token)\n" +
        "5. HIDDEN_FIELD: Hidden form inputs with sensitive values\n" +
        "   ✅ Report: <input type=\"hidden\" name=\"isAdmin\" value=\"true\">\n" +
        "   ❌ Skip: CSRF tokens, generic form IDs\n" +
        "6. DEBUG_CODE: Debug/dev code leaking sensitive data\n" +
        "   ✅ Report: console.log(\"Password:\", userPassword)\n" +
        "   ❌ Skip: console.log(\"Loading...\")\n" +
        "7. SENSITIVE_DATA: PII, credit cards, SSN, connection strings\n" +
        "   ✅ Report: const dbUrl = \"mongodb://admin:pass@localhost\"\n" +
        "   ❌ Skip: const appName = \"MyApp\"\n\n" +
        "DO NOT REPORT:\n" +
        "- Public URLs, CDN links, or public API endpoints\n" +
        "- CSRF tokens in hidden fields (these are expected)\n" +
        "- Security headers (CSP, HSTS, X-Frame-Options) - these are GOOD\n" +
        "- Minified library code (jQuery, React, etc.)\n" +
        "- Theoretical/potential issues without concrete proof\n\n" +
        "RULES:\n" +
        "1. ONLY report findings with CONCRETE evidence - exact code/text snippets from the content\n" +
        "2. NO theoretical, potential, or speculative issues\n" +
        "3. NO false positives - if uncertain, do NOT report\n" +
        "4. NO summary statements or concluding paragraphs\n" +
        "5. If NOTHING found, return EMPTY response (no text at all)\n" +
        "6. Quality over quantity - fewer accurate findings beat many false positives\n\n" +
        "RESPONSE FORMAT (for each finding):\n" +
        "Type: [API_KEY|CREDENTIAL|PRIVATE_IP|TOKEN|DEBUG_CODE|SENSITIVE_DATA|HIDDEN_FIELD|XSS|MISC]\n" +
        "Severity: [CRITICAL|HIGH|MEDIUM|LOW]\n" +
        "Evidence: [exact snippet from the analyzed content]\n" +
        "Description: [one sentence explaining the security impact]";
    
    // Single customizable template (can be modified by user via UI)
    // When set, this replaces DEFAULT_TEMPLATE as the system prompt
    private String customTemplate = null;
    private static final String[] DEFAULT_AI_EXCLUDED_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
        ".css", ".woff", ".woff2", ".ttf", ".eot",
        ".mp4", ".webm", ".mp3", ".wav",
        ".pdf", ".zip", ".tar", ".gz",
        ".xml", ".txt", ".csv"
    };
    
    public IntelligentTrafficAnalyzer(AIService aiService, FindingsManager findingsManager) {
        if (aiService == null) {
            throw new IllegalArgumentException("aiService cannot be null");
        }
        if (findingsManager == null) {
            throw new IllegalArgumentException("findingsManager cannot be null");
        }
        
        this.aiService = aiService;
        this.findingsManager = findingsManager;
        this.scopeManager = null;
    }
    
    public void setScopeManager(com.vista.security.core.ScopeManager scopeManager) {
        this.scopeManager = scopeManager;
    }
    
    private boolean shouldUseAI(String url) {
        if (scopeManager == null) {
            return false;
        }
        
        if (!scopeManager.isScopeEnabled()) {
            return false;
        }
        
        if (scopeManager.size() == 0) {
            return false;
        }
        
        return scopeManager.isInScope(url);
    }
    
    private boolean isAIExcludedExtension(String url) {
        String lowerUrl = url.toLowerCase();
        
        // Use user-configured extensions if available, otherwise use defaults
        AIConfigManager config = AIConfigManager.getInstance();
        String[] extensions = config.getExcludedExtensionsArray();
        if (extensions.length == 0) {
            extensions = DEFAULT_AI_EXCLUDED_EXTENSIONS;
        }
        
        for (String ext : extensions) {
            String trimmedExt = ext.trim().toLowerCase();
            if (!trimmedExt.isEmpty() && lowerUrl.endsWith(trimmedExt)) {
                return true;
            }
        }
        return false;
    }
    
    private boolean isAIEligibleContentType(String contentType) {
        if (contentType == null) {
            return false;
        }
        
        String lowerContentType = contentType.toLowerCase();
        
        // Use user-configured content types if available
        AIConfigManager config = AIConfigManager.getInstance();
        String[] eligibleTypes = config.getEligibleContentTypesArray();
        
        if (eligibleTypes.length == 0) {
            // Fallback to defaults if config is empty
            return lowerContentType.contains("text/html") ||
                   lowerContentType.contains("text/javascript") ||
                   lowerContentType.contains("application/javascript") ||
                   lowerContentType.contains("application/x-javascript");
        }
        
        for (String type : eligibleTypes) {
            String trimmedType = type.trim().toLowerCase();
            if (!trimmedType.isEmpty() && lowerContentType.contains(trimmedType)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check if a transaction is worth sending to AI for analysis.
     * Returns null if analysis-worthy, or a reason string if it should be skipped.
     * Called by AnalysisQueueManager.processTask() to avoid wasting queue time
     * on non-security-relevant traffic.
     */
    public String getSkipReason(com.vista.security.model.HttpTransaction transaction) {
        if (transaction == null) {
            return "Null transaction";
        }
        
        String url = transaction.getUrl();
        if (url == null || url.isEmpty()) {
            return "Empty URL";
        }
        
        // Check excluded file extensions (images, fonts, stylesheets, etc.)
        if (isAIExcludedExtension(url)) {
            return "Excluded extension";
        }
        
        // Check if response exists
        byte[] response = transaction.getResponse();
        if (response == null || response.length == 0) {
            return "No response data";
        }
        
        // Check content type eligibility
        String contentType = transaction.getContentType();
        if (!isAIEligibleContentType(contentType)) {
            String ct = (contentType != null) ? contentType : "unknown";
            return "Non-eligible content-type: " + ct;
        }
        
        // Check scope (AI should only analyze in-scope URLs)
        if (!shouldUseAI(url)) {
            return "Out of AI scope";
        }
        
        return null; // Analysis-worthy
    }
    
    public List<TrafficFinding> analyzeBatch(List<HttpTransaction> transactions) {
        List<TrafficFinding> allFindings = new ArrayList<>();
        
        for (HttpTransaction transaction : transactions) {
            try {
                List<TrafficFinding> findings = analyzeTransaction(transaction);
                allFindings.addAll(findings);
            } catch (Exception e) {
                System.err.println("[Traffic Monitor] Error analyzing: " + e.getMessage());
            }
        }
        
        return allFindings;
    }
    
    public List<TrafficFinding> analyzeTransaction(HttpTransaction transaction) {
        List<TrafficFinding> findings = new ArrayList<>();
        
        // Null checks
        if (transaction == null) {
            return findings;
        }
        
        byte[] response = transaction.getResponse();
        if (response == null) {
            return findings;
        }
        
        String contentType = transaction.getContentType();
        if (contentType == null) {
            contentType = "unknown";
        }
        
        String lowerContentType = contentType.toLowerCase();
        
        if (lowerContentType.contains("javascript")) {
            findings.addAll(analyzeJavaScript(transaction));
        } else if (lowerContentType.contains("text/html")) {
            findings.addAll(analyzeHtmlResponse(transaction));
        } else if (lowerContentType.contains("application/json")) {
            findings.addAll(analyzeJsonResponse(transaction));
        }
        
        return findings;
    }
    
    private List<TrafficFinding> analyzeJavaScript(HttpTransaction transaction) {
        List<TrafficFinding> findings = new ArrayList<>();
        
        byte[] response = transaction.getResponse();
        if (response == null) {
            return findings;
        }
        
        String jsContent = new String(response);
        
        if (!isAIEligibleContentType(transaction.getContentType())) {
            return findings;
        }
        
        if (jsContent.length() < 500_000) {
            if (!shouldUseAI(transaction.getUrl())) {
                return findings;
            }
            
            if (isAIExcludedExtension(transaction.getUrl())) {
                return findings;
            }
            
            // URL deduplication check
            String url = transaction.getUrl();
            if (analyzedUrls.contains(url)) {
                return findings;
            }
            
            findings.addAll(analyzeJavaScriptWithAI(transaction, jsContent));
            
            // Mark URL as analyzed
            analyzedUrls.add(url);
        }
        
        return findings;
    }
    
    private List<TrafficFinding> analyzeJavaScriptWithAI(HttpTransaction transaction, String jsContent) {
        List<TrafficFinding> findings = new ArrayList<>();
        
        try {
            String truncatedContent = jsContent;
            if (jsContent.length() > 2000) {
                truncatedContent = jsContent.substring(0, 2000) + "\n... [truncated]";
            }
            
            String prompt = buildUserDataPrompt("JavaScript", transaction, truncatedContent);
            
            // Use custom template if set by user, otherwise use default template
            String systemPrompt = (customTemplate != null && !customTemplate.isBlank()) 
                ? customTemplate 
                : DEFAULT_TEMPLATE;
            
            // Log to AIRequestLogStore for transparency
            AIRequestLogStore.AIRequestRecord logRecord = AIRequestLogStore.getInstance().logRequest(
                "Traffic Monitor JS", getAIProvider(), getAIModel(),
                "Traffic Monitor JavaScript", systemPrompt, prompt);
            
            long startTime = System.currentTimeMillis();
            // Call the full ask() method with template name and HTTP data for proper logging
            String aiResponse = aiService.ask(
                systemPrompt, 
                prompt, 
                "Traffic Monitor JavaScript",
                new String(transaction.getRequest()),
                truncatedContent
            );
            long duration = System.currentTimeMillis() - startTime;
            
            AIRequestLogStore.getInstance().logResponse(logRecord, aiResponse);
            
            if (aiResponse != null && !aiResponse.trim().isEmpty()) {
                findings.addAll(parseAIFindings(transaction, aiResponse));
            }
        } catch (Exception e) {
            System.err.println("[Traffic Monitor] AI error: " + e.getMessage());
            AIRequestLogger.logError(getAIProvider(), "JavaScript Analysis", e);
        }
        
        return findings;
    }
    
    private List<TrafficFinding> analyzeJsonResponse(HttpTransaction transaction) {
        return new ArrayList<>();
    }
    
    private List<TrafficFinding> analyzeHtmlResponse(HttpTransaction transaction) {
        List<TrafficFinding> findings = new ArrayList<>();
        
        byte[] response = transaction.getResponse();
        if (response == null) {
            return findings;
        }
        
        String htmlContent = new String(response);
        
        if (!isAIEligibleContentType(transaction.getContentType())) {
            return findings;
        }
        
        if (!shouldUseAI(transaction.getUrl())) {
            return findings;
        }
        
        // URL deduplication check
        String url = transaction.getUrl();
        if (analyzedUrls.contains(url)) {
            return findings;
        }
        
        if (htmlContent.length() < 100_000) {
            findings.addAll(analyzeHtmlWithAI(transaction, htmlContent));
            
            // Mark URL as analyzed
            analyzedUrls.add(url);
        }
        
        return findings;
    }
    
    private List<TrafficFinding> analyzeHtmlWithAI(HttpTransaction transaction, String htmlContent) {
        List<TrafficFinding> findings = new ArrayList<>();
        
        try {
            String truncatedContent = htmlContent;
            if (htmlContent.length() > 2000) {
                truncatedContent = htmlContent.substring(0, 2000) + "\n... [truncated]";
            }
            
            String prompt = buildUserDataPrompt("HTML", transaction, truncatedContent);
            
            // Use custom template if set by user, otherwise use default template
            String systemPrompt = (customTemplate != null && !customTemplate.isBlank()) 
                ? customTemplate 
                : DEFAULT_TEMPLATE;
            
            // Log to AIRequestLogStore for transparency
            AIRequestLogStore.AIRequestRecord logRecord = AIRequestLogStore.getInstance().logRequest(
                "Traffic Monitor HTML", getAIProvider(), getAIModel(),
                "Traffic Monitor HTML", systemPrompt, prompt);
            
            long startTime = System.currentTimeMillis();
            // Call the full ask() method with template name and HTTP data for proper logging
            String aiResponse = aiService.ask(
                systemPrompt, 
                prompt, 
                "Traffic Monitor HTML",
                new String(transaction.getRequest()),
                truncatedContent
            );
            long duration = System.currentTimeMillis() - startTime;
            
            AIRequestLogStore.getInstance().logResponse(logRecord, aiResponse);
            
            if (aiResponse != null && !aiResponse.trim().isEmpty()) {
                findings.addAll(parseAIFindings(transaction, aiResponse));
            }
        } catch (Exception e) {
            System.err.println("[Traffic Monitor] AI error: " + e.getMessage());
            AIRequestLogger.logError(getAIProvider(), "HTML Analysis", e);
        }
        
        return findings;
    }
    
    /**
     * Build the user data prompt for AI analysis.
     * This simply passes the HTTP traffic data to analyze.
     * All instructions, rules, and expertise are in the system prompt (the template).
     */
    private String buildUserDataPrompt(String contentLabel, HttpTransaction transaction, String content) {
        return String.format(
            "Analyze this %s for security vulnerabilities.\n\n" +
            "URL: %s\n" +
            "Content-Type: %s\n" +
            "Size: %d bytes\n\n" +
            "Content:\n%s",
            contentLabel,
            transaction.getUrl(),
            transaction.getContentType(),
            content.length(),
            content
        );
    }
    
    private List<TrafficFinding> parseAIFindings(HttpTransaction transaction, String aiResponse) {
        List<TrafficFinding> findings = new ArrayList<>();
        
        try {
            // Quick check for NO_FINDINGS response
            String trimmedResponse = aiResponse.trim().toUpperCase();
            if (trimmedResponse.equals("NO_FINDINGS") || 
                trimmedResponse.startsWith("NO_FINDINGS") ||
                trimmedResponse.contains("NO_FINDINGS")) {
                return findings;
            }
            
            // Also check for common "no issues" phrases
            String lowerResponse = aiResponse.toLowerCase();
            if (lowerResponse.contains("no security issues") ||
                lowerResponse.contains("no vulnerabilities") ||
                lowerResponse.contains("no issues found") ||
                lowerResponse.contains("no findings") ||
                (lowerResponse.contains("nothing") && lowerResponse.contains("found"))) {
                // Check if there's actually a Type: field - if not, skip
                if (!aiResponse.contains("Type:") && !aiResponse.contains("type:")) {
                    return findings;
                }
            }
            
            String[] lines = aiResponse.split("\n");
            String currentType = null;
            String currentSeverity = null;
            String currentEvidence = null;
            String currentDescription = null;
            StringBuilder evidenceBuilder = null;
            StringBuilder descriptionBuilder = null;
            boolean collectingEvidence = false;
            boolean collectingDescription = false;
            
            for (String line : lines) {
                String trimmedLine = line.trim();
                
                // Normalize markdown formatting: **Type:** -> Type:
                String normalizedLine = trimmedLine
                    .replaceAll("\\*\\*([^*]+):\\*\\*", "$1:")  // **Type:** -> Type:
                    .replaceAll("\\*\\*([^*]+)\\*\\*:", "$1:")  // **Type**: -> Type:
                    .trim();
                
                // Check if this line starts a new field (ends evidence/description collection)
                boolean isFieldLine = normalizedLine.matches("(?i)^-?\\s*(Type|Severity|Evidence|Description):.*");
                
                // If we're collecting evidence and hit a new field, stop collecting
                if (collectingEvidence && isFieldLine && !normalizedLine.toLowerCase().contains("evidence:")) {
                    collectingEvidence = false;
                    if (evidenceBuilder != null) {
                        currentEvidence = evidenceBuilder.toString().trim();
                        // Clean up code block markers
                        currentEvidence = currentEvidence.replaceAll("```[a-zA-Z]*", "").replaceAll("```", "").trim();
                    }
                }
                
                // If we're collecting description and hit a new field, stop collecting
                if (collectingDescription && isFieldLine && !normalizedLine.toLowerCase().contains("description:")) {
                    collectingDescription = false;
                    if (descriptionBuilder != null) {
                        currentDescription = descriptionBuilder.toString().trim();
                    }
                }
                
                // Check for Type field
                if (normalizedLine.matches("(?i)^-?\\s*Type:.*")) {
                    // Finalize any ongoing description collection for previous finding
                    if (collectingDescription && descriptionBuilder != null) {
                        currentDescription = descriptionBuilder.toString().trim();
                        collectingDescription = false;
                    }
                    
                    // Save previous finding if complete
                    if (currentType != null && currentSeverity != null) {
                        TrafficFinding finding = createFindingIfValid(transaction, currentType, currentSeverity, currentEvidence, currentDescription);
                        if (finding != null) {
                            findings.add(finding);
                        }
                    }
                    
                    currentType = extractFieldValue(normalizedLine, "Type");
                    currentSeverity = null;
                    currentEvidence = null;
                    currentDescription = null;
                    evidenceBuilder = null;
                    descriptionBuilder = null;
                    collectingEvidence = false;
                    collectingDescription = false;
                    
                } else if (normalizedLine.matches("(?i)^-?\\s*Severity:.*")) {
                    currentSeverity = extractFieldValue(normalizedLine, "Severity");
                    
                } else if (normalizedLine.matches("(?i)^-?\\s*Evidence:.*")) {
                    // Stop description collection when evidence starts
                    if (collectingDescription && descriptionBuilder != null) {
                        currentDescription = descriptionBuilder.toString().trim();
                        collectingDescription = false;
                    }
                    
                    String evidenceValue = extractFieldValue(normalizedLine, "Evidence");
                    if (!evidenceValue.isEmpty()) {
                        evidenceBuilder = new StringBuilder(evidenceValue);
                    } else {
                        evidenceBuilder = new StringBuilder();
                    }
                    collectingEvidence = true;
                    
                } else if (normalizedLine.matches("(?i)^-?\\s*Description:.*")) {
                    // Stop evidence collection when description starts
                    collectingEvidence = false;
                    if (evidenceBuilder != null) {
                        currentEvidence = evidenceBuilder.toString().trim();
                        currentEvidence = currentEvidence.replaceAll("```[a-zA-Z]*", "").replaceAll("```", "").trim();
                    }
                    
                    // Start collecting description (supports multi-line)
                    String descValue = extractFieldValue(normalizedLine, "Description");
                    if (!descValue.isEmpty()) {
                        descriptionBuilder = new StringBuilder(descValue);
                    } else {
                        descriptionBuilder = new StringBuilder();
                    }
                    collectingDescription = true;
                    
                } else if (collectingEvidence && evidenceBuilder != null) {
                    // Continue collecting evidence (multi-line)
                    if (!trimmedLine.isEmpty()) {
                        if (evidenceBuilder.length() > 0) {
                            evidenceBuilder.append("\n");
                        }
                        evidenceBuilder.append(trimmedLine);
                    }
                } else if (collectingDescription && descriptionBuilder != null) {
                    // Continue collecting description (multi-line)
                    if (!trimmedLine.isEmpty()) {
                        if (descriptionBuilder.length() > 0) {
                            descriptionBuilder.append(" ");  // Use space for description (more readable)
                        }
                        descriptionBuilder.append(trimmedLine);
                    }
                }
            }
            
            // Handle last finding - finalize any ongoing collection
            if (collectingEvidence && evidenceBuilder != null) {
                currentEvidence = evidenceBuilder.toString().trim();
                currentEvidence = currentEvidence.replaceAll("```[a-zA-Z]*", "").replaceAll("```", "").trim();
            }
            if (collectingDescription && descriptionBuilder != null) {
                currentDescription = descriptionBuilder.toString().trim();
            }
            
            if (currentType != null && currentSeverity != null) {
                TrafficFinding finding = createFindingIfValid(transaction, currentType, currentSeverity, currentEvidence, currentDescription);
                if (finding != null) {
                    findings.add(finding);
                }
            }
            
        } catch (Exception e) {
            System.err.println("[Traffic Monitor] Error parsing AI findings: " + e.getMessage());
            e.printStackTrace();
        }
        
        return findings;
    }
    
    /**
     * Extract field value from a line like "- Type: API_KEY" or "Type: API_KEY"
     */
    private String extractFieldValue(String line, String fieldName) {
        // Find the field name (case-insensitive) and extract value after colon
        String lowerLine = line.toLowerCase();
        int fieldIndex = lowerLine.indexOf(fieldName.toLowerCase());
        if (fieldIndex >= 0) {
            int colonIndex = line.indexOf(':', fieldIndex);
            if (colonIndex > 0 && colonIndex < line.length() - 1) {
                return line.substring(colonIndex + 1).trim();
            }
        }
        return "";
    }
    
    /**
     * Create a finding if it passes validation.
     */
    private TrafficFinding createFindingIfValid(HttpTransaction transaction, String type, String severity, 
                                                  String evidence, String description) {
        // Clean up type - remove brackets, parentheses, and whitespace
        if (type != null) {
            type = type.replaceAll("[\\[\\]\\(\\)]", "").trim();
        }
        
        // Validate type is not empty or indicates "none found"
        if (type == null || type.isEmpty()) {
            return null;
        }
        
        // Check for various "none found" patterns (case-insensitive)
        String lowerType = type.toLowerCase();
        if (lowerType.contains("none") || 
            lowerType.contains("n/a") || 
            lowerType.contains("not found") ||
            lowerType.contains("no ") ||
            lowerType.equals("null") ||
            lowerType.equals("-")) {
            return null;
        }
        
        if ("HIDDEN_URL".equalsIgnoreCase(type)) {
            return null;
        }
        
        // Block DEBUG_CODE - not required to be reported
        if ("DEBUG_CODE".equalsIgnoreCase(type) || lowerType.contains("debug")) {
            return null;
        }
        
        // Clean up evidence - check for N/A or empty or "no evidence" patterns
        if (evidence != null) {
            evidence = evidence.trim();
            // Remove markdown asterisks from evidence
            evidence = evidence.replaceAll("^\\*+|\\*+$", "").trim();
            
            String lowerEvidence = evidence.toLowerCase();
            
            // Check for exact "no evidence" values
            if (lowerEvidence.equals("n/a") || lowerEvidence.equals("none") || 
                lowerEvidence.equals("-") || lowerEvidence.isEmpty()) {
                evidence = null;
            }
            
            // Check for "no evidence found" type patterns in the evidence text
            if (evidence != null && (
                lowerEvidence.startsWith("no ") ||
                lowerEvidence.startsWith("*no ") ||
                lowerEvidence.contains("no evidence") ||
                lowerEvidence.contains("not found") ||
                lowerEvidence.contains("not present") ||
                lowerEvidence.contains("not detected") ||
                lowerEvidence.contains("were not shown") ||
                lowerEvidence.contains("were not found") ||
                lowerEvidence.contains("cannot be fully ruled out") ||
                lowerEvidence.contains("no explicit") ||
                lowerEvidence.contains("no api key") ||
                lowerEvidence.contains("no credential") ||
                lowerEvidence.contains("no token") ||
                lowerEvidence.contains("no sensitive") ||
                lowerEvidence.contains("none found") ||
                lowerEvidence.contains("none detected") ||
                lowerEvidence.contains("none present") ||
                lowerEvidence.contains("no issues") ||
                lowerEvidence.contains("no security") ||
                lowerEvidence.contains("no private ip") ||
                lowerEvidence.contains("no hidden"))) {
                return null;
            }
        }
        
        if (evidence == null || evidence.isEmpty()) {
            return null;
        }
        
        // Clean up severity
        if (severity != null) {
            severity = severity.replaceAll("[\\[\\]\\(\\)]", "").trim().toUpperCase();
            if (severity.equals("N/A") || severity.isEmpty()) {
                severity = "MEDIUM"; // Default severity
            }
        } else {
            severity = "MEDIUM";
        }
        
        // Block NONE severity findings - not required in UI
        if ("NONE".equalsIgnoreCase(severity) || "INFO".equalsIgnoreCase(severity)) {
            return null;
        }
        
        // Validate description doesn't indicate "no finding"
        if (description != null) {
            String lowerDesc = description.toLowerCase();
            if (lowerDesc.contains("no api key") ||
                lowerDesc.contains("no credential") ||
                lowerDesc.contains("no token") ||
                lowerDesc.contains("no evidence") ||
                lowerDesc.contains("not found") ||
                lowerDesc.contains("not present") ||
                lowerDesc.contains("not detected") ||
                lowerDesc.contains("no issues") ||
                lowerDesc.contains("no security issues") ||
                lowerDesc.contains("no sensitive") ||
                lowerDesc.contains("no private ip") ||
                lowerDesc.contains("no hidden") ||
                lowerDesc.contains("none found") ||
                lowerDesc.contains("none detected") ||
                lowerDesc.contains("were not found") ||
                lowerDesc.contains("does not show") ||
                lowerDesc.contains("does not contain") ||
                lowerDesc.startsWith("no ")) {
                return null;
            }
        }
        
        return new TrafficFinding(
            type,
            severity,
            "🤖 AI: " + type,
            description != null ? description : "AI detected issue",
            evidence,
            transaction,
            "AI Analysis",
            "AI"
        );
    }

    /**
     * Get the AI provider name for logging.
     */
    private String getAIProvider() {
        if (aiService == null) {
            return "Unknown";
        }

        String className = aiService.getClass().getSimpleName();
        if (className.contains("Azure")) {
            return "Azure AI";
        } else if (className.contains("OpenRouter")) {
            return "OpenRouter";
        } else if (className.contains("OpenAI")) {
            return "OpenAI";
        } else {
            return className;
        }
    }

    /**
     * Get the AI model name for logging.
     */
    private String getAIModel() {
        AIConfigManager config = AIConfigManager.getInstance();

        if (!config.isConfigured()) {
            return "Not Configured";
        }

        String provider = config.getProvider();
        if ("Azure AI".equalsIgnoreCase(provider)) {
            return config.getDeployment();
        } else if ("OpenRouter".equalsIgnoreCase(provider)) {
            return config.getOpenRouterModel();
        } else {
            return config.getModel();
        }
    }

    /**
     * Clear the analyzed URLs cache.
     * Call this when starting a new monitoring session or clearing findings.
     */
    public void clearAnalyzedUrls() {
        analyzedUrls.clear();
    }

    /**
     * Get the number of unique URLs analyzed.
     */
    public int getAnalyzedUrlCount() {
        return analyzedUrls.size();
    }
    
    /**
     * Set custom template for AI analysis.
     * This single template replaces the default and is used as the system prompt
     * for ALL HTTP traffic analysis (JavaScript, HTML, etc.).
     * @param template Custom template text (null to revert to default)
     */
    public void setCustomTemplate(String template) {
        this.customTemplate = template;
    }
    
    /**
     * Get the current custom template (null if using default).
     */
    public String getCustomTemplate() {
        return customTemplate;
    }
    
    /**
     * Get the current effective template (custom if set, otherwise default).
     */
    public String getEffectiveTemplate() {
        return (customTemplate != null && !customTemplate.isBlank()) ? customTemplate : DEFAULT_TEMPLATE;
    }
    
    /**
     * Get whether a custom template is active.
     */
    public String getTemplateInfo() {
        return customTemplate == null ? "Default" : "Custom";
    }
    
    /**
     * Get the default template constant.
     */
    public static String getDefaultTemplate() {
        return DEFAULT_TEMPLATE;
    }
}
