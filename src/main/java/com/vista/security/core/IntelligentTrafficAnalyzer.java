package com.vista.security.core;

import com.vista.security.model.HttpTransaction;
import com.vista.security.model.TrafficFinding;
import com.vista.security.service.AIService;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * IntelligentTrafficAnalyzer - AI-ONLY MODE with Enhanced Prompts and URL Deduplication
 * Version: 2.10.5-final
 * 
 * Features:
 * - AI-only analysis (no pattern detection)
 * - Enhanced security prompts for comprehensive detection
 * - URL deduplication to avoid repetitive analysis
 * - AI request/response logging
 * - Validation for "None Detected" and missing evidence
 * - Content-type filtering (HTML/JavaScript only)
 * - Scope-based AI cost control
 */
public class IntelligentTrafficAnalyzer {
    
    private final AIService aiService;
    private final FindingsManager findingsManager;
    private com.vista.security.core.ScopeManager scopeManager;
    private final Set<String> analyzedUrls = Collections.synchronizedSet(new HashSet<>()); // Track analyzed URLs for deduplication
    
    
    // Customizable prompts (can be modified by user)
    private String customSystemPrompt = null;
    private String customUserPromptTemplate = null;
    private static final String[] AI_EXCLUDED_EXTENSIONS = {
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
            System.out.println("[Traffic Monitor] 💰 AI DISABLED (scope manager not configured)");
            return false;
        }
        
        if (!scopeManager.isScopeEnabled()) {
            System.out.println("[Traffic Monitor] 💰 AI DISABLED (scope not enabled)");
            return false;
        }
        
        if (scopeManager.size() == 0) {
            System.out.println("[Traffic Monitor] 💰 AI DISABLED (no domains in scope)");
            return false;
        }
        
        boolean inScope = scopeManager.isInScope(url);
        if (!inScope) {
            System.out.println("[Traffic Monitor] 💰 AI SKIPPED (out of scope): " + url);
        }
        return inScope;
    }
    
    private boolean isAIExcludedExtension(String url) {
        String lowerUrl = url.toLowerCase();
        for (String ext : AI_EXCLUDED_EXTENSIONS) {
            if (lowerUrl.endsWith(ext)) {
                System.out.println("[Traffic Monitor] 💰 AI SKIPPED (excluded extension): " + url);
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
        boolean eligible = lowerContentType.contains("text/html") ||
                          lowerContentType.contains("text/javascript") ||
                          lowerContentType.contains("application/javascript") ||
                          lowerContentType.contains("application/x-javascript");
        
        if (!eligible) {
            System.out.println("[Traffic Monitor] ⏭️ Content-Type not eligible: " + contentType);
        }
        
        return eligible;
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
        
        // Debug logging for null checks
        if (transaction == null) {
            System.out.println("[Traffic Monitor] ❌ analyzeTransaction: transaction is NULL");
            return findings;
        }
        
        byte[] response = transaction.getResponse();
        if (response == null) {
            System.out.println("[Traffic Monitor] ❌ analyzeTransaction: response is NULL for " + transaction.getUrl());
            System.out.println("[Traffic Monitor] ❓ Transaction has request bytes: " + (transaction.getRequest() != null ? "YES" : "NO"));
            return findings;
        }
        
        System.out.println("[Traffic Monitor] ✓ analyzeTransaction: response size = " + response.length + " bytes for " + transaction.getUrl());
        
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
        } else {
            System.out.println("[Traffic Monitor] ⏭️ Skipping content-type: " + contentType);
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
        
        System.out.println("[Traffic Monitor] 📜 Analyzing JavaScript");
        
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
                System.out.println("[Traffic Monitor] ⏭️ SKIPPED (already analyzed): " + url);
                return findings;
            }
            
            System.out.println("[Traffic Monitor] 🤖 Running AI analysis...");
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
            
            String prompt = buildJavaScriptAnalysisPrompt(transaction, truncatedContent);
            
            // Log AI request
            String provider = getAIProvider();
            String model = getAIModel();
            AIRequestLogger.logRequest(
                provider,
                model,
                "Traffic Monitor - JavaScript Analysis",
                prompt,
                "Traffic Monitor JavaScript",
                new String(transaction.getRequest()),
                truncatedContent
            );
            
            long startTime = System.currentTimeMillis();
            String aiResponse = aiService.ask("", prompt);
            long duration = System.currentTimeMillis() - startTime;
            
            if (aiResponse != null && !aiResponse.trim().isEmpty()) {
                // Log AI response
                AIRequestLogger.logResponse(provider, aiResponse, duration);
                
                findings.addAll(parseAIFindings(transaction, aiResponse));
                System.out.println("[Traffic Monitor] 🤖 AI found " + findings.size() + " issues");
            }
        } catch (Exception e) {
            System.err.println("[Traffic Monitor] AI error: " + e.getMessage());
            AIRequestLogger.logError(getAIProvider(), "JavaScript Analysis", e);
        }
        
        return findings;
    }
    
    private List<TrafficFinding> analyzeJsonResponse(HttpTransaction transaction) {
        System.out.println("[Traffic Monitor] ⏭️ Skipping JSON (AI-only mode)");
        return new ArrayList<>();
    }
    
    private List<TrafficFinding> analyzeHtmlResponse(HttpTransaction transaction) {
        List<TrafficFinding> findings = new ArrayList<>();
        
        byte[] response = transaction.getResponse();
        if (response == null) {
            return findings;
        }
        
        String htmlContent = new String(response);
        
        System.out.println("[Traffic Monitor] 🌐 Analyzing HTML");
        
        if (!isAIEligibleContentType(transaction.getContentType())) {
            return findings;
        }
        
        if (!shouldUseAI(transaction.getUrl())) {
            return findings;
        }
        
        // URL deduplication check
        String url = transaction.getUrl();
        if (analyzedUrls.contains(url)) {
            System.out.println("[Traffic Monitor] ⏭️ SKIPPED (already analyzed): " + url);
            return findings;
        }
        
        if (htmlContent.length() < 100_000) {
            System.out.println("[Traffic Monitor] 🤖 Running AI analysis...");
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
            
            String prompt = buildHtmlAnalysisPrompt(transaction, truncatedContent);
            
            // Log AI request
            String provider = getAIProvider();
            String model = getAIModel();
            AIRequestLogger.logRequest(
                provider,
                model,
                "Traffic Monitor - HTML Analysis",
                prompt,
                "Traffic Monitor HTML",
                new String(transaction.getRequest()),
                truncatedContent
            );
            
            long startTime = System.currentTimeMillis();
            String aiResponse = aiService.ask("", prompt);
            long duration = System.currentTimeMillis() - startTime;
            
            if (aiResponse != null && !aiResponse.trim().isEmpty()) {
                // Log AI response
                AIRequestLogger.logResponse(provider, aiResponse, duration);
                
                findings.addAll(parseAIFindings(transaction, aiResponse));
                System.out.println("[Traffic Monitor] 🤖 AI found " + findings.size() + " issues");
            }
        } catch (Exception e) {
            System.err.println("[Traffic Monitor] AI error: " + e.getMessage());
            AIRequestLogger.logError(getAIProvider(), "HTML Analysis", e);
        }
        
        return findings;
    }
    
    private String buildHtmlAnalysisPrompt(HttpTransaction transaction, String htmlContent) {
        return String.format(
            "Analyze this HTML/Response for security vulnerabilities.\n\n" +
            "URL: %s\n" +
            "Content-Type: %s\n" +
            "Size: %d bytes\n\n" +
            "Content:\n%s\n\n" +
            "IMPORTANT INSTRUCTIONS:\n" +
            "- ONLY report issues where you find ACTUAL sensitive data\n" +
            "- Each finding MUST have concrete evidence (exact code/text snippet)\n" +
            "- If you find NOTHING, respond with just: NO_FINDINGS\n" +
            "- Do NOT report potential/theoretical issues\n" +
            "- Do NOT report if evidence is missing or uncertain\n\n" +
            "LOOK FOR:\n" +
            "1. API_KEY: Actual API keys in HTML/JS (AKIA*, AIza*, sk_*, api_key=\"xxx\")\n" +
            "2. CREDENTIAL: Hardcoded passwords, usernames with passwords\n" +
            "3. PRIVATE_IP: Internal IPs (10.x.x.x, 192.168.x.x, 172.16-31.x.x, 127.0.0.1)\n" +
            "4. TOKEN: JWT tokens (eyJ...), session IDs, auth tokens with actual values\n" +
            "5. HIDDEN_FIELD: Hidden inputs with sensitive values (not CSRF tokens)\n" +
            "6. SENSITIVE_DATA: PII, credit cards, SSN, internal paths with secrets\n\n" +
            "DO NOT REPORT:\n" +
            "- Public URLs, CDN links, or public API endpoints\n" +
            "- CSRF tokens in hidden fields (these are expected)\n" +
            "- Empty hidden fields or generic form fields\n" +
            "- Security headers (CSP, HSTS, X-Frame-Options) - these are GOOD\n" +
            "- Theoretical/potential issues without proof\n\n" +
            "OUTPUT FORMAT (only if findings exist):\n" +
            "For EACH finding, output EXACTLY:\n" +
            "---\n" +
            "Type: CREDENTIAL\n" +
            "Severity: CRITICAL\n" +
            "Evidence: <input type=\"hidden\" name=\"admin_pass\" value=\"secret123\">\n" +
            "Description: Admin password exposed in hidden form field\n" +
            "---\n\n" +
            "Remember: NO_FINDINGS if nothing found. Quality over quantity.",
            transaction.getUrl(),
            transaction.getContentType(),
            htmlContent.length(),
            htmlContent
        );
    }
    
    private String buildJavaScriptAnalysisPrompt(HttpTransaction transaction, String jsContent) {
        return String.format(
            "Analyze this JavaScript for security vulnerabilities.\n\n" +
            "URL: %s\n" +
            "Content-Type: %s\n" +
            "Size: %d bytes\n\n" +
            "JavaScript:\n%s\n\n" +
            "IMPORTANT INSTRUCTIONS:\n" +
            "- ONLY report issues where you find ACTUAL sensitive data in the code\n" +
            "- Each finding MUST have concrete evidence (exact code snippet)\n" +
            "- If you find NOTHING, respond with just: NO_FINDINGS\n" +
            "- Do NOT report potential/theoretical issues\n" +
            "- Do NOT report if evidence is missing or uncertain\n\n" +
            "LOOK FOR:\n" +
            "1. API_KEY: Actual API keys like AKIA*, AIza*, sk_*, api_key=\"xxx\"\n" +
            "2. CREDENTIAL: Hardcoded passwords, database credentials\n" +
            "3. PRIVATE_IP: Internal IPs (10.x.x.x, 192.168.x.x, 172.16-31.x.x)\n" +
            "4. TOKEN: JWT tokens (eyJ...), session tokens, auth tokens\n" +
            "5. SENSITIVE_DATA: PII, credit card numbers, SSN, encryption keys\n\n" +
            "DO NOT REPORT:\n" +
            "- Public URLs, CDN links, or public endpoints\n" +
            "- Variable names without actual sensitive values\n" +
            "- Generic patterns without concrete data\n" +
            "- Minified library code (jQuery, React, etc.)\n\n" +
            "OUTPUT FORMAT (only if findings exist):\n" +
            "For EACH finding, output EXACTLY:\n" +
            "---\n" +
            "Type: API_KEY\n" +
            "Severity: HIGH\n" +
            "Evidence: const apiKey = \"AIzaSyD-xxxxxxxxxxxx\"\n" +
            "Description: Google API key exposed in client-side JavaScript\n" +
            "---\n\n" +
            "Remember: NO_FINDINGS if nothing found. Quality over quantity.",
            transaction.getUrl(),
            transaction.getContentType(),
            jsContent.length(),
            jsContent
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
                System.out.println("[Traffic Monitor] ℹ️ AI returned NO_FINDINGS - skipping parse");
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
                    System.out.println("[Traffic Monitor] ℹ️ AI indicated no issues - skipping parse");
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
        
        System.out.println("[Traffic Monitor] 🤖 AI TYPE: " + type);
        
        // Validate type is not empty or indicates "none found"
        if (type == null || type.isEmpty()) {
            System.out.println("[Traffic Monitor] ❌ REJECTED: Empty type");
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
            System.out.println("[Traffic Monitor] ❌ REJECTED: 'None found' type: " + type);
            return null;
        }
        
        if ("HIDDEN_URL".equalsIgnoreCase(type)) {
            System.out.println("[Traffic Monitor] ❌ BLOCKED HIDDEN_URL");
            return null;
        }
        
        // Block DEBUG_CODE - not required to be reported
        if ("DEBUG_CODE".equalsIgnoreCase(type) || lowerType.contains("debug")) {
            System.out.println("[Traffic Monitor] ❌ BLOCKED DEBUG_CODE: " + type);
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
                System.out.println("[Traffic Monitor] ❌ REJECTED: Evidence indicates 'no finding': " + evidence.substring(0, Math.min(50, evidence.length())) + "...");
                return null;
            }
        }
        
        if (evidence == null || evidence.isEmpty()) {
            System.out.println("[Traffic Monitor] ❌ REJECTED: Missing evidence for " + type);
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
            System.out.println("[Traffic Monitor] ❌ REJECTED: NONE/INFO severity for " + type);
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
                System.out.println("[Traffic Monitor] ❌ REJECTED: Description indicates 'no finding': " + description.substring(0, Math.min(50, description.length())) + "...");
                return null;
            }
        }
        
        System.out.println("[Traffic Monitor] ✅ AI ADDED: " + type + " (" + severity + ")");
        System.out.println("[Traffic Monitor]    📝 Description: " + (description != null ? description.substring(0, Math.min(60, description.length())) + "..." : "null"));
        
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
        System.out.println("[Traffic Monitor] 🗑️ Cleared analyzed URLs cache");
    }

    /**
     * Get the number of unique URLs analyzed.
     */
    public int getAnalyzedUrlCount() {
        return analyzedUrls.size();
    }
    
    /**
     * Set custom system prompt for AI analysis
     * @param systemPrompt Custom system prompt (null to use default)
     */
    public void setCustomSystemPrompt(String systemPrompt) {
        this.customSystemPrompt = systemPrompt;
        System.out.println("[Traffic Monitor] Custom system prompt " + (systemPrompt == null ? "cleared" : "set"));
    }
    
    /**
     * Set custom user prompt template for AI analysis
     * Must contain 4 format placeholders: %s (URL), %s (Content-Type), %d (Size), %s (Content)
     * @param promptTemplate Custom prompt template (null to use default)
     */
    public void setCustomUserPromptTemplate(String promptTemplate) {
        this.customUserPromptTemplate = promptTemplate;
        System.out.println("[Traffic Monitor] Custom user prompt template " + (promptTemplate == null ? "cleared" : "set"));
    }
    
    /**
     * Get current system prompt (custom or default indicator)
     */
    public String getSystemPromptInfo() {
        return customSystemPrompt == null ? "Default" : "Custom";
    }
    
    /**
     * Get current user prompt template info
     */
    public String getUserPromptInfo() {
        return customUserPromptTemplate == null ? "Default" : "Custom";
    }
}
