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
        
        if (transaction == null || transaction.getResponse() == null) {
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
        } else {
            System.out.println("[Traffic Monitor] ⏭️ Skipping: " + contentType);
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
            "Analyze this HTML for security issues:\n\n" +
            "URL: %s\n" +
            "Content-Type: %s\n" +
            "Size: %d bytes\n\n" +
            "HTML:\n%s\n\n" +
            "Find the following security issues:\n\n" +
            "1. EXPOSED API KEYS:\n" +
            "   - Look for patterns like: apiKey, api_key, API_KEY, apikey\n" +
            "   - AWS keys (AKIA...), Google API keys (AIza...), Stripe keys (sk_...)\n" +
            "   - Any key-value pairs with 'key' in the name\n\n" +
            "2. HARDCODED CREDENTIALS:\n" +
            "   - Usernames: username, user, login, email\n" +
            "   - Passwords: password, passwd, pwd (plaintext, encrypted, or hashed)\n" +
            "   - Database credentials\n" +
            "   - Admin credentials\n\n" +
            "3. PRIVATE IP ADDRESSES:\n" +
            "   - 10.x.x.x, 172.16-31.x.x, 192.168.x.x\n" +
            "   - Internal network IPs\n" +
            "   - Localhost references (127.0.0.1)\n\n" +
            "4. HIDDEN FORM FIELDS:\n" +
            "   - <input type=\"hidden\" name=\"...\" value=\"...\">\n" +
            "   - Look for sensitive data in hidden fields\n" +
            "   - Session tokens, user IDs, admin flags\n\n" +
            "5. AUTHENTICATION TOKENS:\n" +
            "   - JWT tokens, Bearer tokens\n" +
            "   - Session IDs, CSRF tokens\n" +
            "   - OAuth tokens\n\n" +
            "6. SENSITIVE COMMENTS:\n" +
            "   - <!-- TODO: remove before production -->\n" +
            "   - Debug information\n" +
            "   - Developer notes with credentials\n\n" +
            "DO NOT report:\n" +
            "- Public URLs or endpoints\n" +
            "- Public IP addresses\n" +
            "- Generic form fields without sensitive values\n\n" +
            "Response Format:\n" +
            "- Type: [API_KEY|CREDENTIAL|PRIVATE_IP|HIDDEN_FIELD|TOKEN|DEBUG_CODE|SENSITIVE_DATA]\n" +
            "- Severity: [CRITICAL|HIGH|MEDIUM|LOW]\n" +
            "- Evidence: [exact code snippet]\n" +
            "- Description: [brief explanation of the issue]",
            transaction.getUrl(),
            transaction.getContentType(),
            htmlContent.length(),
            htmlContent
        );
    }
    
    private String buildJavaScriptAnalysisPrompt(HttpTransaction transaction, String jsContent) {
        return String.format(
            "Analyze this JavaScript for security issues:\n\n" +
            "URL: %s\n" +
            "Content-Type: %s\n" +
            "Size: %d bytes\n\n" +
            "JavaScript:\n%s\n\n" +
            "Find the following security issues:\n\n" +
            "1. EXPOSED API KEYS:\n" +
            "   - Look for patterns like: apiKey, api_key, API_KEY, apikey\n" +
            "   - AWS keys (AKIA...), Google API keys (AIza...), Stripe keys (sk_...)\n" +
            "   - Any key-value pairs with 'key' in the name\n" +
            "   - const/var/let declarations with keys\n\n" +
            "2. HARDCODED CREDENTIALS:\n" +
            "   - Usernames: username, user, login, email\n" +
            "   - Passwords: password, passwd, pwd (plaintext, encrypted, or hashed)\n" +
            "   - Database credentials\n" +
            "   - Admin credentials\n\n" +
            "3. PRIVATE IP ADDRESSES:\n" +
            "   - 10.x.x.x, 172.16-31.x.x, 192.168.x.x\n" +
            "   - Internal network IPs\n" +
            "   - Localhost references (127.0.0.1)\n\n" +
            "4. AUTHENTICATION TOKENS:\n" +
            "   - JWT tokens, Bearer tokens\n" +
            "   - Session IDs, CSRF tokens\n" +
            "   - OAuth tokens\n" +
            "   - Authorization headers\n\n" +
            "5. DEBUG CODE:\n" +
            "   - console.log with sensitive data\n" +
            "   - Debug flags (DEBUG=true)\n" +
            "   - Development endpoints\n" +
            "   - TODO comments with credentials\n\n" +
            "6. SENSITIVE CONFIGURATION:\n" +
            "   - Database connection strings\n" +
            "   - API endpoints with credentials\n" +
            "   - Environment variables with secrets\n\n" +
            "DO NOT report:\n" +
            "- Public URLs or endpoints\n" +
            "- Public IP addresses\n" +
            "- Generic variable names without sensitive values\n\n" +
            "Response Format:\n" +
            "- Type: [API_KEY|CREDENTIAL|PRIVATE_IP|TOKEN|DEBUG_CODE|SENSITIVE_DATA]\n" +
            "- Severity: [CRITICAL|HIGH|MEDIUM|LOW]\n" +
            "- Evidence: [exact code snippet]\n" +
            "- Description: [brief explanation of the issue]",
            transaction.getUrl(),
            transaction.getContentType(),
            jsContent.length(),
            jsContent
        );
    }
    
    private List<TrafficFinding> parseAIFindings(HttpTransaction transaction, String aiResponse) {
        List<TrafficFinding> findings = new ArrayList<>();
        
        try {
            String[] lines = aiResponse.split("\n");
            String currentType = null;
            String currentSeverity = null;
            String currentEvidence = null;
            String currentDescription = null;
            
            for (String line : lines) {
                line = line.trim();
                
                if (line.startsWith("- Type:") || line.startsWith("Type:")) {
                    if (currentType != null && currentSeverity != null) {
                        System.out.println("[Traffic Monitor] 🤖 AI TYPE: " + currentType);
                        
                        // Validate type is not empty or "None Detected"
                        if (currentType.isEmpty() || "None Detected".equalsIgnoreCase(currentType)) {
                            System.out.println("[Traffic Monitor] ❌ REJECTED: Empty or 'None Detected' type");
                        } else if ("HIDDEN_URL".equalsIgnoreCase(currentType)) {
                            System.out.println("[Traffic Monitor] ❌ BLOCKED HIDDEN_URL");
                        } else if (currentEvidence == null || currentEvidence.isEmpty()) {
                            System.out.println("[Traffic Monitor] ❌ REJECTED: Missing evidence for " + currentType);
                        } else {
                            TrafficFinding finding = new TrafficFinding(
                                currentType,
                                currentSeverity,
                                "🤖 AI: " + currentType,
                                currentDescription != null ? currentDescription : "AI detected issue",
                                currentEvidence,
                                transaction,
                                "AI Analysis",
                                "AI"
                            );
                            findings.add(finding);
                            System.out.println("[Traffic Monitor] ✅ AI ADDED: " + currentType);
                        }
                    }
                    
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
            
            if (currentType != null && currentSeverity != null) {
                System.out.println("[Traffic Monitor] 🤖 AI TYPE (last): " + currentType);
                
                // Validate type is not empty or "None Detected"
                if (currentType.isEmpty() || "None Detected".equalsIgnoreCase(currentType)) {
                    System.out.println("[Traffic Monitor] ❌ REJECTED: Empty or 'None Detected' type (last)");
                } else if ("HIDDEN_URL".equalsIgnoreCase(currentType)) {
                    System.out.println("[Traffic Monitor] ❌ BLOCKED HIDDEN_URL (last)");
                } else if (currentEvidence == null || currentEvidence.isEmpty()) {
                    System.out.println("[Traffic Monitor] ❌ REJECTED: Missing evidence for " + currentType + " (last)");
                } else {
                    TrafficFinding finding = new TrafficFinding(
                        currentType,
                        currentSeverity,
                        "🤖 AI: " + currentType,
                        currentDescription != null ? currentDescription : "AI detected issue",
                        currentEvidence,
                        transaction,
                        "AI Analysis",
                        "AI"
                    );
                    findings.add(finding);
                    System.out.println("[Traffic Monitor] ✅ AI ADDED (last): " + currentType);
                }
            }
            
        } catch (Exception e) {
            System.err.println("Error parsing AI findings: " + e.getMessage());
        }
        
        return findings;
    }
    
    private String extractValue(String line) {
        int colonIndex = line.indexOf(':');
        if (colonIndex > 0 && colonIndex < line.length() - 1) {
            return line.substring(colonIndex + 1).trim();
        }
        return "";
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
