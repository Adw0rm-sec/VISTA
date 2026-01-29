package com.vista.security.core;

import com.vista.security.model.ExploitFinding;
import com.vista.security.model.FindingTemplate;
import com.vista.security.service.AzureAIService;
import com.vista.security.service.OpenAIService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Global findings manager for VISTA.
 * Stores all exploit findings and notifies listeners.
 * Enhanced with AI-powered report generation.
 */
public class FindingsManager {
    
    private static FindingsManager instance;
    
    private final List<ExploitFinding> findings = new CopyOnWriteArrayList<>();
    private final List<Consumer<ExploitFinding>> listeners = new CopyOnWriteArrayList<>();
    
    // Cache for AI-generated content
    private final Map<String, String> descriptionCache = new HashMap<>();
    private final Map<String, String> impactCache = new HashMap<>();
    private final Map<String, String> remediationCache = new HashMap<>();
    
    // Built-in templates
    private final List<FindingTemplate> templates = new ArrayList<>();
    
    private FindingsManager() {
        loadBuiltInTemplates();
    }
    
    public static synchronized FindingsManager getInstance() {
        if (instance == null) {
            instance = new FindingsManager();
        }
        return instance;
    }
    
    /**
     * Add a new finding and notify listeners.
     */
    public void addFinding(ExploitFinding finding) {
        findings.add(0, finding); // Add to front (newest first)
        notifyListeners(finding);
    }
    
    /**
     * Get all findings (unmodifiable).
     */
    public List<ExploitFinding> getFindings() {
        return Collections.unmodifiableList(findings);
    }
    
    /**
     * Get findings by severity.
     */
    public List<ExploitFinding> getFindingsBySeverity(String severity) {
        List<ExploitFinding> result = new ArrayList<>();
        for (ExploitFinding f : findings) {
            if (f.getSeverity().equalsIgnoreCase(severity)) {
                result.add(f);
            }
        }
        return result;
    }
    
    /**
     * Get findings by host.
     */
    public List<ExploitFinding> getFindingsByHost(String host) {
        List<ExploitFinding> result = new ArrayList<>();
        for (ExploitFinding f : findings) {
            if (f.getHost().equalsIgnoreCase(host)) {
                result.add(f);
            }
        }
        return result;
    }
    
    /**
     * Get finding by ID.
     */
    public ExploitFinding getFindingById(String id) {
        for (ExploitFinding f : findings) {
            if (f.getId().equals(id)) {
                return f;
            }
        }
        return null;
    }
    
    /**
     * Remove a finding.
     */
    public void removeFinding(ExploitFinding finding) {
        findings.remove(finding);
    }
    
    /**
     * Clear all findings.
     */
    public void clearAll() {
        findings.clear();
    }
    
    /**
     * Get count by severity.
     */
    public int getCountBySeverity(String severity) {
        int count = 0;
        for (ExploitFinding f : findings) {
            if (f.getSeverity().equalsIgnoreCase(severity)) {
                count++;
            }
        }
        return count;
    }
    
    /**
     * Get total count.
     */
    public int getTotalCount() {
        return findings.size();
    }
    
    /**
     * Add listener for new findings.
     */
    public void addListener(Consumer<ExploitFinding> listener) {
        listeners.add(listener);
    }
    
    /**
     * Remove listener.
     */
    public void removeListener(Consumer<ExploitFinding> listener) {
        listeners.remove(listener);
    }
    
    private void notifyListeners(ExploitFinding finding) {
        for (Consumer<ExploitFinding> listener : listeners) {
            try {
                listener.accept(finding);
            } catch (Exception e) {
                // Ignore listener errors
            }
        }
    }
    
    /**
     * Generate summary report.
     */
    public String generateSummaryReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════\n");
        sb.append("VISTA FINDINGS SUMMARY\n");
        sb.append("═══════════════════════════════════════════════════════\n\n");
        sb.append("Total Findings: ").append(getTotalCount()).append("\n");
        sb.append("  Critical: ").append(getCountBySeverity("Critical")).append("\n");
        sb.append("  High: ").append(getCountBySeverity("High")).append("\n");
        sb.append("  Medium: ").append(getCountBySeverity("Medium")).append("\n");
        sb.append("  Low: ").append(getCountBySeverity("Low")).append("\n\n");
        
        if (!findings.isEmpty()) {
            sb.append("FINDINGS LIST\n");
            sb.append("───────────────────────────────────────────────────────\n");
            for (ExploitFinding f : findings) {
                sb.append(f.getSummary()).append("\n");
            }
        }
        
        return sb.toString();
    }
    
    // ═══════════════════════════════════════════════════════════════
    // AI-Powered Report Generation
    // ═══════════════════════════════════════════════════════════════
    
    /**
     * Load built-in report templates.
     */
    private void loadBuiltInTemplates() {
        templates.add(FindingTemplate.hackerOneTemplate());
        templates.add(FindingTemplate.bugcrowdTemplate());
        templates.add(FindingTemplate.intigritiTemplate());
        templates.add(FindingTemplate.simpleMarkdownTemplate());
    }
    
    /**
     * Get all available templates.
     */
    public List<FindingTemplate> getTemplates() {
        return Collections.unmodifiableList(templates);
    }
    
    /**
     * Get template by ID.
     */
    public FindingTemplate getTemplate(String id) {
        for (FindingTemplate template : templates) {
            if (template.getId().equals(id)) {
                return template;
            }
        }
        return templates.get(0); // Default to HackerOne
    }
    
    /**
     * Generate AI description for a finding.
     */
    public String generateDescription(ExploitFinding finding) {
        // Check cache first
        String cacheKey = finding.getId() + "_desc";
        if (descriptionCache.containsKey(cacheKey)) {
            return descriptionCache.get(cacheKey);
        }
        
        try {
            String requestStr = finding.getRequest() != null ? 
                new String(finding.getRequest(), java.nio.charset.StandardCharsets.UTF_8) : "";
            String responseStr = finding.getResponse() != null ?
                new String(finding.getResponse(), java.nio.charset.StandardCharsets.UTF_8) : "";
            
            String prompt = String.format("""
                Generate a professional vulnerability description for a bug bounty report.
                
                Vulnerability Type: %s
                Target: %s%s
                Parameter: %s
                Payload: %s
                Indicator: %s
                
                Request (first 1000 chars):
                %s
                
                Response (first 1000 chars):
                %s
                
                Requirements:
                - Professional tone suitable for bug bounty platforms
                - Clear explanation of the vulnerability
                - Technical details about how it works
                - 2-3 paragraphs
                - No recommendations (separate section)
                - Focus on WHAT the vulnerability is, not HOW to fix it
                
                Format: Plain text, no markdown headers
                """,
                finding.getExploitType(),
                finding.getHost(),
                finding.getEndpoint(),
                finding.getParameter(),
                finding.getPayload(),
                finding.getIndicator(),
                truncate(requestStr, 1000),
                truncate(responseStr, 1000)
            );
            
            String description = callAI(prompt);
            descriptionCache.put(cacheKey, description);
            return description;
            
        } catch (Exception e) {
            return "Error generating description: " + e.getMessage();
        }
    }
    
    /**
     * Generate AI impact assessment for a finding.
     */
    public String generateImpact(ExploitFinding finding) {
        // Check cache first
        String cacheKey = finding.getId() + "_impact";
        if (impactCache.containsKey(cacheKey)) {
            return impactCache.get(cacheKey);
        }
        
        try {
            String prompt = String.format("""
                Generate the security impact section for this vulnerability.
                
                Vulnerability Type: %s
                Severity: %s
                Target: %s%s
                Parameter: %s
                
                Requirements:
                - Explain what an attacker can do with this vulnerability
                - Real-world attack scenarios
                - Business impact (data breach, account takeover, etc.)
                - Potential damage to users and organization
                - 2-3 paragraphs
                - Professional tone
                
                Format: Plain text, no markdown headers
                """,
                finding.getExploitType(),
                finding.getSeverity(),
                finding.getHost(),
                finding.getEndpoint(),
                finding.getParameter()
            );
            
            String impact = callAI(prompt);
            impactCache.put(cacheKey, impact);
            return impact;
            
        } catch (Exception e) {
            return "Error generating impact: " + e.getMessage();
        }
    }
    
    /**
     * Generate AI remediation recommendations for a finding.
     */
    public String generateRemediation(ExploitFinding finding) {
        // Check cache first
        String cacheKey = finding.getId() + "_remediation";
        if (remediationCache.containsKey(cacheKey)) {
            return remediationCache.get(cacheKey);
        }
        
        try {
            String prompt = String.format("""
                Generate remediation recommendations for this vulnerability.
                
                Vulnerability Type: %s
                Parameter: %s
                Context: %s endpoint
                
                Requirements:
                - Specific, actionable recommendations
                - Code-level fixes (input validation, output encoding, etc.)
                - Security best practices
                - Framework-specific guidance if applicable
                - 2-3 paragraphs with bullet points
                - Professional tone
                
                Format: Plain text with bullet points, no markdown headers
                """,
                finding.getExploitType(),
                finding.getParameter(),
                finding.getMethod()
            );
            
            String remediation = callAI(prompt);
            remediationCache.put(cacheKey, remediation);
            return remediation;
            
        } catch (Exception e) {
            return "Error generating remediation: " + e.getMessage();
        }
    }
    
    /**
     * Clear AI content cache for a finding.
     */
    public void clearCache(String findingId) {
        descriptionCache.remove(findingId + "_desc");
        impactCache.remove(findingId + "_impact");
        remediationCache.remove(findingId + "_remediation");
    }
    
    /**
     * Clear all AI content caches.
     */
    public void clearAllCaches() {
        descriptionCache.clear();
        impactCache.clear();
        remediationCache.clear();
    }
    
    /**
     * Call AI service with prompt.
     */
    private String callAI(String prompt) throws Exception {
        AIConfigManager config = AIConfigManager.getInstance();
        
        if (!config.isConfigured()) {
            throw new Exception("AI not configured. Please configure in Settings.");
        }
        
        if ("Azure AI".equalsIgnoreCase(config.getProvider())) {
            AzureAIService.Configuration azureConfig = new AzureAIService.Configuration();
            azureConfig.setEndpoint(config.getEndpoint());
            azureConfig.setDeploymentName(config.getDeployment());
            azureConfig.setApiKey(config.getApiKey());
            azureConfig.setTemperature(0.3); // Lower for more consistent output
            return new AzureAIService(azureConfig).ask(
                "You are a professional security researcher writing vulnerability reports.", prompt);
        } else {
            OpenAIService.Configuration openaiConfig = new OpenAIService.Configuration();
            openaiConfig.setApiKey(config.getApiKey());
            openaiConfig.setModel(config.getModel());
            openaiConfig.setTemperature(0.3); // Lower for more consistent output
            return new OpenAIService(openaiConfig).ask(
                "You are a professional security researcher writing vulnerability reports.", prompt);
        }
    }
    
    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
