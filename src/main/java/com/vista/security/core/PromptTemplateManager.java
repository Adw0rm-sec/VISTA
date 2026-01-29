package com.vista.security.core;

import com.vista.security.model.PromptTemplate;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Manages AI prompt templates.
 * Handles loading, saving, and organizing templates.
 */
public class PromptTemplateManager {
    
    private static PromptTemplateManager instance;
    
    private final List<PromptTemplate> templates = new ArrayList<>();
    private final String templatesDir;
    private final String builtInDir;
    private final String customDir;
    
    private PromptTemplateManager() {
        this.templatesDir = System.getProperty("user.home") + "/.vista/prompts/";
        this.builtInDir = templatesDir + "built-in/";
        this.customDir = templatesDir + "custom/";
        
        ensureDirectoriesExist();
        loadBuiltInTemplates();
        loadCustomTemplates();
    }
    
    public static synchronized PromptTemplateManager getInstance() {
        if (instance == null) {
            instance = new PromptTemplateManager();
        }
        return instance;
    }
    
    /**
     * Get all templates.
     */
    public List<PromptTemplate> getAllTemplates() {
        return Collections.unmodifiableList(templates);
    }
    
    /**
     * Get active templates only.
     */
    public List<PromptTemplate> getActiveTemplates() {
        return templates.stream()
            .filter(PromptTemplate::isActive)
            .collect(Collectors.toList());
    }
    
    /**
     * Get templates by category.
     */
    public List<PromptTemplate> getTemplatesByCategory(String category) {
        return templates.stream()
            .filter(t -> t.getCategory().equalsIgnoreCase(category))
            .collect(Collectors.toList());
    }
    
    /**
     * Get template by ID.
     */
    public PromptTemplate getTemplate(String id) {
        return templates.stream()
            .filter(t -> t.getId().equals(id))
            .findFirst()
            .orElse(null);
    }
    
    /**
     * Get template by name.
     */
    public PromptTemplate getTemplateByName(String name) {
        return templates.stream()
            .filter(t -> t.getName().equalsIgnoreCase(name))
            .findFirst()
            .orElse(null);
    }
    
    /**
     * Search templates by name or description.
     */
    public List<PromptTemplate> searchTemplates(String query) {
        String lowerQuery = query.toLowerCase();
        return templates.stream()
            .filter(t -> t.getName().toLowerCase().contains(lowerQuery) ||
                        t.getDescription().toLowerCase().contains(lowerQuery) ||
                        t.getTags().stream().anyMatch(tag -> tag.toLowerCase().contains(lowerQuery)))
            .collect(Collectors.toList());
    }
    
    /**
     * Save a template.
     */
    public void saveTemplate(PromptTemplate template) {
        if (template.isBuiltIn()) {
            throw new IllegalArgumentException("Cannot modify built-in templates");
        }
        
        // Add to list if new
        if (!templates.contains(template)) {
            templates.add(template);
        }
        
        // Save to file
        try {
            String filename = sanitizeFilename(template.getName()) + ".json";
            Path filePath = Paths.get(customDir, filename);
            Files.writeString(filePath, template.toJson());
        } catch (Exception e) {
            throw new RuntimeException("Failed to save template: " + e.getMessage(), e);
        }
    }
    
    /**
     * Delete a template.
     */
    public void deleteTemplate(String id) {
        PromptTemplate template = getTemplate(id);
        if (template == null) {
            throw new IllegalArgumentException("Template not found: " + id);
        }
        
        if (template.isBuiltIn()) {
            throw new IllegalArgumentException("Cannot delete built-in templates");
        }
        
        templates.remove(template);
        
        // Delete file
        try {
            String filename = sanitizeFilename(template.getName()) + ".json";
            Path filePath = Paths.get(customDir, filename);
            Files.deleteIfExists(filePath);
        } catch (Exception e) {
            throw new RuntimeException("Failed to delete template: " + e.getMessage(), e);
        }
    }
    
    /**
     * Process template with variable substitution.
     */
    public String processTemplate(PromptTemplate template, VariableContext context) {
        template.incrementUsageCount();
        
        // Only save custom templates (not built-in) to persist usage count
        if (!template.isBuiltIn()) {
            try {
                saveTemplate(template);
            } catch (Exception e) {
                // Ignore save errors for usage count updates
                System.err.println("Failed to update template usage count: " + e.getMessage());
            }
        }
        
        String systemPrompt = VariableProcessor.process(template.getSystemPrompt(), context);
        String userPrompt = VariableProcessor.process(template.getUserPrompt(), context);
        
        return systemPrompt + "\n\n" + userPrompt;
    }
    
    /**
     * Export template to file.
     */
    public void exportTemplate(String id, File destination) {
        PromptTemplate template = getTemplate(id);
        if (template == null) {
            throw new IllegalArgumentException("Template not found: " + id);
        }
        
        try {
            Files.writeString(destination.toPath(), template.toJson());
        } catch (Exception e) {
            throw new RuntimeException("Failed to export template: " + e.getMessage(), e);
        }
    }
    
    /**
     * Import template from file.
     */
    public void importTemplate(File source) {
        try {
            String json = Files.readString(source.toPath());
            PromptTemplate template = PromptTemplate.fromJson(json);
            
            // Make it non-built-in
            PromptTemplate imported = new PromptTemplate(
                template.getName() + " (Imported)",
                template.getCategory(),
                template.getAuthor(),
                template.getDescription(),
                template.getSystemPrompt(),
                template.getUserPrompt()
            );
            imported.setTags(template.getTags());
            imported.setModelOverride(template.getModelOverride());
            imported.setTemperatureOverride(template.getTemperatureOverride());
            imported.setMaxTokensOverride(template.getMaxTokensOverride());
            
            saveTemplate(imported);
        } catch (Exception e) {
            throw new RuntimeException("Failed to import template: " + e.getMessage(), e);
        }
    }
    
    /**
     * Get all categories.
     */
    public List<String> getCategories() {
        return templates.stream()
            .map(PromptTemplate::getCategory)
            .distinct()
            .sorted()
            .collect(Collectors.toList());
    }
    
    // Private helper methods
    
    private void ensureDirectoriesExist() {
        try {
            Files.createDirectories(Paths.get(builtInDir));
            Files.createDirectories(Paths.get(customDir));
        } catch (Exception e) {
            System.err.println("Failed to create template directories: " + e.getMessage());
        }
    }
    
    private void loadBuiltInTemplates() {
        // XSS Templates
        templates.add(createXssReflectedBasic());
        templates.add(createXssReflectedAggressive());
        templates.add(createXssStored());
        templates.add(createXssDomBased());
        
        // SQLi Templates
        templates.add(createSqliErrorBased());
        templates.add(createSqliBlindBoolean());
        templates.add(createSqliTimeBased());
        
        // SSTI Templates
        templates.add(createSstiDetection());
        templates.add(createSstiExploitation());
        
        // Other Vulnerabilities
        templates.add(createCommandInjection());
        templates.add(createSsrfBasic());
        templates.add(createSsrfCloudMetadata());
        templates.add(createAuthBypass());
        templates.add(createApiSecurity());
        
        // WAF Bypass
        templates.add(createWafBypassGeneric());
        templates.add(createWafBypassCloudflare());
        
        // Reconnaissance
        templates.add(createParameterDiscovery());
        templates.add(createEndpointAnalysis());
        templates.add(createErrorAnalysis());
        
        // Quick Scan
        templates.add(createQuickVulnScan());
        
        // Clean up any built-in templates that were accidentally saved to disk
        cleanupBuiltInDuplicates();
    }
    
    private void loadCustomTemplates() {
        try {
            File customDirFile = new File(customDir);
            if (!customDirFile.exists()) return;
            
            File[] files = customDirFile.listFiles((dir, name) -> name.endsWith(".json"));
            if (files == null) return;
            
            for (File file : files) {
                try {
                    String json = Files.readString(file.toPath());
                    PromptTemplate template = PromptTemplate.fromJson(json);
                    
                    // Skip if this is a duplicate of a built-in template
                    if (!isDuplicateOfBuiltIn(template)) {
                        templates.add(template);
                    } else {
                        // Delete the duplicate file
                        System.out.println("Removing duplicate built-in template: " + file.getName());
                        file.delete();
                    }
                } catch (Exception e) {
                    System.err.println("Failed to load template " + file.getName() + ": " + e.getMessage());
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to load custom templates: " + e.getMessage());
        }
    }
    
    /**
     * Check if a template is a duplicate of a built-in template.
     */
    private boolean isDuplicateOfBuiltIn(PromptTemplate template) {
        for (PromptTemplate existing : templates) {
            if (existing.isBuiltIn() && existing.getName().equals(template.getName())) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Clean up any built-in templates that were accidentally saved to custom directory.
     */
    private void cleanupBuiltInDuplicates() {
        try {
            File customDirFile = new File(customDir);
            if (!customDirFile.exists()) return;
            
            File[] files = customDirFile.listFiles((dir, name) -> name.endsWith(".json"));
            if (files == null) return;
            
            for (File file : files) {
                try {
                    String json = Files.readString(file.toPath());
                    PromptTemplate template = PromptTemplate.fromJson(json);
                    
                    // If this matches a built-in template name, delete it
                    if (isDuplicateOfBuiltIn(template)) {
                        System.out.println("Cleaning up duplicate built-in template: " + file.getName());
                        file.delete();
                    }
                } catch (Exception e) {
                    // Ignore errors during cleanup
                }
            }
        } catch (Exception e) {
            // Ignore errors during cleanup
        }
    }
    
    private String sanitizeFilename(String name) {
        return name.toLowerCase()
            .replaceAll("[^a-z0-9-]", "-")
            .replaceAll("-+", "-")
            .replaceAll("^-|-$", "");
    }
    
    // Built-in template creators
    
    private PromptTemplate createXssReflectedBasic() {
        PromptTemplate template = new PromptTemplate(
            "XSS - Reflected (Basic)",
            "Exploitation",
            "@vista",
            "Standard reflected XSS testing with common payloads",
            "You are an expert XSS penetration tester. Provide clear, actionable testing guidance.",
            """
            USER'S QUESTION: {{USER_QUERY}}
            
            Analyze this request for reflected XSS vulnerabilities.
            
            REQUEST:
            {{REQUEST}}
            
            RESPONSE:
            {{RESPONSE}}
            
            REFLECTION ANALYSIS:
            {{REFLECTION_ANALYSIS}}
            
            WAF DETECTION:
            {{WAF_DETECTION}}
            
            Provide:
            1. Analysis of where parameters are reflected
            2. Context-specific XSS payloads (HTML body, attribute, JavaScript)
            3. Step-by-step testing instructions
            4. Expected results
            5. Bypass techniques if WAF detected
            
            Focus on practical, ready-to-use payloads.
            Address the user's specific question above.
            """
        );
        template.addTag("xss");
        template.addTag("reflected");
        template.addTag("basic");
        return template;
    }
    
    private PromptTemplate createXssReflectedAggressive() {
        PromptTemplate template = new PromptTemplate(
            "XSS - Reflected (Aggressive)",
            "Exploitation",
            "@vista",
            "Aggressive XSS testing with WAF bypass and obfuscation",
            "You are an expert XSS penetration tester specializing in WAF bypass techniques.",
            """
            Perform aggressive reflected XSS testing with bypass techniques.
            
            REQUEST: {{REQUEST}}
            RESPONSE: {{RESPONSE}}
            REFLECTION: {{REFLECTION_ANALYSIS}}
            WAF: {{WAF_DETECTION}}
            RISK SCORE: {{RISK_SCORE}}/10
            
            Provide advanced XSS payloads including:
            1. Encoding variations (URL, HTML entity, Unicode)
            2. Obfuscation techniques
            3. WAF-specific bypasses
            4. Polyglot payloads
            5. Event handler variations
            6. Protocol smuggling
            
            Be creative and thorough. Include 10+ payload variations.
            """
        );
        template.addTag("xss");
        template.addTag("reflected");
        template.addTag("aggressive");
        template.addTag("waf-bypass");
        return template;
    }
    
    private PromptTemplate createXssStored() {
        PromptTemplate template = new PromptTemplate(
            "XSS - Stored",
            "Exploitation",
            "@vista",
            "Persistent XSS testing for stored input",
            "You are an expert in stored XSS vulnerabilities.",
            """
            Analyze for stored/persistent XSS vulnerabilities.
            
            REQUEST: {{REQUEST}}
            ENDPOINT TYPE: {{ENDPOINT_TYPE}}
            PARAMETERS: {{PARAMETERS_LIST}}
            
            Consider:
            1. Where is data stored? (Database, file, cache)
            2. Where is it displayed? (Profile, comments, admin panel)
            3. Who can trigger it? (Same user, other users, admins)
            4. What encoding is applied?
            5. Time delay between storage and display
            
            Provide payloads that:
            - Survive storage and retrieval
            - Work in display context
            - Consider character limits
            - Include verification methods
            """
        );
        template.addTag("xss");
        template.addTag("stored");
        template.addTag("persistent");
        return template;
    }
    
    private PromptTemplate createXssDomBased() {
        PromptTemplate template = new PromptTemplate(
            "XSS - DOM Based",
            "Exploitation",
            "@vista",
            "Client-side DOM XSS testing",
            "You are an expert in DOM-based XSS vulnerabilities.",
            """
            Analyze for DOM-based XSS vulnerabilities.
            
            REQUEST: {{REQUEST}}
            RESPONSE: {{RESPONSE}}
            
            Look for:
            1. JavaScript that processes URL parameters
            2. document.location, window.location usage
            3. innerHTML, outerHTML assignments
            4. eval(), setTimeout(), setInterval() with user input
            5. jQuery .html(), .append() with user data
            
            Provide:
            - DOM sinks to test
            - Payloads for each sink
            - Browser DevTools debugging steps
            - Verification methods
            """
        );
        template.addTag("xss");
        template.addTag("dom");
        template.addTag("client-side");
        return template;
    }
    
    private PromptTemplate createSqliErrorBased() {
        PromptTemplate template = new PromptTemplate(
            "SQLi - Error Based",
            "Exploitation",
            "@vista",
            "SQL injection testing with error messages",
            "You are an expert SQL injection penetration tester.",
            """
            USER'S QUESTION: {{USER_QUERY}}
            
            Test for error-based SQL injection.
            
            REQUEST: {{REQUEST}}
            RESPONSE: {{RESPONSE}}
            ERROR MESSAGES: {{ERROR_MESSAGES}}
            PARAMETERS: {{PARAMETERS_LIST}}
            
            Provide:
            1. SQL injection detection payloads (', ", --, #, etc.)
            2. Database fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle)
            3. Error-based extraction techniques
            4. Union-based queries
            5. Information schema queries
            
            Include specific payloads for detected database type.
            Address the user's specific question above.
            """
        );
        template.addTag("sqli");
        template.addTag("error-based");
        template.addTag("database");
        return template;
    }
    
    private PromptTemplate createSqliBlindBoolean() {
        PromptTemplate template = new PromptTemplate(
            "SQLi - Blind Boolean",
            "Exploitation",
            "@vista",
            "Boolean-based blind SQL injection",
            "You are an expert in blind SQL injection techniques.",
            """
            Test for boolean-based blind SQL injection.
            
            REQUEST: {{REQUEST}}
            RESPONSE SIZE: {{RESPONSE_SIZE}}
            PARAMETERS: {{PARAMETERS_LIST}}
            
            Provide:
            1. True/false condition payloads
            2. Response differentiation methods
            3. Character-by-character extraction technique
            4. Automated testing approach
            5. Time-saving optimization tips
            
            Focus on reliable boolean conditions that produce different responses.
            """
        );
        template.addTag("sqli");
        template.addTag("blind");
        template.addTag("boolean");
        return template;
    }
    
    private PromptTemplate createSqliTimeBased() {
        PromptTemplate template = new PromptTemplate(
            "SQLi - Time Based",
            "Exploitation",
            "@vista",
            "Time-based blind SQL injection",
            "You are an expert in time-based blind SQL injection.",
            """
            Test for time-based blind SQL injection.
            
            REQUEST: {{REQUEST}}
            PARAMETERS: {{PARAMETERS_LIST}}
            
            Provide:
            1. Time delay payloads (SLEEP, WAITFOR, pg_sleep)
            2. Database-specific timing functions
            3. Baseline response time measurement
            4. Reliable delay detection (5-10 seconds)
            5. Data extraction methodology
            
            Include payloads for MySQL, PostgreSQL, MSSQL, Oracle.
            """
        );
        template.addTag("sqli");
        template.addTag("blind");
        template.addTag("time-based");
        return template;
    }
    
    private PromptTemplate createSstiDetection() {
        PromptTemplate template = new PromptTemplate(
            "SSTI - Detection",
            "Exploitation",
            "@vista",
            "Server-side template injection detection",
            "You are an expert in SSTI vulnerabilities.",
            """
            Detect server-side template injection vulnerabilities.
            
            REQUEST: {{REQUEST}}
            RESPONSE: {{RESPONSE}}
            ENDPOINT TYPE: {{ENDPOINT_TYPE}}
            
            Test for template engines:
            1. Jinja2 (Python): {{7*7}}, {{config}}
            2. Twig (PHP): {{7*7}}, {{_self}}
            3. Freemarker (Java): ${7*7}, <#assign>
            4. Velocity (Java): #set($x=7*7)
            5. ERB (Ruby): <%= 7*7 %>
            
            Provide:
            - Detection payloads for each engine
            - Expected responses
            - Engine fingerprinting
            - Next steps after detection
            """
        );
        template.addTag("ssti");
        template.addTag("detection");
        template.addTag("template");
        return template;
    }
    
    private PromptTemplate createSstiExploitation() {
        PromptTemplate template = new PromptTemplate(
            "SSTI - Exploitation",
            "Exploitation",
            "@vista",
            "Server-side template injection exploitation",
            "You are an expert in SSTI exploitation and RCE.",
            """
            Exploit server-side template injection for RCE.
            
            REQUEST: {{REQUEST}}
            DETECTED ENGINE: (from previous testing)
            
            Provide exploitation payloads for:
            1. File read
            2. Command execution
            3. Reverse shell
            4. Environment variable access
            5. Configuration disclosure
            
            Include:
            - Step-by-step exploitation
            - Payload encoding if needed
            - Verification commands
            - Cleanup/stealth considerations
            """
        );
        template.addTag("ssti");
        template.addTag("exploitation");
        template.addTag("rce");
        return template;
    }
    
    private PromptTemplate createCommandInjection() {
        PromptTemplate template = new PromptTemplate(
            "Command Injection",
            "Exploitation",
            "@vista",
            "OS command injection testing",
            "You are an expert in command injection vulnerabilities.",
            """
            Test for OS command injection.
            
            REQUEST: {{REQUEST}}
            PARAMETERS: {{PARAMETERS_LIST}}
            ENDPOINT TYPE: {{ENDPOINT_TYPE}}
            
            Provide:
            1. Command injection payloads (; | & && ||)
            2. OS detection (Linux vs Windows)
            3. Blind vs direct injection techniques
            4. Out-of-band verification (DNS, HTTP)
            5. Data exfiltration methods
            
            Include both inline and chained command payloads.
            """
        );
        template.addTag("command-injection");
        template.addTag("rce");
        template.addTag("os");
        return template;
    }
    
    private PromptTemplate createSsrfBasic() {
        PromptTemplate template = new PromptTemplate(
            "SSRF - Basic",
            "Exploitation",
            "@vista",
            "Server-side request forgery testing",
            "You are an expert in SSRF vulnerabilities.",
            """
            Test for server-side request forgery.
            
            REQUEST: {{REQUEST}}
            PARAMETERS: {{PARAMETERS_LIST}}
            
            Test targets:
            1. Internal IPs (127.0.0.1, 192.168.x.x, 10.x.x.x)
            2. Localhost variations (localhost, 0.0.0.0, [::1])
            3. Internal services (ports 22, 80, 443, 3306, 6379, etc.)
            4. URL encoding bypasses
            5. Protocol smuggling (file://, gopher://, dict://)
            
            Provide payloads and expected responses for each target.
            """
        );
        template.addTag("ssrf");
        template.addTag("internal");
        return template;
    }
    
    private PromptTemplate createSsrfCloudMetadata() {
        PromptTemplate template = new PromptTemplate(
            "SSRF - Cloud Metadata",
            "Exploitation",
            "@vista",
            "SSRF targeting cloud metadata services",
            "You are an expert in cloud security and SSRF.",
            """
            Test SSRF for cloud metadata access.
            
            REQUEST: {{REQUEST}}
            
            Target cloud metadata endpoints:
            1. AWS: http://169.254.169.254/latest/meta-data/
            2. GCP: http://metadata.google.internal/computeMetadata/v1/
            3. Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
            4. DigitalOcean: http://169.254.169.254/metadata/v1/
            
            Provide:
            - Detection payloads
            - Credential extraction paths
            - Required headers (X-aws-ec2-metadata-token, Metadata: true)
            - Impact assessment
            """
        );
        template.addTag("ssrf");
        template.addTag("cloud");
        template.addTag("metadata");
        template.addTag("aws");
        return template;
    }
    
    private PromptTemplate createAuthBypass() {
        PromptTemplate template = new PromptTemplate(
            "Authentication Bypass",
            "Exploitation",
            "@vista",
            "Authentication and authorization bypass testing",
            "You are an expert in authentication bypass techniques.",
            """
            Test for authentication bypass vulnerabilities.
            
            REQUEST: {{REQUEST}}
            ENDPOINT TYPE: {{ENDPOINT_TYPE}}
            
            Test vectors:
            1. SQL injection in login (admin'-- , admin'#)
            2. Default credentials
            3. Password reset flaws
            4. Session fixation
            5. JWT manipulation
            6. OAuth misconfigurations
            7. HTTP method tampering
            8. Path traversal in auth checks
            
            Provide specific payloads and testing methodology.
            """
        );
        template.addTag("auth");
        template.addTag("bypass");
        template.addTag("authentication");
        return template;
    }
    
    private PromptTemplate createApiSecurity() {
        PromptTemplate template = new PromptTemplate(
            "API Security Audit",
            "Reconnaissance",
            "@vista",
            "Comprehensive API security testing",
            "You are an expert in API security testing.",
            """
            Perform comprehensive API security audit.
            
            REQUEST: {{REQUEST}}
            RESPONSE: {{RESPONSE}}
            ENDPOINT TYPE: {{ENDPOINT_TYPE}}
            
            Test for:
            1. Broken authentication (missing/weak tokens)
            2. Excessive data exposure
            3. Lack of rate limiting
            4. Mass assignment
            5. IDOR (insecure direct object references)
            6. Security misconfiguration
            7. Injection flaws
            8. Improper asset management
            
            Provide API-specific testing methodology.
            """
        );
        template.addTag("api");
        template.addTag("rest");
        template.addTag("security-audit");
        return template;
    }
    
    private PromptTemplate createWafBypassGeneric() {
        PromptTemplate template = new PromptTemplate(
            "WAF Bypass - Generic",
            "Bypass",
            "@vista",
            "Generic WAF bypass techniques",
            "You are an expert in WAF bypass techniques.",
            """
            Provide WAF bypass techniques for this request.
            
            REQUEST: {{REQUEST}}
            WAF DETECTED: {{WAF_DETECTION}}
            ORIGINAL PAYLOAD: (from previous testing)
            
            Bypass techniques:
            1. Encoding (URL, double URL, Unicode, hex)
            2. Case variation
            3. Comment injection
            4. Null byte injection
            5. Newline/CRLF injection
            6. Parameter pollution
            7. Content-Type manipulation
            8. Chunked encoding
            
            Provide 10+ bypass variations.
            """
        );
        template.addTag("waf");
        template.addTag("bypass");
        template.addTag("evasion");
        return template;
    }
    
    private PromptTemplate createWafBypassCloudflare() {
        PromptTemplate template = new PromptTemplate(
            "WAF Bypass - Cloudflare",
            "Bypass",
            "@vista",
            "Cloudflare-specific bypass techniques",
            "You are an expert in Cloudflare WAF bypass.",
            """
            Bypass Cloudflare WAF protection.
            
            REQUEST: {{REQUEST}}
            WAF: Cloudflare detected
            
            Cloudflare-specific bypasses:
            1. Origin IP discovery
            2. HTTP/2 smuggling
            3. Cache poisoning
            4. Rate limit bypass
            5. Encoding variations
            6. Header manipulation
            7. Protocol downgrade
            
            Provide specific payloads that work against Cloudflare.
            """
        );
        template.addTag("waf");
        template.addTag("bypass");
        template.addTag("cloudflare");
        return template;
    }
    
    private PromptTemplate createParameterDiscovery() {
        PromptTemplate template = new PromptTemplate(
            "Parameter Discovery",
            "Reconnaissance",
            "@vista",
            "Hidden parameter discovery",
            "You are an expert in parameter discovery and fuzzing.",
            """
            Discover hidden parameters in this endpoint.
            
            REQUEST: {{REQUEST}}
            KNOWN PARAMETERS: {{PARAMETERS_LIST}}
            
            Suggest:
            1. Common parameter names to test
            2. Parameter fuzzing wordlists
            3. HTTP method variations (GET, POST, PUT, DELETE)
            4. Content-Type variations
            5. Array/object parameter formats
            6. Nested parameter structures
            
            Focus on parameters that might reveal functionality or vulnerabilities.
            """
        );
        template.addTag("recon");
        template.addTag("parameters");
        template.addTag("discovery");
        return template;
    }
    
    private PromptTemplate createEndpointAnalysis() {
        PromptTemplate template = new PromptTemplate(
            "Endpoint Analysis",
            "Reconnaissance",
            "@vista",
            "Comprehensive endpoint analysis",
            "You are an expert security analyst.",
            """
            Analyze this endpoint comprehensively.
            
            REQUEST: {{REQUEST}}
            RESPONSE: {{RESPONSE}}
            DEEP ANALYSIS: {{DEEP_REQUEST_ANALYSIS}}
            RISK SCORE: {{RISK_SCORE}}/10
            
            Provide:
            1. Endpoint purpose and functionality
            2. Technology stack identification
            3. Security controls present
            4. Attack surface analysis
            5. Recommended testing priorities
            6. Potential vulnerabilities
            
            Be thorough and systematic.
            """
        );
        template.addTag("recon");
        template.addTag("analysis");
        return template;
    }
    
    private PromptTemplate createErrorAnalysis() {
        PromptTemplate template = new PromptTemplate(
            "Error Message Analysis",
            "Reconnaissance",
            "@vista",
            "Analyze error messages for information disclosure",
            "You are an expert in information disclosure vulnerabilities.",
            """
            Analyze error messages and responses.
            
            RESPONSE: {{RESPONSE}}
            ERROR MESSAGES: {{ERROR_MESSAGES}}
            SENSITIVE DATA: {{SENSITIVE_DATA}}
            
            Look for:
            1. Stack traces (language, framework, versions)
            2. Database errors (type, structure)
            3. File paths (OS, directory structure)
            4. Internal IPs and hostnames
            5. Debug information
            6. API keys or tokens
            
            Assess information disclosure risk and exploitation potential.
            """
        );
        template.addTag("recon");
        template.addTag("errors");
        template.addTag("information-disclosure");
        return template;
    }
    
    private PromptTemplate createQuickVulnScan() {
        PromptTemplate template = new PromptTemplate(
            "Quick Vulnerability Scan",
            "General",
            "@vista",
            "Fast general vulnerability assessment",
            "You are an expert penetration tester performing quick assessments.",
            """
            USER'S QUESTION: {{USER_QUERY}}
            
            Perform a quick vulnerability scan of this endpoint.
            
            REQUEST: {{REQUEST}}
            RESPONSE: {{RESPONSE}}
            RISK SCORE: {{RISK_SCORE}}/10
            PREDICTED VULNS: {{PREDICTED_VULNS}}
            
            Quickly assess for:
            1. XSS (reflected, stored, DOM)
            2. SQL injection
            3. Command injection
            4. SSRF
            5. Authentication issues
            6. Information disclosure
            
            Provide top 3 most likely vulnerabilities with quick test payloads.
            Be concise and actionable.
            Address the user's specific question above.
            """
        );
        template.addTag("quick");
        template.addTag("scan");
        template.addTag("general");
        return template;
    }
}
