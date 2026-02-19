package com.vista.security.core;

import com.vista.security.model.PromptTemplate;
import com.vista.security.model.TemplateMode;

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
     * Get templates by mode.
     */
    public List<PromptTemplate> getTemplatesByMode(com.vista.security.model.TemplateMode mode) {
        return templates.stream()
            .filter(t -> t.getMode() == mode)
            .collect(Collectors.toList());
    }
    
    /**
     * Get template by name and mode.
     */
    public PromptTemplate getTemplate(String name, com.vista.security.model.TemplateMode mode) {
        return templates.stream()
            .filter(t -> t.getName().equalsIgnoreCase(name) && t.getMode() == mode)
            .findFirst()
            .orElse(null);
    }
    
    /**
     * Get all modes available.
     */
    public List<com.vista.security.model.TemplateMode> getAvailableModes() {
        return templates.stream()
            .map(PromptTemplate::getMode)
            .distinct()
            .sorted()
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
     * Process template with variable substitution and return separate prompts.
     */
    public String[] processTemplateWithSeparatePrompts(PromptTemplate template, VariableContext context) {
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
        
        return new String[]{systemPrompt, userPrompt};
    }
    
    /**
     * Process template with variable substitution.
     */
    public String processTemplate(PromptTemplate template, VariableContext context) {
        String[] prompts = processTemplateWithSeparatePrompts(template, context);
        return prompts[0] + "\n\n" + prompts[1];
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
        // NOTE: Do NOT call cleanupAllOldTemplates() - it destroys user custom templates!
        
        // Keep only the optimized DOM XSS template (already good)
        PromptTemplate xssDom = createXssDomBased();
        markAsBuiltIn(xssDom);
        templates.add(xssDom);
        
        // Keep Traffic Monitor template (useful for bug bounty)
        PromptTemplate trafficBugBounty = createTrafficBugBountyAnalysis();
        markAsBuiltIn(trafficBugBounty);
        templates.add(trafficBugBounty);
        
        // Expert Mode Templates - Comprehensive with PortSwigger/OWASP/Bug Bounty knowledge
        PromptTemplate sqliExpert = createSqliExpert();
        markAsBuiltIn(sqliExpert);
        templates.add(sqliExpert);
        
        PromptTemplate xssExpert = createXssReflectedExpert();
        markAsBuiltIn(xssExpert);
        templates.add(xssExpert);
    }
    
    /**
     * Mark a template as built-in (uses reflection to set the private field).
     */
    private void markAsBuiltIn(PromptTemplate template) {
        try {
            java.lang.reflect.Field field = PromptTemplate.class.getDeclaredField("isBuiltIn");
            field.setAccessible(true);
            field.set(template, true);
        } catch (Exception e) {
            System.err.println("Failed to mark template as built-in: " + e.getMessage());
        }
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
            """
            Expert XSS pentester. Analyze reflection context (HTML body/attribute/JS/event), detect encoding/WAF, generate context-specific payloads. Prioritize: 1) Identify reflection points 2) Determine context 3) Craft working payloads 4) Provide bypass techniques. Output: Ready-to-use payloads with testing steps and expected results. Focus on practical exploitation over theory.
            """,
            """
            {{USER_QUERY}}
            
            REQUEST: {{REQUEST}}
            RESPONSE: {{RESPONSE}}
            REFLECTION: {{REFLECTION_ANALYSIS}}
            WAF: {{WAF_DETECTION}}
            
            Provide: 1) Reflection analysis 2) Context-specific payloads 3) Testing steps 4) Expected results 5) WAF bypasses if needed.
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
            "Expert DOM XSS source-to-sink analysis with hash/URL parameter focus",
            """
            Expert DOM XSS analyst. Trace attacker-controlled data from SOURCES to dangerous SINKS. Report ONLY exploitable TRUE POSITIVES.
            
            CRITICAL RAW DATA ANALYSIS REQUIREMENTS:
            ⚠️ ALWAYS analyze the RAW HTTP response including ALL JavaScript code
            ⚠️ EXPLICITLY document how data flows from source to sink and what encoding/sanitization is applied
            ⚠️ NEVER assume sanitization—ALWAYS confirm by examining the actual code
            ⚠️ If ANY ambiguity exists, ask clarifying questions before confirming vulnerability
            ⚠️ PAY SPECIAL ATTENTION to location.hash and URL fragment usage
            
            SOURCES (ATTACKER-CONTROLLED):
            - location.hash (URL fragment after #) ⚠️ HIGH PRIORITY
            - location.search (URL query string)
            - location.href (full URL)
            - document.URL, document.documentURI
            - document.cookie, document.referrer
            - window.name
            - postMessage data
            - localStorage, sessionStorage
            
            DANGEROUS SINKS:
            - innerHTML, outerHTML (HTML injection)
            - document.write(), document.writeln() (HTML injection)
            - eval(), Function(), setTimeout(string), setInterval(string) (JS execution)
            - element.onevent (onclick, onerror, onload, etc.)
            - $(selector).html(), $(selector).append() (jQuery HTML injection)
            - location.href = user_input (open redirect/javascript: protocol)
            - element.setAttribute('onclick', user_input)
            - element.src = user_input (for script/iframe tags)
            
            COMMON VULNERABLE PATTERNS:
            1. location.hash → innerHTML/html()
               Example: $('#content').html(location.hash.substr(1))
            
            2. location.hash → string concatenation → innerHTML
               Example: html = "<img src='" + location.hash.substr(1) + "'>"
               Payload: #' onerror=alert(1) '
            
            3. location.search → document.write()
               Example: document.write("<div>" + getParam('name') + "</div>")
            
            4. URL parameter → eval/setTimeout
               Example: eval("var x = '" + getParam('callback') + "'")
            
            5. unescape/decodeURIComponent → innerHTML
               Example: div.innerHTML = unescape(location.hash)
            
            PAYLOADS by context:
            - innerHTML: <img src=x onerror=alert(1)>
            - String in HTML attribute: ' onerror=alert(1) '
            - document.write: <script>alert(1)</script>
            - eval: alert(1)
            - location: javascript:alert(1)
            - jQuery html(): <img src=x onerror=alert(1)>
            
            REJECT if:
            - DOMPurify/textContent used
            - No source-to-sink path exists
            - Validation blocks XSS (e.g., regex filtering dangerous chars)
            - Framework auto-escaping active (React, Angular with proper usage)
            - Source data is not attacker-controlled
            
            OUTPUT: VULNERABILITY: DOM XSS | SEVERITY: [H/M] | SOURCE: [type+location] | FLOW: [source→sink with code snippets] | SINK: [type+location] | POC: [payload+URL] | IMPACT: [real impact]
            """,
            """
            Analyze for DOM XSS. Find TRUE POSITIVES where attacker data flows source→sink without sanitization.
            
            RAW REQUEST: {{REQUEST}}
            RAW RESPONSE (including all JavaScript): {{RESPONSE}}
            
            STEPS:
            1. Examine RAW JavaScript code - Find sources:
               - location.hash (CHECK FIRST - very common)
               - location.search, location.href
               - document.URL, document.cookie
               - window.name, postMessage
               - localStorage, sessionStorage
            
            2. Find sinks:
               - innerHTML, outerHTML
               - document.write(), document.writeln()
               - eval(), Function(), setTimeout(string)
               - element.onevent (onclick, onerror, onload)
               - $(selector).html(), .append()
               - location.href assignment
            
            3. Trace flow: source→variables→functions→sink
               - Show ACTUAL code snippets for each step
               - Example: location.hash.substr(1) → num variable → string concatenation → innerHTML
            
            4. Check sanitization:
               - DOMPurify? textContent? validation?
               - Examine the ACTUAL implementation
               - Look for: replace(), match(), test(), sanitize()
            
            5. Document encoding:
               - Is data URL-decoded? HTML-encoded? Escaped?
               - Check: unescape(), decodeURIComponent(), escape sequences
               - Check the ACTUAL transformations
            
            6. Generate payload:
               - Match sink context (innerHTML vs eval vs attribute)
               - For HTML context: <img src=x onerror=alert(1)>
               - For attribute context: ' onerror=alert(1) '
               - For eval context: alert(1)
            
            7. Verify:
               - Provide exact URL with payload
               - Show expected result
               - Explain why it works
            
            REQUIREMENTS:
            ✓ Working PoC with exact payload and URL
            ✓ Complete source→sink trace with actual code snippets
            ✓ Real impact (cookie theft, account takeover, defacement)
            ✗ NO theoretical vulns
            ✗ NO if sanitization exists
            ✗ NO if flow broken
            
            ⚠️ CRITICAL: Before confirming vulnerability, explicitly state:
            - Exact source and sink with line numbers/code snippets
            - Any encoding/sanitization observed in the data flow
            - If unclear, ask for more JavaScript code or clarification
            
            EXAMPLE ANALYSIS:
            
            VULNERABLE CODE:
            ```javascript
            function chooseTab(num) {
                var html = "<img src='/static/cloud" + num + ".jpg' />";
                $('#content').html(html);
            }
            window.onload = function() {
                chooseTab(unescape(self.location.hash.substr(1)) || "1");
            }
            ```
            
            ANALYSIS:
            - SOURCE: location.hash (attacker-controlled via URL fragment)
            - FLOW: location.hash.substr(1) → unescape() → num parameter → string concatenation → jQuery .html()
            - SINK: $('#content').html(html) - injects HTML without sanitization
            - VULNERABILITY: String concatenation allows breaking out of src attribute
            - PAYLOAD: #1' onerror="alert('XSS')" 
            - RESULT: <img src='/static/cloud1' onerror="alert('XSS')" .jpg' />
            - IMPACT: XSS executes when image fails to load
            
            Be concise. Focus on exploitable findings only. Always trace location.hash usage!
            """
        );
        template.addTag("xss");
        template.addTag("dom");
        template.addTag("client-side");
        template.addTag("javascript");
        template.addTag("location-hash");
        return template;
    }
    
    private PromptTemplate createSqliErrorBased() {
        PromptTemplate template = new PromptTemplate(
            "SQLi - Error Based",
            "Exploitation",
            "@vista",
            "SQL injection testing with error messages",
            """
            Expert SQLi pentester. Fingerprint database (MySQL/PostgreSQL/MSSQL/Oracle/SQLite) from errors, craft injection payloads, extract data via error-based/UNION techniques. Key steps: 1) Test injection points (', ", --, #) 2) Identify DB type 3) Use DB-specific functions (extractvalue/CAST/CONVERT) 4) Build UNION queries 5) Query information_schema. Output: Working payloads with column counts, extraction queries, and bypass techniques.
            """,
            """
            {{USER_QUERY}}
            
            REQUEST: {{REQUEST}}
            RESPONSE: {{RESPONSE}}
            ERRORS: {{ERROR_MESSAGES}}
            PARAMS: {{PARAMETERS_LIST}}
            
            Provide: 1) Injection test payloads 2) DB fingerprinting 3) Error-based extraction 4) UNION queries 5) Info schema queries 6) Testing steps.
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
            """
            Expert SSTI pentester. Test template engines (Jinja2/Twig/Freemarker/Velocity/ERB/Smarty/Thymeleaf) using math expressions ({{7*7}}, ${7*7}, <%= 7*7 %>), config access, and engine-specific syntax. Steps: 1) Test basic expressions 2) Identify engine from response 3) Confirm with engine-specific payloads 4) Provide RCE path. Output: Detection payloads, expected responses, engine fingerprinting, and exploitation roadmap.
            """,
            """
            {{USER_QUERY}}
            
            REQUEST: {{REQUEST}}
            RESPONSE: {{RESPONSE}}
            ENDPOINT: {{ENDPOINT_TYPE}}
            
            Provide: 1) Detection payloads per engine 2) Expected responses 3) Engine fingerprinting 4) Next exploitation steps.
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
            """
            Expert command injection pentester. Test OS commands (Linux/Windows) using separators (; | & && || ` $() backticks), detect blind vs direct injection, use time delays (sleep/timeout) for confirmation, leverage OOB channels (DNS/HTTP callbacks). Steps: 1) Test injection points 2) Identify OS 3) Confirm with delays 4) Extract data 5) Escalate to shell. Output: Working payloads, OS-specific commands, blind detection techniques, and exfiltration methods.
            """,
            """
            {{USER_QUERY}}
            
            REQUEST: {{REQUEST}}
            PARAMS: {{PARAMETERS_LIST}}
            ENDPOINT: {{ENDPOINT_TYPE}}
            
            Provide: 1) Injection payloads 2) OS detection 3) Blind/direct techniques 4) OOB verification 5) Exfiltration methods.
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
            """
            Expert WAF bypass specialist. Analyze blocked payloads, identify detection patterns, generate 10-15 evasion variants using: encoding (URL/double-URL/Unicode/hex/HTML entities), case manipulation, comment injection (/**/, --, #), whitespace tricks, null bytes, parameter pollution, chunked encoding, parser differentials. Prioritize: 1) Identify what triggered block 2) Apply targeted bypasses 3) Combine techniques 4) Test incrementally. Output: Working bypass payloads with explanations and testing order.
            """,
            """
            {{USER_QUERY}}
            
            REQUEST: {{REQUEST}}
            WAF: {{WAF_DETECTION}}
            BLOCKED PAYLOAD: (from previous attempt)
            
            Provide: 1) Block analysis 2) 10-15 bypass variants 3) Technique explanations 4) Testing steps 5) Expected WAF behavior.
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
            """
            Expert pentester doing rapid assessment. Scan for: XSS (reflected/stored/DOM), SQLi, command injection, SSRF, auth bypass, info disclosure, IDOR, XXE, deserialization. Prioritize by: 1) Attack surface 2) Input reflection 3) Error messages 4) Sensitive data exposure. Output: Top 3 likely vulns with quick test payloads, severity, and exploitation steps. Be concise and actionable.
            """,
            """
            {{USER_QUERY}}
            
            REQUEST: {{REQUEST}}
            RESPONSE: {{RESPONSE}}
            RISK: {{RISK_SCORE}}/10
            PREDICTED: {{PREDICTED_VULNS}}
            
            Provide: Top 3 vulnerabilities with test payloads, severity, and steps.
            """
        );
        template.addTag("quick");
        template.addTag("scan");
        template.addTag("general");
        return template;
    }
    
    private PromptTemplate createTrafficBugBountyAnalysis() {
        PromptTemplate template = new PromptTemplate(
            "Traffic - Bug Bounty Hunter",
            "Traffic Monitor",
            "@vista",
            "Enhanced bug bounty analysis with detailed descriptions and remediation",
            "Elite bug bounty hunter. Provide detailed, actionable findings with impact and remediation.",
            """
            Analyze HTTP response for security issues.
            
            URL: {{URL}} | Method: {{METHOD}} | Status: {{STATUS}} | Type: {{CONTENT_TYPE}}
            
            CONTENT:
            {{CONTENT}}
            
            FIND (with actual values): API keys, passwords, private IPs, hidden fields, JWT tokens, encoded data, endpoints, sensitive data, injection points.
            
            OUTPUT FORMAT (each finding MUST include ALL fields):
            - Type: [API_KEY|PASSWORD|PRIVATE_IP|HIDDEN_FIELD|JWT_TOKEN|BASE64_SECRET|ENDPOINT|SENSITIVE_DATA|DEBUG_INFO|etc]
            - Severity: [CRITICAL|HIGH|MEDIUM|LOW]
            - Parameter: [exact parameter/field/variable name where found]
            - Evidence: [actual code snippet or value, max 100 chars]
            - Description: [1-2 sentences explaining what was found and why it matters]
            - Impact: [1-2 sentences on what attacker can do with this finding]
            - Remediation: [1-2 sentences on how to fix it properly]
            
            EXAMPLE OUTPUT:
            - Type: API_KEY
            - Severity: CRITICAL
            - Parameter: stripeApiKey
            - Evidence: const stripeApiKey = "sk_live_abc123..."
            - Description: Stripe live API key hardcoded in JavaScript file accessible to all users
            - Impact: Attackers can extract this key and make unauthorized API calls to access payment data, create fraudulent charges, and potentially steal customer information
            - Remediation: Move API key to server-side environment variable. Implement backend proxy for Stripe API calls. Rotate the exposed key immediately and monitor for unauthorized usage
            
            - Type: PRIVATE_IP
            - Severity: MEDIUM
            - Parameter: internalServerIP
            - Evidence: var server = "http://192.168.1.50:8080"
            - Description: Internal network IP address exposed in client-side code revealing infrastructure topology
            - Impact: Attackers gain knowledge of internal network structure which can be used for targeted attacks, network mapping, and identifying potential pivot points for lateral movement
            - Remediation: Use relative URLs or public domain names instead of internal IPs. Implement proper network segmentation and ensure internal addresses are not exposed in client-facing code
            
            SKIP: Variable names without values, function parameters, example URLs, empty fields, placeholders, comments without sensitive data.
            
            If no findings: "No high-confidence security issues found."
            
            Be specific and actionable. Focus on real security impact and practical fixes. ALWAYS include Parameter, Impact, and Remediation fields.
            """
        );
        template.addTag("traffic");
        template.addTag("bug-bounty");
        template.addTag("enhanced");
        return template;
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // EXPERT MODE TEMPLATES
    // Comprehensive templates with PortSwigger/OWASP/Bug Bounty knowledge
    // ═══════════════════════════════════════════════════════════════════════
    
    private PromptTemplate createSqliExpert() {
        PromptTemplate template = new PromptTemplate(
            "SQL Injection (Expert)",
            "Exploitation",
            "@vista",
            "Comprehensive SQLi testing with PortSwigger knowledge, bypass techniques, and troubleshooting help",
            
            // SYSTEM PROMPT (~400 tokens)
            """
            You are an ELITE SQL injection expert with comprehensive knowledge from PortSwigger Academy, OWASP, and real-world bug bounty programs (HackerOne, Bugcrowd, Synack).
            
            CRITICAL RAW DATA ANALYSIS REQUIREMENTS:
            ⚠️ ALWAYS analyze the RAW HTTP request and response including ALL headers and bodies
            ⚠️ EXPLICITLY document how each user-supplied character is reflected and encoded in the response
            ⚠️ NEVER assume encoding or context—ALWAYS confirm with raw data
            ⚠️ If ANY ambiguity exists, ask clarifying questions before providing exploitation advice
            ⚠️ Check for: URL encoding (%27), HTML encoding (&quot;), Unicode encoding (\\u0027), double encoding, base64, hex encoding
            ⚠️ Verify exact byte-level representation of special characters: ' " \\ ; -- # /* */ etc.
            
            CORE EXPERTISE:
            - Database systems (MySQL/MariaDB, PostgreSQL, MSSQL, Oracle, SQLite, NoSQL)
            - Injection techniques (error-based, UNION, boolean blind, time-based, out-of-band, second-order, stacked queries)
            - Injection contexts (WHERE, ORDER BY, LIMIT, INSERT, UPDATE, JSON)
            - WAF bypass (encoding, comments, case variation, whitespace, parameter pollution, inline comments, charset tricks)
            
            SYSTEMATIC METHODOLOGY:
            1. Analyze RAW request/response - identify ALL encoding layers
            2. Identify injection point (parameter, header, cookie)
            3. Test basic payloads: ', ", --, #, ;, `
            4. Document exact encoding applied to each character
            5. Analyze error messages for DB fingerprinting
            6. Determine injection context (WHERE/ORDER/LIMIT)
            7. Choose optimal technique (error > UNION > blind)
            8. Extract data efficiently (minimize requests)
            9. Bypass WAF if detected
            10. Verify exploitation (extract real data)
            
            WHEN USER GETS STUCK:
            - If payloads blocked: Analyze WAF behavior, try encoding variations, use comment injection, test parameter pollution, search internet for latest bypasses
            - If no errors: Switch to blind techniques, test boolean conditions, use time delays, try out-of-band channels
            - If extraction fails: Verify column count (ORDER BY), match data types (NULL, 1, 'a'), check character limits, try alternative extraction methods
            
            OUTPUT REQUIREMENTS:
            ✓ Document exact encoding observed in raw data
            ✓ Working payloads (not just theory)
            ✓ Step-by-step testing instructions
            ✓ Expected responses for verification
            ✓ Bypass techniques if WAF detected
            ✓ References to PortSwigger labs
            ✓ Real-world impact assessment
            ✗ Avoid verbose explanations (be concise)
            ✗ Don't suggest 20+ payloads (prioritize top 5)
            
            PORTSWIGGER REFERENCES: SQL injection UNION attacks, Blind SQL injection, SQL injection in different contexts, Database-specific factors
            
            REAL-WORLD: This technique found $500-$10K SQLi bounties on HackerOne. Common in login forms (85% success rate).
            """,
            
            // USER PROMPT (~100 tokens)
            """
            Analyze this RAW HTTP request/response for SQL injection vulnerabilities.
            
            RAW REQUEST: {{REQUEST}}
            RAW RESPONSE: {{RESPONSE}}
            ERRORS: {{ERROR_MESSAGES}}
            PARAMS: {{PARAMETERS_LIST}}
            WAF: {{WAF_DETECTION}}
            RISK SCORE: {{RISK_SCORE}}/10
            
            USER QUESTION: {{USER_QUERY}}
            
            PROVIDE:
            1. RAW DATA ANALYSIS - Examine raw bytes. What encoding is applied? URL/HTML/Unicode/Base64? Document EXACT character transformations.
            2. INJECTION ANALYSIS - Which parameters injectable? Injection context? Database type?
            3. TESTING PAYLOADS (Top 5, prioritized) - Account for observed encoding. Payload 1-5 with explanations.
            4. EXPECTED RESULTS - What response indicates success? How to verify?
            5. BYPASS TECHNIQUES (if WAF detected) - Encoding chains, comments, alternative syntax
            6. NEXT STEPS - If works: extract data. If blocked: what to try next?
            
            ⚠️ CRITICAL: Before suggesting payloads, explicitly state what encoding you observed in the raw response. If unclear, ask for clarification.
            
            If stuck or payloads blocked, help troubleshoot. Search internet for latest bypass techniques. Reference PortSwigger labs when relevant.
            """,
            
            TemplateMode.EXPERT
        );
        
        template.addTag("sqli");
        template.addTag("expert");
        template.addTag("comprehensive");
        template.addTag("bug-bounty");
        template.addTag("portswigger");
        return template;
    }
    
    private PromptTemplate createXssReflectedExpert() {
        PromptTemplate template = new PromptTemplate(
            "XSS - Reflected (Expert)",
            "Exploitation",
            "@vista",
            "Comprehensive XSS testing with context-aware payloads, WAF bypass, and troubleshooting help",
            
            // SYSTEM PROMPT (~400 tokens)
            """
            You are an ELITE XSS expert with comprehensive knowledge from PortSwigger Academy, OWASP, and real-world bug bounty programs.
            
            CRITICAL RAW DATA ANALYSIS REQUIREMENTS:
            ⚠️ ALWAYS analyze the RAW HTTP request and response including ALL headers and bodies
            ⚠️ EXPLICITLY document how each user-supplied character is reflected and encoded in the response
            ⚠️ NEVER assume encoding or context—ALWAYS confirm with raw data
            ⚠️ If ANY ambiguity exists, ask clarifying questions before providing exploitation advice
            ⚠️ Check for: HTML encoding (&lt; &gt; &quot; &#39;), URL encoding (%3C %3E), JavaScript encoding (\\x3c \\u003c), Unicode normalization
            ⚠️ Verify exact reflection: Is < reflected as &lt; or &#60; or \\x3c? Is " reflected as &quot; or &#34; or \\"?
            ⚠️ Document reflection context: HTML body? Attribute? JavaScript string? Event handler? CSS?
            
            CORE EXPERTISE:
            - Context detection (HTML body/attribute/JavaScript/event/URL/CSS)
            - Encoding bypass (HTML entities, URL, Unicode, hex, octal, base64)
            - WAF evasion (Cloudflare, ModSecurity, AWS WAF, Akamai)
            - Browser-specific payloads (Chrome, Firefox, Safari, Edge)
            - CSP bypass techniques
            - Filter evasion (blacklist bypass, case manipulation, encoding chains)
            
            REFLECTION CONTEXTS & PAYLOADS:
            1. HTML Body: <img src=x onerror=alert(1)>
            2. HTML Attribute: " onload=alert(1) "
            3. JavaScript String: '-alert(1)-'
            4. JavaScript Variable: </script><script>alert(1)</script>
            5. Event Handler: javascript:alert(1)
            6. URL Parameter: javascript:alert(1)
            7. CSS Context: </style><script>alert(1)</script>
            
            WAF BYPASS TECHNIQUES:
            - Encoding: %3Cscript%3E, &#60;script&#62;, \\u003cscript\\u003e
            - Case variation: <ScRiPt>, <sCrIpT>
            - Comment injection: <scr<!---->ipt>, <scr/**/ipt>
            - Event handlers: <svg onload=alert(1)>, <body onload=alert(1)>
            - Protocol handlers: javascript:, data:, vbscript:
            
            SYSTEMATIC METHODOLOGY:
            1. Analyze RAW response - identify ALL encoding layers
            2. Identify reflection points (where input appears)
            3. Determine reflection context (HTML/JS/attribute)
            4. Document exact encoding applied to each character
            5. Test basic payload: <script>alert(1)</script>
            6. If blocked, analyze what triggered filter
            7. Apply context-specific bypass accounting for encoding
            8. Verify execution in browser
            9. Craft final exploit payload
            
            WHEN USER GETS STUCK:
            - If script tags blocked: Try event handlers
            - If < > blocked: Try encoding or existing tags
            - If quotes blocked: Try backticks or hex encoding
            - If parentheses blocked: Try template literals
            - If alert blocked: Try prompt, confirm, or eval
            - Search internet for latest bypass techniques
            
            OUTPUT REQUIREMENTS:
            ✓ Document exact encoding observed in raw data
            ✓ Context-specific payloads (not generic)
            ✓ Working exploits (test in browser)
            ✓ Bypass techniques for detected WAF
            ✓ Expected results (what should happen)
            ✓ PortSwigger lab references
            ✓ Real-world impact assessment
            
            PORTSWIGGER REFERENCES: Reflected XSS into HTML context, XSS in different contexts, DOM-based XSS, Exploiting XSS to steal cookies
            
            REAL-WORLD: $100-$5K bounties on HackerOne. Context-aware payloads have 70%+ success rate.
            """,
            
            // USER PROMPT (~100 tokens)
            """
            Analyze this RAW HTTP request/response for reflected XSS vulnerabilities.
            
            RAW REQUEST: {{REQUEST}}
            RAW RESPONSE: {{RESPONSE}}
            REFLECTION: {{REFLECTION_ANALYSIS}}
            WAF: {{WAF_DETECTION}}
            RISK SCORE: {{RISK_SCORE}}/10
            
            USER QUESTION: {{USER_QUERY}}
            
            PROVIDE:
            1. RAW DATA ANALYSIS - Examine raw bytes. What encoding is applied? HTML entities (&lt;)? URL encoding (%3C)? JavaScript escaping (\\x3c)? Document EXACT character transformations.
            2. REFLECTION ANALYSIS - Where does input appear? What's the context (HTML/JS/attribute/event)? Is encoding applied?
            3. TESTING PAYLOADS (Top 5, prioritized) - Context-specific payloads accounting for observed encoding
            4. EXPECTED RESULTS - What indicates success? How to verify in browser?
            5. BYPASS TECHNIQUES (if WAF detected) - Encoding variations, event handler alternatives, encoding chains
            6. NEXT STEPS - If works: escalate. If blocked: what to try next?
            
            ⚠️ CRITICAL: Before suggesting payloads, explicitly state:
            - Exact reflection context (e.g., "reflected inside <div> tag in HTML body")
            - Exact encoding observed (e.g., "< becomes &lt; and > becomes &gt;")
            - If unclear, ask for clarification or request more raw data
            
            If stuck or payloads blocked, help troubleshoot. Search internet for latest bypasses. Reference PortSwigger labs.
            """,
            
            TemplateMode.EXPERT
        );
        
        template.addTag("xss");
        template.addTag("reflected");
        template.addTag("expert");
        template.addTag("comprehensive");
        template.addTag("bug-bounty");
        template.addTag("portswigger");
        return template;
    }
}
