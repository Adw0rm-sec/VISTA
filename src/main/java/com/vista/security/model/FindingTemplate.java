package com.vista.security.model;

/**
 * Template for generating vulnerability reports in different formats.
 * Supports HackerOne, Bugcrowd, Intigriti, and custom formats.
 */
public class FindingTemplate {
    
    private final String id;
    private final String name;
    private final String platform;
    private final String description;
    private final boolean isBuiltIn;
    
    // Template sections
    private final String titleFormat;
    private final String summaryFormat;
    private final String descriptionFormat;
    private final String stepsFormat;
    private final String impactFormat;
    private final String remediationFormat;
    private final String proofOfConceptFormat;
    
    // Options
    private final boolean includeScreenshots;
    private final boolean includeCurl;
    private final boolean includeRawRequest;
    private final boolean includeRawResponse;
    
    public FindingTemplate(String id, String name, String platform, String description,
                          String titleFormat, String summaryFormat, String descriptionFormat,
                          String stepsFormat, String impactFormat, String remediationFormat,
                          String proofOfConceptFormat, boolean includeScreenshots,
                          boolean includeCurl, boolean includeRawRequest, boolean includeRawResponse,
                          boolean isBuiltIn) {
        this.id = id;
        this.name = name;
        this.platform = platform;
        this.description = description;
        this.titleFormat = titleFormat;
        this.summaryFormat = summaryFormat;
        this.descriptionFormat = descriptionFormat;
        this.stepsFormat = stepsFormat;
        this.impactFormat = impactFormat;
        this.remediationFormat = remediationFormat;
        this.proofOfConceptFormat = proofOfConceptFormat;
        this.includeScreenshots = includeScreenshots;
        this.includeCurl = includeCurl;
        this.includeRawRequest = includeRawRequest;
        this.includeRawResponse = includeRawResponse;
        this.isBuiltIn = isBuiltIn;
    }
    
    // Getters
    public String getId() { return id; }
    public String getName() { return name; }
    public String getPlatform() { return platform; }
    public String getDescription() { return description; }
    public String getTitleFormat() { return titleFormat; }
    public String getSummaryFormat() { return summaryFormat; }
    public String getDescriptionFormat() { return descriptionFormat; }
    public String getStepsFormat() { return stepsFormat; }
    public String getImpactFormat() { return impactFormat; }
    public String getRemediationFormat() { return remediationFormat; }
    public String getProofOfConceptFormat() { return proofOfConceptFormat; }
    public boolean isIncludeScreenshots() { return includeScreenshots; }
    public boolean isIncludeCurl() { return includeCurl; }
    public boolean isIncludeRawRequest() { return includeRawRequest; }
    public boolean isIncludeRawResponse() { return includeRawResponse; }
    public boolean isBuiltIn() { return isBuiltIn; }
    
    @Override
    public String toString() {
        return name + " (" + platform + ")";
    }
    
    /**
     * Built-in template: HackerOne format
     */
    public static FindingTemplate hackerOneTemplate() {
        return new FindingTemplate(
            "hackerone",
            "HackerOne Report",
            "HackerOne",
            "Standard HackerOne vulnerability report format",
            "{{EXPLOIT_TYPE}} in {{PARAMETER}} parameter",
            "## Summary\n\n{{AI_DESCRIPTION}}",
            "## Description\n\n{{AI_DESCRIPTION}}\n\n" +
            "The application is vulnerable to {{EXPLOIT_TYPE}} through the `{{PARAMETER}}` parameter. " +
            "This vulnerability allows an attacker to {{AI_IMPACT}}.",
            "## Steps to Reproduce\n\n" +
            "1. Navigate to `{{HOST}}{{ENDPOINT}}`\n" +
            "2. Inject the following payload into the `{{PARAMETER}}` parameter:\n" +
            "   ```\n   {{PAYLOAD}}\n   ```\n" +
            "3. Observe that {{INDICATOR}}\n" +
            "4. The response confirms the vulnerability with status code {{STATUS_CODE}}",
            "## Impact\n\n{{AI_IMPACT}}\n\n" +
            "An attacker could exploit this vulnerability to:\n" +
            "- Execute arbitrary code\n" +
            "- Access sensitive data\n" +
            "- Compromise user accounts\n" +
            "- Perform unauthorized actions",
            "## Remediation\n\n{{AI_REMEDIATION}}\n\n" +
            "Recommended fixes:\n" +
            "1. Implement proper input validation\n" +
            "2. Use parameterized queries/prepared statements\n" +
            "3. Apply output encoding\n" +
            "4. Implement Content Security Policy (CSP)",
            "## Proof of Concept\n\n" +
            "**Request:**\n```http\n{{REQUEST}}\n```\n\n" +
            "**Response:**\n```http\n{{RESPONSE}}\n```\n\n" +
            "**cURL Command:**\n```bash\n{{CURL}}\n```",
            true, true, true, true, true
        );
    }
    
    /**
     * Built-in template: Bugcrowd format
     */
    public static FindingTemplate bugcrowdTemplate() {
        return new FindingTemplate(
            "bugcrowd",
            "Bugcrowd Report",
            "Bugcrowd",
            "Standard Bugcrowd vulnerability report format",
            "{{EXPLOIT_TYPE}} - {{HOST}}",
            "## Vulnerability Summary\n\n{{AI_DESCRIPTION}}",
            "## Vulnerability Details\n\n{{AI_DESCRIPTION}}\n\n" +
            "**Affected Parameter:** `{{PARAMETER}}`\n" +
            "**Vulnerability Type:** {{EXPLOIT_TYPE}}\n" +
            "**Severity:** {{SEVERITY}}",
            "## Reproduction Steps\n\n" +
            "1. Access the target endpoint: `{{METHOD}} {{HOST}}{{ENDPOINT}}`\n" +
            "2. Submit the following payload in the `{{PARAMETER}}` parameter:\n" +
            "   ```\n   {{PAYLOAD}}\n   ```\n" +
            "3. Observe the response: {{INDICATOR}}\n" +
            "4. Verify the vulnerability is exploitable",
            "## Business Impact\n\n{{AI_IMPACT}}",
            "## Remediation Recommendations\n\n{{AI_REMEDIATION}}",
            "## Supporting Evidence\n\n" +
            "**HTTP Request:**\n```\n{{REQUEST}}\n```\n\n" +
            "**HTTP Response:**\n```\n{{RESPONSE}}\n```",
            true, true, true, true, true
        );
    }
    
    /**
     * Built-in template: Intigriti format
     */
    public static FindingTemplate intigritiTemplate() {
        return new FindingTemplate(
            "intigriti",
            "Intigriti Report",
            "Intigriti",
            "Standard Intigriti vulnerability report format",
            "{{EXPLOIT_TYPE}} vulnerability in {{PARAMETER}}",
            "## Executive Summary\n\n{{AI_DESCRIPTION}}",
            "## Technical Details\n\n{{AI_DESCRIPTION}}\n\n" +
            "- **Endpoint:** {{METHOD}} {{ENDPOINT}}\n" +
            "- **Parameter:** {{PARAMETER}}\n" +
            "- **Attack Vector:** {{EXPLOIT_TYPE}}\n" +
            "- **Payload:** `{{PAYLOAD}}`",
            "## Proof of Concept\n\n" +
            "### Step 1: Access the vulnerable endpoint\n" +
            "Navigate to: `{{HOST}}{{ENDPOINT}}`\n\n" +
            "### Step 2: Inject the payload\n" +
            "Insert the following into the `{{PARAMETER}}` parameter:\n" +
            "```\n{{PAYLOAD}}\n```\n\n" +
            "### Step 3: Verify exploitation\n" +
            "Observe: {{INDICATOR}}",
            "## Security Impact\n\n{{AI_IMPACT}}",
            "## Recommended Fix\n\n{{AI_REMEDIATION}}",
            "## Evidence\n\n" +
            "**Request:**\n```http\n{{REQUEST}}\n```\n\n" +
            "**Response:**\n```http\n{{RESPONSE}}\n```\n\n" +
            "**cURL:**\n```bash\n{{CURL}}\n```",
            true, true, true, true, true
        );
    }
    
    /**
     * Built-in template: Simple Markdown format
     */
    public static FindingTemplate simpleMarkdownTemplate() {
        return new FindingTemplate(
            "simple-markdown",
            "Simple Markdown",
            "Generic",
            "Clean, simple markdown format for any platform",
            "# {{EXPLOIT_TYPE}} Vulnerability",
            "{{AI_DESCRIPTION}}",
            "## Description\n\n{{AI_DESCRIPTION}}",
            "## How to Reproduce\n\n" +
            "1. Go to `{{HOST}}{{ENDPOINT}}`\n" +
            "2. Use payload: `{{PAYLOAD}}`\n" +
            "3. Result: {{INDICATOR}}",
            "## Impact\n\n{{AI_IMPACT}}",
            "## Fix\n\n{{AI_REMEDIATION}}",
            "## Proof\n\n```\n{{REQUEST}}\n```",
            false, false, true, false, true
        );
    }
}
