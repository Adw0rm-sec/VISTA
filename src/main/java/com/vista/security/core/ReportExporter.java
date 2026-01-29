package com.vista.security.core;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import com.vista.security.model.ExploitFinding;
import com.vista.security.model.FindingTemplate;

import java.io.ByteArrayOutputStream;
import java.net.URL;
import java.util.Base64;
import java.util.List;

/**
 * Exports findings to various formats using templates.
 * Supports Markdown, HTML, and plain text.
 */
public class ReportExporter {
    
    private final IExtensionHelpers helpers;
    
    public ReportExporter(IExtensionHelpers helpers) {
        this.helpers = helpers;
    }
    
    /**
     * Export a single finding using a template.
     */
    public String exportFinding(ExploitFinding finding, FindingTemplate template,
                               String aiDescription, String aiImpact, String aiRemediation) {
        StringBuilder report = new StringBuilder();
        
        // Title
        report.append(processTemplate(template.getTitleFormat(), finding, 
            aiDescription, aiImpact, aiRemediation)).append("\n\n");
        
        // Summary (if different from description)
        if (!template.getSummaryFormat().equals(template.getDescriptionFormat())) {
            report.append(processTemplate(template.getSummaryFormat(), finding,
                aiDescription, aiImpact, aiRemediation)).append("\n\n");
        }
        
        // Description
        report.append(processTemplate(template.getDescriptionFormat(), finding,
            aiDescription, aiImpact, aiRemediation)).append("\n\n");
        
        // Steps to Reproduce
        report.append(processTemplate(template.getStepsFormat(), finding,
            aiDescription, aiImpact, aiRemediation)).append("\n\n");
        
        // Impact
        report.append(processTemplate(template.getImpactFormat(), finding,
            aiDescription, aiImpact, aiRemediation)).append("\n\n");
        
        // Remediation
        report.append(processTemplate(template.getRemediationFormat(), finding,
            aiDescription, aiImpact, aiRemediation)).append("\n\n");
        
        // Proof of Concept
        if (template.isIncludeRawRequest() || template.isIncludeCurl()) {
            report.append(processTemplate(template.getProofOfConceptFormat(), finding,
                aiDescription, aiImpact, aiRemediation)).append("\n\n");
        }
        
        // Metadata
        report.append("---\n\n");
        report.append("**Finding ID:** ").append(finding.getId()).append("\n");
        report.append("**Discovered:** ").append(finding.getFormattedTimestamp()).append("\n");
        report.append("**Severity:** ").append(finding.getSeverity()).append("\n");
        report.append("**Verified:** ").append(finding.isVerified() ? "Yes" : "No").append("\n");
        
        return report.toString();
    }
    
    /**
     * Export multiple findings with summary.
     */
    public String exportFindings(List<ExploitFinding> findings, FindingTemplate template,
                                String aiDescription, String aiImpact, String aiRemediation) {
        StringBuilder report = new StringBuilder();
        
        // Header
        report.append("# VISTA Security Assessment Report\n\n");
        report.append("**Generated:** ").append(java.time.LocalDateTime.now()).append("\n");
        report.append("**Platform:** ").append(template.getPlatform()).append("\n");
        report.append("**Total Findings:** ").append(findings.size()).append("\n\n");
        
        // Executive Summary
        report.append("## Executive Summary\n\n");
        report.append("This report contains ").append(findings.size())
              .append(" security vulnerabilities discovered during testing.\n\n");
        
        // Severity breakdown
        report.append("### Severity Breakdown\n\n");
        long critical = findings.stream().filter(f -> f.getSeverity().equalsIgnoreCase("Critical")).count();
        long high = findings.stream().filter(f -> f.getSeverity().equalsIgnoreCase("High")).count();
        long medium = findings.stream().filter(f -> f.getSeverity().equalsIgnoreCase("Medium")).count();
        long low = findings.stream().filter(f -> f.getSeverity().equalsIgnoreCase("Low")).count();
        
        report.append("- **Critical:** ").append(critical).append("\n");
        report.append("- **High:** ").append(high).append("\n");
        report.append("- **Medium:** ").append(medium).append("\n");
        report.append("- **Low:** ").append(low).append("\n\n");
        
        // Individual findings
        report.append("## Detailed Findings\n\n");
        
        int findingNumber = 1;
        for (ExploitFinding finding : findings) {
            report.append("---\n\n");
            report.append("### Finding #").append(findingNumber++).append("\n\n");
            report.append(exportFinding(finding, template, aiDescription, aiImpact, aiRemediation));
            report.append("\n\n");
        }
        
        return report.toString();
    }
    
    /**
     * Process template and replace variables.
     */
    private String processTemplate(String template, ExploitFinding finding,
                                  String aiDescription, String aiImpact, String aiRemediation) {
        String result = template;
        
        // Basic finding info
        result = result.replace("{{EXPLOIT_TYPE}}", finding.getExploitType());
        result = result.replace("{{HOST}}", finding.getHost());
        result = result.replace("{{ENDPOINT}}", finding.getEndpoint());
        result = result.replace("{{METHOD}}", finding.getMethod());
        result = result.replace("{{PARAMETER}}", finding.getParameter());
        result = result.replace("{{PAYLOAD}}", finding.getPayload());
        result = result.replace("{{INDICATOR}}", finding.getIndicator());
        result = result.replace("{{STATUS_CODE}}", String.valueOf(finding.getStatusCode()));
        result = result.replace("{{RESPONSE_LENGTH}}", String.valueOf(finding.getResponseLength()));
        result = result.replace("{{RESPONSE_TIME}}", String.valueOf(finding.getResponseTime()));
        result = result.replace("{{SEVERITY}}", finding.getSeverity());
        result = result.replace("{{TIMESTAMP}}", finding.getFormattedTimestamp());
        result = result.replace("{{ID}}", finding.getId());
        
        // AI-generated content
        result = result.replace("{{AI_DESCRIPTION}}", aiDescription != null ? aiDescription : "");
        result = result.replace("{{AI_IMPACT}}", aiImpact != null ? aiImpact : "");
        result = result.replace("{{AI_REMEDIATION}}", aiRemediation != null ? aiRemediation : "");
        
        // Request/Response
        if (finding.getRequest() != null) {
            String requestStr = new String(finding.getRequest(), java.nio.charset.StandardCharsets.UTF_8);
            result = result.replace("{{REQUEST}}", requestStr);
            result = result.replace("{{CURL}}", generateCurl(finding));
        } else {
            result = result.replace("{{REQUEST}}", "(No request data)");
            result = result.replace("{{CURL}}", "(No request data)");
        }
        
        if (finding.getResponse() != null) {
            String responseStr = new String(finding.getResponse(), java.nio.charset.StandardCharsets.UTF_8);
            // Truncate if too long
            if (responseStr.length() > 5000) {
                responseStr = responseStr.substring(0, 5000) + "\n\n... (truncated)";
            }
            result = result.replace("{{RESPONSE}}", responseStr);
        } else {
            result = result.replace("{{RESPONSE}}", "(No response data)");
        }
        
        return result;
    }
    
    /**
     * Generate cURL command from finding.
     */
    private String generateCurl(ExploitFinding finding) {
        if (finding.getRequest() == null) {
            return "(No request data)";
        }
        
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(finding.getRequest());
            List<String> headers = requestInfo.getHeaders();
            
            StringBuilder curl = new StringBuilder();
            curl.append("curl -X ").append(finding.getMethod());
            
            // URL
            curl.append(" '").append(finding.getHost()).append(finding.getEndpoint()).append("'");
            
            // Headers (skip first line which is the request line)
            for (int i = 1; i < headers.size(); i++) {
                String header = headers.get(i);
                if (!header.isEmpty()) {
                    curl.append(" \\\n  -H '").append(header).append("'");
                }
            }
            
            // Body (if POST/PUT)
            if (requestInfo.getBodyOffset() < finding.getRequest().length) {
                byte[] body = new byte[finding.getRequest().length - requestInfo.getBodyOffset()];
                System.arraycopy(finding.getRequest(), requestInfo.getBodyOffset(), 
                               body, 0, body.length);
                String bodyStr = new String(body, java.nio.charset.StandardCharsets.UTF_8);
                if (!bodyStr.isEmpty()) {
                    curl.append(" \\\n  -d '").append(bodyStr.replace("'", "\\'")).append("'");
                }
            }
            
            return curl.toString();
        } catch (Exception e) {
            return "(Error generating cURL: " + e.getMessage() + ")";
        }
    }
    
    /**
     * Export to HTML format.
     */
    public String exportToHtml(List<ExploitFinding> findings, FindingTemplate template,
                              String aiDescription, String aiImpact, String aiRemediation) {
        String markdown = exportFindings(findings, template, aiDescription, aiImpact, aiRemediation);
        
        // Simple markdown to HTML conversion
        String html = markdown
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replaceAll("### (.*)", "<h3>$1</h3>")
            .replaceAll("## (.*)", "<h2>$1</h2>")
            .replaceAll("# (.*)", "<h1>$1</h1>")
            .replaceAll("\\*\\*(.*?)\\*\\*", "<strong>$1</strong>")
            .replaceAll("\\*(.*?)\\*", "<em>$1</em>")
            .replaceAll("`(.*?)`", "<code>$1</code>")
            .replaceAll("```([\\s\\S]*?)```", "<pre><code>$1</code></pre>")
            .replace("\n\n", "</p><p>")
            .replace("\n", "<br>");
        
        return "<!DOCTYPE html>\n" +
               "<html>\n" +
               "<head>\n" +
               "  <meta charset=\"UTF-8\">\n" +
               "  <title>VISTA Security Report</title>\n" +
               "  <style>\n" +
               "    body { font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; padding: 20px; }\n" +
               "    h1 { color: #d32f2f; border-bottom: 3px solid #d32f2f; }\n" +
               "    h2 { color: #1976d2; border-bottom: 2px solid #1976d2; margin-top: 30px; }\n" +
               "    h3 { color: #388e3c; }\n" +
               "    pre { background: #f5f5f5; padding: 15px; border-left: 4px solid #1976d2; overflow-x: auto; }\n" +
               "    code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }\n" +
               "    strong { color: #d32f2f; }\n" +
               "  </style>\n" +
               "</head>\n" +
               "<body>\n" +
               "<p>" + html + "</p>\n" +
               "</body>\n" +
               "</html>";
    }
}
