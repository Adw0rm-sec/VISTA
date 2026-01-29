package com.vista.security.core;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Processes prompt templates and replaces variables with actual values.
 * Supports {{VARIABLE}} syntax.
 */
public class VariableProcessor {
    
    private static final Pattern VARIABLE_PATTERN = Pattern.compile("\\{\\{([A-Z_0-9]+)\\}\\}");
    
    /**
     * Process template and replace all variables with values from context.
     */
    public static String process(String template, VariableContext context) {
        if (template == null || template.isEmpty()) {
            return "";
        }
        
        if (context == null) {
            return template; // Return as-is if no context
        }
        
        String result = template;
        Matcher matcher = VARIABLE_PATTERN.matcher(template);
        
        while (matcher.find()) {
            String varName = matcher.group(1);
            String value = context.getVariable(varName);
            
            // Replace the variable with its value
            result = result.replace("{{" + varName + "}}", value);
        }
        
        return result;
    }
    
    /**
     * Extract all variable names from a template.
     */
    public static List<String> extractVariables(String template) {
        List<String> variables = new ArrayList<>();
        
        if (template == null || template.isEmpty()) {
            return variables;
        }
        
        Matcher matcher = VARIABLE_PATTERN.matcher(template);
        while (matcher.find()) {
            String varName = matcher.group(1);
            if (!variables.contains(varName)) {
                variables.add(varName);
            }
        }
        
        return variables;
    }
    
    /**
     * Validate that all variables in template are supported.
     */
    public static List<String> validateVariables(String template) {
        List<String> unsupported = new ArrayList<>();
        List<String> variables = extractVariables(template);
        
        for (String var : variables) {
            if (!isSupportedVariable(var)) {
                unsupported.add(var);
            }
        }
        
        return unsupported;
    }
    
    /**
     * Check if a variable name is supported.
     */
    public static boolean isSupportedVariable(String varName) {
        return getSupportedVariables().contains(varName);
    }
    
    /**
     * Get list of all supported variables.
     */
    public static List<String> getSupportedVariables() {
        return List.of(
            // Request variables
            "REQUEST", "REQUEST_METHOD", "REQUEST_URL", "REQUEST_PATH",
            "REQUEST_HEADERS", "REQUEST_PARAMETERS", "REQUEST_BODY", "REQUEST_COOKIES",
            
            // Response variables
            "RESPONSE", "RESPONSE_STATUS", "RESPONSE_HEADERS", "RESPONSE_BODY", "RESPONSE_SIZE",
            
            // Analysis variables
            "REFLECTION_ANALYSIS", "DEEP_REQUEST_ANALYSIS", "DEEP_RESPONSE_ANALYSIS",
            "WAF_DETECTION", "RISK_SCORE", "PREDICTED_VULNS", "ENDPOINT_TYPE",
            "PARAMETERS_LIST", "ERROR_MESSAGES", "SENSITIVE_DATA",
            
            // Context variables
            "TESTING_HISTORY", "CONVERSATION_CONTEXT", "ATTACHED_REQUESTS_COUNT"
        );
    }
    
    /**
     * Get variable descriptions for documentation.
     */
    public static String getVariableDescription(String varName) {
        return switch (varName) {
            case "REQUEST" -> "Full HTTP request";
            case "REQUEST_METHOD" -> "HTTP method (GET, POST, etc.)";
            case "REQUEST_URL" -> "Full URL";
            case "REQUEST_PATH" -> "URL path only";
            case "REQUEST_HEADERS" -> "All request headers";
            case "REQUEST_PARAMETERS" -> "All parameters with values";
            case "REQUEST_BODY" -> "Request body content";
            case "REQUEST_COOKIES" -> "All cookies";
            
            case "RESPONSE" -> "Full HTTP response";
            case "RESPONSE_STATUS" -> "HTTP status code";
            case "RESPONSE_HEADERS" -> "All response headers";
            case "RESPONSE_BODY" -> "Response body content";
            case "RESPONSE_SIZE" -> "Response size in bytes";
            
            case "REFLECTION_ANALYSIS" -> "Reflection analysis results";
            case "DEEP_REQUEST_ANALYSIS" -> "Deep request analysis";
            case "DEEP_RESPONSE_ANALYSIS" -> "Deep response analysis";
            case "WAF_DETECTION" -> "WAF detection and bypass suggestions";
            case "RISK_SCORE" -> "Risk score (0-10)";
            case "PREDICTED_VULNS" -> "Predicted vulnerabilities";
            case "ENDPOINT_TYPE" -> "Endpoint type (Login, API, etc.)";
            case "PARAMETERS_LIST" -> "Comma-separated parameter names";
            case "ERROR_MESSAGES" -> "Detected error messages";
            case "SENSITIVE_DATA" -> "Detected sensitive data";
            
            case "TESTING_HISTORY" -> "Previous testing steps";
            case "CONVERSATION_CONTEXT" -> "Chat conversation history";
            case "ATTACHED_REQUESTS_COUNT" -> "Number of attached requests";
            
            default -> "Unknown variable";
        };
    }
    
    /**
     * Get variable category for grouping in UI.
     */
    public static String getVariableCategory(String varName) {
        if (varName.startsWith("REQUEST")) return "Request";
        if (varName.startsWith("RESPONSE")) return "Response";
        if (varName.contains("ANALYSIS") || varName.contains("DETECTION") || 
            varName.contains("SCORE") || varName.contains("VULNS") || 
            varName.contains("ENDPOINT") || varName.contains("PARAMETERS") ||
            varName.contains("ERROR") || varName.contains("SENSITIVE")) {
            return "Analysis";
        }
        if (varName.contains("HISTORY") || varName.contains("CONVERSATION") || varName.contains("ATTACHED")) {
            return "Context";
        }
        return "Other";
    }
}
