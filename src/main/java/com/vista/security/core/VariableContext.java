package com.vista.security.core;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import com.vista.security.model.ChatSession;
import com.vista.security.ui.TestingSuggestionsPanel;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Context for variable substitution in prompt templates.
 * Holds all available data that can be used in templates.
 */
public class VariableContext {
    
    private final IExtensionHelpers helpers;
    private final IHttpRequestResponse request;
    private final RequestAnalysis deepRequestAnalysis;
    private final ResponseAnalysis deepResponseAnalysis;
    private final ReflectionAnalyzer.ReflectionAnalysis reflectionAnalysis;
    private final List<WAFDetector.WAFInfo> wafDetection;
    private final List<ChatSession.TestingStep> testingHistory;
    private final List<TestingSuggestionsPanel.ConversationMessage> conversationHistory;
    private final Map<String, String> customVariables;
    private String userQuery; // User's current question/prompt
    private int attachedRequestsCount = 0; // Count of attached requests in active session
    
    public VariableContext(IExtensionHelpers helpers,
                          IHttpRequestResponse request,
                          RequestAnalysis deepRequestAnalysis,
                          ResponseAnalysis deepResponseAnalysis,
                          ReflectionAnalyzer.ReflectionAnalysis reflectionAnalysis,
                          List<WAFDetector.WAFInfo> wafDetection,
                          List<ChatSession.TestingStep> testingHistory,
                          List<TestingSuggestionsPanel.ConversationMessage> conversationHistory) {
        this.helpers = helpers;
        this.request = request;
        this.deepRequestAnalysis = deepRequestAnalysis;
        this.deepResponseAnalysis = deepResponseAnalysis;
        this.reflectionAnalysis = reflectionAnalysis;
        this.wafDetection = wafDetection;
        this.testingHistory = testingHistory;
        this.conversationHistory = conversationHistory;
        this.customVariables = new HashMap<>();
        this.userQuery = "";
    }
    
    /**
     * Set the user's current query/question.
     */
    public void setUserQuery(String userQuery) {
        this.userQuery = userQuery != null ? userQuery : "";
    }
    
    /**
     * Set the count of attached requests from the active session.
     */
    public void setAttachedRequestsCount(int count) {
        this.attachedRequestsCount = count;
    }
    
    /**
     * Get variable value by name.
     */
    public String getVariable(String varName) {
        return switch (varName) {
            // User query
            case "USER_QUERY" -> userQuery;
            
            // Request variables
            case "REQUEST" -> getRequest();
            case "REQUEST_METHOD" -> getRequestMethod();
            case "REQUEST_URL" -> getRequestUrl();
            case "REQUEST_PATH" -> getRequestPath();
            case "REQUEST_HEADERS" -> getRequestHeaders();
            case "REQUEST_PARAMETERS" -> getRequestParameters();
            case "REQUEST_BODY" -> getRequestBody();
            case "REQUEST_COOKIES" -> getRequestCookies();
            
            // Response variables
            case "RESPONSE" -> getResponse();
            case "RESPONSE_STATUS" -> getResponseStatus();
            case "RESPONSE_HEADERS" -> getResponseHeaders();
            case "RESPONSE_BODY" -> getResponseBody();
            case "RESPONSE_SIZE" -> getResponseSize();
            
            // Analysis variables
            case "REFLECTION_ANALYSIS" -> getReflectionAnalysis();
            case "DEEP_REQUEST_ANALYSIS" -> getDeepRequestAnalysis();
            case "DEEP_RESPONSE_ANALYSIS" -> getDeepResponseAnalysis();
            case "WAF_DETECTION" -> getWafDetection();
            case "RISK_SCORE" -> getRiskScore();
            case "PREDICTED_VULNS" -> getPredictedVulns();
            case "ENDPOINT_TYPE" -> getEndpointType();
            case "PARAMETERS_LIST" -> getParametersList();
            case "ERROR_MESSAGES" -> getErrorMessages();
            case "SENSITIVE_DATA" -> getSensitiveData();
            
            // Context variables
            case "TESTING_HISTORY" -> getTestingHistory();
            case "CONVERSATION_CONTEXT" -> getConversationContext();
            case "ATTACHED_REQUESTS_COUNT" -> getAttachedRequestsCount();
            
            // Custom variables
            default -> customVariables.getOrDefault(varName, "");
        };
    }
    
    /**
     * Set custom variable.
     */
    public void setCustomVariable(String name, String value) {
        customVariables.put(name, value);
    }
    
    // Request variable getters
    private String getRequest() {
        if (request == null || request.getRequest() == null) return "(No request)";
        return new String(request.getRequest(), java.nio.charset.StandardCharsets.UTF_8);
    }
    
    private String getRequestMethod() {
        if (request == null || request.getRequest() == null) return "";
        String requestStr = new String(request.getRequest(), java.nio.charset.StandardCharsets.UTF_8);
        String[] lines = requestStr.split("\r?\n");
        if (lines.length > 0) {
            String[] parts = lines[0].split(" ");
            return parts.length > 0 ? parts[0] : "";
        }
        return "";
    }
    
    private String getRequestUrl() {
        if (request == null || request.getRequest() == null) return "";
        String requestStr = new String(request.getRequest(), java.nio.charset.StandardCharsets.UTF_8);
        String[] lines = requestStr.split("\r?\n");
        if (lines.length > 0) {
            String[] parts = lines[0].split(" ");
            if (parts.length > 1) {
                // Extract host from headers
                String host = "";
                for (String line : lines) {
                    if (line.toLowerCase().startsWith("host:")) {
                        host = line.substring(5).trim();
                        break;
                    }
                }
                return "https://" + host + parts[1];
            }
        }
        return "";
    }
    
    private String getRequestPath() {
        if (request == null || request.getRequest() == null) return "";
        String requestStr = new String(request.getRequest(), java.nio.charset.StandardCharsets.UTF_8);
        String[] lines = requestStr.split("\r?\n");
        if (lines.length > 0) {
            String[] parts = lines[0].split(" ");
            return parts.length > 1 ? parts[1] : "";
        }
        return "";
    }
    
    private String getRequestHeaders() {
        if (request == null || request.getRequest() == null) return "";
        IRequestInfo info = helpers.analyzeRequest(request.getRequest());
        StringBuilder headers = new StringBuilder();
        for (String header : info.getHeaders()) {
            headers.append(header).append("\n");
        }
        return headers.toString();
    }
    
    private String getRequestParameters() {
        if (request == null || request.getRequest() == null) return "";
        if (deepRequestAnalysis == null || deepRequestAnalysis.parameters == null) return "";
        StringBuilder params = new StringBuilder();
        for (DeepRequestAnalyzer.ParameterInfo param : deepRequestAnalysis.parameters) {
            params.append(param.name).append("=").append(param.value).append("\n");
        }
        return params.toString();
    }
    
    private String getRequestBody() {
        if (request == null || request.getRequest() == null) return "";
        IRequestInfo info = helpers.analyzeRequest(request.getRequest());
        int bodyOffset = info.getBodyOffset();
        if (bodyOffset >= request.getRequest().length) return "";
        byte[] body = new byte[request.getRequest().length - bodyOffset];
        System.arraycopy(request.getRequest(), bodyOffset, body, 0, body.length);
        return new String(body, java.nio.charset.StandardCharsets.UTF_8);
    }
    
    private String getRequestCookies() {
        if (request == null || request.getRequest() == null) return "";
        // Extract cookies from headers
        IRequestInfo info = helpers.analyzeRequest(request.getRequest());
        for (String header : info.getHeaders()) {
            if (header.toLowerCase().startsWith("cookie:")) {
                return header.substring(7).trim();
            }
        }
        return "";
    }
    
    // Response variable getters
    private String getResponse() {
        if (request == null || request.getResponse() == null) return "(No response)";
        return new String(request.getResponse(), java.nio.charset.StandardCharsets.UTF_8);
    }
    
    private String getResponseStatus() {
        if (request == null || request.getResponse() == null) return "";
        String responseStr = new String(request.getResponse(), java.nio.charset.StandardCharsets.UTF_8);
        String[] lines = responseStr.split("\r?\n");
        if (lines.length > 0) {
            String[] parts = lines[0].split(" ");
            return parts.length > 1 ? parts[1] : "";
        }
        return "";
    }
    
    private String getResponseHeaders() {
        if (request == null || request.getResponse() == null) return "";
        IResponseInfo info = helpers.analyzeResponse(request.getResponse());
        StringBuilder headers = new StringBuilder();
        for (String header : info.getHeaders()) {
            headers.append(header).append("\n");
        }
        return headers.toString();
    }
    
    private String getResponseBody() {
        if (request == null || request.getResponse() == null) return "";
        IResponseInfo info = helpers.analyzeResponse(request.getResponse());
        int bodyOffset = info.getBodyOffset();
        if (bodyOffset >= request.getResponse().length) return "";
        byte[] body = new byte[request.getResponse().length - bodyOffset];
        System.arraycopy(request.getResponse(), bodyOffset, body, 0, body.length);
        return new String(body, java.nio.charset.StandardCharsets.UTF_8);
    }
    
    private String getResponseSize() {
        if (request == null || request.getResponse() == null) return "0";
        return String.valueOf(request.getResponse().length);
    }
    
    // Analysis variable getters
    private String getReflectionAnalysis() {
        if (reflectionAnalysis == null) return "(No reflection analysis)";
        return reflectionAnalysis.getSummary();
    }
    
    private String getDeepRequestAnalysis() {
        if (deepRequestAnalysis == null) return "(No deep request analysis)";
        return deepRequestAnalysis.toFormattedString();
    }
    
    private String getDeepResponseAnalysis() {
        if (deepResponseAnalysis == null) return "(No deep response analysis)";
        return deepResponseAnalysis.toFormattedString();
    }
    
    private String getWafDetection() {
        if (wafDetection == null || wafDetection.isEmpty()) return "No WAF detected";
        return WAFDetector.getBypassSuggestions(wafDetection);
    }
    
    private String getRiskScore() {
        if (deepRequestAnalysis == null) return "0";
        return String.valueOf(deepRequestAnalysis.riskScore);
    }
    
    private String getPredictedVulns() {
        if (deepRequestAnalysis == null || deepRequestAnalysis.predictedVulnerabilities == null) return "";
        return String.join(", ", deepRequestAnalysis.predictedVulnerabilities);
    }
    
    private String getEndpointType() {
        if (deepRequestAnalysis == null) return "";
        return deepRequestAnalysis.endpointType;
    }
    
    private String getParametersList() {
        if (deepRequestAnalysis == null || deepRequestAnalysis.parameters == null) return "";
        StringBuilder params = new StringBuilder();
        for (DeepRequestAnalyzer.ParameterInfo param : deepRequestAnalysis.parameters) {
            if (params.length() > 0) params.append(", ");
            params.append(param.name);
        }
        return params.toString();
    }
    
    private String getErrorMessages() {
        if (deepResponseAnalysis == null || deepResponseAnalysis.errorMessages == null) return "";
        return String.join(", ", deepResponseAnalysis.errorMessages);
    }
    
    private String getSensitiveData() {
        if (deepResponseAnalysis == null || deepResponseAnalysis.sensitiveData == null) return "";
        return String.join(", ", deepResponseAnalysis.sensitiveData);
    }
    
    // Context variable getters
    private String getTestingHistory() {
        if (testingHistory == null || testingHistory.isEmpty()) return "(No testing history)";
        StringBuilder history = new StringBuilder();
        for (int i = 0; i < testingHistory.size(); i++) {
            ChatSession.TestingStep step = testingHistory.get(i);
            history.append("Test ").append(i + 1).append(": ").append(step.observation).append("\n");
        }
        return history.toString();
    }
    
    private String getConversationContext() {
        if (conversationHistory == null || conversationHistory.isEmpty()) return "(No conversation)";
        StringBuilder conversation = new StringBuilder();
        for (TestingSuggestionsPanel.ConversationMessage msg : conversationHistory) {
            conversation.append(msg.role.toUpperCase()).append(": ").append(msg.content).append("\n");
        }
        return conversation.toString();
    }
    
    private String getAttachedRequestsCount() {
        return String.valueOf(attachedRequestsCount);
    }
}
