package com.vista.security.service;

import com.vista.security.core.AIRequestLogger;
import com.vista.security.model.ChatMessage;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

/**
 * Azure AI service — supports two endpoint flavours and two auth modes:
 *
 * Endpoint flavours (auto-detected from URL):
 *   • Azure AI Foundry  — *.services.ai.azure.com/openai/v1
 *       URL:  {endpoint}/chat/completions        (no deployment in path)
 *       Body: includes "model": "<deploymentName>"
 *
 *   • Classic Azure OpenAI — *.openai.azure.com
 *       URL:  {endpoint}/openai/deployments/{name}/chat/completions?api-version=X
 *       Body: no "model" field needed
 *
 * Auth modes (set via Configuration.authMode):
 *   • "api-key"         — api-key: <key>  header  (classic)
 *   • "azure-identity"  — Authorization: Bearer <token>  via DefaultAzureCredential chain
 *                         (env AZURE_TENANT_ID / CLIENT_ID / CLIENT_SECRET  OR  az CLI)
 */
public class AzureAIService implements AIService {

    // Auth mode constants
    public static final String AUTH_API_KEY        = "api-key";
    public static final String AUTH_AZURE_IDENTITY = "azure-identity";

    // Scope used when getting Bearer tokens for Azure AI Foundry
    private static final String FOUNDRY_SCOPE = "https://ai.azure.com/.default";
    // Scope used for classic Azure OpenAI with Entra auth
    private static final String OPENAI_SCOPE  = "https://cognitiveservices.azure.com/.default";

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(45);

    private static final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(CONNECT_TIMEOUT)
            .executor(java.util.concurrent.Executors.newFixedThreadPool(4, r -> {
                Thread t = new Thread(r, "VISTA-Azure-HTTP");
                t.setDaemon(true);
                return t;
            }))
            .build();

    private final Configuration config;

    public AzureAIService(Configuration config) {
        this.config = config;
    }

    // ═══════════════════════════════════════════════════════════════
    // Configuration
    // ═══════════════════════════════════════════════════════════════

    public static class Configuration extends AIService.Configuration {
        private String endpoint;
        private String deploymentName;
        private String apiVersion = "2025-01-01-preview";
        private String authMode   = AUTH_API_KEY;

        public String getEndpoint()        { return endpoint; }
        public void   setEndpoint(String v){ this.endpoint = v; }

        public String getDeploymentName()         { return deploymentName; }
        public void   setDeploymentName(String v) { this.deploymentName = v; }

        public String getApiVersion()        { return apiVersion; }
        public void   setApiVersion(String v){ this.apiVersion = (v != null && !v.isBlank()) ? v : "2025-01-01-preview"; }

        public String getAuthMode()        { return authMode; }
        public void   setAuthMode(String v){ this.authMode = (v != null && !v.isBlank()) ? v : AUTH_API_KEY; }

        @Override
        public boolean isValid() {
            if (endpoint == null || endpoint.isBlank())        return false;
            if (deploymentName == null || deploymentName.isBlank()) return false;
            if (AUTH_AZURE_IDENTITY.equalsIgnoreCase(authMode)) return true; // no API key needed
            return apiKey != null && !apiKey.isBlank();
        }

        public String getValidationError() {
            if (endpoint == null || endpoint.isBlank())        return "Endpoint is required.";
            if (deploymentName == null || deploymentName.isBlank()) return "Deployment name is required.";
            if (!AUTH_AZURE_IDENTITY.equalsIgnoreCase(authMode) &&
                    (apiKey == null || apiKey.isBlank()))       return "API key is required.";
            return null;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Public API
    // ═══════════════════════════════════════════════════════════════

    @Override
    public String testConnection() throws Exception {
        String url  = buildUrl();
        String body = buildRequestBody("You are a short responder.", "Say 'ok'", 0.1);
        HttpRequest req = buildHttpRequest(url, body, Duration.ofSeconds(20));
        HttpResponse<String> res = httpClient.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        String content = parseResponse(res);
        return "Success: " + truncate(content, 120);
    }

    @Override
    public String ask(String systemPrompt, String userPrompt) throws Exception {
        return ask(systemPrompt, userPrompt, null, null, null);
    }

    @Override
    public String ask(String systemPrompt, String userPrompt, String templateName) throws Exception {
        return ask(systemPrompt, userPrompt, templateName, null, null);
    }

    @Override
    public String ask(String systemPrompt, String userPrompt, String templateName,
                      String httpRequest, String httpResponse) throws Exception {
        AIRequestLogger.logRequest("Azure AI", config.getDeploymentName(), systemPrompt, userPrompt,
                                   templateName, httpRequest, httpResponse);
        long startTime = System.currentTimeMillis();
        try {
            String url  = buildUrl();
            String body = buildRequestBody(systemPrompt, userPrompt, config.getTemperature());
            HttpRequest req = buildHttpRequest(url, body, REQUEST_TIMEOUT);
            HttpResponse<String> res = httpClient.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            String result = parseResponse(res);
            AIRequestLogger.logResponse("Azure AI", result, System.currentTimeMillis() - startTime);
            return result;
        } catch (Exception e) {
            AIRequestLogger.logError("Azure AI", "ask", e);
            throw e;
        }
    }

    @Override
    public String askWithHistory(List<ChatMessage> messages) throws Exception {
        return askWithHistory(messages, null, null, null);
    }

    @Override
    public String askWithHistory(List<ChatMessage> messages, String templateName) throws Exception {
        return askWithHistory(messages, templateName, null, null);
    }

    @Override
    public String askWithHistory(List<ChatMessage> messages, String templateName,
                                 String httpRequest, String httpResponse) throws Exception {
        AIRequestLogger.logRequestWithHistory("Azure AI", config.getDeploymentName(), messages,
                                              templateName, httpRequest, httpResponse);
        long startTime = System.currentTimeMillis();
        try {
            String url  = buildUrl();
            String body = buildRequestBodyWithHistory(messages, config.getTemperature());
            HttpRequest req = buildHttpRequest(url, body, REQUEST_TIMEOUT);
            HttpResponse<String> res = httpClient.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            String result = parseResponse(res);
            AIRequestLogger.logResponse("Azure AI", result, System.currentTimeMillis() - startTime);
            return result;
        } catch (Exception e) {
            AIRequestLogger.logError("Azure AI", "askWithHistory", e);
            throw e;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // URL & Request building
    // ═══════════════════════════════════════════════════════════════

    /**
     * Detect whether this is an Azure AI Foundry endpoint.
     * Foundry endpoints look like: https://xxx.services.ai.azure.com/openai/v1
     */
    private boolean isFoundryEndpoint() {
        String ep = config.getEndpoint();
        if (ep == null) return false;
        String lower = ep.toLowerCase();
        // services.ai.azure.com is the Foundry host pattern
        return lower.contains("services.ai.azure.com");
    }

    /**
     * Build the chat completions URL.
     *
     * Foundry  →  {endpoint}/chat/completions
     * Classic  →  {endpoint}/openai/deployments/{name}/chat/completions?api-version=X
     */
    private String buildUrl() {
        String base = normalizeUrl(config.getEndpoint());
        if (isFoundryEndpoint()) {
            // endpoint already includes /openai/v1 (or similar); just append the path
            return base + "/chat/completions";
        }
        return base + "/openai/deployments/"
                + pathEncode(config.getDeploymentName())
                + "/chat/completions?api-version="
                + urlEncode(config.getApiVersion());
    }

    /**
     * Build the HTTP request with the correct auth header.
     *
     * API Key mode       → api-key: <key>
     * Azure Identity mode → Authorization: Bearer <token from DefaultAzureCredential chain>
     */
    private HttpRequest buildHttpRequest(String url, String body, Duration timeout) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(timeout)
                .header("Content-Type", "application/json");

        if (AUTH_AZURE_IDENTITY.equalsIgnoreCase(config.getAuthMode())) {
            String scope = isFoundryEndpoint() ? FOUNDRY_SCOPE : OPENAI_SCOPE;
            String token = AzureCredentialProvider.getInstance().getToken(scope);
            builder.header("Authorization", "Bearer " + token);
        } else {
            String key = config.getApiKey();
            if (key == null || key.isBlank()) {
                throw new IllegalStateException("Azure API key is not configured.");
            }
            builder.header("api-key", key.trim());
        }

        return builder.POST(HttpRequest.BodyPublishers.ofString(body)).build();
    }

    /**
     * Build request body.
     * Uses max_completion_tokens (replaces deprecated max_tokens, required by gpt-5.x / o-series).
     * Omits temperature for reasoning models (o1/o3/o4-series) that reject it.
     */
    private String buildRequestBody(String systemPrompt, String userPrompt, double temperature) {
        String tempField = isReasoningModel(config.getDeploymentName())
                ? "" : "\"temperature\": %.2f,\n    ".formatted(temperature);
        return """
                {
                    "model": %s,
                    %s"max_completion_tokens": %d,
                    "messages": [
                        {"role":"system","content":%s},
                        {"role":"user","content":%s}
                    ]
                }
                """.formatted(
                toJsonString(config.getDeploymentName()),
                tempField,
                config.getMaxTokens(),
                toJsonString(systemPrompt),
                toJsonString(userPrompt));
    }

    private String buildRequestBodyWithHistory(List<ChatMessage> messages, double temperature) {
        StringBuilder msgs = new StringBuilder("[\n");
        for (int i = 0; i < messages.size(); i++) {
            ChatMessage msg = messages.get(i);
            String role = switch (msg.getRole()) {
                case SYSTEM    -> "system";
                case USER      -> "user";
                case ASSISTANT -> "assistant";
            };
            msgs.append("        {\"role\":\"").append(role).append("\",\"content\":")
                .append(toJsonString(msg.getContent())).append("}");
            if (i < messages.size() - 1) msgs.append(",");
            msgs.append("\n");
        }
        msgs.append("    ]");

        String tempField = isReasoningModel(config.getDeploymentName())
                ? "" : "\"temperature\": %.2f,\n    ".formatted(temperature);
        return """
                {
                    "model": %s,
                    %s"max_completion_tokens": %d,
                    "messages": %s
                }
                """.formatted(
                toJsonString(config.getDeploymentName()),
                tempField,
                config.getMaxTokens(),
                msgs.toString());
    }

    /**
     * Reasoning models (o1, o3, o4-series) reject temperature and max_tokens.
     * They only accept max_completion_tokens and require temperature to be omitted.
     */
    private static boolean isReasoningModel(String modelName) {
        if (modelName == null) return false;
        String lower = modelName.toLowerCase();
        return lower.matches("o\\d+.*") // o1, o1-mini, o3, o3-mini, o4-mini …
            || lower.startsWith("o1")
            || lower.startsWith("o3")
            || lower.startsWith("o4");
    }

    // ═══════════════════════════════════════════════════════════════
    // Response parsing
    // ═══════════════════════════════════════════════════════════════

    private String parseResponse(HttpResponse<String> response) throws Exception {
        if (response.statusCode() >= 300) {
            String errorCode    = extractJsonField(response.body(), "code");
            String errorMessage = extractJsonField(response.body(), "message");
            String detail = (errorCode != null ? errorCode + ": " : "")
                          + (errorMessage != null ? errorMessage : truncate(response.body(), 800));
            throw new Exception("HTTP " + response.statusCode() + ": " + detail);
        }
        String content = extractContent(response.body());
        if (content == null || content.isBlank()) {
            throw new Exception("Empty response from Azure AI: " + truncate(response.body(), 400));
        }
        return content;
    }

    private String extractContent(String json) {
        int choicesIdx = json.indexOf("\"choices\"");
        if (choicesIdx < 0) return null;
        int messageIdx = json.indexOf("\"message\"", choicesIdx);
        if (messageIdx < 0) return null;
        int contentIdx = json.indexOf("\"content\"", messageIdx);
        if (contentIdx < 0) return null;
        int colonIdx   = json.indexOf(':', contentIdx);
        if (colonIdx  < 0) return null;
        int firstQuote = json.indexOf('"', colonIdx + 1);
        if (firstQuote < 0) return null;

        StringBuilder result  = new StringBuilder();
        boolean escaped = false;
        for (int i = firstQuote + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (escaped) {
                switch (c) {
                    case 'n'  -> result.append('\n');
                    case 'r'  -> result.append('\r');
                    case 't'  -> result.append('\t');
                    case '"'  -> result.append('"');
                    case '\\' -> result.append('\\');
                    default   -> result.append(c);
                }
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                break;
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    private String extractJsonField(String json, String fieldName) {
        int idx       = json.indexOf("\"" + fieldName + "\"");
        if (idx < 0)  return null;
        int colonIdx  = json.indexOf(':', idx);
        if (colonIdx < 0) return null;
        int quoteStart = json.indexOf('"', colonIdx + 1);
        if (quoteStart < 0) return null;
        int quoteEnd  = json.indexOf('"', quoteStart + 1);
        if (quoteEnd  < 0) return null;
        return json.substring(quoteStart + 1, quoteEnd);
    }

    // ═══════════════════════════════════════════════════════════════
    // Utility
    // ═══════════════════════════════════════════════════════════════

    private static String normalizeUrl(String url) {
        return (url != null && url.endsWith("/")) ? url.substring(0, url.length() - 1) : url;
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String pathEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String truncate(String s, int max) {
        if (s == null) return null;
        return s.length() <= max ? s : s.substring(0, max) + "\n...[truncated]...";
    }

    private static String toJsonString(String value) {
        if (value == null) value = "";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else          sb.append(c);
                }
            }
        }
        sb.append('"');
        return sb.toString();
    }
}
