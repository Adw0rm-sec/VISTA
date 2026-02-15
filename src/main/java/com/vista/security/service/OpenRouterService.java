package com.vista.security.service;

import com.vista.security.core.AIRequestLogger;
import com.vista.security.model.ChatMessage;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

/**
 * OpenRouter API service implementation.
 * Provides access to 500+ AI models through OpenRouter's unified gateway.
 * OpenAI-compatible API with additional routing capabilities.
 */
public class OpenRouterService implements AIService {
    
    private static final String BASE_URL = "https://openrouter.ai/api/v1";
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(15);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(60);
    
    private static final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(CONNECT_TIMEOUT)
            .build();
    
    private final Configuration config;
    
    public OpenRouterService(Configuration config) {
        this.config = config;
    }
    
    /**
     * OpenRouter-specific configuration.
     */
    public static class Configuration extends AIService.Configuration {
        private String model = "meta-llama/llama-3.1-8b-instruct:free";
        
        public String getModel() { return model; }
        public void setModel(String model) { this.model = model; }
        
        @Override
        public boolean isValid() {
            return model != null && !model.isBlank() 
                && apiKey != null && !apiKey.isBlank();
        }
    }
    
    @Override
    public String testConnection() throws Exception {
        String url = BASE_URL + "/chat/completions";
        String body = buildRequestBody("You are a short responder.", "Say 'ok'", 0.1);
        
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", "Bearer " + config.getApiKey())
                .header("Content-Type", "application/json")
                .header("HTTP-Referer", "https://github.com/Adw0rm-sec/VISTA")
                .header("X-Title", "VISTA Security Testing")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        
        HttpResponse<String> response = httpClient.send(request, 
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        
        if (response.statusCode() >= 300) {
            return "HTTP " + response.statusCode() + ": " + truncate(response.body(), 400);
        }
        
        String content = extractContent(response.body());
        return content != null ? "Success: " + truncate(content, 120) : "Success (no content parsed)";
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
        // Log the request
        AIRequestLogger.logRequest("OpenRouter", config.getModel(), systemPrompt, userPrompt, 
                                   templateName, httpRequest, httpResponse);
        
        long startTime = System.currentTimeMillis();
        
        try {
            String url = BASE_URL + "/chat/completions";
            String body = buildRequestBody(systemPrompt, userPrompt, config.getTemperature());
            
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(REQUEST_TIMEOUT)
                    .header("Authorization", "Bearer " + config.getApiKey())
                    .header("Content-Type", "application/json")
                    .header("HTTP-Referer", "https://github.com/Adw0rm-sec/VISTA")
                    .header("X-Title", "VISTA Security Testing")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            
            HttpResponse<String> response = httpClient.send(request, 
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            
            String result = parseResponse(response);
            long duration = System.currentTimeMillis() - startTime;
            
            // Log the response
            AIRequestLogger.logResponse("OpenRouter", result, duration);
            
            return result;
        } catch (Exception e) {
            AIRequestLogger.logError("OpenRouter", "ask", e);
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
        // Log the request with history
        AIRequestLogger.logRequestWithHistory("OpenRouter", config.getModel(), messages, 
                                             templateName, httpRequest, httpResponse);
        
        long startTime = System.currentTimeMillis();
        
        try {
            String url = BASE_URL + "/chat/completions";
            String body = buildRequestBodyWithHistory(messages, config.getTemperature());
            
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(REQUEST_TIMEOUT)
                    .header("Authorization", "Bearer " + config.getApiKey())
                    .header("Content-Type", "application/json")
                    .header("HTTP-Referer", "https://github.com/Adw0rm-sec/VISTA")
                    .header("X-Title", "VISTA Security Testing")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            
            HttpResponse<String> response = httpClient.send(request, 
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            
            String result = parseResponse(response);
            long duration = System.currentTimeMillis() - startTime;
            
            // Log the response
            AIRequestLogger.logResponse("OpenRouter", result, duration);
            
            return result;
        } catch (Exception e) {
            AIRequestLogger.logError("OpenRouter", "askWithHistory", e);
            throw e;
        }
    }

    private String buildRequestBody(String systemPrompt, String userPrompt, double temperature) {
        return """
                {
                    "model": %s,
                    "temperature": %.2f,
                    "messages": [
                        {"role":"system","content":%s},
                        {"role":"user","content":%s}
                    ]
                }
                """.formatted(
                    toJsonString(config.getModel()), 
                    temperature,
                    toJsonString(systemPrompt), 
                    toJsonString(userPrompt)
                );
    }
    
    private String buildRequestBodyWithHistory(List<ChatMessage> messages, double temperature) {
        StringBuilder messagesJson = new StringBuilder();
        messagesJson.append("[\n");
        
        for (int i = 0; i < messages.size(); i++) {
            ChatMessage msg = messages.get(i);
            String role = switch (msg.getRole()) {
                case SYSTEM -> "system";
                case USER -> "user";
                case ASSISTANT -> "assistant";
            };
            
            messagesJson.append("        {\"role\":\"").append(role).append("\",\"content\":")
                       .append(toJsonString(msg.getContent())).append("}");
            
            if (i < messages.size() - 1) {
                messagesJson.append(",");
            }
            messagesJson.append("\n");
        }
        
        messagesJson.append("    ]");
        
        return """
                {
                    "model": %s,
                    "temperature": %.2f,
                    "messages": %s
                }
                """.formatted(
                    toJsonString(config.getModel()), 
                    temperature,
                    messagesJson.toString()
                );
    }
    
    private String parseResponse(HttpResponse<String> response) {
        if (response.statusCode() >= 300) {
            return "OpenRouter API error: HTTP " + response.statusCode() + " — " + truncate(response.body(), 800);
        }
        
        String content = extractContent(response.body());
        if (content == null || content.isBlank()) {
            return "Received response but couldn't parse content:\n" + truncate(response.body(), 1000);
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
        
        int colonIdx = json.indexOf(':', contentIdx);
        if (colonIdx < 0) return null;
        
        int firstQuote = json.indexOf('"', colonIdx + 1);
        if (firstQuote < 0) return null;
        
        StringBuilder result = new StringBuilder();
        boolean escaped = false;
        
        for (int i = firstQuote + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (escaped) {
                switch (c) {
                    case 'n' -> result.append('\n');
                    case 'r' -> result.append('\r');
                    case 't' -> result.append('\t');
                    case '"' -> result.append('"');
                    case '\\' -> result.append('\\');
                    default -> result.append(c);
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
    
    private static String truncate(String s, int maxLength) {
        if (s == null) return null;
        return s.length() <= maxLength ? s : s.substring(0, maxLength) + "\n...[truncated]...";
    }
    
    private static String toJsonString(String value) {
        if (value == null) value = "";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
        return sb.toString();
    }
}
