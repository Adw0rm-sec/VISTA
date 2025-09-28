package com.burpraj.ai;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

public class OpenAIClient {
    public static class Config {
        public String baseUrl = "https://api.openai.com/v1"; // allow override if needed
        public String model; // e.g., gpt-4o-mini
        public String apiKey; // sk-...
        public boolean isComplete() {
            return notBlank(model) && notBlank(apiKey);
        }
    }

    private static final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build();

    public static String test(Config cfg) throws Exception {
        String url = trimSlash(cfg.baseUrl) + "/chat/completions";
        String body = """
                {
                    "model": %s,
                    "messages": [
                        {"role":"system","content":"You are a short responder."},
                        {"role":"user","content":"Say 'ok'"}
                    ]
                }
                """.trim().formatted(jsonString(cfg.model));
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", "Bearer " + cfg.apiKey)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> rsp = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (rsp.statusCode() >= 300) {
            return "HTTP " + rsp.statusCode() + ": " + trim(rsp.body(), 400);
        }
        String content = extractChoiceContent(rsp.body());
        return content != null ? "Success: " + trim(content, 120) : "Success (no content parsed)";
    }

    public static String ask(Config cfg, String systemPrompt, String userPrompt) throws Exception {
        String url = trimSlash(cfg.baseUrl) + "/chat/completions";
        String body = """
                {
                    "model": %s,
                    "messages": [
                        {"role":"system","content":%s},
                        {"role":"user","content":%s}
                    ]
                }
                """.trim().formatted(jsonString(cfg.model), jsonString(systemPrompt), jsonString(userPrompt));
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(60))
                .header("Authorization", "Bearer " + cfg.apiKey)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> rsp = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        return parseContentOrError(rsp);
    }

    private static String parseContentOrError(HttpResponse<String> rsp) {
        if (rsp.statusCode() >= 300) {
            return "OpenAI API error: HTTP " + rsp.statusCode() + " — " + trim(rsp.body(), 800);
        }
        String content = extractChoiceContent(rsp.body());
        if (content == null || content.isBlank()) {
            return "Received response but couldn't parse content:\n" + trim(rsp.body(), 1000);
        }
        return content;
    }

    private static String extractChoiceContent(String json) {
        int i = json.indexOf("\"choices\"");
        if (i < 0) return null;
        int msgIdx = json.indexOf("\"message\"", i);
        if (msgIdx < 0) return null;
        int contentIdx = json.indexOf("\"content\"", msgIdx);
        if (contentIdx < 0) return null;
        int colon = json.indexOf(':', contentIdx);
        if (colon < 0) return null;
        int firstQuote = json.indexOf('"', colon + 1);
        if (firstQuote < 0) return null;
        StringBuilder sb = new StringBuilder();
        boolean escape = false;
        for (int k = firstQuote + 1; k < json.length(); k++) {
            char c = json.charAt(k);
            if (escape) {
                switch (c) {
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    default: sb.append(c); break;
                }
                escape = false;
            } else if (c == '\\') {
                escape = true;
            } else if (c == '"') {
                break;
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static boolean notBlank(String s) { return s != null && !s.isBlank(); }
    private static String trimSlash(String s) { return s != null && s.endsWith("/") ? s.substring(0, s.length()-1) : s; }
    private static String trim(String s, int max) {
        if (s == null) return null;
        if (s.length() <= max) return s;
        return s.substring(0, max) + "\n...[truncated]...";
    }
    private static String jsonString(String s) {
        if (s == null) s = "";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int)c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }
}
