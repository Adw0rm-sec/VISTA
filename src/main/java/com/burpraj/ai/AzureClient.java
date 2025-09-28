package com.burpraj.ai;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

public class AzureClient {
    public static class Config {
        public String endpoint;
        public String deployment;
        public String apiVersion;
        public String apiKey;
        public boolean isComplete() {
            return notBlank(endpoint) && notBlank(deployment) && notBlank(apiVersion) && notBlank(apiKey);
        }
    }

    private static final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build();

    public static String ask(Config cfg, String systemPrompt, String userPrompt) throws Exception {
        String base = trimSlash(cfg.endpoint);
        String url = base + "/openai/deployments/" + urlEncode(cfg.deployment)
                + "/chat/completions?api-version=" + urlEncode(cfg.apiVersion);

                String body = """
                {
                    "messages": [
                        {"role":"system","content":%s},
                        {"role":"user","content":%s}
                    ]
                }
                """.trim().formatted(jsonString(systemPrompt), jsonString(userPrompt));

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(60))
                .header("api-key", cfg.apiKey)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> rsp = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        return parseContentOrError(rsp);
    }

    public static String test(Config cfg) throws Exception {
        String base = trimSlash(cfg.endpoint);
        String url = base + "/openai/deployments/" + urlEncode(cfg.deployment)
                + "/chat/completions?api-version=" + urlEncode(cfg.apiVersion);
                String body = """
                {
                    "messages": [
                        {"role":"system","content":"You are a short responder."},
                        {"role":"user","content":"Say 'ok'"}
                    ]
                }
                """;
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .header("api-key", cfg.apiKey)
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

    private static String parseContentOrError(HttpResponse<String> rsp) {
        if (rsp.statusCode() >= 300) {
            String code = extractErrorCode(rsp.body());
            String msg = extractErrorMessage(rsp.body());
            String detail = (code != null ? code + ": " : "") + (msg != null ? msg : trim(rsp.body(), 800));
            return "Azure API error: HTTP " + rsp.statusCode() + " — " + detail;
        }
        String content = extractChoiceContent(rsp.body());
        if (content == null || content.isBlank()) {
            return "Received response but couldn't parse content:\n" + trim(rsp.body(), 1000);
        }
        return content;
    }

    private static String extractErrorCode(String json) {
        int i = json.indexOf("\"code\"");
        if (i < 0) return null;
        int colon = json.indexOf(':', i);
        if (colon < 0) return null;
        int q1 = json.indexOf('"', colon + 1);
        if (q1 < 0) return null;
        int q2 = json.indexOf('"', q1 + 1);
        if (q2 < 0) return null;
        return json.substring(q1 + 1, q2);
    }

    private static String extractErrorMessage(String json) {
        int i = json.indexOf("\"message\"");
        if (i < 0) return null;
        int colon = json.indexOf(':', i);
        if (colon < 0) return null;
        int q1 = json.indexOf('"', colon + 1);
        if (q1 < 0) return null;
        int q2 = json.indexOf('"', q1 + 1);
        if (q2 < 0) return null;
        return json.substring(q1 + 1, q2);
    }

    private static String extractChoiceContent(String json) {
        // Minimal parsing to find choices[0].message.content
        int i = json.indexOf("\"choices\"");
        if (i < 0) return null;
        int msgIdx = json.indexOf("\"message\"", i);
        if (msgIdx < 0) return null;
        int contentIdx = json.indexOf("\"content\"", msgIdx);
        if (contentIdx < 0) return null;
        int colon = json.indexOf(':', contentIdx);
        if (colon < 0) return null;
        // Value can be string with escapes. Find next quote and parse until matching quote.
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
    private static String urlEncode(String s) { return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8); }
    private static String trimSlash(String s) { return s != null && s.endsWith("/") ? s.substring(0, s.length()-1) : s; }

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

    private static String trim(String s, int max) {
        if (s == null) return null;
        if (s.length() <= max) return s;
        return s.substring(0, max) + "\n...[truncated]...";
    }
}
