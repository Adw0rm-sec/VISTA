package com.vista.security.service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Java equivalent of Python's DefaultAzureCredential.
 *
 * Credential chain (tried in order):
 *   1. Environment variables  — AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET
 *   2. Azure CLI              — `az account get-access-token --scope <scope>`
 *
 * Tokens are cached until 5 minutes before expiry.
 */
public class AzureCredentialProvider {

    private static final AzureCredentialProvider INSTANCE = new AzureCredentialProvider();

    // Per-scope token cache
    private final java.util.Map<String, CachedToken> cache = new java.util.concurrent.ConcurrentHashMap<>();
    private final ReentrantLock lock = new ReentrantLock();

    private AzureCredentialProvider() {}

    public static AzureCredentialProvider getInstance() {
        return INSTANCE;
    }

    /**
     * Returns a valid Bearer token for the given scope.
     * Tries env-var client credentials first, then Azure CLI.
     */
    public String getToken(String scope) throws Exception {
        lock.lock();
        try {
            CachedToken cached = cache.get(scope);
            if (cached != null && !cached.isExpired()) {
                return cached.token;
            }

            // 1. Environment credential (client credentials flow)
            String tenantId   = System.getenv("AZURE_TENANT_ID");
            String clientId   = System.getenv("AZURE_CLIENT_ID");
            String clientSec  = System.getenv("AZURE_CLIENT_SECRET");

            if (notBlank(tenantId) && notBlank(clientId) && notBlank(clientSec)) {
                CachedToken t = fetchClientCredentialsToken(tenantId, clientId, clientSec, scope);
                cache.put(scope, t);
                return t.token;
            }

            // 2. Azure CLI credential
            CachedToken t = fetchAzureCliToken(scope);
            cache.put(scope, t);
            return t.token;

        } finally {
            lock.unlock();
        }
    }

    /** Clear cached tokens (e.g. after config change). */
    public void clearCache() {
        cache.clear();
    }

    // ─── Client credentials (env vars) ───────────────────────────────────────

    private CachedToken fetchClientCredentialsToken(String tenantId, String clientId,
                                                     String clientSecret, String scope) throws Exception {
        String tokenUrl = "https://login.microsoftonline.com/" + tenantId + "/oauth2/v2.0/token";
        String body = "grant_type=client_credentials"
                + "&client_id=" + urlEncode(clientId)
                + "&client_secret=" + urlEncode(clientSecret)
                + "&scope=" + urlEncode(scope);

        HttpURLConnection conn = (HttpURLConnection) new URL(tokenUrl).openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setConnectTimeout(15_000);
        conn.setReadTimeout(15_000);
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.getBytes(StandardCharsets.UTF_8));
        }

        String json = readResponse(conn);

        if (conn.getResponseCode() >= 300) {
            String err = extractJsonString(json, "error_description");
            throw new Exception("Azure token error: " + (err != null ? err : json));
        }

        String token     = extractJsonString(json, "access_token");
        String expiresIn = extractJsonString(json, "expires_in");
        if (token == null) throw new Exception("No access_token in Azure response");

        long ttlMs = expiresIn != null ? Long.parseLong(expiresIn) * 1000L : 3600_000L;
        return new CachedToken(token, System.currentTimeMillis() + ttlMs - 300_000L);
    }

    // ─── Azure CLI ────────────────────────────────────────────────────────────

    private CachedToken fetchAzureCliToken(String scope) throws Exception {
        // `az account get-access-token` returns JSON with accessToken and expiresOn
        ProcessBuilder pb = new ProcessBuilder("az", "account", "get-access-token", "--scope", scope);
        pb.redirectErrorStream(false);
        Process proc;
        try {
            proc = pb.start();
        } catch (Exception e) {
            throw new Exception("Azure CLI not found. Install az CLI or set AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET env vars.");
        }

        StringBuilder out = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) out.append(line);
        }

        int exitCode = proc.waitFor();
        if (exitCode != 0) {
            StringBuilder err = new StringBuilder();
            try (BufferedReader er = new BufferedReader(
                    new InputStreamReader(proc.getErrorStream(), StandardCharsets.UTF_8))) {
                String l;
                while ((l = er.readLine()) != null) err.append(l);
            }
            throw new Exception("az CLI failed (exit " + exitCode + "): " + err);
        }

        String json = out.toString();
        String token = extractJsonString(json, "accessToken");
        if (token == null) throw new Exception("No accessToken in az CLI output: " + json);

        // expiresOn format: "2025-01-01 12:00:00.000000" — treat as 1 hour from now if parsing fails
        long expiry = System.currentTimeMillis() + 3600_000L - 300_000L;
        String expiresOn = extractJsonString(json, "expiresOn");
        if (expiresOn != null) {
            try {
                // Try ISO instant first
                java.time.Instant instant = java.time.Instant.parse(expiresOn);
                expiry = instant.toEpochMilli() - 300_000L;
            } catch (Exception ignored) {
                // az CLI format: "2025-01-01 12:00:00.000000"
                try {
                    java.time.LocalDateTime ldt = java.time.LocalDateTime.parse(
                        expiresOn.substring(0, 19),
                        java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
                    expiry = ldt.toInstant(java.time.ZoneOffset.UTC).toEpochMilli() - 300_000L;
                } catch (Exception ignored2) { /* use default */ }
            }
        }

        return new CachedToken(token, expiry);
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private String readResponse(HttpURLConnection conn) throws Exception {
        boolean error = conn.getResponseCode() >= 300;
        try (BufferedReader br = new BufferedReader(new InputStreamReader(
                error ? conn.getErrorStream() : conn.getInputStream(), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            return sb.toString();
        }
    }

    /** Minimal JSON string-field extractor (no library dependency). */
    private String extractJsonString(String json, String key) {
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1).replace("\\\"", "\"").replace("\\\\", "\\") : null;
    }

    private static String urlEncode(String v) {
        return java.net.URLEncoder.encode(v, StandardCharsets.UTF_8);
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }

    // ─── Token cache entry ────────────────────────────────────────────────────

    private static final class CachedToken {
        final String token;
        final long expiryMs;

        CachedToken(String token, long expiryMs) {
            this.token = token;
            this.expiryMs = expiryMs;
        }

        boolean isExpired() {
            return System.currentTimeMillis() >= expiryMs;
        }
    }
}
