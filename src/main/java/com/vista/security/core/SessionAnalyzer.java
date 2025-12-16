package com.vista.security.core;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Analyzes HTTP requests/responses for session-related cookies and tokens.
 * Detects common session management patterns and potential security issues.
 */
public final class SessionAnalyzer {
    
    private SessionAnalyzer() {}
    
    // Common session cookie name patterns
    private static final String[] SESSION_COOKIE_PATTERNS = {
        "session", "sess", "sid", "ssid", "jsessionid", "phpsessid", "aspsessionid",
        "asp.net_sessionid", "cfid", "cftoken", "auth", "token", "jwt", "access_token",
        "refresh_token", "id_token", "bearer", "apikey", "api_key", "x-auth", "xsrf",
        "csrf", "_csrf", "remember", "login", "user", "uid", "userid", "identity"
    };
    
    // Patterns that indicate session/auth tokens in headers
    private static final String[] AUTH_HEADER_PATTERNS = {
        "authorization", "x-auth-token", "x-access-token", "x-api-key", "x-csrf-token",
        "x-xsrf-token", "x-session-token", "bearer"
    };

    /**
     * Detected session information from a request/response pair.
     */
    public static class SessionInfo {
        public final List<SessionCookie> cookies = new ArrayList<>();
        public final List<AuthHeader> authHeaders = new ArrayList<>();
        public final List<String> securityIssues = new ArrayList<>();
        public String summary;
        
        public boolean hasSessionData() {
            return !cookies.isEmpty() || !authHeaders.isEmpty();
        }
    }
    
    public static class SessionCookie {
        public final String name;
        public final String value;
        public final boolean isSecure;
        public final boolean isHttpOnly;
        public final String sameSite;
        public final String expires;
        public final CookieType type;
        public final int confidenceScore; // 0-100
        
        public SessionCookie(String name, String value, boolean isSecure, boolean isHttpOnly, 
                           String sameSite, String expires, CookieType type, int confidence) {
            this.name = name;
            this.value = value;
            this.isSecure = isSecure;
            this.isHttpOnly = isHttpOnly;
            this.sameSite = sameSite;
            this.expires = expires;
            this.type = type;
            this.confidenceScore = confidence;
        }
    }
    
    public static class AuthHeader {
        public final String name;
        public final String value;
        public final AuthType type;
        
        public AuthHeader(String name, String value, AuthType type) {
            this.name = name;
            this.value = value;
            this.type = type;
        }
    }
    
    public enum CookieType {
        SESSION_ID, AUTH_TOKEN, CSRF_TOKEN, JWT, API_KEY, REMEMBER_ME, UNKNOWN
    }
    
    public enum AuthType {
        BEARER, BASIC, API_KEY, CUSTOM_TOKEN, UNKNOWN
    }

    /**
     * Analyze a request/response pair for session information.
     */
    public static SessionInfo analyze(IExtensionHelpers helpers, IHttpRequestResponse message) {
        SessionInfo info = new SessionInfo();
        
        if (message == null) return info;
        
        String requestText = message.getRequest() != null 
            ? HttpMessageParser.requestToText(helpers, message.getRequest()) : "";
        String responseText = message.getResponse() != null 
            ? HttpMessageParser.responseToText(helpers, message.getResponse()) : "";
        
        // Analyze request cookies
        analyzeRequestCookies(requestText, info);
        
        // Analyze response Set-Cookie headers
        analyzeResponseCookies(responseText, info);
        
        // Analyze auth headers
        analyzeAuthHeaders(requestText, info);
        
        // Check for security issues
        checkSecurityIssues(info);
        
        // Generate summary
        info.summary = generateSummary(info);
        
        return info;
    }

    private static void analyzeRequestCookies(String requestText, SessionInfo info) {
        String cookieHeader = HttpMessageParser.extractHeader(requestText, "Cookie");
        if (cookieHeader == null || cookieHeader.isBlank()) return;
        
        String[] cookies = cookieHeader.split(";");
        for (String cookie : cookies) {
            cookie = cookie.trim();
            int eq = cookie.indexOf('=');
            if (eq <= 0) continue;
            
            String name = cookie.substring(0, eq).trim();
            String value = cookie.substring(eq + 1).trim();
            
            CookieType type = detectCookieType(name, value);
            int confidence = calculateConfidence(name, value, type);
            
            if (confidence > 30) { // Only include likely session cookies
                info.cookies.add(new SessionCookie(name, value, false, false, null, null, type, confidence));
            }
        }
    }
    
    private static void analyzeResponseCookies(String responseText, SessionInfo info) {
        String[] lines = responseText.split("\\r?\\n");
        
        for (String line : lines) {
            if (line.toLowerCase().startsWith("set-cookie:")) {
                String cookieStr = line.substring(11).trim();
                parseSetCookie(cookieStr, info);
            }
        }
    }
    
    private static void parseSetCookie(String cookieStr, SessionInfo info) {
        String[] parts = cookieStr.split(";");
        if (parts.length == 0) return;
        
        // First part is name=value
        String nameValue = parts[0].trim();
        int eq = nameValue.indexOf('=');
        if (eq <= 0) return;
        
        String name = nameValue.substring(0, eq).trim();
        String value = nameValue.substring(eq + 1).trim();
        
        boolean secure = false;
        boolean httpOnly = false;
        String sameSite = null;
        String expires = null;
        
        for (int i = 1; i < parts.length; i++) {
            String attr = parts[i].trim().toLowerCase();
            if (attr.equals("secure")) secure = true;
            else if (attr.equals("httponly")) httpOnly = true;
            else if (attr.startsWith("samesite=")) sameSite = attr.substring(9);
            else if (attr.startsWith("expires=")) expires = attr.substring(8);
            else if (attr.startsWith("max-age=")) expires = "max-age:" + attr.substring(8);
        }
        
        CookieType type = detectCookieType(name, value);
        int confidence = calculateConfidence(name, value, type);
        
        if (confidence > 30) {
            info.cookies.add(new SessionCookie(name, value, secure, httpOnly, sameSite, expires, type, confidence));
        }
    }
    
    private static void analyzeAuthHeaders(String requestText, SessionInfo info) {
        String[] lines = requestText.split("\\r?\\n");
        
        for (String line : lines) {
            String lower = line.toLowerCase();
            
            for (String pattern : AUTH_HEADER_PATTERNS) {
                if (lower.startsWith(pattern + ":")) {
                    String value = line.substring(pattern.length() + 1).trim();
                    AuthType type = detectAuthType(pattern, value);
                    info.authHeaders.add(new AuthHeader(line.substring(0, pattern.length()), value, type));
                    break;
                }
            }
        }
    }
    
    private static CookieType detectCookieType(String name, String value) {
        String lowerName = name.toLowerCase();
        
        // JWT detection
        if (value.matches("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$")) {
            return CookieType.JWT;
        }
        
        // CSRF token
        if (lowerName.contains("csrf") || lowerName.contains("xsrf") || lowerName.equals("_token")) {
            return CookieType.CSRF_TOKEN;
        }
        
        // Session ID patterns
        if (lowerName.contains("session") || lowerName.contains("sess") || 
            lowerName.equals("sid") || lowerName.equals("ssid") ||
            lowerName.contains("jsessionid") || lowerName.contains("phpsessid") ||
            lowerName.contains("aspsession")) {
            return CookieType.SESSION_ID;
        }
        
        // Auth token
        if (lowerName.contains("auth") || lowerName.contains("token") || 
            lowerName.contains("access") || lowerName.contains("bearer")) {
            return CookieType.AUTH_TOKEN;
        }
        
        // API key
        if (lowerName.contains("api") || lowerName.contains("key")) {
            return CookieType.API_KEY;
        }
        
        // Remember me
        if (lowerName.contains("remember") || lowerName.contains("persistent") ||
            lowerName.contains("stay_logged")) {
            return CookieType.REMEMBER_ME;
        }
        
        return CookieType.UNKNOWN;
    }
    
    private static AuthType detectAuthType(String headerName, String value) {
        String lowerValue = value.toLowerCase();
        
        if (lowerValue.startsWith("bearer ")) return AuthType.BEARER;
        if (lowerValue.startsWith("basic ")) return AuthType.BASIC;
        if (headerName.toLowerCase().contains("api")) return AuthType.API_KEY;
        if (value.matches("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$")) return AuthType.BEARER;
        
        return AuthType.CUSTOM_TOKEN;
    }
    
    private static int calculateConfidence(String name, String value, CookieType type) {
        int score = 0;
        String lowerName = name.toLowerCase();
        
        // Name-based scoring
        for (String pattern : SESSION_COOKIE_PATTERNS) {
            if (lowerName.contains(pattern)) {
                score += 40;
                break;
            }
        }
        
        // Value-based scoring
        if (value.length() > 20) score += 15; // Long values more likely to be tokens
        if (value.matches("^[A-Fa-f0-9]+$")) score += 20; // Hex string
        if (value.matches("^[A-Za-z0-9+/=]+$") && value.length() > 30) score += 15; // Base64-like
        if (type == CookieType.JWT) score += 30;
        if (type != CookieType.UNKNOWN) score += 20;
        
        return Math.min(100, score);
    }
    
    private static void checkSecurityIssues(SessionInfo info) {
        for (SessionCookie cookie : info.cookies) {
            if (cookie.type == CookieType.SESSION_ID || cookie.type == CookieType.AUTH_TOKEN) {
                if (!cookie.isSecure) {
                    info.securityIssues.add("Cookie '" + cookie.name + "' missing Secure flag - vulnerable to MITM");
                }
                if (!cookie.isHttpOnly) {
                    info.securityIssues.add("Cookie '" + cookie.name + "' missing HttpOnly flag - vulnerable to XSS theft");
                }
                if (cookie.sameSite == null || cookie.sameSite.equalsIgnoreCase("none")) {
                    info.securityIssues.add("Cookie '" + cookie.name + "' has weak SameSite - potential CSRF risk");
                }
            }
        }
        
        for (AuthHeader header : info.authHeaders) {
            if (header.type == AuthType.BASIC) {
                info.securityIssues.add("Basic authentication detected - credentials sent with each request");
            }
        }
    }
    
    private static String generateSummary(SessionInfo info) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== SESSION ANALYSIS ===\n\n");
        
        if (!info.cookies.isEmpty()) {
            sb.append("Session Cookies Detected:\n");
            for (SessionCookie c : info.cookies) {
                sb.append("  • ").append(c.name).append(" [").append(c.type).append("]");
                sb.append(" (confidence: ").append(c.confidenceScore).append("%)\n");
                sb.append("    Value: ").append(truncate(c.value, 50)).append("\n");
                if (c.isSecure || c.isHttpOnly || c.sameSite != null) {
                    sb.append("    Flags: ");
                    if (c.isSecure) sb.append("Secure ");
                    if (c.isHttpOnly) sb.append("HttpOnly ");
                    if (c.sameSite != null) sb.append("SameSite=").append(c.sameSite);
                    sb.append("\n");
                }
            }
            sb.append("\n");
        }
        
        if (!info.authHeaders.isEmpty()) {
            sb.append("Auth Headers Detected:\n");
            for (AuthHeader h : info.authHeaders) {
                sb.append("  • ").append(h.name).append(": [").append(h.type).append("]\n");
                sb.append("    Value: ").append(truncate(h.value, 50)).append("\n");
            }
            sb.append("\n");
        }
        
        if (!info.securityIssues.isEmpty()) {
            sb.append("⚠️ Security Issues:\n");
            for (String issue : info.securityIssues) {
                sb.append("  • ").append(issue).append("\n");
            }
            sb.append("\n");
        }
        
        if (!info.hasSessionData()) {
            sb.append("No session cookies or auth headers detected.\n");
        }
        
        return sb.toString();
    }
    
    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
