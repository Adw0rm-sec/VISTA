package com.vista.security.core;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility for detecting and decoding encoded data in HTTP traffic.
 * Supports Base64, JWT, Hex, and URL encoding.
 */
public class DataDecoder {
    
    // Regex patterns for detection
    private static final Pattern BASE64_PATTERN = Pattern.compile("[A-Za-z0-9+/]{20,}={0,2}");
    private static final Pattern JWT_PATTERN = Pattern.compile("eyJ[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]*");
    private static final Pattern HEX_PATTERN = Pattern.compile("[0-9a-fA-F]{32,}");
    private static final Pattern URL_ENCODED_PATTERN = Pattern.compile("(%[0-9A-Fa-f]{2}){3,}");
    
    /**
     * Decoded data result.
     */
    public static class DecodedData {
        public final String original;
        public final String decoded;
        public final String encodingType;
        public final boolean containsSensitiveData;
        public final List<String> sensitiveFindings;
        
        public DecodedData(String original, String decoded, String encodingType) {
            this.original = original;
            this.decoded = decoded;
            this.encodingType = encodingType;
            this.sensitiveFindings = new ArrayList<>();
            this.containsSensitiveData = analyzeSensitiveData(decoded);
        }
        
        private boolean analyzeSensitiveData(String data) {
            if (data == null || data.isEmpty()) return false;
            
            String lower = data.toLowerCase();
            
            // Check for credentials
            if (lower.contains("password") || lower.contains("pwd") || lower.contains("pass")) {
                sensitiveFindings.add("Contains password reference");
                return true;
            }
            if (lower.contains("api_key") || lower.contains("apikey") || lower.contains("api-key")) {
                sensitiveFindings.add("Contains API key reference");
                return true;
            }
            if (lower.contains("token") || lower.contains("secret") || lower.contains("key")) {
                sensitiveFindings.add("Contains token/secret reference");
                return true;
            }
            if (lower.contains("username") || lower.contains("user") || lower.contains("login")) {
                sensitiveFindings.add("Contains username reference");
                return true;
            }
            
            // Check for private IPs
            if (containsPrivateIP(data)) {
                sensitiveFindings.add("Contains private IP address");
                return true;
            }
            
            // Check for email addresses
            if (data.matches(".*[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}.*")) {
                sensitiveFindings.add("Contains email address");
                return true;
            }
            
            return false;
        }
    }
    
    /**
     * JWT token data.
     */
    public static class JWTData {
        public final String header;
        public final String payload;
        public final String signature;
        public final String decodedHeader;
        public final String decodedPayload;
        public final boolean containsSensitiveData;
        public final List<String> sensitiveFindings;
        
        public JWTData(String header, String payload, String signature, 
                      String decodedHeader, String decodedPayload) {
            this.header = header;
            this.payload = payload;
            this.signature = signature;
            this.decodedHeader = decodedHeader;
            this.decodedPayload = decodedPayload;
            this.sensitiveFindings = new ArrayList<>();
            this.containsSensitiveData = analyzeJWTSensitiveData();
        }
        
        private boolean analyzeJWTSensitiveData() {
            String combined = (decodedHeader + " " + decodedPayload).toLowerCase();
            
            // Check for weak algorithms
            if (combined.contains("\"alg\":\"none\"")) {
                sensitiveFindings.add("JWT uses 'none' algorithm (insecure)");
                return true;
            }
            
            // Check for sensitive claims
            if (combined.contains("admin") || combined.contains("role")) {
                sensitiveFindings.add("JWT contains role/admin claims");
                return true;
            }
            if (combined.contains("password") || combined.contains("secret")) {
                sensitiveFindings.add("JWT contains password/secret");
                return true;
            }
            
            // Check for long expiration
            if (combined.contains("\"exp\"")) {
                sensitiveFindings.add("JWT has expiration claim");
            }
            
            return !sensitiveFindings.isEmpty();
        }
    }
    
    /**
     * Detect and decode Base64 data.
     */
    public static List<DecodedData> detectAndDecodeBase64(String content) {
        List<DecodedData> results = new ArrayList<>();
        if (content == null) return results;
        
        Matcher matcher = BASE64_PATTERN.matcher(content);
        while (matcher.find()) {
            String encoded = matcher.group();
            try {
                byte[] decoded = Base64.getDecoder().decode(encoded);
                String decodedStr = new String(decoded, StandardCharsets.UTF_8);
                
                // Only include if decoded string is printable
                if (isPrintable(decodedStr)) {
                    results.add(new DecodedData(encoded, decodedStr, "Base64"));
                }
            } catch (Exception e) {
                // Not valid Base64, skip
            }
        }
        
        return results;
    }
    
    /**
     * Detect and decode JWT tokens.
     */
    public static List<JWTData> detectAndDecodeJWT(String content) {
        List<JWTData> results = new ArrayList<>();
        if (content == null) return results;
        
        Matcher matcher = JWT_PATTERN.matcher(content);
        while (matcher.find()) {
            String jwt = matcher.group();
            try {
                String[] parts = jwt.split("\\.");
                if (parts.length >= 2) {
                    String header = parts[0];
                    String payload = parts[1];
                    String signature = parts.length > 2 ? parts[2] : "";
                    
                    // Decode header and payload (Base64URL)
                    String decodedHeader = decodeBase64URL(header);
                    String decodedPayload = decodeBase64URL(payload);
                    
                    results.add(new JWTData(header, payload, signature, 
                                           decodedHeader, decodedPayload));
                }
            } catch (Exception e) {
                // Not valid JWT, skip
            }
        }
        
        return results;
    }
    
    /**
     * Detect and decode hex data.
     */
    public static List<DecodedData> detectAndDecodeHex(String content) {
        List<DecodedData> results = new ArrayList<>();
        if (content == null) return results;
        
        Matcher matcher = HEX_PATTERN.matcher(content);
        while (matcher.find()) {
            String hex = matcher.group();
            try {
                String decoded = hexToString(hex);
                
                // Only include if decoded string is printable
                if (isPrintable(decoded)) {
                    results.add(new DecodedData(hex, decoded, "Hex"));
                }
            } catch (Exception e) {
                // Not valid hex, skip
            }
        }
        
        return results;
    }
    
    /**
     * Detect and decode URL encoded data.
     */
    public static List<DecodedData> detectAndDecodeURL(String content) {
        List<DecodedData> results = new ArrayList<>();
        if (content == null) return results;
        
        Matcher matcher = URL_ENCODED_PATTERN.matcher(content);
        while (matcher.find()) {
            String encoded = matcher.group();
            try {
                String decoded = java.net.URLDecoder.decode(encoded, StandardCharsets.UTF_8);
                
                // Only include if significantly different from original
                if (!encoded.equals(decoded) && isPrintable(decoded)) {
                    results.add(new DecodedData(encoded, decoded, "URL"));
                }
            } catch (Exception e) {
                // Not valid URL encoding, skip
            }
        }
        
        return results;
    }
    
    /**
     * Decode Base64URL (used in JWT).
     */
    private static String decodeBase64URL(String base64URL) {
        // Convert Base64URL to standard Base64
        String base64 = base64URL.replace('-', '+').replace('_', '/');
        
        // Add padding if needed
        int padding = (4 - base64.length() % 4) % 4;
        for (int i = 0; i < padding; i++) {
            base64 += "=";
        }
        
        byte[] decoded = Base64.getDecoder().decode(base64);
        return new String(decoded, StandardCharsets.UTF_8);
    }
    
    /**
     * Convert hex string to regular string.
     */
    private static String hexToString(String hex) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            String str = hex.substring(i, i + 2);
            result.append((char) Integer.parseInt(str, 16));
        }
        return result.toString();
    }
    
    /**
     * Check if string contains mostly printable characters.
     */
    private static boolean isPrintable(String str) {
        if (str == null || str.isEmpty()) return false;
        
        int printable = 0;
        for (char c : str.toCharArray()) {
            if (c >= 32 && c <= 126) {
                printable++;
            }
        }
        
        // At least 80% printable
        return (double) printable / str.length() >= 0.8;
    }
    
    /**
     * Check if content contains private IP addresses.
     */
    public static boolean containsPrivateIP(String content) {
        if (content == null) return false;
        
        // 10.x.x.x
        if (content.matches(".*\\b10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b.*")) return true;
        
        // 172.16-31.x.x
        if (content.matches(".*\\b172\\.(1[6-9]|2[0-9]|3[0-1])\\.\\d{1,3}\\.\\d{1,3}\\b.*")) return true;
        
        // 192.168.x.x
        if (content.matches(".*\\b192\\.168\\.\\d{1,3}\\.\\d{1,3}\\b.*")) return true;
        
        // 127.x.x.x
        if (content.matches(".*\\b127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b.*")) return true;
        
        return false;
    }
    
    /**
     * Extract private IP addresses from content.
     */
    public static List<String> extractPrivateIPs(String content) {
        List<String> ips = new ArrayList<>();
        if (content == null) return ips;
        
        Pattern ipPattern = Pattern.compile(
            "\\b(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|" +
            "172\\.(1[6-9]|2[0-9]|3[0-1])\\.\\d{1,3}\\.\\d{1,3}|" +
            "192\\.168\\.\\d{1,3}\\.\\d{1,3}|" +
            "127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b"
        );
        
        Matcher matcher = ipPattern.matcher(content);
        while (matcher.find()) {
            ips.add(matcher.group());
        }
        
        return ips;
    }
}
