package com.vista.security.core;

import java.util.*;
import java.util.regex.*;

/**
 * SecurityContentExtractor - Intelligent HTTP Response Content Extraction
 * 
 * Instead of blindly truncating large HTTP responses (which loses security-relevant
 * content buried deep in the HTML), this extractor pulls out ONLY the parts that
 * matter for security analysis:
 * 
 *   1. HTTP headers (always kept fully — cookies, CSP, security headers)
 *   2. Areas around reflected parameter values (±200 chars context)
 *   3. All <script> blocks (inline JS often contains vulnerabilities)
 *   4. All <form> elements (hidden fields, action URLs, CSRF tokens)
 *   5. HTML comments (often contain debug info, internal paths, TODOs)
 *   6. Error messages / stack traces
 *   7. Sensitive patterns (API keys, tokens, internal IPs, credentials)
 *   8. <meta> tags (CSP, refresh, sensitive headers)
 *   9. <iframe> / <object> / <embed> tags (injection surfaces)
 *
 * For a 1.6M real estate page, this typically extracts ~15-25K chars of pure
 * security-relevant content — BETTER quality than blind truncation and well
 * within token budgets.
 */
public class SecurityContentExtractor {

    // Maximum budget for extracted content (chars)
    private static final int DEFAULT_BUDGET = 30_000;
    
    // Context window around each reflection point (chars before + after)
    private static final int REFLECTION_CONTEXT = 200;
    
    // Safety limits for production robustness
    private static final int MAX_BODY_FOR_REGEX = 500_000;    // Cap body for regex to prevent slow scans on huge pages
    private static final int MAX_SINGLE_EXTRACTION = 5_000;   // Cap individual extractions (e.g., huge minified JS bundles)
    private static final int FALLBACK_PREVIEW_SIZE = 3_000;   // Body preview when no security-specific patterns found

    /**
     * Extract security-relevant content from a full HTTP response.
     * 
     * @param fullResponse  The complete HTTP response (headers + body)
     * @param paramValues   Parameter values to look for reflections (can be null)
     * @param budget        Max chars for the output (0 = use default 30K)
     * @return Extracted security-relevant content with section labels
     */
    public static String extract(String fullResponse, List<String> paramValues, int budget) {
        if (fullResponse == null || fullResponse.isEmpty()) return "(No response)";
        if (budget <= 0) budget = DEFAULT_BUDGET;
        
        // If the response is already small enough, return it as-is
        if (fullResponse.length() <= budget) return fullResponse;
        
        StringBuilder result = new StringBuilder();
        
        // ═══ 1. HTTP HEADERS (always kept fully) ═══
        String headers = "";
        String body = fullResponse;
        int headerEnd = fullResponse.indexOf("\r\n\r\n");
        if (headerEnd < 0) headerEnd = fullResponse.indexOf("\n\n");
        
        if (headerEnd > 0) {
            headers = fullResponse.substring(0, headerEnd);
            body = fullResponse.substring(headerEnd + (fullResponse.charAt(headerEnd) == '\r' ? 4 : 2));
            result.append(headers).append("\n\n");
        }
        
        // Skip extraction for binary/non-text responses (images, PDFs, etc.)
        if (isNonTextResponse(headers, body)) {
            result.append("[Binary/non-text response — body extraction skipped]\n");
            result.append("Response size: ").append(fullResponse.length()).append(" bytes\n");
            return result.toString();
        }
        
        // Track remaining budget after headers
        int remaining = budget - result.length() - 200; // reserve 200 for summary
        
        // Collect all extractions with labels and dedup overlaps
        List<Extraction> extractions = new ArrayList<>();
        
        // ═══ 2. REFLECTION POINTS — areas where user input appears ═══
        if (paramValues != null) {
            for (String value : paramValues) {
                if (value == null || value.length() < 2) continue;
                
                // Search for exact value and common encoded variants
                List<String> variants = new ArrayList<>();
                variants.add(value);
                variants.add(htmlEncode(value));
                variants.add(value.replace("'", "&#039;").replace("\"", "&quot;"));
                variants.add(value.replace("'", "&#x27;").replace("\"", "&#x22;"));
                
                for (String variant : variants) {
                    int idx = 0;
                    while ((idx = body.indexOf(variant, idx)) >= 0) {
                        int start = Math.max(0, idx - REFLECTION_CONTEXT);
                        int end = Math.min(body.length(), idx + variant.length() + REFLECTION_CONTEXT);
                        extractions.add(new Extraction("REFLECTION [" + value + "]", start, end, 10)); // highest priority
                        idx = end;
                    }
                }
            }
        }
        
        // ═══ 3. SCRIPT BLOCKS — inline JavaScript ═══
        extractByPattern(body, Pattern.compile("<script[^>]*>[\\s\\S]*?</script>", Pattern.CASE_INSENSITIVE),
                "SCRIPT", 8, extractions);
        
        // ═══ 4. FORM ELEMENTS — hidden fields, actions ═══
        extractByPattern(body, Pattern.compile("<form[^>]*>[\\s\\S]*?</form>", Pattern.CASE_INSENSITIVE),
                "FORM", 7, extractions);
        
        // Also catch standalone hidden inputs not inside forms
        extractByPattern(body, Pattern.compile("<input[^>]*type=[\"']?hidden[\"']?[^>]*>", Pattern.CASE_INSENSITIVE),
                "HIDDEN_INPUT", 7, extractions);
        
        // ═══ 5. HTML COMMENTS — debug info, TODOs, internal paths ═══
        extractByPattern(body, Pattern.compile("<!--[\\s\\S]*?-->"),
                "COMMENT", 5, extractions);
        
        // ═══ 6. ERROR MESSAGES / STACK TRACES ═══
        extractByPattern(body, Pattern.compile(
                "(?i)(exception|error|stacktrace|traceback|warning|fatal|debug|at\\s+\\w+\\.\\w+\\()" +
                "[^<]{0,500}"),
                "ERROR", 6, extractions);
        
        // ═══ 7. SENSITIVE PATTERNS ═══
        // API keys
        extractByPattern(body, Pattern.compile(
                "(?i)(api[_-]?key|apikey|api_secret|access[_-]?key|secret[_-]?key|auth[_-]?token)" +
                "\\s*[=:\"']\\s*[\"']?[A-Za-z0-9_\\-]{10,}"),
                "API_KEY", 9, extractions);
        
        // AWS keys
        extractByPattern(body, Pattern.compile("AKIA[0-9A-Z]{16}"),
                "AWS_KEY", 9, extractions);
        
        // JWT tokens
        extractByPattern(body, Pattern.compile("eyJ[A-Za-z0-9_-]{20,}\\.eyJ[A-Za-z0-9_-]{20,}"),
                "JWT", 9, extractions);
        
        // Internal IPs
        extractByPattern(body, Pattern.compile(
                "(?:10\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}|" +
                "192\\.168\\.[0-9]{1,3}\\.[0-9]{1,3}|" +
                "172\\.(?:1[6-9]|2[0-9]|3[01])\\.[0-9]{1,3}\\.[0-9]{1,3})"),
                "PRIVATE_IP", 6, extractions);
        
        // Database connection strings
        extractByPattern(body, Pattern.compile(
                "(?i)(mongodb|mysql|postgres|jdbc|redis|amqp)://[^\\s\"'<]{10,}"),
                "DB_CONNECTION", 9, extractions);
        
        // Hardcoded credentials
        extractByPattern(body, Pattern.compile(
                "(?i)(password|passwd|pwd|secret)\\s*[=:\"']\\s*[\"']?[^\\s\"'<]{3,30}"),
                "CREDENTIAL", 9, extractions);
        
        // ═══ 8. META TAGS ═══
        extractByPattern(body, Pattern.compile("<meta[^>]*>", Pattern.CASE_INSENSITIVE),
                "META", 3, extractions);
        
        // ═══ 9. IFRAME / OBJECT / EMBED ═══
        extractByPattern(body, Pattern.compile(
                "<(?:iframe|object|embed|applet)[^>]*>", Pattern.CASE_INSENSITIVE),
                "EMBED", 6, extractions);
        
        // ═══ 10. EVENT HANDLERS in any tag ═══
        extractByPattern(body, Pattern.compile(
                "<[^>]+\\s+on(?:click|load|error|mouseover|focus|blur|submit|change|input)" +
                "\\s*=\\s*[\"'][^\"']{0,200}[\"'][^>]*>", Pattern.CASE_INSENSITIVE),
                "EVENT_HANDLER", 7, extractions);
        
        // ═══ Sort by priority (highest first), then merge overlapping ranges ═══
        extractions.sort((a, b) -> b.priority - a.priority);
        List<Extraction> merged = mergeOverlapping(extractions);
        
        // ═══ Build output within budget ═══
        int charsUsed = 0;
        int sectionsIncluded = 0;
        
        for (Extraction ext : merged) {
            String content = body.substring(ext.start, ext.end);
            
            // Cap individual extraction size (minified JS bundles can be 500K+)
            if (content.length() > MAX_SINGLE_EXTRACTION) {
                int half = MAX_SINGLE_EXTRACTION / 2;
                content = content.substring(0, half) 
                    + "\n...[" + (content.length() - MAX_SINGLE_EXTRACTION) + " chars of " + ext.label + " omitted]...\n"
                    + content.substring(content.length() - half);
            }
            
            int needed = ext.label.length() + content.length() + 20; // label + content + formatting
            
            if (charsUsed + needed > remaining) {
                // Try to fit a truncated version if it's high priority
                if (ext.priority >= 7 && remaining - charsUsed > 200) {
                    int available = remaining - charsUsed - ext.label.length() - 30;
                    if (available > 100) {
                        result.append("\n--- ").append(ext.label).append(" ---\n");
                        result.append(content, 0, Math.min(content.length(), available));
                        result.append("...[truncated]");
                        charsUsed += available + ext.label.length() + 30;
                        sectionsIncluded++;
                    }
                }
                continue;
            }
            
            result.append("\n--- ").append(ext.label).append(" ---\n");
            result.append(content).append("\n");
            charsUsed += needed;
            sectionsIncluded++;
        }
        
        // Fallback: if no security patterns found, include body preview so AI has something to analyze
        // (common for JSON APIs, plain text responses, clean HTML pages)
        if (sectionsIncluded == 0) {
            int previewLen = Math.min(body.length(), FALLBACK_PREVIEW_SIZE);
            result.append("\n--- BODY PREVIEW (no security-specific patterns detected) ---\n");
            result.append(body, 0, previewLen);
            if (body.length() > previewLen) {
                result.append("\n...[body truncated at ").append(previewLen)
                      .append(" of ").append(body.length()).append(" chars]");
            }
            result.append("\n");
            sectionsIncluded = 1;
        }
        
        // ═══ Add summary footer ═══
        result.append("\n\n[SECURITY EXTRACTION SUMMARY: Extracted ").append(sectionsIncluded)
              .append(" security-relevant sections (").append(result.length()).append(" chars) from ")
              .append(fullResponse.length()).append(" char response. ")
              .append("Removed ").append(fullResponse.length() - result.length())
              .append(" chars of non-security content (page layout, styling, images, text content)]");
        
        return result.toString();
    }
    
    /**
     * Convenience method: extract with no known parameter values.
     */
    public static String extract(String fullResponse, int budget) {
        return extract(fullResponse, null, budget);
    }
    
    /**
     * Extract parameter values from a raw HTTP request string.
     * Looks at URL query parameters and POST body parameters.
     */
    public static List<String> extractParamValues(String requestText) {
        List<String> values = new ArrayList<>();
        if (requestText == null || requestText.isEmpty()) return values;
        
        // Extract from URL query string
        String firstLine = requestText.split("\r?\n")[0];
        int qmark = firstLine.indexOf('?');
        int space = firstLine.lastIndexOf(' ');
        if (qmark > 0 && space > qmark) {
            String query = firstLine.substring(qmark + 1, space);
            extractParamValuesFromString(query, values);
        }
        
        // Extract from POST body
        int bodyStart = requestText.indexOf("\r\n\r\n");
        if (bodyStart < 0) bodyStart = requestText.indexOf("\n\n");
        if (bodyStart > 0) {
            String body = requestText.substring(bodyStart).trim();
            if (!body.isEmpty()) {
                if (body.startsWith("{") || body.startsWith("[")) {
                    // JSON body — extract string values for reflection search
                    extractJsonStringValues(body, values);
                } else {
                    // URL-encoded form body
                    extractParamValuesFromString(body, values);
                }
            }
        }
        
        return values;
    }
    
    private static void extractParamValuesFromString(String paramString, List<String> values) {
        String[] pairs = paramString.split("&");
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            if (eq > 0 && eq < pair.length() - 1) {
                String val = pair.substring(eq + 1);
                try {
                    val = java.net.URLDecoder.decode(val, "UTF-8");
                } catch (Exception e) {
                    // Use as-is
                }
                if (val.length() >= 2) { // Skip very short values like "1" or "a"
                    values.add(val);
                }
            }
        }
    }
    
    // ═══ Internal helpers ═══
    
    private static void extractByPattern(String body, Pattern pattern, String label,
                                          int priority, List<Extraction> extractions) {
        // Safety: cap regex scanning to prevent slow scans on huge bodies (1.6M+)
        // indexOf-based reflection search still uses the full body
        String scanTarget = body.length() > MAX_BODY_FOR_REGEX 
            ? body.substring(0, MAX_BODY_FOR_REGEX) : body;
        Matcher m = pattern.matcher(scanTarget);
        while (m.find()) {
            extractions.add(new Extraction(label, m.start(), m.end(), priority));
        }
    }
    
    private static List<Extraction> mergeOverlapping(List<Extraction> extractions) {
        if (extractions.isEmpty()) return extractions;
        
        // Sort by start position for merging
        List<Extraction> sorted = new ArrayList<>(extractions);
        sorted.sort((a, b) -> a.start - b.start);
        
        List<Extraction> merged = new ArrayList<>();
        Extraction current = sorted.get(0);
        
        for (int i = 1; i < sorted.size(); i++) {
            Extraction next = sorted.get(i);
            if (next.start <= current.end) {
                // Overlapping — merge, keep higher priority label
                String label = current.priority >= next.priority ? current.label : next.label;
                int maxPriority = Math.max(current.priority, next.priority);
                current = new Extraction(label, current.start, Math.max(current.end, next.end), maxPriority);
            } else {
                merged.add(current);
                current = next;
            }
        }
        merged.add(current);
        
        // Re-sort by priority for output ordering
        merged.sort((a, b) -> b.priority - a.priority);
        return merged;
    }
    
    private static String htmlEncode(String s) {
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");
    }
    
    /**
     * Detect binary/non-text HTTP responses that shouldn't be extracted.
     * Checks Content-Type header + body null bytes.
     */
    private static boolean isNonTextResponse(String headers, String body) {
        // Check Content-Type header for known binary types
        if (headers != null && !headers.isEmpty()) {
            String lower = headers.toLowerCase();
            if (lower.contains("image/") || lower.contains("video/") ||
                lower.contains("audio/") || lower.contains("font/") ||
                lower.contains("octet-stream") || lower.contains("/pdf") ||
                lower.contains("/zip") || lower.contains("/gzip") ||
                lower.contains("protobuf") || lower.contains("/grpc") ||
                lower.contains("/woff") || lower.contains("/wasm")) {
                return true;
            }
        }
        // Check body for null bytes (binary content indicator)
        if (body != null) {
            int checkLen = Math.min(body.length(), 512);
            for (int i = 0; i < checkLen; i++) {
                if (body.charAt(i) == '\0') return true;
            }
        }
        return false;
    }
    
    /**
     * Extract string values from JSON request body for reflection searching.
     * Capped at 20 values to prevent excessive reflection searches.
     */
    private static void extractJsonStringValues(String json, List<String> values) {
        Matcher m = Pattern.compile("\"[^\"]{1,50}\"\\s*:\\s*\"([^\"]{2,100})\"").matcher(json);
        int maxValues = 20;
        int count = 0;
        while (m.find() && count < maxValues) {
            String val = m.group(1);
            // Skip URLs, timestamps, UUIDs — not likely user input reflections
            if (val.startsWith("http") || val.matches("\\d{4}-\\d{2}-\\d{2}.*") || 
                val.matches("[0-9a-f]{8}-[0-9a-f]{4}-.*")) continue;
            if (!values.contains(val)) {
                values.add(val);
                count++;
            }
        }
    }
    
    /**
     * Internal class to represent an extracted section.
     */
    private static class Extraction {
        final String label;
        final int start;
        final int end;
        final int priority; // Higher = more important
        
        Extraction(String label, int start, int end, int priority) {
            this.label = label;
            this.start = start;
            this.end = end;
            this.priority = priority;
        }
    }
}
